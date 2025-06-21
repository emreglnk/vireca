import os
import requests
import base64
import httpx
from datetime import datetime, timedelta
from typing import Optional, List
from dotenv import load_dotenv
from fastapi import FastAPI, UploadFile, File, HTTPException, Body, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from jose import JWTError, jwt

from soroban_rpc_client import Server
from stellar_sdk import Keypair, TransactionBuilder
from stellar_sdk.xdr import SCVal

# .env dosyasındaki ayarları yükle
load_dotenv()

# --- Yapılandırma ---
LAUNCHTUBE_API_KEY = os.getenv("LAUNCHTUBE_API_KEY")
LAUNCHTUBE_BASE_URL = os.getenv("LAUNCHTUBE_BASE_URL", "https://api.launchtube.xyz")
LAUNCHTUBE_NETWORK = os.getenv("LAUNCHTUBE_NETWORK", "testnet")

PINATA_JWT = os.getenv("PINATA_JWT")
CONTRACT_ID = os.getenv("CONTRACT_ID")
NETWORK_PASSPHRASE = os.getenv("NETWORK_PASSPHRASE")
RPC_URL = os.getenv("RPC_URL")

IPFS_GATEWAY_URL = os.getenv("IPFS_GATEWAY_URL", "https://gateway.pinata.cloud/ipfs/")
IPFS_PIN_URL = os.getenv("IPFS_PIN_URL", "https://api.pinata.cloud/pinning/pinFileToIPFS")

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-super-secret-jwt-key-change-this-in-production")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))

MAX_FILE_SIZE_MB = int(os.getenv("MAX_FILE_SIZE_MB", "50"))
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000,https://launchtube.xyz").split(",")

# FastAPI ve Soroban Sunucu Bağlantısı
app = FastAPI(
    title="Vireca Backend API - Launchtube Edition",
    version="1.0.0",
    description="Launchtube platformu için özel olarak geliştirilmiş sağlık veri yönetimi API'si"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

server = Server(RPC_URL)
security = HTTPBearer()

# --- API Modelleri (Pydantic) ---
class LaunchtubeUser(BaseModel):
    public_key: str
    username: Optional[str] = None
    email: Optional[str] = None
    profile_id: Optional[str] = None

class PrepareRegisterRequest(BaseModel):
    owner_public_key: str
    encrypted_key_for_owner: str = Field(..., description="Base64 encoded encrypted data key")
    metadata: Optional[dict] = Field(None, description="Ek metadata bilgileri")

class PrepareGrantRequest(BaseModel):
    granter_public_key: str
    doctor_public_key: str
    ipfs_hash: str
    encrypted_key_for_doctor: str = Field(..., description="Base64 encoded encrypted data key")
    duration_in_ledgers: int = Field(..., gt=0, description="Number of ledgers for permission validity (~5s per ledger)")
    access_reason: Optional[str] = Field(None, description="Erişim nedeni")

class PrepareRevokeRequest(BaseModel):
    granter_public_key: str
    doctor_public_key: str
    ipfs_hash: str
    revoke_reason: Optional[str] = Field(None, description="İptal nedeni")

class SubmitRequest(BaseModel):
    signed_xdr: str
    launchtube_signature: Optional[str] = Field(None, description="Launchtube platform imzası")

class LaunchtubeAuthRequest(BaseModel):
    public_key: str
    signature: str
    message: str

class HealthDataMetadata(BaseModel):
    title: str
    description: Optional[str] = None
    data_type: str  # "medical_report", "lab_result", "prescription", etc.
    tags: Optional[List[str]] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

# --- Yardımcı Fonksiyonlar ---
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        public_key: str = payload.get("sub")
        if public_key is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token geçersiz",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return public_key
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token geçersiz",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def verify_launchtube_user(public_key: str) -> LaunchtubeUser:
    """Launchtube platformundan kullanıcı bilgilerini doğrular"""
    try:
        headers = {
            "Authorization": f"Bearer {LAUNCHTUBE_API_KEY}",
            "Content-Type": "application/json"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{LAUNCHTUBE_BASE_URL}/users/{public_key}",
                headers=headers
            )
            
        if response.status_code == 200:
            user_data = response.json()
            return LaunchtubeUser(**user_data)
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Launchtube kullanıcısı bulunamadı"
            )
    except httpx.RequestError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Launchtube servisi geçici olarak kullanılamıyor"
        )

def build_and_prepare_transaction(source_public_key: str, contract_function: str, parameters: list[SCVal]) -> str:
    """Tekrar eden işlem oluşturma ve hazırlama mantığını soyutlar."""
    try:
        source_account = server.get_account(source_public_key)
        source_keypair = Keypair.from_public_key(source_public_key)

        tx_builder = TransactionBuilder(
            source_account=source_account,
            network_passphrase=NETWORK_PASSPHRASE,
            base_fee=100,
        )
        tx_builder.append_invoke_contract_function_op(
            contract_id=CONTRACT_ID,
            function_name=contract_function,
            parameters=parameters,
        )
        
        transaction = tx_builder.build()
        prepared_transaction = server.prepare_transaction(transaction)
        return prepared_transaction.to_xdr()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"İşlem hazırlama hatası: {str(e)}"
        )

async def upload_to_ipfs_with_metadata(file_content: bytes, filename: str, metadata: dict = None) -> str:
    """IPFS'e dosya ve metadata yükler"""
    try:
        files = {"file": (filename, file_content)}
        
        if metadata:
            files["pinataMetadata"] = (None, str(metadata))
        
        headers = {"Authorization": f"Bearer {PINATA_JWT}"}
        
        async with httpx.AsyncClient() as client:
            response = await client.post(IPFS_PIN_URL, files=files, headers=headers)
            response.raise_for_status()
            
        return response.json()["IpfsHash"]
    except httpx.RequestError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"IPFS Upload Error: {str(e)}"
        )

# --- API ENDPOINTS ---

@app.post("/auth/launchtube", summary="Launchtube platformu ile kimlik doğrulama")
async def authenticate_with_launchtube(request: LaunchtubeAuthRequest):
    """Launchtube kullanıcısını doğrular ve JWT token oluşturur"""
    
    # Launchtube kullanıcısını doğrula
    user = await verify_launchtube_user(request.public_key)
    
    # JWT token oluştur
    access_token = create_access_token(
        data={"sub": request.public_key, "username": user.username}
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user,
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }

@app.post("/prepare/register-data", summary="Launchtube kullanıcısı için veri kaydı hazırlar")
async def prepare_register_data(
    request: PrepareRegisterRequest,
    file: UploadFile = File(...),
    current_user: str = Depends(verify_token)
):
    """Launchtube kullanıcısı için sağlık verisi kaydı hazırlar"""
    
    # Dosya boyutu kontrolü
    if file.size > MAX_FILE_SIZE_MB * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Dosya boyutu {MAX_FILE_SIZE_MB}MB'dan büyük olamaz"
        )
    
    # Kullanıcı doğrulama
    if current_user != request.owner_public_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Sadece kendi verilerinizi kaydedebilirsiniz"
        )
    
    # Launchtube kullanıcısını doğrula
    user = await verify_launchtube_user(request.owner_public_key)
    
    # Dosyayı oku
    file_content = await file.read()
    
    # Metadata hazırla
    metadata = {
        "uploader": user.username or request.owner_public_key,
        "filename": file.filename,
        "content_type": file.content_type,
        "upload_date": datetime.utcnow().isoformat(),
        "platform": "launchtube",
        **(request.metadata or {})
    }
    
    # IPFS'e yükle
    ipfs_hash = await upload_to_ipfs_with_metadata(file_content, file.filename, metadata)
    
    # Smart contract parametrelerini hazırla
    ipfs_hash_bytes = ipfs_hash.encode('utf-8')
    encrypted_key_bytes = base64.b64decode(request.encrypted_key_for_owner)
    
    params = [
        SCVal.from_bytes(ipfs_hash_bytes),
        SCVal.from_bytes(encrypted_key_bytes),
    ]

    unsigned_xdr = build_and_prepare_transaction(
        request.owner_public_key, 
        "register_data", 
        params
    )
    
    return {
        "unsigned_xdr": unsigned_xdr,
        "ipfs_hash": ipfs_hash,
        "ipfs_url": f"{IPFS_GATEWAY_URL}{ipfs_hash}",
        "metadata": metadata,
        "user": user
    }

@app.post("/prepare/grant-access", summary="Launchtube doktoruna erişim izni verme")
async def prepare_grant_access(
    request: PrepareGrantRequest,
    current_user: str = Depends(verify_token)
):
    """Launchtube doktoruna sağlık verisi erişim izni verme"""
    
    # Kullanıcı doğrulama
    if current_user != request.granter_public_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Sadece kendi verilerinize erişim izni verebilirsiniz"
        )
    
    # Hasta ve doktor bilgilerini doğrula
    granter = await verify_launchtube_user(request.granter_public_key)
    doctor = await verify_launchtube_user(request.doctor_public_key)
    
    # Smart contract parametrelerini hazırla
    params = [
        SCVal.from_address(request.doctor_public_key),
        SCVal.from_bytes(request.ipfs_hash.encode('utf-8')),
        SCVal.from_bytes(base64.b64decode(request.encrypted_key_for_doctor)),
        SCVal.from_u32(request.duration_in_ledgers)
    ]
    
    unsigned_xdr = build_and_prepare_transaction(
        request.granter_public_key, 
        "grant_access", 
        params
    )
    
    return {
        "unsigned_xdr": unsigned_xdr,
        "granter": granter,
        "doctor": doctor,
        "duration_hours": request.duration_in_ledgers * 5 / 3600,  # Yaklaşık saat cinsinden
        "access_reason": request.access_reason
    }

@app.post("/prepare/revoke-access", summary="Launchtube doktorunun erişim iznini iptal etme")
async def prepare_revoke_access(
    request: PrepareRevokeRequest,
    current_user: str = Depends(verify_token)
):
    """Launchtube doktorunun erişim iznini iptal etme"""
    
    # Kullanıcı doğrulama
    if current_user != request.granter_public_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Sadece kendi verilerinizin erişim iznini iptal edebilirsiniz"
        )
    
    # Kullanıcı bilgilerini doğrula
    granter = await verify_launchtube_user(request.granter_public_key)
    doctor = await verify_launchtube_user(request.doctor_public_key)
    
    params = [
        SCVal.from_address(request.doctor_public_key),
        SCVal.from_bytes(request.ipfs_hash.encode('utf-8')),
    ]
    
    unsigned_xdr = build_and_prepare_transaction(
        request.granter_public_key, 
        "revoke_access", 
        params
    )
    
    return {
        "unsigned_xdr": unsigned_xdr,
        "granter": granter,
        "doctor": doctor,
        "revoke_reason": request.revoke_reason
    }

@app.post("/transaction/submit", summary="İmzalı işlemi Launchtube ile Stellar ağına gönderir")
async def submit_transaction(
    request: SubmitRequest,
    current_user: str = Depends(verify_token)
):
    """İmzalı işlemi Stellar ağına gönderir"""
    try:
        # Launchtube imzası varsa doğrula
        if request.launchtube_signature:
            # Launchtube platform imzasını doğrula
            headers = {
                "Authorization": f"Bearer {LAUNCHTUBE_API_KEY}",
                "Content-Type": "application/json"
            }
            
            async with httpx.AsyncClient() as client:
                verify_response = await client.post(
                    f"{LAUNCHTUBE_BASE_URL}/verify-signature",
                    json={
                        "xdr": request.signed_xdr,
                        "signature": request.launchtube_signature,
                        "user": current_user
                    },
                    headers=headers
                )
                
            if verify_response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Launchtube imzası doğrulanamadı"
                )
        
        # İşlemi Stellar ağına gönder
        tx_result = await server.send_transaction(request.signed_xdr)
        
        if tx_result.status == "FAILED":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"İşlem başarısız: {tx_result.result_xdr}"
            )
        
        return {
            "status": "success",
            "result": tx_result,
            "network": LAUNCHTUBE_NETWORK,
            "processed_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"İşlem gönderme hatası: {str(e)}"
        )

@app.get("/health", summary="Launchtube API sağlık durumu")
async def health_check():
    """API ve bağlantı durumunu kontrol eder"""
    try:
        # Stellar ağı bağlantısını test et
        stellar_status = "connected"
        try:
            await server.get_health()
        except:
            stellar_status = "disconnected"
            
        # Launchtube API bağlantısını test et
        launchtube_status = "connected"
        try:
            async with httpx.AsyncClient() as client:
                health_response = await client.get(
                    f"{LAUNCHTUBE_BASE_URL}/health",
                    headers={"Authorization": f"Bearer {LAUNCHTUBE_API_KEY}"}
                )
                if health_response.status_code != 200:
                    launchtube_status = "disconnected"
        except:
            launchtube_status = "disconnected"
            
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "services": {
                "stellar_network": stellar_status,
                "launchtube_platform": launchtube_status,
                "ipfs_gateway": "connected" if PINATA_JWT else "not_configured"
            },
            "version": "1.0.0",
            "platform": "launchtube"
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Sağlık kontrolü başarısız: {str(e)}"
        )

@app.get("/")
def read_root():
    return {
        "message": "Vireca Backend API - Launchtube Edition is running!",
        "platform": "launchtube",
        "version": "1.0.0",
        "docs_url": "/docs"
    }