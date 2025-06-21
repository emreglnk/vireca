import os
import requests
import base64
import httpx
import json
from datetime import datetime, timedelta
from typing import Optional, List
from dotenv import load_dotenv
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Body, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from jose import JWTError, jwt

from stellar_sdk import Keypair, TransactionBuilder, SorobanServer
from stellar_sdk.scval import to_bytes, to_address, to_uint32
from crypto_utils import VireacaCrypto

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

server = SorobanServer(RPC_URL)
security = HTTPBearer()

# In-memory storage for uploaded files (In production, use a database)
uploaded_files = {}  # {user_public_key: [file_info_dict, ...]}

# In-memory storage for data keys in test mode (In production, use a database)
test_data_keys = {}  # {ipfs_hash: data_key_bytes}

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
        # Test mode için mock token kontrolü
        if credentials.credentials.startswith("mock_token_"):
            # Mock token formatı: mock_token_patient_timestamp veya mock_token_doctor_timestamp
            parts = credentials.credentials.split("_")
            if len(parts) >= 3:
                wallet_type = parts[2]
                if wallet_type == "patient":
                    return WALLETS["patient"] if "WALLETS" in globals() else "GA5HNMXP4XZL634C3DXKU6AM5WAJ6OKMOIKZ2R3SN22WZXRKCS2XA4MZ"
                elif wallet_type == "doctor":
                    return WALLETS["doctor"] if "WALLETS" in globals() else "GDOCTOREXAMPLEADDRESS1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        
        # Gerçek JWT doğrulama
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

def build_and_prepare_transaction(source_public_key: str, contract_function: str, parameters: list) -> str:
    """Tekrar eden işlem oluşturma ve hazırlama mantığını soyutlar."""
    try:
        # SorobanServer'da load_account kullanılıyor (get_account değil)
        source_account = server.load_account(source_public_key)
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
    """IPFS'e dosya ve metadata yükler - Pinata API v3 uyumlu"""
    try:
        # Pinata API güncel format kontrolü
        if not PINATA_JWT:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="PINATA_JWT environment variable is not set"
            )
        
        # Basit multipart form data (v3 API ile uyumlu)
        files = {
            "file": (filename, file_content, "application/octet-stream")
        }
        
        # Metadata formatting (yeni API formatı)
        data = {}
        if metadata:
            # Pinata v3 metadata format
            pinata_metadata = {
                "name": filename,
                "keyvalues": {
                    # Sadece string değerleri metadata olarak ekle
                    str(k): str(v) for k, v in metadata.items() if v is not None
                }
            }
            data["pinataMetadata"] = json.dumps(pinata_metadata)
            
            # CID version (optional)
            data["pinataOptions"] = json.dumps({"cidVersion": 1})
        
        headers = {
            "Authorization": f"Bearer {PINATA_JWT}"
        }
        
        # Debug için request bilgilerini yazdır
        print(f"📤 Uploading to IPFS: {filename} ({len(file_content)} bytes)")
        print(f"🔑 Auth header: Bearer {PINATA_JWT[:20]}...")
        if metadata:
            print(f"📋 Metadata keys ({len(metadata)}): {list(metadata.keys())}")
        
        # Timeout ve retry ile daha güvenilir upload
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                IPFS_PIN_URL, 
                files=files, 
                data=data, 
                headers=headers
            )
            
            # Detailed response debugging
            print(f"📥 Response Status: {response.status_code}")
            if response.status_code != 200:
                print(f"❌ Response Body: {response.text}")
                print(f"📋 Request Headers: {headers}")
                print(f"📋 Request URL: {IPFS_PIN_URL}")
                
            response.raise_for_status()
            result = response.json()
            
        print(f"✅ IPFS Upload Success: {result.get('IpfsHash', 'Unknown')}")
        return result["IpfsHash"]
        
    except httpx.HTTPStatusError as e:
        error_detail = f"HTTP {e.response.status_code}: {e.response.text}"
        print(f"❌ IPFS Upload HTTP Error: {error_detail}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"IPFS Upload HTTP Error: {error_detail}"
        )
    except httpx.TimeoutException:
        print(f"⏰ IPFS Upload Timeout")
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="IPFS Upload Timeout - file too large or network issue"
        )
    except Exception as e:
        print(f"💥 IPFS Upload General Error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"IPFS Upload Error: {str(e)}"
        )

async def upload_to_ipfs_simple(file_content: bytes, filename: str) -> str:
    """IPFS'e sadece dosya yükler (metadata olmadan)"""
    try:
        # Basit file upload - metadata yok
        files = {
            "file": (filename, file_content, "application/octet-stream")
        }
        
        headers = {
            "Authorization": f"Bearer {PINATA_JWT}"
        }
        
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                IPFS_PIN_URL, 
                files=files, 
                headers=headers
            )
            
            if response.status_code != 200:
                print(f"Pinata Simple Upload Error: {response.status_code}")
                print(f"Response: {response.text}")
                
            response.raise_for_status()
            result = response.json()
            
        return result["IpfsHash"]
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"IPFS Simple Upload Error: {str(e)}"
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
    file: UploadFile = File(...),
    owner_public_key: str = Form(...),
    patient_signature: str = Form(..., description="Patient signature for 'Vireca_key_v1'"),
    metadata: str = Form(None),
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
    if current_user != owner_public_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Sadece kendi verilerinizi kaydedebilirsiniz"
        )
    
    # Test mode için mock user veya gerçek Launchtube kullanıcısını doğrula
    try:
        user = await verify_launchtube_user(owner_public_key)
    except HTTPException:
        # Test mode için mock user oluştur
        user = LaunchtubeUser(
            public_key=owner_public_key,
            username=f"test_user_{owner_public_key[:8]}",
            email="test@example.com"
        )
    
    # Dosyayı oku
    file_content = await file.read()
    
    # === ENCRYPTION FLOW ===
    crypto = VireacaCrypto()
    
    # 1. Generate AES-256 data key
    data_key = crypto.generate_data_key()
    
    # 2. Encrypt medical data
    encrypted_data = crypto.encrypt_data(file_content, data_key)
    
    # 3. Derive patient key from signature
    try:
        # Test mode için mock signature kontrolü
        if patient_signature.startswith("mock_"):
            # Mock signature için deterministic key oluştur
            patient_key = crypto.derive_patient_key_from_mock(patient_signature)
        else:
            # Gerçek signature doğrulama
            if not VireacaCrypto.verify_stellar_signature(
                owner_public_key, 
                VireacaCrypto.FIXED_SIGNATURE_MESSAGE, 
                patient_signature
            ):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid patient signature for key derivation"
                )
            patient_key = crypto.derive_patient_key(patient_signature)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Signature processing error: {str(e)}"
        )
    
    # 4. Encrypt data key for patient
    encrypted_data_key_for_patient = crypto.encrypt_data_key_for_patient(data_key, patient_key)
    
    # Metadata parse et ve hazırla
    parsed_metadata = {}
    if metadata:
        try:
            parsed_metadata = json.loads(metadata)
        except json.JSONDecodeError:
            parsed_metadata = {}
    
    # Pinata metadata limit: maksimum 10 key-value pair
    base_metadata = {
        "filename": file.filename,
        "platform": "launchtube",
        "encrypted": "true",  # Boolean'ı string'e çevir
        "upload_date": datetime.utcnow().strftime("%Y-%m-%d"),  # Kısa format
    }
    
    # Kullanıcıdan gelen metadata'dan sadece ilk 6 tanesini al (4+6=10)
    if parsed_metadata:
        limited_metadata = {}
        count = 0
        for key, value in parsed_metadata.items():
            if count < 6:  # 4 base + 6 user = 10 total
                limited_metadata[str(key)] = str(value)
                count += 1
            else:
                break
        base_metadata.update(limited_metadata)
    
    metadata_dict = base_metadata
    
    # Gerçek IPFS upload - encrypted data'yı yükle
    try:
        ipfs_hash = await upload_to_ipfs_with_metadata(
            encrypted_data, 
            f"encrypted_{file.filename}",
            metadata_dict
        )
    except HTTPException as e:
        # İlk denemede metadata ile hata aldıysak, metadata olmadan dene
        if "400" in str(e.detail) or "key values" in str(e.detail).lower():
            try:
                print("🔄 Metadata limitini aştı - metadata olmadan deneniyor...")
                ipfs_hash = await upload_to_ipfs_simple(
                    encrypted_data, 
                    f"encrypted_{file.filename}"
                )
                print("✅ Metadata olmadan upload başarılı!")
            except Exception as e2:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"IPFS upload failed both with and without metadata: {str(e2)}"
                )
        else:
            raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"IPFS upload failed: {str(e)}"
        )
    
    # Smart contract parametrelerini hazırla
    ipfs_hash_bytes = ipfs_hash.encode('utf-8')
    encrypted_key_bytes = base64.b64decode(encrypted_data_key_for_patient)
    
    params = [
        to_bytes(ipfs_hash_bytes),
        to_bytes(encrypted_key_bytes),
    ]

    # Test mode için mock transaction XDR, production'da gerçek transaction building
    if patient_signature.startswith("mock_"):
        # Mock transaction XDR (test mode)
        unsigned_xdr = f"mock_xdr_{hash(ipfs_hash + owner_public_key)}"
    else:
        # Gerçek transaction building
        unsigned_xdr = build_and_prepare_transaction(
            owner_public_key, 
            "register_data", 
            params
        )
    
    # Dosya bilgilerini memory'de sakla (production'da database kullan)
    file_info = {
        "id": f"file_{hash(ipfs_hash)}",
        "filename": file.filename,
        "original_filename": file.filename,
        "encrypted_filename": f"encrypted_{file.filename}",
        "ipfs_hash": ipfs_hash,
        "ipfs_url": f"{IPFS_GATEWAY_URL}{ipfs_hash}",
        "file_size": len(file_content),
        "encrypted_size": len(encrypted_data),
        "content_type": file.content_type,
        "upload_date": datetime.utcnow().isoformat(),
        "metadata": metadata_dict,
        "owner_public_key": owner_public_key,
        "encrypted_data_key": encrypted_data_key_for_patient,
        "status": "uploaded",
        "blockchain_status": "pending"
    }
    
    # User'ın dosya listesine ekle
    if owner_public_key not in uploaded_files:
        uploaded_files[owner_public_key] = []
    uploaded_files[owner_public_key].append(file_info)
    
    # Test mode için data key'i sakla
    if patient_signature.startswith("mock_"):
        test_data_keys[ipfs_hash] = data_key
    
    return {
        "unsigned_xdr": unsigned_xdr,
        "ipfs_hash": ipfs_hash,
        "ipfs_url": f"{IPFS_GATEWAY_URL}{ipfs_hash}",
        "metadata": metadata_dict,
        "user": user,
        "file_info": file_info
    }

@app.post("/prepare/grant-access", summary="Launchtube doktoruna erişim izni verme")
async def prepare_grant_access(
    granter_public_key: str = Form(...),
    doctor_public_key: str = Form(...),
    ipfs_hash: str = Form(...),
    patient_signature: str = Form(..., description="Patient signature for 'Vireca_key_v1'"),
    patient_encrypted_data_key: str = Form(..., description="Patient's encrypted data key from blockchain"),
    duration_in_ledgers: int = Form(..., gt=0),
    access_reason: str = Form(None),
    current_user: str = Depends(verify_token)
):
    """Launchtube doktoruna sağlık verisi erişim izni verme"""
    
    # Kullanıcı doğrulama
    if current_user != granter_public_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Sadece kendi verilerinize erişim izni verebilirsiniz"
        )
    
    # === DOCTOR SHARING CRYPTO FLOW ===
    crypto = VireacaCrypto()
    
    # 1. Derive patient key from signature
    try:
        # Test mode için mock signature kontrolü
        if patient_signature.startswith("mock_"):
            patient_key = crypto.derive_patient_key_from_mock(patient_signature)
        else:
            # Gerçek signature doğrulama
            if not VireacaCrypto.verify_stellar_signature(
                granter_public_key, 
                VireacaCrypto.FIXED_SIGNATURE_MESSAGE, 
                patient_signature
            ):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid patient signature for key derivation"
                )
            patient_key = crypto.derive_patient_key(patient_signature)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Signature processing error: {str(e)}"
        )
    
    # 2. Decrypt data key with patient key
    try:
        # Test mode için stored data key kullan
        if patient_signature.startswith("mock_"):
            # Test mode: use the stored real data key for this IPFS hash
            if ipfs_hash in test_data_keys:
                data_key = test_data_keys[ipfs_hash]
            else:
                # Fallback to mock data key if not found
                data_key = b"mock_data_key_32_bytes_for_test_!"
        else:
            data_key = crypto.decrypt_data_key_for_patient(patient_encrypted_data_key, patient_key)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to decrypt data key: {str(e)}"
        )
    
    # 3. Re-encrypt data key for doctor
    if patient_signature.startswith("mock_"):
        # Mock encrypted data key for doctor (test mode)
        encrypted_data_key_for_doctor = f"mock_doctor_key_{hash(doctor_public_key)}"
    else:
        encrypted_data_key_for_doctor = crypto.encrypt_data_key_for_doctor(data_key, doctor_public_key)
    
    # Test mode için mock user veya gerçek Launchtube kullanıcılarını doğrula
    try:
        granter = await verify_launchtube_user(granter_public_key)
    except HTTPException:
        granter = LaunchtubeUser(
            public_key=granter_public_key,
            username=f"test_patient_{granter_public_key[:8]}",
            email="patient@example.com"
        )
    
    try:
        doctor = await verify_launchtube_user(doctor_public_key)
    except HTTPException:
        doctor = LaunchtubeUser(
            public_key=doctor_public_key,
            username=f"test_doctor_{doctor_public_key[:8]}",
            email="doctor@example.com"
        )
    
    # Test mode için mock transaction XDR, production'da gerçek transaction building
    if patient_signature.startswith("mock_"):
        # Mock transaction XDR (test mode)
        unsigned_xdr = f"mock_grant_xdr_{hash(granter_public_key + doctor_public_key + ipfs_hash)}"
    else:
        # Smart contract parametrelerini hazırla
        params = [
            to_address(doctor_public_key),
            to_bytes(ipfs_hash.encode('utf-8')),
            to_bytes(base64.b64decode(encrypted_data_key_for_doctor)),
            to_uint32(duration_in_ledgers)
        ]
        
        unsigned_xdr = build_and_prepare_transaction(
            granter_public_key, 
            "grant_access", 
            params
        )
    
    return {
        "unsigned_xdr": unsigned_xdr,
        "granter": granter,
        "doctor": doctor,
        "duration_hours": duration_in_ledgers * 5 / 3600,  # Yaklaşık saat cinsinden
        "access_reason": access_reason,
        "encrypted_data_key_for_doctor": encrypted_data_key_for_doctor,
        "crypto_status": "Data key successfully re-encrypted for doctor"
    }

@app.post("/doctor/decrypt-data", summary="Doctor'ın encrypted data'yı decrypt etmesi")
async def doctor_decrypt_data(
    doctor_public_key: str = Form(...),
    ipfs_hash: str = Form(...),
    encrypted_data_key_for_doctor: str = Form(..., description="Doctor's encrypted data key from permission"),
    current_user: str = Depends(verify_token)
):
    """Doctor permission'ı ile encrypted data'yı decrypt eder"""
    
    # Kullanıcı doğrulama
    if current_user != doctor_public_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Sadece kendi verilerinize erişebilirsiniz"
        )
    
    # === DOCTOR ACCESS CRYPTO FLOW ===
    crypto = VireacaCrypto()
    
    try:
        # 1. Decrypt data key with doctor's key
        # Test mode için stored data key kullan
        if encrypted_data_key_for_doctor.startswith("mock_"):
            # Test mode: use the stored real data key for this IPFS hash
            if ipfs_hash in test_data_keys:
                data_key = test_data_keys[ipfs_hash]
            else:
                # Fallback to mock data key if not found
                data_key = b"mock_data_key_32_bytes_for_test_!"
        else:
            data_key = crypto.decrypt_data_key_for_doctor(encrypted_data_key_for_doctor, doctor_public_key)
        
        # 2. Download encrypted data from IPFS
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                ipfs_response = await client.get(f"{IPFS_GATEWAY_URL}{ipfs_hash}")
                ipfs_response.raise_for_status()
                encrypted_data = ipfs_response.content
                
                if not encrypted_data:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="IPFS data not found or empty"
                    )
                    
            except httpx.TimeoutException:
                raise HTTPException(
                    status_code=status.HTTP_408_REQUEST_TIMEOUT,
                    detail="IPFS gateway timeout"
                )
            except httpx.HTTPStatusError as e:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"IPFS data not found: {e.response.status_code}"
                )
        
        # 3. Decrypt medical data
        decrypted_data = crypto.decrypt_data(encrypted_data, data_key)
        
        return {
            "status": "success",
            "ipfs_hash": ipfs_hash,
            "data_size": len(decrypted_data),
            "decrypted_data": base64.b64encode(decrypted_data).decode('utf-8'),
            "crypto_status": "Data successfully decrypted for doctor access",
            "access_time": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to decrypt data: {str(e)}"
        )

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
        to_address(request.doctor_public_key),
        to_bytes(request.ipfs_hash.encode('utf-8')),
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
        # Environment variables kontrolü
        env_status = {
            "pinata_jwt": "configured" if PINATA_JWT else "missing",
            "contract_id": "configured" if CONTRACT_ID else "missing",
            "rpc_url": "configured" if RPC_URL else "missing",
            "launchtube_api_key": "configured" if LAUNCHTUBE_API_KEY else "missing"
        }
        
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
            "environment": env_status,
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

@app.post("/test-upload")
async def test_upload(
    file: UploadFile = File(...),
    test_field: str = Form(...),
    current_user: str = Depends(verify_token)
):
    """Test endpoint for debugging upload issues"""
    return {
        "message": "Test upload success",
        "filename": file.filename,
        "test_field": test_field,
        "current_user": current_user,
        "file_size": file.size
    }

@app.get("/files/my-files", summary="Kullanıcının yüklediği dosyaları listele")
async def get_my_files(current_user: str = Depends(verify_token)):
    """Kullanıcının yüklediği dosyaları listeler"""
    try:
        user_files = uploaded_files.get(current_user, [])
        
        return {
            "status": "success",
            "files": user_files,
            "total_files": len(user_files),
            "user": current_user
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Dosyalar listelenirken hata oluştu: {str(e)}"
        )

@app.get("/files/{file_id}", summary="Belirli bir dosyanın detaylarını al")
async def get_file_details(
    file_id: str,
    current_user: str = Depends(verify_token)
):
    """Belirli bir dosyanın detaylarını getirir"""
    try:
        user_files = uploaded_files.get(current_user, [])
        
        for file_info in user_files:
            if file_info["id"] == file_id:
                return {
                    "status": "success",
                    "file": file_info
                }
        
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Dosya bulunamadı"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Dosya detayları alınırken hata oluştu: {str(e)}"
        )

@app.get("/files", summary="Tüm dosyaları listele (admin/debug)")
async def get_all_files():
    """Tüm yüklenen dosyaları listeler (debug için)"""
    return {
        "status": "success",
        "all_files": uploaded_files,
        "total_users": len(uploaded_files),
        "total_files": sum(len(files) for files in uploaded_files.values())
    }

@app.get("/test-pinata")
async def test_pinata():
    """Test Pinata API connection"""
    try:
        headers = {"Authorization": f"Bearer {PINATA_JWT}"}
        
        async with httpx.AsyncClient() as client:
            # Test Pinata authentication
            response = await client.get(
                "https://api.pinata.cloud/data/testAuthentication",
                headers=headers
            )
            
        if response.status_code == 200:
            return {
                "status": "success",
                "message": "Pinata authentication successful",
                "pinata_response": response.json()
            }
        else:
            return {
                "status": "error",
                "message": f"Pinata auth failed: {response.status_code}",
                "response": response.text
            }
            
    except Exception as e:
        return {
            "status": "error",
            "message": f"Pinata test failed: {str(e)}"
        }

@app.get("/")
def read_root():
    return {
        "message": "Vireca Backend API - Launchtube Edition is running!",
        "platform": "launchtube",
        "version": "1.0.0",
        "docs_url": "/docs"
    }