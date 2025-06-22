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

# Load settings from .env file
load_dotenv()

# --- Configuration ---
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

# FastAPI and Soroban Server Connection
app = FastAPI(
    title="Vireca Backend API - Launchtube Edition",
    version="1.0.0",
    description="Health data management API specially developed for the Launchtube platform"
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

# In-memory storage for doctor access permissions (In production, use a database)
doctor_permissions = {}  # {doctor_public_key: [permission_dict, ...]}

# --- API Models (Pydantic) ---
class LaunchtubeUser(BaseModel):
    public_key: str
    username: Optional[str] = None
    email: Optional[str] = None
    profile_id: Optional[str] = None

class PrepareRegisterRequest(BaseModel):
    owner_public_key: str
    encrypted_key_for_owner: str = Field(..., description="Base64 encoded encrypted data key")
    metadata: Optional[dict] = Field(None, description="Additional metadata information")

class PrepareGrantRequest(BaseModel):
    granter_public_key: str
    doctor_public_key: str
    ipfs_hash: str
    encrypted_key_for_doctor: str = Field(..., description="Base64 encoded encrypted data key")
    duration_in_ledgers: int = Field(..., gt=0, description="Number of ledgers for permission validity (~5s per ledger)")
    access_reason: Optional[str] = Field(None, description="Access reason")

class PrepareRevokeRequest(BaseModel):
    granter_public_key: str
    doctor_public_key: str
    ipfs_hash: str
    revoke_reason: Optional[str] = Field(None, description="Revocation reason")

class SubmitRequest(BaseModel):
    signed_xdr: str
    launchtube_signature: Optional[str] = Field(None, description="Launchtube platform signature")

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

# --- Helper Functions ---
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
        # Mock token check for test mode
        if credentials.credentials.startswith("mock_token_"):
            # Mock token format: mock_token_patient_timestamp or mock_token_doctor_timestamp
            parts = credentials.credentials.split("_")
            if len(parts) >= 3:
                wallet_type = parts[2]
                if wallet_type == "patient":
                    return WALLETS["patient"] if "WALLETS" in globals() else "GA5HNMXP4XZL634C3DXKU6AM5WAJ6OKMOIKZ2R3SN22WZXRKCS2XA4MZ"
                elif wallet_type == "doctor":
                    return WALLETS["doctor"] if "WALLETS" in globals() else "GDOCTOREXAMPLEADDRESS1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        
        # Real JWT verification
        payload = jwt.decode(credentials.credentials, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        public_key: str = payload.get("sub")
        if public_key is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return public_key
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def verify_launchtube_user(public_key: str) -> LaunchtubeUser:
    """Verifies user information from Launchtube platform"""
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
                detail="Launchtube user not found"
            )
    except httpx.RequestError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Launchtube service temporarily unavailable"
        )

def build_and_prepare_transaction(source_public_key: str, contract_function: str, parameters: list) -> str:
    """Abstracts recurring transaction creation and preparation logic."""
    try:
        # Using load_account in SorobanServer (not get_account)
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
            detail=f"Transaction preparation error: {str(e)}"
        )

async def upload_to_ipfs_with_metadata(file_content: bytes, filename: str, metadata: dict = None) -> str:
    """Uploads file and metadata to IPFS - Pinata API v3 compatible"""
    try:
        # Pinata API current format check
        if not PINATA_JWT:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="PINATA_JWT environment variable is not set"
            )
        
        # Simple multipart form data (v3 API compatible)
        files = {
            "file": (filename, file_content, "application/octet-stream")
        }
        
        # Metadata formatting (new API format)
        data = {}
        if metadata:
            # Pinata v3 metadata format
            pinata_metadata = {
                "name": filename,
                "keyvalues": {
                    # Add only string values as metadata
                    str(k): str(v) for k, v in metadata.items() if v is not None
                }
            }
            data["pinataMetadata"] = json.dumps(pinata_metadata)
            
            # CID version (optional)
            data["pinataOptions"] = json.dumps({"cidVersion": 1})
        
        headers = {
            "Authorization": f"Bearer {PINATA_JWT}"
        }
        
        # Print request information for debugging
        print(f"📤 Uploading to IPFS: {filename} ({len(file_content)} bytes)")
        print(f"🔑 Auth header: Bearer {PINATA_JWT[:20]}...")
        if metadata:
            print(f"📋 Metadata keys ({len(metadata)}): {list(metadata.keys())}")
        
        # More reliable upload with timeout and retry
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
    """Uploads only file to IPFS (without metadata)"""
    try:
        # Simple file upload - no metadata
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

@app.post("/auth/launchtube", summary="Authentication with Launchtube platform")
async def authenticate_with_launchtube(request: LaunchtubeAuthRequest):
    """Verifies Launchtube user and creates JWT token"""
    
    # Verify Launchtube user
    user = await verify_launchtube_user(request.public_key)
    
    # Create JWT token
    access_token = create_access_token(
        data={"sub": request.public_key, "username": user.username}
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user,
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }

@app.post("/prepare/register-data", summary="Prepares data registration for Launchtube user")
async def prepare_register_data(
    file: UploadFile = File(...),
    owner_public_key: str = Form(...),
    patient_signature: str = Form(..., description="Patient signature for 'Vireca_key_v1'"),
    metadata: str = Form(None),
    current_user: str = Depends(verify_token)
):
    """Prepares health data registration for Launchtube user"""
    
    # File size check
    if file.size > MAX_FILE_SIZE_MB * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File size cannot exceed {MAX_FILE_SIZE_MB}MB"
        )
    
    # User verification
    if current_user != owner_public_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only register your own data"
        )
    
    # Verify mock user for test mode or real Launchtube user
    try:
        user = await verify_launchtube_user(owner_public_key)
    except HTTPException:
        # Create mock user for test mode
        user = LaunchtubeUser(
            public_key=owner_public_key,
            username=f"test_user_{owner_public_key[:8]}",
            email="test@example.com"
        )
    
    # Read file
    file_content = await file.read()
    
    # === ENCRYPTION FLOW ===
    crypto = VireacaCrypto()
    
    # 1. Generate AES-256 data key
    data_key = crypto.generate_data_key()
    
    # 2. Encrypt medical data
    encrypted_data = crypto.encrypt_data(file_content, data_key)
    
    # 3. Derive patient key from signature
    try:
        # Mock signature check for test mode
        if patient_signature.startswith("mock_"):
            # Create deterministic key for mock signature
            patient_key = crypto.derive_patient_key_from_mock(patient_signature)
        else:
            # Real signature verification
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
    
    # Parse and prepare metadata
    parsed_metadata = {}
    if metadata:
        try:
            parsed_metadata = json.loads(metadata)
        except json.JSONDecodeError:
            parsed_metadata = {}
    
    # Pinata metadata limit: maximum 10 key-value pairs
    base_metadata = {
        "filename": file.filename,
        "platform": "launchtube",
        "encrypted": "true",  # Convert boolean to string
        "upload_date": datetime.utcnow().strftime("%Y-%m-%d"),  # Short format
    }
    
    # Take only first 6 from user metadata (4+6=10 total)
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
    
    # Real IPFS upload - upload encrypted data
    try:
        ipfs_hash = await upload_to_ipfs_with_metadata(
            encrypted_data, 
            f"encrypted_{file.filename}",
            metadata_dict
        )
    except HTTPException as e:
        # If first attempt with metadata failed, try without metadata
        if "400" in str(e.detail) or "key values" in str(e.detail).lower():
            try:
                print("🔄 Exceeded metadata limit - trying without metadata...")
                ipfs_hash = await upload_to_ipfs_simple(
                    encrypted_data, 
                    f"encrypted_{file.filename}"
                )
                print("✅ Upload successful without metadata!")
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
    
    # Prepare smart contract parameters
    ipfs_hash_bytes = ipfs_hash.encode('utf-8')
    encrypted_key_bytes = base64.b64decode(encrypted_data_key_for_patient)
    
    params = [
        to_bytes(ipfs_hash_bytes),
        to_bytes(encrypted_key_bytes),
    ]

    # Mock transaction XDR for test mode, real transaction building in production
    if patient_signature.startswith("mock_"):
        # Mock transaction XDR (test mode)
        unsigned_xdr = f"mock_xdr_{hash(ipfs_hash + owner_public_key)}"
    else:
        # Real transaction building
        unsigned_xdr = build_and_prepare_transaction(
            owner_public_key, 
            "register_data", 
            params
        )
    
    # Store file information in memory (use database in production)
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
    
    # Add to user's file list
    if owner_public_key not in uploaded_files:
        uploaded_files[owner_public_key] = []
    uploaded_files[owner_public_key].append(file_info)
    
    # Store data key for test mode
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

@app.post("/prepare/grant-access", summary="Grant access permission to Launchtube doctor")
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
    """Grant health data access permission to Launchtube doctor"""
    
    # User verification
    if current_user != granter_public_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only grant access to your own data"
        )
    
    # === DOCTOR SHARING CRYPTO FLOW ===
    crypto = VireacaCrypto()
    
    # 1. Derive patient key from signature
    try:
        # Mock signature check for test mode
        if patient_signature.startswith("mock_"):
            patient_key = crypto.derive_patient_key_from_mock(patient_signature)
        else:
            # Real signature verification
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
        # Use stored data key for test mode
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
        # Mock encrypted data key for doctor (test mode) - proper base64 format
        import base64
        mock_key = f"mock_doctor_key_{hash(doctor_public_key)}".encode('utf-8')
        encrypted_data_key_for_doctor = base64.b64encode(mock_key).decode('utf-8')
    else:
        encrypted_data_key_for_doctor = crypto.encrypt_data_key_for_doctor(data_key, doctor_public_key)
    
    # Verify mock users for test mode or real Launchtube users
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
    
    # Mock transaction XDR for test mode, real transaction building in production
    if patient_signature.startswith("mock_"):
        # Mock transaction XDR (test mode)
        unsigned_xdr = f"mock_grant_xdr_{hash(granter_public_key + doctor_public_key + ipfs_hash)}"
    else:
        # Prepare smart contract parameters
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
    
    # Save doctor permission
    permission_info = {
        "permission_id": f"perm_{hash(granter_public_key + doctor_public_key + ipfs_hash)}",
        "ipfs_hash": ipfs_hash,
        "granter_public_key": granter_public_key,
        "granter_username": granter.username if hasattr(granter, 'username') else f"user_{granter_public_key[:8]}",
        "encrypted_data_key_for_doctor": encrypted_data_key_for_doctor,
        "duration_in_ledgers": duration_in_ledgers,
        "duration_hours": duration_in_ledgers * 5 / 3600,
        "access_reason": access_reason,
        "granted_at": datetime.utcnow().isoformat(),
        "status": "active"
    }
    
    # Add to doctor permission list
    if doctor_public_key not in doctor_permissions:
        doctor_permissions[doctor_public_key] = []
    doctor_permissions[doctor_public_key].append(permission_info)
    
    return {
        "unsigned_xdr": unsigned_xdr,
        "granter": granter,
        "doctor": doctor,
        "duration_hours": duration_in_ledgers * 5 / 3600,  # Approximately in hours
        "access_reason": access_reason,
        "encrypted_data_key_for_doctor": encrypted_data_key_for_doctor,
        "crypto_status": "Data key successfully re-encrypted for doctor",
        "permission_info": permission_info
    }

@app.post("/doctor/decrypt-data", summary="Doctor decrypts encrypted data")
async def doctor_decrypt_data(
    doctor_public_key: str = Form(...),
    ipfs_hash: str = Form(...),
    encrypted_data_key_for_doctor: str = Form(..., description="Doctor's encrypted data key from permission"),
    current_user: str = Depends(verify_token)
):
    """Doctor decrypts encrypted data with permission"""
    
    # User verification
    if current_user != doctor_public_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only access your own data"
        )
    
    # Check if doctor has permission to access this file
    doctor_perms = doctor_permissions.get(doctor_public_key, [])
    has_permission = False
    for perm in doctor_perms:
        if perm["ipfs_hash"] == ipfs_hash and perm["status"] == "active":
            has_permission = True
            break
    
    if not has_permission:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Doctor does not have active permission to access IPFS hash {ipfs_hash}. Please request access from the patient first."
        )
    
    # === DOCTOR ACCESS CRYPTO FLOW ===
    crypto = VireacaCrypto()
    
    # Debug logging
    print(f"🔍 Doctor decrypt request:")
    print(f"   IPFS Hash: {ipfs_hash}")
    print(f"   Doctor Key: {doctor_public_key[:8]}...")
    print(f"   Encrypted Data Key Length: {len(encrypted_data_key_for_doctor)}")
    print(f"   Encrypted Data Key Preview: {encrypted_data_key_for_doctor[:20]}...")
    
    try:
        # 1. Decrypt data key with doctor's key
        # Use stored data key for test mode
        is_mock_mode = False
        
        try:
            # Try to decode base64 to check if it's a mock key
            import base64
            # Add padding if needed for proper base64 decoding
            padded_key = encrypted_data_key_for_doctor
            missing_padding = len(padded_key) % 4
            if missing_padding:
                padded_key += '=' * (4 - missing_padding)
            
            decoded_key = base64.b64decode(padded_key).decode('utf-8')
            if decoded_key.startswith("mock_doctor_key_"):
                is_mock_mode = True
        except Exception:
            # If base64 decode fails, check if it starts with mock directly
            if encrypted_data_key_for_doctor.startswith("mock_"):
                is_mock_mode = True
        
        if is_mock_mode:
            # Test mode: use the stored real data key for this IPFS hash
            if ipfs_hash in test_data_keys:
                data_key = test_data_keys[ipfs_hash]
            else:
                # No data key found for this IPFS hash in test mode
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"No data key found for IPFS hash {ipfs_hash} in test mode. Please upload the file first and grant access to the doctor."
                )
        else:
            # Production mode: decrypt with doctor's key
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
        try:
            decrypted_data = crypto.decrypt_data(encrypted_data, data_key)
        except Exception as decrypt_error:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to decrypt medical data: {str(decrypt_error)}"
            )
        
        return {
            "status": "success",
            "ipfs_hash": ipfs_hash,
            "data_size": len(decrypted_data),
            "decrypted_data": base64.b64encode(decrypted_data).decode('utf-8'),
            "crypto_status": "Data successfully decrypted for doctor access",
            "access_time": datetime.utcnow().isoformat(),
            "mock_mode": is_mock_mode
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to decrypt data: {str(e)}"
        )

@app.post("/prepare/revoke-access", summary="Revoke Launchtube doctor's access permission")
async def prepare_revoke_access(
    request: PrepareRevokeRequest,
    current_user: str = Depends(verify_token)
):
    """Revoke Launchtube doctor's access permission"""
    
    # User verification
    if current_user != request.granter_public_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only revoke access permissions for your own data"
        )
    
    # Verify user information
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

@app.post("/transaction/submit", summary="Submit signed transaction to Stellar network via Launchtube")
async def submit_transaction(
    request: SubmitRequest,
    current_user: str = Depends(verify_token)
):
    """Submit signed transaction to Stellar network"""
    try:
        # Verify Launchtube signature if present
        if request.launchtube_signature:
            # Verify Launchtube platform signature
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
                    detail="Launchtube signature could not be verified"
                )
        
        # Send transaction to Stellar network
        tx_result = await server.send_transaction(request.signed_xdr)
        
        if tx_result.status == "FAILED":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Transaction failed: {tx_result.result_xdr}"
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
            detail=f"Transaction submission error: {str(e)}"
        )

@app.get("/health", summary="Launchtube API health status")
async def health_check():
    """Check API and connection status"""
    try:
        # Environment variables check
        env_status = {
            "pinata_jwt": "configured" if PINATA_JWT else "missing",
            "contract_id": "configured" if CONTRACT_ID else "missing",
            "rpc_url": "configured" if RPC_URL else "missing",
            "launchtube_api_key": "configured" if LAUNCHTUBE_API_KEY else "missing"
        }
        
        # Test Stellar network connection
        stellar_status = "connected"
        try:
            await server.get_health()
        except:
            stellar_status = "disconnected"
            
        # Test Launchtube API connection
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
            detail=f"Health check failed: {str(e)}"
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

@app.get("/files/my-files", summary="List user's uploaded files")
async def get_my_files(current_user: str = Depends(verify_token)):
    """List user's uploaded files"""
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
            detail=f"Error occurred while listing files: {str(e)}"
        )

@app.get("/files/{file_id}", summary="Get specific file details")
async def get_file_details(
    file_id: str,
    current_user: str = Depends(verify_token)
):
    """Get specific file details"""
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
            detail="File not found"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error occurred while getting file details: {str(e)}"
        )

@app.get("/doctor/accessible-files", summary="List files accessible to doctor")
async def get_doctor_accessible_files(current_user: str = Depends(verify_token)):
    """List files accessible to doctor"""
    try:
        doctor_perms = doctor_permissions.get(current_user, [])
        accessible_files = []
        
        for permission in doctor_perms:
            ipfs_hash = permission["ipfs_hash"]
            granter_key = permission["granter_public_key"]
            
            # Find files from granter with this IPFS hash
            granter_files = uploaded_files.get(granter_key, [])
            for file_info in granter_files:
                if file_info["ipfs_hash"] == ipfs_hash:
                    # Combine file information with permission information
                    accessible_file = {
                        **file_info,
                        "permission_info": permission,
                        "patient_name": permission["granter_username"],
                        "access_granted_at": permission["granted_at"],
                        "access_reason": permission["access_reason"],
                        "access_duration_hours": permission["duration_hours"],
                        "access_status": permission["status"],
                        "encrypted_data_key_for_doctor": permission["encrypted_data_key_for_doctor"]
                    }
                    accessible_files.append(accessible_file)
                    break
        
        return {
            "status": "success",
            "accessible_files": accessible_files,
            "total_accessible_files": len(accessible_files),
            "doctor_public_key": current_user
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error occurred while listing accessible files: {str(e)}"
        )

@app.get("/files", summary="List all files (admin/debug)")
async def get_all_files():
    """List all uploaded files (for debugging)"""
    return {
        "status": "success",
        "all_files": uploaded_files,
        "doctor_permissions": doctor_permissions,
        "total_users": len(uploaded_files),
        "total_files": sum(len(files) for files in uploaded_files.values()),
        "total_permissions": sum(len(perms) for perms in doctor_permissions.values())
    }

@app.get("/doctor/permissions", summary="List all doctor permissions")
async def get_doctor_permissions(current_user: str = Depends(verify_token)):
    """List all permissions owned by doctor"""
    try:
        doctor_perms = doctor_permissions.get(current_user, [])
        
        return {
            "status": "success",
            "permissions": doctor_perms,
            "total_permissions": len(doctor_perms),
            "doctor_public_key": current_user
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error occurred while listing permissions: {str(e)}"
        )

@app.get("/patient/granted-permissions", summary="List patient's granted permissions")
async def get_patient_granted_permissions(current_user: str = Depends(verify_token)):
    """List permissions granted by patient to doctors"""
    try:
        granted_permissions = []
        
        # Scan all doctor permissions and find permissions granted by this patient
        for doctor_key, perms in doctor_permissions.items():
            for perm in perms:
                if perm["granter_public_key"] == current_user:
                    granted_permissions.append({
                        **perm,
                        "doctor_public_key": doctor_key,
                        "doctor_username": f"doctor_{doctor_key[:8]}"
                    })
        
        return {
            "status": "success",
            "granted_permissions": granted_permissions,
            "total_granted": len(granted_permissions),
            "patient_public_key": current_user
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error occurred while listing granted permissions: {str(e)}"
        )

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