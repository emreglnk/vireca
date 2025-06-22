import os
import requests
import base64
from dotenv import load_dotenv
from fastapi import FastAPI, UploadFile, File, HTTPException, Body
from pydantic import BaseModel, Field

from soroban_rpc_client import Server
from stellar_sdk import Keypair, TransactionBuilder
from stellar_sdk.xdr import SCVal

# Load settings from .env file
load_dotenv()

# --- Configuration ---
PINATA_JWT = os.getenv("PINATA_JWT")
CONTRACT_ID = os.getenv("CONTRACT_ID")
NETWORK_PASSPHRASE = os.getenv("NETWORK_PASSPHRASE")
RPC_URL = os.getenv("RPC_URL")
PINATA_BASE_URL = "https://api.pinata.cloud/"

# FastAPI and Soroban Server Connection
app = FastAPI(title="Vireca Backend API", version="1.0.0")
server = Server(RPC_URL)

# --- API Models (Pydantic) ---
class PrepareRegisterRequest(BaseModel):
    owner_public_key: str
    encrypted_key_for_owner: str = Field(..., description="Base64 encoded encrypted data key")

class PrepareGrantRequest(BaseModel):
    granter_public_key: str
    doctor_public_key: str
    ipfs_hash: str
    encrypted_key_for_doctor: str = Field(..., description="Base64 encoded encrypted data key")
    duration_in_ledgers: int = Field(..., gt=0, description="Number of ledgers for permission validity (~5s per ledger)")

class PrepareRevokeRequest(BaseModel):
    granter_public_key: str
    doctor_public_key: str
    ipfs_hash: str

class SubmitRequest(BaseModel):
    signed_xdr: str

# --- Helper Function ---
def build_and_prepare_transaction(source_public_key: str, contract_function: str, parameters: list[SCVal]) -> str:
    """Abstracts recurring transaction creation and preparation logic."""
    source_account = server.get_account(source_public_key)
    source_keypair = Keypair.from_public_key(source_public_key)

    tx_builder = TransactionBuilder(
        source_account=source_keypair,
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

# --- API ENDPOINTS ---

@app.post("/prepare/register-data", summary="Prepare transaction for new data registration")
async def prepare_register_data(
    owner_public_key: str = Body(...),
    encrypted_key_for_owner: str = Body(...),
    file: UploadFile = File(...)
):
    try:
        files = {"file": (file.filename, await file.read(), file.content_type)}
        headers = {"Authorization": f"Bearer {PINATA_JWT}"}
        response = requests.post(f"{PINATA_BASE_URL}pinning/pinFileToIPFS", files=files, headers=headers)
        response.raise_for_status()
        ipfs_hash = response.json()["IpfsHash"]
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=f"IPFS Upload Error: {e}")

    # Note: In real application, IPFS hash needs to be converted to 32-byte format.
    # Using Bytes for example purposes for now.
    ipfs_hash_bytes = ipfs_hash.encode('utf-8')
    encrypted_key_bytes = base64.b64decode(encrypted_key_for_owner)
    
    params = [
        SCVal.from_bytes(ipfs_hash_bytes),
        SCVal.from_bytes(encrypted_key_bytes),
    ]

    unsigned_xdr = build_and_prepare_transaction(owner_public_key, "register_data", params)
    return {"unsigned_xdr": unsigned_xdr, "ipfs_hash": ipfs_hash}

@app.post("/prepare/grant-access", summary="Prepare transaction to grant access to doctor")
async def prepare_grant_access(request: PrepareGrantRequest):
    params = [
        SCVal.from_address(request.doctor_public_key),
        SCVal.from_bytes(request.ipfs_hash.encode('utf-8')),
        SCVal.from_bytes(base64.b64decode(request.encrypted_key_for_doctor)),
        SCVal.from_u32(request.duration_in_ledgers)
    ]
    unsigned_xdr = build_and_prepare_transaction(request.granter_public_key, "grant_access", params)
    return {"unsigned_xdr": unsigned_xdr}

@app.post("/prepare/revoke-access", summary="Prepare transaction to revoke access permission")
async def prepare_revoke_access(request: PrepareRevokeRequest):
    params = [
        SCVal.from_address(request.doctor_public_key),
        SCVal.from_bytes(request.ipfs_hash.encode('utf-8')),
    ]
    unsigned_xdr = build_and_prepare_transaction(request.granter_public_key, "revoke_access", params)
    return {"unsigned_xdr": unsigned_xdr}

@app.post("/transaction/submit", summary="Submit signed transaction to Stellar network")
async def submit_transaction(request: SubmitRequest):
    try:
        tx_result = await server.send_transaction(request.signed_xdr)
        if tx_result.status == "FAILED":
             raise HTTPException(status_code=400, detail=f"Transaction failed: {tx_result.result_xdr}")
        return {"status": "success", "result": tx_result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Transaction submission error: {e}")

@app.get("/")
def read_root():
    return {"message": "Vireca Backend API is running!"} 