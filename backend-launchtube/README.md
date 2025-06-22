# Vireca Backend - Launchtube Edition

Vireca health data management backend API specially developed for the Launchtube platform.

## Features

### 🚀 Launchtube Integration
- Launchtube user authentication
- Platform-specific JWT token management
- User profile integration
- Role-based access control

### 🔐 Advanced Security
- JWT-based authentication
- Launchtube platform signature verification
- CORS protection
- Rate limiting
- File size and type validation

### 📊 Health Data Management
- IPFS-based secure file storage
- Metadata support
- Encrypted data keys
- Time-limited access permissions

### 🌐 API Endpoints

#### Authentication
- `POST /auth/launchtube` - Login with Launchtube
- `GET /health` - API status

#### Data Management
- `POST /prepare/register-data` - New data registration
- `POST /prepare/grant-access` - Grant access permission
- `POST /prepare/revoke-access` - Revoke access
- `POST /transaction/submit` - Submit transaction

## Installation

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure Environment Variables

Copy the `env.example` file to `.env`:

```bash
cp env.example .env
```

Fill in the required values:

```env
# Launchtube Platform Configuration
LAUNCHTUBE_API_KEY="your_launchtube_api_key"
LAUNCHTUBE_BASE_URL="https://api.launchtube.xyz"
LAUNCHTUBE_NETWORK="testnet"

# Stellar Network Configuration
PINATA_JWT="your_pinata_jwt_key"
CONTRACT_ID="your_soroban_contract_id"
NETWORK_PASSPHRASE="Test SDF Network ; September 2015"
RPC_URL="https://soroban-testnet.stellar.org:443"

# Security Configuration
JWT_SECRET_KEY="your-super-secret-jwt-key"
```

### 3. Run the Application

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

API documentation: http://localhost:8000/docs

## Launchtube Integration

### User Authentication

```python
# 1. Login with Launchtube
response = requests.post("/auth/launchtube", {
    "public_key": "GA...",
    "signature": "...",
    "message": "..."
})

# 2. Get JWT token
token = response.json()["access_token"]

# 3. Use in other API calls
headers = {"Authorization": f"Bearer {token}"}
```

### Data Registration

```python
# Register data with file and metadata
files = {"file": open("medical_report.pdf", "rb")}
data = {
    "owner_public_key": "GA...",
    "encrypted_key_for_owner": "base64_encrypted_key",
    "metadata": {
        "title": "Blood Test Result",
        "data_type": "lab_result",
        "tags": ["blood", "test", "2024"]
    }
}

response = requests.post(
    "/prepare/register-data", 
    data=data, 
    files=files,
    headers=headers
)
```

### Grant Access Permission

```python
# Grant access permission to doctor
response = requests.post("/prepare/grant-access", {
    "granter_public_key": "GA...",
    "doctor_public_key": "GB...",
    "ipfs_hash": "Qm...",
    "encrypted_key_for_doctor": "base64_key",
    "duration_in_ledgers": 17280,  # 24 hours
    "access_reason": "For routine checkup"
}, headers=headers)
```

## Security Features

### 1. Multi-layer Authentication
- Launchtube user verification
- JWT token validation
- Stellar signature verification
- Platform signature validation

### 2. Data Protection
- End-to-end encryption
- IPFS secure storage
- Metadata encryption
- Access logs

### 3. Compliance
- HIPAA (Health Insurance Portability and Accountability Act)
- GDPR (General Data Protection Regulation) 
- KVKK (Personal Data Protection Law - Turkey)

## Error Codes

| Code | Description |
|-----|----------|
| 404001 | User not found |
| 400001 | Invalid signature |
| 403001 | Permission denied |
| 413001 | File too large |
| 415001 | Unsupported file type |
| 429001 | Rate limit exceeded |
| 500001 | IPFS upload error |
| 500002 | Stellar network error |
| 500003 | Launchtube API error |

## Supported File Types

- PDF documents
- JPEG/PNG images
- TIFF medical images
- DICOM files
- JSON data files
- Plain text files

## Rate Limiting

- Default: 100 requests/minute
- Authenticated users: 500 requests/minute
- Premium users: 1000 requests/minute

## Monitoring and Logging

The application automatically:
- Logs API requests
- Tracks error conditions
- Collects performance metrics
- Records security events

## Support

For issues related to the Launchtube platform:
- Launchtube Discord: https://discord.gg/launchtube
- Email: support@launchtube.xyz
- Documentation: https://docs.launchtube.xyz

## License

This project is licensed under the MIT License. 