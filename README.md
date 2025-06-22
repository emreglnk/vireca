# Vireca Project

Vireca is a blockchain-based health data management system. This system allows patients to securely store their health data and provide controlled access to doctors.

## Project Structure

```
vireca/
├── contracts/          # Soroban smart contract
│   ├── src/
│   │   ├── lib.rs     # Main contract code
│   │   └── main.rs    # Binary entry point
│   └── Cargo.toml     # Rust dependencies
├── backend/           # Python FastAPI backend
│   ├── main.py        # Main API application
│   ├── requirements.txt # Python dependencies
│   └── env.example    # Environment variables example
└── README.md          # This file
```

## Installation

### 1. Soroban Contract

First, you need to install Soroban CLI:

```bash
# Install Soroban CLI
cargo install --locked soroban-cli
```

To compile and deploy the contract:

```bash
cd contracts
cargo build --target wasm32-unknown-unknown --release
soroban contract deploy --wasm target/wasm32-unknown-unknown/release/vireca_contract.wasm --source alice --network testnet
```

### 2. Python Backend

Install Python dependencies:

```bash
cd backend

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure Environment Variables

Copy `backend/env.example` to `backend/.env` and fill in the values:

```bash
cd backend
cp env.example .env
```

Replace the values in the `.env` file with your own information:

- `PINATA_JWT`: JWT token from your Pinata IPFS service
- `CONTRACT_ID`: ID of your deployed contract
- `NETWORK_PASSPHRASE`: Default value for Stellar test network
- `RPC_URL`: Soroban RPC server address

### 4. Run the Application

```bash
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

You can access the API documentation at: http://localhost:8000/docs

## API Endpoints

### Data Registration
- `POST /prepare/register-data` - Prepares transaction for registering new health data
- `POST /transaction/submit` - Submits signed transaction to blockchain

### Access Management
- `POST /prepare/grant-access` - Prepares transaction for granting access to doctor
- `POST /prepare/revoke-access` - Prepares transaction for revoking access permission

## Security

- All data is stored encrypted on IPFS
- Encryption keys are securely stored on blockchain
- Access permissions are time-limited
- Only data owner can grant/revoke access permissions

## License

This project is licensed under the MIT License. 