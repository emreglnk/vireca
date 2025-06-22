# Vireca Contract Devnet Deployment Guide

Step-by-step guide to deploy the Vireca smart contract to Stellar Devnet with the Launchtube platform.

## 🚀 What is Devnet?

**Stellar Devnet** (Development Network):
- ⚡ **Fast reset**: Periodically reset
- 🔄 **Continuous updates**: Latest features are tested  
- 🆓 **Free**: Test XLM can be easily obtained
- 🛠️ **Development-focused**: Ideal for rapid iteration

## 📋 Prerequisites

### 1. Soroban CLI Installation
```bash
# Install Soroban CLI
cargo install --locked soroban-cli

# Check version
soroban --version
```

### 2. Create Stellar Wallet
```bash
# Generate new wallet
soroban keys generate --global alice

# Display public key
soroban keys address alice
```

### 3. Get XLM for Devnet
```bash
# Get XLM from Friendbot (for devnet)
soroban keys fund alice --network devnet
```

## 🔧 Network Configuration

### Devnet Settings
```bash
# Add devnet network
soroban network add \
  --global devnet \
  --rpc-url https://rpc-devnet.stellar.org:443 \
  --network-passphrase "Standalone Network ; February 2017"
```

### Network Check
```bash
# List available networks
soroban network ls

# Test devnet connection
soroban network status --network devnet
```

## 📦 Deploy Contract

### 1. Compile Contract
```bash
cd contracts
cargo build --target wasm32-unknown-unknown --release
```

### 2. Deploy Contract
```bash
# Deploy WASM file
soroban contract deploy \
  --wasm target/wasm32-unknown-unknown/release/vireca_contract.wasm \
  --source alice \
  --network devnet
```

### 3. Save Contract ID
After deployment, you'll receive a Contract ID:
```
Contract deployed successfully with ID: CABC123...XYZ789
```

Use this ID in your `.env` file:
```env
CONTRACT_ID="CABC123...XYZ789"
```

## 🔧 Backend Configuration

### 1. Environment Settings
Update your `.env` file:

```env
# Launchtube Platform Configuration
LAUNCHTUBE_API_KEY="your_launchtube_api_key"
LAUNCHTUBE_BASE_URL="https://api.launchtube.xyz"
LAUNCHTUBE_NETWORK="devnet"

# Stellar Network Configuration - DEVNET
PINATA_JWT="your_pinata_jwt_key"
CONTRACT_ID="CABC123...XYZ789"  # ID you received above
NETWORK_PASSPHRASE="Standalone Network ; February 2017"
RPC_URL="https://rpc-devnet.stellar.org:443"

# Security Configuration
JWT_SECRET_KEY="your-super-secret-jwt-key"
```

### 2. Start Backend
```bash
cd backend-launchtube
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

## 🧪 Testing

### 1. Health Check
```bash
curl http://localhost:8000/health
```

Successful response:
```json
{
  "status": "healthy", 
  "services": {
    "stellar_network": "connected",
    "launchtube_platform": "connected",
    "ipfs_gateway": "connected"
  },
  "platform": "launchtube"
}
```

### 2. Test Contract Functions
```bash
# Display contract information
soroban contract inspect \
  --id CABC123...XYZ789 \
  --network devnet
```

## 🌐 Network Comparison

| Feature | Devnet | Testnet | Mainnet |
|---------|--------|---------|---------|
| **Speed** | Fastest | Medium | Slowest |
| **Stability** | Low (reset) | High | Highest |
| **Cost** | Free | Free | Paid |
| **Usage** | Development | Testing | Production |
| **XLM Source** | Friendbot | Friendbot | Purchase |

## 🔄 Network Switching

### Switch to Testnet
```env
LAUNCHTUBE_NETWORK="testnet"
NETWORK_PASSPHRASE="Test SDF Network ; September 2015"
RPC_URL="https://soroban-testnet.stellar.org:443"
```

### Switch to Mainnet
```env
LAUNCHTUBE_NETWORK="mainnet"
NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"
RPC_URL="https://soroban-mainnet.stellar.org:443"
```

## ⚠️ Devnet Warnings

### 1. Data Persistence
- Devnet **resets periodically**
- Your data may be lost
- Don't store production data

### 2. Performance
- May be slower
- Experimental features are tested
- Instability may occur

### 3. Contract Lifecycle
- Contracts may be deleted
- Take regular backups
- Use test data

## 🚀 Moving to Production

When development is complete:

1. **Deploy to testnet** (final tests)
2. **Deploy to mainnet** (production)
3. **Configure DNS and domain** settings
4. **Enable monitoring and logging**
5. **Create backup strategy**

## 🔍 Debugging

### Log Check
```bash
# Backend logs
tail -f logs/vireca.log

# Stellar network status
soroban network status --network devnet
```

### Contract Events
```bash
# Monitor contract events
soroban events --start-ledger latest --network devnet
```

## 📞 Support

If you encounter issues:

- **Launchtube Discord**: https://discord.gg/launchtube
- **Stellar Discord**: https://discord.gg/stellardev
- **GitHub Issues**: Repository issues section

## ✅ Checklist

Pre-deployment checklist:

- [ ] Soroban CLI installed
- [ ] Stellar wallet created
- [ ] Devnet XLM obtained
- [ ] Contract compiled
- [ ] Network configured
- [ ] Environment set up
- [ ] Backend tested
- [ ] API endpoints working

## 🎯 Conclusion

Using Devnet allows you to:
- ✅ Develop rapidly
- ✅ Test for free  
- ✅ Try new features
- ✅ Test Launchtube integration

**Happy deployments! 🚀** 