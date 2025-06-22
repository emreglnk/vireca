# 🚀 Vireca Testnet Quick Start Guide

This guide will help you quickly test the Vireca protocol on Stellar Testnet.

## 📋 Prerequisites

- Python 3.8+
- Backend dependencies installed (`pip install -r requirements.txt`)
- Internet connection for IPFS and Stellar Testnet

## 🏃‍♂️ Quick Start (3 Steps)

### Step 1: Start the Backend Server
```bash
cd backend-launchtube
RPC_URL="https://soroban-testnet.stellar.org:443" \
NETWORK_PASSPHRASE="Test SDF Network ; September 2015" \
CONTRACT_ID="CCPYZFKEAXHHS5VVW5J45TOU7S2EODJ7TZNJIA5LKDVL3PESCES6FNCI" \
python3 -m uvicorn main:app --host 0.0.0.0 --port 8000
```

### Step 2: Open the Test UI
Open `backend-launchtube/test-ui.html` in your web browser.

### Step 3: Test the Complete Workflow
1. **Upload a medical file** as a patient
2. **Grant access** to the doctor
3. **Switch to doctor view** and decrypt the file

## 🧪 Alternative: Automated Testing

Run the automated test script:
```bash
cd backend-launchtube
python3 test_testnet_workflow.py
```

## 🌐 Testnet Information

- **Contract ID**: `CCPYZFKEAXHHS5VVW5J45TOU7S2EODJ7TZNJIA5LKDVL3PESCES6FNCI`
- **Network**: Stellar Testnet
- **Contract Explorer**: [View on Stellar Expert](https://stellar.expert/explorer/testnet/contract/CCPYZFKEAXHHS5VVW5J45TOU7S2EODJ7TZNJIA5LKDVL3PESCES6FNCI)

## 🔧 Test Accounts

The test UI uses these mock accounts:
- **Patient**: `GA5HNMXP4XZL634C3DXKU6AM5WAJ6OKMOIKZ2R3SN22WZXRKCS2XA4MZ`
- **Doctor**: `GDOCTOREXAMPLEADDRESS1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ`

## ✅ Expected Results

After completing the workflow, you should see:
- ✅ File successfully uploaded to IPFS
- ✅ File encrypted with AES-256
- ✅ Access permission granted to doctor
- ✅ Doctor can decrypt and view the medical file
- ✅ All operations logged in the activity log

## 🆘 Troubleshooting

### Backend Won't Start
- Check if port 8000 is already in use: `lsof -i :8000`
- Kill existing processes: `pkill -f uvicorn`

### Test UI Shows "API: Disconnected"
- Ensure the backend server is running on port 8000
- Check the browser console for CORS errors
- Verify the API_BASE URL in the test UI matches your server

### File Upload Fails
- Check PINATA_JWT environment variable is set
- Verify internet connection for IPFS access
- Check file size (max 50MB by default)

### Doctor Can't Decrypt Files
- Ensure you granted access to the correct doctor public key
- Check that the encrypted_data_key_for_doctor field is present
- Verify the doctor has permission to access the specific file

## 📚 Additional Resources

- [Complete Deployment Report](../TESTNET_DEPLOYMENT.md)
- [Backend API Documentation](http://localhost:8000/docs) (when server is running)
- [Smart Contract Source](../contracts/src/lib.rs)
- [Main README](../README.md)

---

**🎉 Happy Testing!**

The Vireca protocol is ready for comprehensive testing on Stellar Testnet. 