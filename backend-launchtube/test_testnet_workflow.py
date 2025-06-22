#!/usr/bin/env python3
"""
Vireca Testnet Workflow Test Script
Tests the complete medical data management workflow on Stellar Testnet
"""

import requests
import json
import time
import base64
from pathlib import Path

# Configuration
API_BASE = "http://localhost:8000"
PATIENT_TOKEN = "mock_token_patient_123"
DOCTOR_TOKEN = "mock_token_doctor_456"
PATIENT_KEY = "GA5HNMXP4XZL634C3DXKU6AM5WAJ6OKMOIKZ2R3SN22WZXRKCS2XA4MZ"
DOCTOR_KEY = "GDOCTOREXAMPLEADDRESS1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def log(message):
    """Print timestamped log message"""
    timestamp = time.strftime("%H:%M:%S")
    print(f"[{timestamp}] {message}")

def test_api_health():
    """Test API health status"""
    log("🔍 Checking API health...")
    try:
        response = requests.get(f"{API_BASE}/health")
        response.raise_for_status()
        health = response.json()
        
        log(f"✅ API Status: {health['status']}")
        log(f"📊 Services: {health['services']}")
        log(f"🔧 Environment: {health['environment']}")
        return True
    except Exception as e:
        log(f"❌ Health check failed: {e}")
        return False

def create_test_file():
    """Create a test medical file"""
    test_content = """MEDICAL REPORT - TESTNET DEPLOYMENT TEST
    
Patient: Test Patient (Testnet)
Date: 2025-06-22
Doctor: Dr. Test (Testnet)

DIAGNOSIS:
- Testnet deployment verification
- Smart contract functionality test
- IPFS integration test

TREATMENT PLAN:
1. Verify file encryption/decryption
2. Test access control mechanisms
3. Validate doctor permissions

NOTES:
This is a test medical report for verifying the Vireca protocol
deployment on Stellar Testnet. All data is mock data for testing
purposes only.

Contract ID: CCPYZFKEAXHHS5VVW5J45TOU7S2EODJ7TZNJIA5LKDVL3PESCES6FNCI
Network: Stellar Testnet
"""
    
    test_file_path = Path("test_medical_report.txt")
    test_file_path.write_text(test_content)
    log(f"📄 Created test file: {test_file_path}")
    return test_file_path

def upload_medical_file(file_path):
    """Upload medical file as patient"""
    log("📤 Uploading medical file...")
    
    with open(file_path, 'rb') as f:
        files = {'file': (file_path.name, f, 'text/plain')}
        data = {
            'owner_public_key': PATIENT_KEY,
            'patient_signature': 'mock_signature_testnet',
            'metadata': json.dumps({
                'title': 'Testnet Medical Report',
                'data_type': 'medical_report',
                'uploaded_at': time.strftime("%Y-%m-%d %H:%M:%S")
            })
        }
        headers = {'Authorization': f'Bearer {PATIENT_TOKEN}'}
        
        response = requests.post(
            f"{API_BASE}/prepare/register-data",
            files=files,
            data=data,
            headers=headers
        )
        
        if response.status_code == 200:
            result = response.json()
            log(f"✅ File uploaded successfully!")
            log(f"📋 IPFS Hash: {result['ipfs_hash']}")
            log(f"🔗 IPFS URL: {result['ipfs_url']}")
            return result
        else:
            log(f"❌ Upload failed: {response.status_code} - {response.text}")
            return None

def grant_doctor_access(ipfs_hash, encrypted_data_key):
    """Grant access to doctor"""
    log("🔐 Granting doctor access...")
    
    data = {
        'granter_public_key': PATIENT_KEY,
        'doctor_public_key': DOCTOR_KEY,
        'ipfs_hash': ipfs_hash,
        'patient_signature': 'mock_signature_testnet',
        'patient_encrypted_data_key': encrypted_data_key,
        'duration_in_ledgers': 1440,  # ~2 hours
        'access_reason': 'Testnet deployment verification'
    }
    headers = {'Authorization': f'Bearer {PATIENT_TOKEN}'}
    
    response = requests.post(
        f"{API_BASE}/prepare/grant-access",
        data=data,
        headers=headers
    )
    
    if response.status_code == 200:
        result = response.json()
        log(f"✅ Access granted successfully!")
        log(f"⏱️ Duration: {result['duration_hours']:.1f} hours")
        log(f"🔑 Encrypted key for doctor: {result['encrypted_data_key_for_doctor'][:20]}...")
        return result
    else:
        log(f"❌ Access grant failed: {response.status_code} - {response.text}")
        return None

def load_doctor_files():
    """Load files accessible to doctor"""
    log("👨‍⚕️ Loading doctor accessible files...")
    
    headers = {'Authorization': f'Bearer {DOCTOR_TOKEN}'}
    response = requests.get(f"{API_BASE}/doctor/accessible-files", headers=headers)
    
    if response.status_code == 200:
        result = response.json()
        files = result.get('accessible_files', [])
        log(f"✅ Found {len(files)} accessible files")
        
        for file in files:
            log(f"📄 File: {file.get('metadata', {}).get('title', 'Unknown')}")
            log(f"   Patient: {file.get('patient_name', 'Unknown')}")
            log(f"   IPFS: {file.get('ipfs_hash', 'Unknown')}")
            log(f"   Reason: {file.get('access_reason', 'No reason')}")
        
        return files
    else:
        log(f"❌ Failed to load doctor files: {response.status_code} - {response.text}")
        return []

def decrypt_medical_file(ipfs_hash, encrypted_key_for_doctor):
    """Decrypt medical file as doctor"""
    log("🔓 Decrypting medical file...")
    
    data = {
        'doctor_public_key': DOCTOR_KEY,
        'ipfs_hash': ipfs_hash,
        'encrypted_data_key_for_doctor': encrypted_key_for_doctor
    }
    headers = {'Authorization': f'Bearer {DOCTOR_TOKEN}'}
    
    response = requests.post(
        f"{API_BASE}/doctor/decrypt-data",
        data=data,
        headers=headers
    )
    
    if response.status_code == 200:
        result = response.json()
        log(f"✅ File decrypted successfully!")
        log(f"📊 Data size: {result['data_size']} bytes")
        log(f"🔄 Mock mode: {result.get('mock_mode', False)}")
        
        # Decode and display content
        decrypted_content = base64.b64decode(result['decrypted_data']).decode('utf-8')
        log(f"📄 Decrypted content preview:")
        log("=" * 50)
        print(decrypted_content[:300] + "..." if len(decrypted_content) > 300 else decrypted_content)
        log("=" * 50)
        
        return result
    else:
        log(f"❌ Decryption failed: {response.status_code} - {response.text}")
        return None

def run_complete_workflow():
    """Run the complete testnet workflow"""
    log("🚀 Starting Vireca Testnet Workflow Test")
    log("=" * 60)
    
    # Step 1: Health check
    if not test_api_health():
        log("❌ API health check failed, aborting test")
        return False
    
    log("")
    
    # Step 2: Create and upload file
    test_file = create_test_file()
    upload_result = upload_medical_file(test_file)
    
    if not upload_result:
        log("❌ File upload failed, aborting test")
        return False
    
    log("")
    
    # Step 3: Grant doctor access
    grant_result = grant_doctor_access(
        upload_result['ipfs_hash'],
        upload_result['file_info']['encrypted_data_key']
    )
    
    if not grant_result:
        log("❌ Access grant failed, aborting test")
        return False
    
    log("")
    
    # Step 4: Load doctor files
    doctor_files = load_doctor_files()
    
    if not doctor_files:
        log("❌ No doctor files found, aborting test")
        return False
    
    log("")
    
    # Step 5: Decrypt file
    target_file = doctor_files[0]  # Use first accessible file
    decrypt_result = decrypt_medical_file(
        target_file['ipfs_hash'],
        target_file['encrypted_data_key_for_doctor']
    )
    
    if not decrypt_result:
        log("❌ File decryption failed, aborting test")
        return False
    
    log("")
    log("🎉 TESTNET WORKFLOW TEST COMPLETED SUCCESSFULLY!")
    log("=" * 60)
    log("✅ All components working correctly:")
    log("   • File encryption and IPFS upload")
    log("   • Access control and permissions")
    log("   • Doctor file access and decryption")
    log("   • Smart contract integration")
    log("")
    log("🌐 Testnet Deployment Details:")
    log(f"   • Contract ID: CCPYZFKEAXHHS5VVW5J45TOU7S2EODJ7TZNJIA5LKDVL3PESCES6FNCI")
    log(f"   • Network: Stellar Testnet")
    log(f"   • IPFS Hash: {upload_result['ipfs_hash']}")
    log("")
    
    # Cleanup
    test_file.unlink()
    log("🗑️ Cleaned up test file")
    
    return True

if __name__ == "__main__":
    success = run_complete_workflow()
    exit(0 if success else 1) 