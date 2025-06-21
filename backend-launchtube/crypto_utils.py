import os
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from stellar_sdk import Keypair
from typing import Tuple

class VireacaCrypto:
    """Vireca Healthcare Data Encryption System"""
    
    FIXED_SIGNATURE_MESSAGE = "Vireca_key_v1"
    
    @staticmethod
    def generate_data_key() -> bytes:
        """AES-256 için random data key oluştur"""
        return Fernet.generate_key()
    
    @staticmethod
    def encrypt_data(data: bytes, data_key: bytes) -> bytes:
        """Data'yı AES-256 ile şifrele"""
        f = Fernet(data_key)
        return f.encrypt(data)
    
    @staticmethod
    def decrypt_data(encrypted_data: bytes, data_key: bytes) -> bytes:
        """Data'yı AES-256 ile decrypt et"""
        f = Fernet(data_key)
        return f.decrypt(encrypted_data)
    
    @staticmethod
    def derive_patient_key(signature: str) -> bytes:
        """Patient signature'dan deterministic key türet"""
        try:
            # Signature'ı bytes'a çevir
            signature_bytes = base64.b64decode(signature)
        except Exception as e:
            raise ValueError(f"Invalid base64 signature format: {str(e)}")
        
        # PBKDF2 ile key derivation
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bit key
            salt=b'vireca_patient_salt_v1',  # Fixed salt for deterministic keys
            iterations=100000,
        )
        
        return base64.urlsafe_b64encode(kdf.derive(signature_bytes))
    
    @staticmethod
    def derive_patient_key_from_mock(mock_signature: str) -> bytes:
        """Mock signature'dan deterministic key türet (test için)"""
        # Mock signature'ı bytes'a çevir (base64 decode gerektirmez)
        signature_bytes = mock_signature.encode('utf-8')
        
        # PBKDF2 ile key derivation
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bit key
            salt=b'vireca_patient_salt_v1',  # Fixed salt for deterministic keys
            iterations=100000,
        )
        
        return base64.urlsafe_b64encode(kdf.derive(signature_bytes))
    
    @staticmethod
    def encrypt_data_key_for_patient(data_key: bytes, patient_key: bytes) -> str:
        """DataKey'i patient key ile şifrele"""
        f = Fernet(patient_key)
        encrypted = f.encrypt(data_key)
        return base64.b64encode(encrypted).decode('utf-8')
    
    @staticmethod
    def decrypt_data_key_for_patient(encrypted_data_key: str, patient_key: bytes) -> bytes:
        """Patient key ile DataKey'i decrypt et"""
        f = Fernet(patient_key)
        encrypted_bytes = base64.b64decode(encrypted_data_key)
        return f.decrypt(encrypted_bytes)
    
    @staticmethod
    def encrypt_data_key_for_doctor(data_key: bytes, doctor_public_key: str) -> str:
        """DataKey'i doctor'ın public key'i ile şifrele (Stellar keypair kullanarak)"""
        # Bu basitleştirilmiş bir implementasyon
        # Gerçek durumda RSA public key encryption kullanılmalı
        
        # Şimdilik doctor public key'den deterministic key türetelim
        doctor_bytes = doctor_public_key.encode('utf-8')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'vireca_doctor_salt_v1',
            iterations=100000,
        )
        doctor_key = base64.urlsafe_b64encode(kdf.derive(doctor_bytes))
        
        f = Fernet(doctor_key)
        encrypted = f.encrypt(data_key)
        return base64.b64encode(encrypted).decode('utf-8')
    
    @staticmethod
    def decrypt_data_key_for_doctor(encrypted_data_key: str, doctor_private_key: str) -> bytes:
        """Doctor'ın private key'i ile DataKey'i decrypt et"""
        # Doctor public key'den aynı key'i türet
        doctor_bytes = doctor_private_key.encode('utf-8')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'vireca_doctor_salt_v1',
            iterations=100000,
        )
        doctor_key = base64.urlsafe_b64encode(kdf.derive(doctor_bytes))
        
        f = Fernet(doctor_key)
        encrypted_bytes = base64.b64decode(encrypted_data_key)
        return f.decrypt(encrypted_bytes)
    
    @staticmethod
    def sign_message_with_stellar(private_key: str, message: str) -> str:
        """Stellar keypair ile mesaj imzala"""
        try:
            keypair = Keypair.from_secret(private_key)
            signature = keypair.sign(message.encode('utf-8'))
            return base64.b64encode(signature).decode('utf-8')
        except Exception as e:
            raise ValueError(f"Signature error: {str(e)}")
    
    @staticmethod
    def verify_stellar_signature(public_key: str, message: str, signature: str) -> bool:
        """Stellar signature doğrula"""
        try:
            keypair = Keypair.from_public_key(public_key)
            # Base64 decode ile signature'ı bytes'a çevir
            signature_bytes = base64.b64decode(signature)
            keypair.verify(message.encode('utf-8'), signature_bytes)
            return True
        except Exception as e:
            # Debug için hata bilgisini log'la
            print(f"Signature verification failed: {str(e)}")
            return False

# Test fonksiyonları
def test_crypto_flow():
    """Complete crypto flow test"""
    print("🔐 Testing Vireca Crypto Flow...")
    
    # Test data
    medical_data = b"Patient: John Doe\nDiagnosis: Healthy\nDate: 2025-06-21"
    patient_private_key = "SAMEPL3PRIVATEK3Y..." # Mock
    patient_public_key = "GA5HNMXP4XZL634C3DXKU6AM5WAJ6OKMOIKZ2R3SN22WZXRKCS2XA4MZ"
    doctor_public_key = "GDOCTOREXAMPLEADDRESS1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    
    crypto = VireacaCrypto()
    
    # 1. Generate data key
    data_key = crypto.generate_data_key()
    print(f"✅ Data key generated: {len(data_key)} bytes")
    
    # 2. Encrypt medical data
    encrypted_data = crypto.encrypt_data(medical_data, data_key)
    print(f"✅ Data encrypted: {len(encrypted_data)} bytes")
    
    # 3. Patient signature simulation
    patient_signature = "mock_patient_signature_for_key_derivation"
    patient_key = crypto.derive_patient_key_from_mock(patient_signature)
    print(f"✅ Patient key derived from mock signature")
    
    # 4. Encrypt data key for patient
    encrypted_data_key_patient = crypto.encrypt_data_key_for_patient(data_key, patient_key)
    print(f"✅ Data key encrypted for patient")
    
    # 5. Decrypt data key (patient access)
    decrypted_data_key = crypto.decrypt_data_key_for_patient(encrypted_data_key_patient, patient_key)
    assert decrypted_data_key == data_key
    print(f"✅ Patient can decrypt data key")
    
    # 6. Encrypt data key for doctor
    encrypted_data_key_doctor = crypto.encrypt_data_key_for_doctor(data_key, doctor_public_key)
    print(f"✅ Data key encrypted for doctor")
    
    # 7. Doctor decrypts data key
    doctor_data_key = crypto.decrypt_data_key_for_doctor(encrypted_data_key_doctor, doctor_public_key)
    assert doctor_data_key == data_key
    print(f"✅ Doctor can decrypt data key")
    
    # 8. Doctor decrypts medical data
    decrypted_medical_data = crypto.decrypt_data(encrypted_data, doctor_data_key)
    assert decrypted_medical_data == medical_data
    print(f"✅ Doctor can decrypt medical data")
    
    print("🎉 All crypto tests passed!")
    return True

if __name__ == "__main__":
    test_crypto_flow() 