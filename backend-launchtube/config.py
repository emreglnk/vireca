"""
Launchtube Platform Configuration
Vireca Healthcare Data Management System için özel yapılandırma
"""

import os
from typing import List, Dict, Any
from pydantic import BaseSettings, Field


class LaunchtubeConfig(BaseSettings):
    """Launchtube platform yapılandırması"""
    
    # Launchtube Platform Settings
    launchtube_api_key: str = Field(..., env="LAUNCHTUBE_API_KEY")
    launchtube_base_url: str = Field("https://api.launchtube.xyz", env="LAUNCHTUBE_BASE_URL")
    launchtube_network: str = Field("testnet", env="LAUNCHTUBE_NETWORK")
    launchtube_version: str = Field("v1", env="LAUNCHTUBE_VERSION")
    
    # Stellar/Soroban Settings
    contract_id: str = Field(..., env="CONTRACT_ID")
    network_passphrase: str = Field("Test SDF Network ; September 2015", env="NETWORK_PASSPHRASE")
    rpc_url: str = Field("https://soroban-testnet.stellar.org:443", env="RPC_URL")
    
    # IPFS Settings
    pinata_jwt: str = Field(..., env="PINATA_JWT")
    ipfs_gateway_url: str = Field("https://gateway.pinata.cloud/ipfs/", env="IPFS_GATEWAY_URL")
    ipfs_pin_url: str = Field("https://api.pinata.cloud/pinning/pinFileToIPFS", env="IPFS_PIN_URL")
    
    # Security Settings
    jwt_secret_key: str = Field(..., env="JWT_SECRET_KEY")
    jwt_algorithm: str = Field("HS256", env="JWT_ALGORITHM")
    access_token_expire_minutes: int = Field(1440, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    
    # API Settings
    max_file_size_mb: int = Field(50, env="MAX_FILE_SIZE_MB")
    cors_origins: List[str] = Field(
        ["http://localhost:3000", "https://launchtube.xyz"],
        env="CORS_ORIGINS"
    )
    
    # Rate Limiting
    rate_limit_requests: int = Field(100, env="RATE_LIMIT_REQUESTS")
    rate_limit_period: int = Field(60, env="RATE_LIMIT_PERIOD")  # seconds
    
    # Logging
    log_level: str = Field("INFO", env="LOG_LEVEL")
    log_format: str = Field("json", env="LOG_FORMAT")  # json or standard
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Launchtube platform özel sabitler
LAUNCHTUBE_CONSTANTS = {
    "SUPPORTED_FILE_TYPES": [
        "application/pdf",
        "image/jpeg",
        "image/png",
        "image/tiff",
        "application/dicom",
        "text/plain",
        "application/json"
    ],
    
    "MEDICAL_DATA_TYPES": {
        "medical_report": "Tıbbi Rapor",
        "lab_result": "Laboratuvar Sonucu",
        "prescription": "Reçete",
        "radiology": "Radyoloji",
        "pathology": "Patoloji",
        "surgery_report": "Ameliyat Raporu",
        "consultation": "Konsültasyon",
        "other": "Diğer"
    },
    
    "ACCESS_LEVELS": {
        "read": "Okuma",
        "read_write": "Okuma/Yazma", 
        "full": "Tam Erişim"
    },
    
    "NETWORK_CONFIG": {
        "devnet": {
            "name": "Stellar Devnet",
            "rpc_url": "https://rpc-devnet.stellar.org:443",
            "network_passphrase": "Standalone Network ; February 2017",
            "explorer_url": "https://stellar.expert/explorer/devnet",
            "friendbot_url": "https://friendbot-devnet.stellar.org",
            "description": "Development network - Hızlı reset, geliştirme için ideal"
        },
        "testnet": {
            "name": "Stellar Testnet",
            "rpc_url": "https://soroban-testnet.stellar.org:443",
            "network_passphrase": "Test SDF Network ; September 2015",
            "explorer_url": "https://stellar.expert/explorer/testnet",
            "friendbot_url": "https://friendbot.stellar.org",
            "description": "Test network - Stabil test ortamı"
        },
        "mainnet": {
            "name": "Stellar Mainnet",
            "rpc_url": "https://soroban-mainnet.stellar.org:443",
            "network_passphrase": "Public Global Stellar Network ; September 2015",
            "explorer_url": "https://stellar.expert/explorer/public",
            "friendbot_url": None,
            "description": "Production network - Gerçek XLM gerektirir"
        }
    },
    
    "LAUNCHTUBE_ROLES": {
        "patient": "Hasta",
        "doctor": "Doktor",
        "nurse": "Hemşire",
        "admin": "Yönetici",
        "researcher": "Araştırmacı"
    }
}

# Error codes
LAUNCHTUBE_ERROR_CODES = {
    "USER_NOT_FOUND": 404001,
    "INVALID_SIGNATURE": 400001,
    "PERMISSION_DENIED": 403001,
    "FILE_TOO_LARGE": 413001,
    "UNSUPPORTED_FILE_TYPE": 415001,
    "RATE_LIMIT_EXCEEDED": 429001,
    "IPFS_UPLOAD_FAILED": 500001,
    "STELLAR_NETWORK_ERROR": 500002,
    "LAUNCHTUBE_API_ERROR": 500003
}

# Default metadata template
DEFAULT_METADATA_TEMPLATE = {
    "version": "1.0",
    "platform": "launchtube",
    "encryption": "AES-256-GCM",
    "created_at": None,  # Will be set automatically
    "updated_at": None,   # Will be set automatically
    "tags": [],
    "access_history": [],
    "compliance": {
        "hipaa": True,
        "gdpr": True,
        "kvkk": True  # Türkiye KVKK
    }
}

def get_config() -> LaunchtubeConfig:
    """Yapılandırma nesnesini döndürür"""
    return LaunchtubeConfig()

def get_network_config(network: str = "testnet") -> Dict[str, Any]:
    """Ağ yapılandırmasını döndürür"""
    return LAUNCHTUBE_CONSTANTS["NETWORK_CONFIG"].get(network, LAUNCHTUBE_CONSTANTS["NETWORK_CONFIG"]["testnet"])

def get_friendbot_url(network: str = "testnet") -> str:
    """Network için friendbot URL'sini döndürür"""
    config = get_network_config(network)
    return config.get("friendbot_url", "https://friendbot.stellar.org")

def is_development_network(network: str) -> bool:
    """Network'ün development network olup olmadığını kontrol eder"""
    return network in ["devnet", "testnet"]

def is_supported_file_type(content_type: str) -> bool:
    """Dosya tipinin desteklenip desteklenmediğini kontrol eder"""
    return content_type in LAUNCHTUBE_CONSTANTS["SUPPORTED_FILE_TYPES"]

def get_medical_data_type_name(data_type: str) -> str:
    """Tıbbi veri tipinin Türkçe adını döndürür"""
    return LAUNCHTUBE_CONSTANTS["MEDICAL_DATA_TYPES"].get(data_type, "Bilinmeyen")

def get_role_name(role: str) -> str:
    """Rol adının Türkçe karşılığını döndürür"""
    return LAUNCHTUBE_CONSTANTS["LAUNCHTUBE_ROLES"].get(role, "Bilinmeyen Rol") 