#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype, panic_with_error, Address, Bytes, BytesN, Env,
};

// --- HATA TİPLERİ ---
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    AlreadyInitialized = 1,
    DataNotFound = 2,
    PermissionNotFound = 3,
    NotOwner = 4,
    PermissionExpired = 5,
    DataAlreadyRegistered = 6,
}

// --- VERİ YAPILARI ---
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataRecord {
    pub owner: Address,
    pub ipfs_hash: BytesN<32>,
    pub encrypted_key_for_owner: Bytes,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Permission {
    pub granter: Address,
    pub ipfs_hash: BytesN<32>,
    pub encrypted_key_for_doctor: Bytes,
    pub expiration_ledger: u32,
}

// --- KONTRAKT ---
#[contract]
pub struct VirecaContract;

// --- KONTRAKT FONKSİYONLARI ---
#[contractimpl]
impl VirecaContract {
    pub fn register_data(
        env: Env,
        ipfs_hash: BytesN<32>,
        encrypted_key_for_owner: Bytes,
    ) {
        let owner = env.require_auth();
        let key = (owner.clone(), ipfs_hash.clone());

        if env.storage().instance().has(&key) {
            panic_with_error!(&env, Error::DataAlreadyRegistered);
        }

        let record = DataRecord {
            owner: owner.clone(),
            ipfs_hash,
            encrypted_key_for_owner,
        };

        env.storage().instance().set(&key, &record);
    }

    pub fn grant_access(
        env: Env,
        doctor: Address,
        ipfs_hash: BytesN<32>,
        encrypted_key_for_doctor: Bytes,
        duration_in_ledgers: u32,
    ) {
        let granter = env.require_auth();
        let data_key = (granter.clone(), ipfs_hash.clone());

        if !env.storage().instance().has(&data_key) {
            panic_with_error!(&env, Error::DataNotFound);
        }
        
        let expiration_ledger = env.ledger().sequence() + duration_in_ledgers;

        let permission_record = Permission {
            granter,
            ipfs_hash: ipfs_hash.clone(),
            encrypted_key_for_doctor,
            expiration_ledger,
        };
        
        let permission_key = (doctor, ipfs_hash);
        env.storage().instance().set(&permission_key, &permission_record);
    }

    pub fn revoke_access(env: Env, doctor: Address, ipfs_hash: BytesN<32>) {
        let granter = env.require_auth();
        let permission_key = (doctor.clone(), ipfs_hash.clone());

        let permission: Permission = env.storage().instance()
            .get(&permission_key)
            .unwrap_or_else(|| panic_with_error!(&env, Error::PermissionNotFound));

        if permission.granter != granter {
            panic_with_error!(&env, Error::NotOwner);
        }

        env.storage().instance().remove(&permission_key);
    }

    pub fn get_permission(env: Env, doctor: Address, ipfs_hash: BytesN<32>) -> Permission {
        let key = (doctor, ipfs_hash);
        
        let permission: Permission = env.storage().instance()
            .get(&key)
            .unwrap_or_else(|| panic_with_error!(&env, Error::PermissionNotFound));

        if env.ledger().sequence() > permission.expiration_ledger {
            panic_with_error!(&env, Error::PermissionExpired);
        }

        permission
    }

    pub fn get_data_record(env: Env, owner: Address, ipfs_hash: BytesN<32>) -> DataRecord {
        let key = (owner, ipfs_hash);
        env.storage().instance()
            .get(&key)
            .unwrap_or_else(|| panic_with_error!(&env, Error::DataNotFound))
    }
} 