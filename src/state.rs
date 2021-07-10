use crate::constants::VIEWING_KEY_KEY;
use crate::viewing_key::ViewingKey;
use cosmwasm_std::{CanonicalAddr, HumanAddr, ReadonlyStorage, StdResult, Storage};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};
use schemars::JsonSchema;
use secret_toolkit::serialization::{Bincode2, Serde};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Config {
    pub admin: HumanAddr,
    pub buttcoin: SecretContract,
    pub contract_address: HumanAddr,
    pub prng_seed: Vec<u8>,
    pub pool_shares_token: SecretContract,
    pub profit_tokens: Vec<SecretContract>,
    pub total_shares: u128,
    pub viewing_key: String,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone)]
pub struct Pool {
    pub per_share_scaled: u128,
    pub residue: u128,
    pub total_added: u128,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PoolUser {
    pub debt: u128,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone, JsonSchema)]
pub struct SecretContract {
    pub address: HumanAddr,
    pub contract_hash: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct User {
    pub shares: u128,
}

// === PoolsUsers Storage ===
pub struct PoolUserReadonlyStorage<'a, S: Storage> {
    storage: ReadonlyPrefixedStorage<'a, S>,
}
impl<'a, S: Storage> PoolUserReadonlyStorage<'a, S> {
    pub fn from_storage(storage: &'a S, token_address: HumanAddr) -> Self {
        Self {
            storage: ReadonlyPrefixedStorage::new(token_address.0.as_bytes(), storage),
        }
    }

    pub fn get(&mut self, user_address: HumanAddr) -> Option<PoolUser> {
        self.as_readonly().get(user_address.0.as_bytes())
    }

    // private

    fn as_readonly(&self) -> ReadonlyPoolUserStorageImpl<ReadonlyPrefixedStorage<S>> {
        ReadonlyPoolUserStorageImpl(&self.storage)
    }
}

pub struct PoolUserStorage<'a, S: Storage> {
    storage: PrefixedStorage<'a, S>,
}
impl<'a, S: Storage> PoolUserStorage<'a, S> {
    pub fn from_storage(storage: &'a mut S, token_address: HumanAddr) -> Self {
        Self {
            storage: PrefixedStorage::new(token_address.0.as_bytes(), storage),
        }
    }

    pub fn get(&mut self, user_address: HumanAddr) -> Option<PoolUser> {
        self.as_readonly().get(user_address.0.as_bytes())
    }

    pub fn set(&mut self, user_address: HumanAddr, value: PoolUser) {
        save(&mut self.storage, user_address.0.as_bytes(), &value).ok();
    }

    // private

    fn as_readonly(&self) -> ReadonlyPoolUserStorageImpl<PrefixedStorage<S>> {
        ReadonlyPoolUserStorageImpl(&self.storage)
    }
}

struct ReadonlyPoolUserStorageImpl<'a, S: ReadonlyStorage>(&'a S);
impl<'a, S: ReadonlyStorage> ReadonlyPoolUserStorageImpl<'a, S> {
    pub fn get(&self, key: &[u8]) -> Option<PoolUser> {
        may_load(self.0, &key).ok().unwrap()
    }
}

// === VIEWING KEYS ===
pub fn write_viewing_key<S: Storage>(store: &mut S, owner: &CanonicalAddr, key: &ViewingKey) {
    let mut balance_store = PrefixedStorage::new(VIEWING_KEY_KEY, store);
    balance_store.set(owner.as_slice(), &key.to_hashed());
}

pub fn read_viewing_key<S: Storage>(store: &S, owner: &CanonicalAddr) -> Option<Vec<u8>> {
    let balance_store = ReadonlyPrefixedStorage::new(VIEWING_KEY_KEY, store);
    balance_store.get(owner.as_slice())
}

// === FUNCTIONS ===
fn may_load<T: DeserializeOwned, S: ReadonlyStorage>(
    storage: &S,
    key: &[u8],
) -> StdResult<Option<T>> {
    match storage.get(key) {
        Some(value) => Bincode2::deserialize(&value).map(Some),
        None => Ok(None),
    }
}

fn save<T: Serialize, S: Storage>(storage: &mut S, key: &[u8], value: &T) -> StdResult<()> {
    storage.set(key, &Bincode2::serialize(value)?);
    Ok(())
}
