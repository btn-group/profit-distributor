use crate::msg::ProfitDistributorHandleAnswer;
use crate::msg::ProfitDistributorResponseStatus::Success;
use cosmwasm_std::{
    to_binary, Api, CanonicalAddr, Env, Extern, HandleResponse, Querier, ReadonlyStorage,
    StdResult, Storage,
};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};
use schemars::JsonSchema;
use secret_toolkit::crypto::{sha_256, Prng};
use serde::{Deserialize, Serialize};
use std::fmt;
use subtle::ConstantTimeEq;

// === CONSTANTS ===
pub const VIEWING_KEY_SIZE: usize = 32;
pub const VIEWING_KEY_PREFIX: &str = "api_key_";
pub const VIEWING_KEY_STORAGE_KEY: &[u8] = b"viewingkey";

// === VIEWING KEY STRUCT ===
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub struct ViewingKey(pub String);
impl ViewingKey {
    pub fn check_viewing_key(&self, hashed_pw: &[u8]) -> bool {
        let mine_hashed = create_hashed_password(&self.0);

        ct_slice_compare(&mine_hashed, hashed_pw)
    }

    pub fn new(env: &Env, seed: &[u8], entropy: &[u8]) -> Self {
        // 16 here represents the lengths in bytes of the block height and time.
        let entropy_len = 16 + env.message.sender.len() + entropy.len();
        let mut rng_entropy = Vec::with_capacity(entropy_len);
        rng_entropy.extend_from_slice(&env.block.height.to_be_bytes());
        rng_entropy.extend_from_slice(&env.block.time.to_be_bytes());
        rng_entropy.extend_from_slice(&env.message.sender.0.as_bytes());
        rng_entropy.extend_from_slice(entropy);

        let mut rng = Prng::new(seed, &rng_entropy);

        let rand_slice = rng.rand_bytes();

        let key = sha_256(&rand_slice);

        Self(VIEWING_KEY_PREFIX.to_string() + &base64::encode(key))
    }

    pub fn to_hashed(&self) -> [u8; VIEWING_KEY_SIZE] {
        create_hashed_password(&self.0)
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}
impl fmt::Display for ViewingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// === PUBLIC FUNCTIONS ===
pub fn create_viewing_key<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    entropy: String,
    prng_seed: Vec<u8>,
) -> StdResult<HandleResponse> {
    let key = ViewingKey::new(&env, &prng_seed, (&entropy).as_ref());
    let mut vk_store = PrefixedStorage::new(VIEWING_KEY_STORAGE_KEY, &mut deps.storage);
    vk_store.set(env.message.sender.0.as_bytes(), &key.to_hashed());

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(
            &ProfitDistributorHandleAnswer::CreateViewingKey { status: Success },
        )?),
    })
}

pub fn read_viewing_key<S: Storage>(store: &S, owner: &CanonicalAddr) -> Option<Vec<u8>> {
    let viewing_key_store = ReadonlyPrefixedStorage::new(VIEWING_KEY_STORAGE_KEY, store);
    viewing_key_store.get(owner.as_slice())
}

pub fn set_viewing_key<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    key: String,
) -> StdResult<HandleResponse> {
    let vk = ViewingKey(key);
    let mut vk_store = PrefixedStorage::new(VIEWING_KEY_STORAGE_KEY, &mut deps.storage);
    vk_store.set(env.message.sender.0.as_bytes(), &vk.to_hashed());

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(
            &ProfitDistributorHandleAnswer::CreateViewingKey { status: Success },
        )?),
    })
}

// === PRIVATE FUNCTIONS ===
fn ct_slice_compare(s1: &[u8], s2: &[u8]) -> bool {
    bool::from(s1.ct_eq(s2))
}

fn create_hashed_password(s1: &str) -> [u8; VIEWING_KEY_SIZE] {
    sha_256(s1.as_bytes())
}
