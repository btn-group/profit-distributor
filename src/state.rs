use cosmwasm_std::HumanAddr;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone, JsonSchema)]
pub struct SecretContract {
    pub address: HumanAddr,
    pub contract_hash: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Config {
    pub admin: HumanAddr,
    pub buttcoin: SecretContract,
    pub contract_address: HumanAddr,
    pub prng_seed: Vec<u8>,
    pub profit_tokens: Vec<SecretContract>,
    pub pool_shares_token: SecretContract,
    pub viewing_key: String,
}
