use crate::state::SecretContract;
use cosmwasm_std::{Binary, HumanAddr, Uint128};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ProfitDistributorInitMsg {
    pub buttcoin: SecretContract,
    pub pool_shares_token: SecretContract,
    pub viewing_key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProfitDistributorHandleMsg {
    AddProfitToken {
        token: SecretContract,
    },
    ChangeAdmin {
        address: HumanAddr,
    },
    Receive {
        sender: HumanAddr,
        from: HumanAddr,
        amount: Uint128,
        msg: Binary,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProfitDistributorQueryMsg {
    Balance { token: SecretContract },
    Config {},
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProfitDistributorReceiveMsg {
    Deposit {},
}

// QUERY RESPONSE STRUCTS
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ProfitDistributorBalanceResponse {
    pub amount: Uint128,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ProfitDistributorConfigResponse {
    pub admin: HumanAddr,
    pub buttcoin: SecretContract,
    pub profit_tokens: Vec<SecretContract>,
}
