use crate::state::SecretContract;
use cosmwasm_std::{Binary, HumanAddr, Uint128};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ProfitDistributorInitMsg {
    pub buttcoin: SecretContract,
    pub pool_shares_token: SecretContract,
    pub prng_seed: Binary,
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
    CreateViewingKey {
        entropy: String,
        padding: Option<String>,
    },
    Receive {
        sender: HumanAddr,
        from: HumanAddr,
        amount: Uint128,
        msg: Binary,
    },
    SetViewingKey {
        key: String,
        padding: Option<String>,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProfitDistributorQueryMsg {
    Balance { token: SecretContract },
    Config {},
    Pool { token_address: HumanAddr },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProfitDistributorReceiveMsg {
    AddProfit {},
    DepositButtcoin {},
    Withdraw {},
}

// QUERY RESPONSE STRUCTS
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ProfitDistributorBalanceResponse {
    pub amount: Uint128,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ProfitDistributorPoolResponse {
    pub total_added: Uint128,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ProfitDistributorConfigResponse {
    pub admin: HumanAddr,
    pub buttcoin: SecretContract,
    pub contract_address: HumanAddr,
    pub pool_shares_token: SecretContract,
    pub profit_tokens: Vec<SecretContract>,
}
