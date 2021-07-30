use crate::state::SecretContract;
use crate::viewing_key::ViewingKey;
use cosmwasm_std::{Binary, HumanAddr, Uint128};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ProfitDistributorInitMsg {
    pub buttcoin: SecretContract,
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
    SetPoolSharesToken {
        token: SecretContract,
    },
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ProfitDistributorHandleAnswer {
    AddProfitToken {
        status: ProfitDistributorResponseStatus,
    },
    ChangeAdmin {
        status: ProfitDistributorResponseStatus,
    },
    CreateViewingKey {
        key: ViewingKey,
    },
    SetPoolSharesToken {
        status: ProfitDistributorResponseStatus,
    },
    SetViewingKey {
        status: ProfitDistributorResponseStatus,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProfitDistributorQueryMsg {
    Balance {
        token: SecretContract,
    },
    Config {},
    Pool {
        token_address: HumanAddr,
    },
    ClaimableProfit {
        token_address: HumanAddr,
        user_address: HumanAddr,
        key: String,
    },
}
impl ProfitDistributorQueryMsg {
    pub fn get_validation_params(&self) -> (&HumanAddr, ViewingKey) {
        match self {
            ProfitDistributorQueryMsg::ClaimableProfit {
                user_address, key, ..
            } => (user_address, ViewingKey(key.clone())),
            _ => panic!("This should never happen"),
        }
    }
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ProfitDistributorQueryAnswer {
    Balance {
        amount: Uint128,
    },
    ClaimableProfit {
        amount: Uint128,
    },
    Pool {
        total_added: Uint128,
    },
    Config {
        admin: HumanAddr,
        buttcoin: SecretContract,
        contract_address: HumanAddr,
        pool_shares_token: Option<SecretContract>,
        profit_tokens: Vec<SecretContract>,
    },

    QueryError {
        msg: String,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProfitDistributorReceiveMsg {
    AddProfit {},
    DepositButtcoin {},
    Withdraw {},
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ProfitDistributorReceiveAnswer {
    AddProfit {
        status: ProfitDistributorResponseStatus,
    },
    DepositButtcoin {
        status: ProfitDistributorResponseStatus,
    },
    Withdraw {
        status: ProfitDistributorResponseStatus,
    },
}

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ProfitDistributorResponseStatus {
    Success,
    Failure,
}
