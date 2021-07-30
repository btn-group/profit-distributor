use crate::state::SecretContract;
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
    Receive {
        sender: HumanAddr,
        from: HumanAddr,
        amount: Uint128,
        msg: Binary,
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
