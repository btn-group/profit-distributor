use crate::state::SecretContract;
use cosmwasm_std::{Binary, HumanAddr, Uint128};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ProfitDistributorInitMsg {
    pub buttcoin: SecretContract,
    pub profit_token: SecretContract,
    pub viewing_key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProfitDistributorHandleMsg {
    Receive {
        sender: HumanAddr,
        from: HumanAddr,
        amount: Uint128,
        msg: Binary,
    },
    Withdraw {
        amount: Uint128,
    },
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ProfitDistributorHandleAnswer {
    Withdraw {
        status: ProfitDistributorResponseStatus,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProfitDistributorQueryMsg {
    Config {},
    ClaimableProfit { user_address: HumanAddr },
    User { user_address: HumanAddr },
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ProfitDistributorQueryAnswer {
    ClaimableProfit {
        amount: Uint128,
    },
    Config {
        buttcoin: SecretContract,
        per_share_scaled: Uint128,
        residue: Uint128,
        profit_token: SecretContract,
        total_shares: Uint128,
        viewing_key: String,
    },
    User {
        debt: Uint128,
        shares: Uint128,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProfitDistributorReceiveMsg {
    AddProfit {},
    DepositButtcoin {},
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
}

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ProfitDistributorResponseStatus {
    Success,
}
