use cosmwasm_schema::{export_schema, remove_schemas, schema_for};
use cw_profit_distributor::msg::{
    ProfitDistributorConfigResponse, ProfitDistributorHandleMsg, ProfitDistributorInitMsg,
    ProfitDistributorQueryMsg,
};
use std::env::current_dir;
use std::fs::create_dir_all;

fn main() {
    let mut out_dir = current_dir().unwrap();
    out_dir.push("schema");
    create_dir_all(&out_dir).unwrap();
    remove_schemas(&out_dir).unwrap();

    export_schema(&schema_for!(ProfitDistributorConfigResponse), &out_dir);
    export_schema(&schema_for!(ProfitDistributorHandleMsg), &out_dir);
    export_schema(&schema_for!(ProfitDistributorInitMsg), &out_dir);
    export_schema(&schema_for!(ProfitDistributorQueryMsg), &out_dir);
}
