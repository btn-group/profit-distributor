use crate::constants::{CONFIG_KEY, RESPONSE_BLOCK_SIZE};
use crate::msg::{BalanceResponse, ConfigResponse, HandleMsg, InitMsg, QueryMsg};
use crate::state::{Config, SecretContract};
use cosmwasm_std::{
    to_binary, Api, Binary, Env, Extern, HandleResponse, HumanAddr, InitResponse, Querier,
    StdError, StdResult, Storage, Uint128,
};
use secret_toolkit::snip20;
use secret_toolkit::storage::{TypedStore, TypedStoreMut};

pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: InitMsg,
) -> StdResult<InitResponse> {
    let mut config_store = TypedStoreMut::attach(&mut deps.storage);
    let config = Config {
        admin: env.message.sender,
        buttcoin: msg.buttcoin.clone(),
        contract_address: env.contract.address,
        profit_tokens: vec![],
        pool_shares_token: msg.pool_shares_token.clone(),
        viewing_key: msg.viewing_key.clone(),
    };
    config_store.store(CONFIG_KEY, &config)?;

    // https://github.com/enigmampc/secret-toolkit/tree/master/packages/snip20
    let messages = vec![
        snip20::register_receive_msg(
            env.contract_code_hash.clone(),
            None,
            1,
            msg.buttcoin.contract_hash.clone(),
            msg.buttcoin.address.clone(),
        )?,
        snip20::set_viewing_key_msg(
            msg.viewing_key,
            None,
            RESPONSE_BLOCK_SIZE,
            msg.buttcoin.contract_hash,
            msg.buttcoin.address,
        )?,
    ];

    Ok(InitResponse {
        messages,
        log: vec![],
    })
}

pub fn handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: HandleMsg,
) -> StdResult<HandleResponse> {
    match msg {
        HandleMsg::AddProfitToken { token } => add_profit_token(deps, env, token),
        HandleMsg::ChangeAdmin { address, .. } => change_admin(deps, env, address),
        HandleMsg::Receive {
            from, amount, msg, ..
        } => receive(deps, env, from, amount, msg),
        HandleMsg::SetViewingKey { token } => set_viewing_key(deps, token),
    }
}

pub fn query<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    msg: QueryMsg,
) -> StdResult<Binary> {
    match msg {
        QueryMsg::Balance { token } => to_binary(&balance(deps, token)?),
        QueryMsg::Config {} => to_binary(&public_config(deps)?),
    }
}

fn add_profit_token<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    token: SecretContract,
) -> StdResult<HandleResponse> {
    let mut config: Config = TypedStoreMut::attach(&mut deps.storage).load(CONFIG_KEY)?;
    authorize(config.admin.clone(), env.message.sender)?;

    config.profit_tokens.push(token.clone());
    TypedStoreMut::<Config, S>::attach(&mut deps.storage).store(CONFIG_KEY, &config)?;
    let messages = vec![
        snip20::register_receive_msg(
            env.contract_code_hash.clone(),
            None,
            1,
            token.contract_hash.clone(),
            token.address.clone(),
        )?,
        snip20::set_viewing_key_msg(
            config.viewing_key,
            None,
            RESPONSE_BLOCK_SIZE,
            token.contract_hash,
            token.address,
        )?,
    ];

    Ok(HandleResponse {
        messages: messages,
        log: vec![],
        data: None,
    })
}

fn authorize(expected: HumanAddr, received: HumanAddr) -> StdResult<()> {
    if expected != received {
        return Err(StdError::Unauthorized { backtrace: None });
    }

    Ok(())
}

fn receive<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    from: HumanAddr,
    amount: Uint128,
    _msg: Binary,
) -> StdResult<HandleResponse> {
    let mut messages = vec![];
    let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY)?;
    // If Buttcoin is sent to this contract, mint the user the pool share tokens
    if env.message.sender == config.buttcoin.address {
        messages.push(snip20::mint_msg(
            from,
            amount,
            None,
            RESPONSE_BLOCK_SIZE,
            config.pool_shares_token.contract_hash,
            config.pool_shares_token.address,
        )?)
    }

    Ok(HandleResponse {
        messages: messages,
        log: vec![],
        data: None,
    })
}

fn balance<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    token: SecretContract,
) -> StdResult<BalanceResponse> {
    let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY)?;
    let balance = snip20::balance_query(
        &deps.querier,
        config.contract_address,
        config.viewing_key,
        RESPONSE_BLOCK_SIZE,
        token.contract_hash,
        token.address,
    )?;
    Ok(BalanceResponse {
        amount: balance.amount,
    })
}

fn change_admin<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    address: HumanAddr,
) -> StdResult<HandleResponse> {
    let mut config: Config = TypedStoreMut::attach(&mut deps.storage).load(CONFIG_KEY)?;
    authorize(config.admin, env.message.sender)?;

    config.admin = address;
    TypedStoreMut::<Config, S>::attach(&mut deps.storage).store(CONFIG_KEY, &config)?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: None,
    })
}

fn public_config<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
) -> StdResult<ConfigResponse> {
    let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY)?;
    Ok(ConfigResponse {
        admin: config.admin,
        buttcoin: config.buttcoin,
        profit_tokens: config.profit_tokens,
    })
}

fn set_viewing_key<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    token: SecretContract,
) -> StdResult<HandleResponse> {
    let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY)?;

    let messages = vec![snip20::set_viewing_key_msg(
        config.viewing_key,
        None,
        RESPONSE_BLOCK_SIZE,
        token.contract_hash,
        token.address,
    )?];

    Ok(HandleResponse {
        messages: messages,
        log: vec![],
        data: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::ReceiveMsg;
    use crate::state::SecretContract;
    use cosmwasm_std::from_binary;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, MockApi, MockQuerier, MockStorage};

    pub const MOCK_ADMIN: &str = "admin";

    // === HELPERS ===
    fn init_helper() -> (
        StdResult<InitResponse>,
        Extern<MockStorage, MockApi, MockQuerier>,
    ) {
        let env = mock_env(MOCK_ADMIN, &[]);
        let pool_shares_token = mock_pool_shares_token();
        let mut deps = mock_dependencies(20, &[]);
        let msg = InitMsg {
            buttcoin: mock_buttcoin(),
            pool_shares_token: pool_shares_token.clone(),
            viewing_key: "nannofromthegirlfromnowhereisathaidemon?".to_string(),
        };
        (init(&mut deps, env.clone(), msg), deps)
    }

    fn mock_buttcoin() -> SecretContract {
        SecretContract {
            address: HumanAddr::from("buttcoincontractaddress"),
            contract_hash: "buttcoincontracthash".to_string(),
        }
    }

    fn mock_pool_shares_token() -> SecretContract {
        SecretContract {
            address: HumanAddr::from("pool-shares-address"),
            contract_hash: "pool-shares-contract-hash".to_string(),
        }
    }

    fn mock_profit_token() -> SecretContract {
        SecretContract {
            address: HumanAddr::from("profit-token-address"),
            contract_hash: "profit-token-contract-hash".to_string(),
        }
    }

    // === QUERY TESTS ===

    #[test]
    fn test_change_admin() {
        let (init_result, mut deps) = init_helper();

        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::ChangeAdmin {
            address: HumanAddr("bob".to_string()),
        };
        let handle_result = handle(&mut deps, mock_env(MOCK_ADMIN, &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let res = query(&deps, QueryMsg::Config {}).unwrap();
        let value: ConfigResponse = from_binary(&res).unwrap();
        assert_eq!(value.admin, HumanAddr("bob".to_string()));
    }

    #[test]
    fn test_public_config() {
        let (_init_result, deps) = init_helper();

        let res = query(&deps, QueryMsg::Config {}).unwrap();
        let value: ConfigResponse = from_binary(&res).unwrap();
        // Test response does not include viewing key.
        // Test that the desired fields are returned.
        assert_eq!(
            ConfigResponse {
                admin: HumanAddr::from(MOCK_ADMIN),
                buttcoin: mock_buttcoin(),
                profit_tokens: vec![],
            },
            value
        );
    }

    // === HANDLE TESTS ===

    #[test]
    fn test_handle_add_profit_token() {
        let (_init_result, mut deps) = init_helper();
        let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY).unwrap();

        // When called by a non-admin
        // It returns an unauthorized error
        let msg = HandleMsg::AddProfitToken {
            token: mock_profit_token(),
        };
        let env = mock_env(mock_profit_token().address.to_string(), &[]);
        let handle_response = handle(&mut deps, env, msg.clone());
        assert_eq!(
            handle_response.unwrap_err(),
            StdError::Unauthorized { backtrace: None }
        );

        // When called by an admin
        // It registers a receive message for that token for this contract as well as setting a viewing key
        let env = mock_env(MOCK_ADMIN, &[]);
        let handle_response = handle(&mut deps, env.clone(), msg.clone());
        assert_eq!(
            handle_response.unwrap(),
            HandleResponse {
                messages: vec![
                    snip20::register_receive_msg(
                        env.contract_code_hash,
                        None,
                        1,
                        mock_profit_token().contract_hash,
                        mock_profit_token().address,
                    )
                    .unwrap(),
                    snip20::set_viewing_key_msg(
                        config.viewing_key.clone(),
                        None,
                        RESPONSE_BLOCK_SIZE,
                        mock_profit_token().contract_hash,
                        mock_profit_token().address,
                    )
                    .unwrap(),
                ],
                log: vec![],
                data: None,
            },
        );
        // It stores the profit token in config as a distributable token
        let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY).unwrap();
        assert_eq!(config.profit_tokens, vec![mock_profit_token()],)
    }

    #[test]
    fn test_receive_buttcoin_callback() {
        let (_init_result, mut deps) = init_helper();
        let amount: Uint128 = Uint128(333);
        let from: HumanAddr = HumanAddr::from("someuser");

        // Accepted token
        let msg = HandleMsg::Receive {
            amount: amount,
            from: from.clone(),
            sender: from.clone(),
            msg: to_binary(&ReceiveMsg::Deposit {}).unwrap(),
        };
        let handle_response = handle(
            &mut deps,
            mock_env(mock_buttcoin().address.to_string(), &[]),
            msg.clone(),
        );
        let res = handle_response.unwrap();
        assert_eq!(1, res.messages.len());

        // Other token
        let msg = HandleMsg::Receive {
            amount: amount,
            from: from.clone(),
            sender: from,
            msg: to_binary(&ReceiveMsg::Deposit {}).unwrap(),
        };
        let handle_response = handle(
            &mut deps,
            mock_env(mock_pool_shares_token().address.to_string(), &[]),
            msg.clone(),
        );
        let res = handle_response.unwrap();
        assert_eq!(0, res.messages.len());
    }

    #[test]
    fn test_set_viewing_key() {
        let (init_result, mut deps) = init_helper();

        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::SetViewingKey {
            token: mock_buttcoin(),
        };
        let handle_response = handle(&mut deps, mock_env("anyone", &[]), handle_msg);
        let res = handle_response.unwrap();
        assert_eq!(1, res.messages.len());
    }
}
