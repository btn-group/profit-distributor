use crate::constants::{CALCULATION_SCALE, CONFIG_KEY, RESPONSE_BLOCK_SIZE, VIEWING_KEY_KEY};
use crate::msg::{
    ProfitDistributorBalanceResponse, ProfitDistributorConfigResponse, ProfitDistributorHandleMsg,
    ProfitDistributorInitMsg, ProfitDistributorQueryMsg, ProfitDistributorReceiveMsg,
};
use crate::state::{Config, Pool, PoolUser, PoolUserStorage, SecretContract};
use crate::viewing_key::ViewingKey;
use cosmwasm_std::{
    from_binary, to_binary, Api, Binary, Env, Extern, HandleResponse, HumanAddr, InitResponse,
    Querier, StdError, StdResult, Storage, Uint128,
};
use cosmwasm_storage::PrefixedStorage;
use secret_toolkit::crypto::sha_256;

use secret_toolkit::snip20;
use secret_toolkit::storage::{TypedStore, TypedStoreMut};

pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: ProfitDistributorInitMsg,
) -> StdResult<InitResponse> {
    let prng_seed_hashed = sha_256(&msg.prng_seed.0);
    let mut config_store = TypedStoreMut::attach(&mut deps.storage);
    let config = Config {
        admin: env.message.sender,
        buttcoin: msg.buttcoin.clone(),
        contract_address: env.contract.address,
        prng_seed: prng_seed_hashed.to_vec(),
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
    msg: ProfitDistributorHandleMsg,
) -> StdResult<HandleResponse> {
    match msg {
        ProfitDistributorHandleMsg::AddProfitToken { token } => add_profit_token(deps, env, token),
        ProfitDistributorHandleMsg::ChangeAdmin { address, .. } => change_admin(deps, env, address),
        ProfitDistributorHandleMsg::CreateViewingKey { entropy, .. } => {
            create_viewing_key(deps, env, entropy)
        }
        ProfitDistributorHandleMsg::SetViewingKey { key, .. } => set_viewing_key(deps, env, key),
        ProfitDistributorHandleMsg::Receive {
            from, amount, msg, ..
        } => receive(deps, env, from, amount.u128(), msg),
    }
}

pub fn query<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    msg: ProfitDistributorQueryMsg,
) -> StdResult<Binary> {
    match msg {
        ProfitDistributorQueryMsg::Balance { token } => to_binary(&balance(deps, token)?),
        ProfitDistributorQueryMsg::Config {} => to_binary(&public_config(deps)?),
    }
}

fn add_profit_token<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    token: SecretContract,
) -> StdResult<HandleResponse> {
    let mut config: Config = TypedStoreMut::attach(&mut deps.storage).load(CONFIG_KEY)?;
    authorize(config.admin.clone(), env.message.sender)?;

    if config.profit_tokens.contains(&token) {
        return Err(StdError::generic_err(format!("Record not unique")));
    }

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

fn create_viewing_key<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    entropy: String,
) -> StdResult<HandleResponse> {
    let config: Config = TypedStoreMut::attach(&mut deps.storage).load(CONFIG_KEY)?;
    let prng_seed = config.prng_seed;

    let key = ViewingKey::new(&env, &prng_seed, (&entropy).as_ref());

    let mut vk_store = PrefixedStorage::new(VIEWING_KEY_KEY, &mut deps.storage);
    vk_store.set(env.message.sender.0.as_bytes(), &key.to_hashed());

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: None,
    })
}

fn find_pool_user<S: Storage>(
    storage: &mut S,
    token_address: HumanAddr,
    user_address: HumanAddr,
) -> PoolUser {
    let mut pool_user_storage = PoolUserStorage::from_storage(storage, token_address);
    pool_user_storage.get(user_address).unwrap_or(PoolUser {
        debt: 0,
        deposited: 0,
    })
}

fn update_pool_user<S: Storage>(
    storage: &mut S,
    pool_user: PoolUser,
    token_address: HumanAddr,
    user_address: HumanAddr,
) -> StdResult<()> {
    let mut pool_user_storage = PoolUserStorage::from_storage(storage, token_address);
    pool_user_storage.set(user_address, pool_user);
    Ok(())
}

fn deposit_buttcoin<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    from: HumanAddr,
    amount: u128,
) -> StdResult<HandleResponse> {
    let config = TypedStore::<Config, S>::attach(&deps.storage).load(CONFIG_KEY)?;
    authorize(config.buttcoin.address.clone(), env.message.sender.clone())?;

    // Load buttcoin_pool
    let mut buttcoin_pool = TypedStoreMut::<Pool, S>::attach(&mut deps.storage)
        .load(env.message.sender.0.as_bytes())
        .unwrap_or(Pool {
            deposited: 0,
            residue: 0,
            total: 0,
        });

    // Load buttcoin_pool_user
    let mut buttcoin_pool_user =
        find_pool_user(&mut deps.storage, env.message.sender.clone(), from.clone());
    let mut messages = vec![];

    // If the user must claim all claimables first
    if buttcoin_pool_user.deposited > 0 {
        for profit_token in config.profit_tokens {
            let pool: Pool = if profit_token.address == config.buttcoin.address {
                buttcoin_pool.clone()
            } else {
                TypedStoreMut::<Pool, S>::attach(&mut deps.storage)
                    .load(profit_token.address.0.as_bytes())
                    .unwrap_or(Pool {
                        deposited: 0,
                        residue: 0,
                        total: 0,
                    })
            };

            let mut pool_user: PoolUser = if profit_token.address == config.buttcoin.address {
                buttcoin_pool_user.clone()
            } else {
                find_pool_user(
                    &mut deps.storage,
                    profit_token.address.clone(),
                    from.clone(),
                )
            };

            let new_debt = buttcoin_pool_user.deposited * pool.total * CALCULATION_SCALE
                / buttcoin_pool.deposited
                / CALCULATION_SCALE;
            let pending = new_debt - buttcoin_pool_user.debt;
            if pending > 0 {
                messages.push(secret_toolkit::snip20::transfer_msg(
                    from.clone(),
                    Uint128(pending),
                    None,
                    RESPONSE_BLOCK_SIZE,
                    profit_token.contract_hash,
                    profit_token.address.clone(),
                )?);

                pool_user.debt = new_debt;
                if profit_token.address != config.buttcoin.address {
                    update_pool_user(
                        &mut deps.storage,
                        pool_user,
                        profit_token.address,
                        from.clone(),
                    )?;
                }
            }
        }
    }

    // Update buttcoin_pool
    buttcoin_pool.deposited += amount;
    buttcoin_pool.total += amount;
    TypedStoreMut::<Pool, S>::attach(&mut deps.storage)
        .store(env.message.sender.0.as_bytes(), &buttcoin_pool)?;

    // Update buttcoin pool_user
    buttcoin_pool_user.deposited += amount;
    update_pool_user(
        &mut deps.storage,
        buttcoin_pool_user,
        config.buttcoin.address,
        from.clone(),
    )?;

    // Mint share tokens
    messages.push(snip20::mint_msg(
        from,
        Uint128(amount),
        None,
        RESPONSE_BLOCK_SIZE,
        config.pool_shares_token.contract_hash,
        config.pool_shares_token.address,
    )?);

    Ok(HandleResponse {
        messages: messages,
        log: vec![],
        data: None,
    })
}

fn receive<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    from: HumanAddr,
    amount: u128,
    msg: Binary,
) -> StdResult<HandleResponse> {
    let msg: ProfitDistributorReceiveMsg = from_binary(&msg)?;

    match msg {
        ProfitDistributorReceiveMsg::DepositButtcoin {} => {
            deposit_buttcoin(deps, env, from, amount)
        }
    }
}

fn balance<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    token: SecretContract,
) -> StdResult<ProfitDistributorBalanceResponse> {
    let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY)?;
    let balance = snip20::balance_query(
        &deps.querier,
        config.contract_address,
        config.viewing_key,
        RESPONSE_BLOCK_SIZE,
        token.contract_hash,
        token.address,
    )?;
    Ok(ProfitDistributorBalanceResponse {
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
) -> StdResult<ProfitDistributorConfigResponse> {
    let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY)?;
    Ok(ProfitDistributorConfigResponse {
        admin: config.admin,
        buttcoin: config.buttcoin,
        profit_tokens: config.profit_tokens,
    })
}

fn set_viewing_key<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    key: String,
) -> StdResult<HandleResponse> {
    let vk = ViewingKey(key);

    let mut vk_store = PrefixedStorage::new(VIEWING_KEY_KEY, &mut deps.storage);
    vk_store.set(env.message.sender.0.as_bytes(), &vk.to_hashed());

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::ProfitDistributorReceiveMsg;
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
        let msg = ProfitDistributorInitMsg {
            buttcoin: mock_buttcoin(),
            pool_shares_token: pool_shares_token.clone(),
            prng_seed: Binary::from("some-prng-seed".as_bytes()),
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

        let handle_msg = ProfitDistributorHandleMsg::ChangeAdmin {
            address: HumanAddr("bob".to_string()),
        };
        let handle_result = handle(&mut deps, mock_env(MOCK_ADMIN, &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let res = query(&deps, ProfitDistributorQueryMsg::Config {}).unwrap();
        let value: ProfitDistributorConfigResponse = from_binary(&res).unwrap();
        assert_eq!(value.admin, HumanAddr("bob".to_string()));
    }

    #[test]
    fn test_public_config() {
        let (_init_result, deps) = init_helper();

        let res = query(&deps, ProfitDistributorQueryMsg::Config {}).unwrap();
        let value: ProfitDistributorConfigResponse = from_binary(&res).unwrap();
        // Test response does not include viewing key.
        // Test that the desired fields are returned.
        assert_eq!(
            ProfitDistributorConfigResponse {
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
        let msg = ProfitDistributorHandleMsg::AddProfitToken {
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
                        env.contract_code_hash.clone(),
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
        assert_eq!(config.profit_tokens, vec![mock_profit_token()],);

        // When adding a profit token that has already been added
        let handle_response = handle(&mut deps, env.clone(), msg.clone());
        assert_eq!(
            handle_response.unwrap_err(),
            StdError::generic_err(format!("Record not unique"))
        );
    }

    #[test]
    fn test_receive_deposit_buttcoin() {
        let (_init_result, mut deps) = init_helper();
        let amount: Uint128 = Uint128(333);
        let from: HumanAddr = HumanAddr::from("someuser");

        // When received token is not Buttcoin
        let msg = ProfitDistributorHandleMsg::Receive {
            amount: amount,
            from: from.clone(),
            sender: from.clone(),
            msg: to_binary(&ProfitDistributorReceiveMsg::DepositButtcoin {}).unwrap(),
        };
        let handle_response = handle(
            &mut deps,
            mock_env(mock_pool_shares_token().address.to_string(), &[]),
            msg.clone(),
        );
        assert_eq!(
            handle_response.unwrap_err(),
            StdError::Unauthorized { backtrace: None }
        );

        // When received token is Buttcoin
        // It add to the total buttcoin
        let msg = ProfitDistributorHandleMsg::Receive {
            amount: amount,
            from: from.clone(),
            sender: from.clone(),
            msg: to_binary(&ProfitDistributorReceiveMsg::DepositButtcoin {}).unwrap(),
        };
        let handle_response = handle(
            &mut deps,
            mock_env(mock_buttcoin().address.to_string(), &[]),
            msg.clone(),
        );
        let res = handle_response.unwrap();
        assert_eq!(1, res.messages.len());
    }
}
