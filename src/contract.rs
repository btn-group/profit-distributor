use crate::authorize::authorize;
use crate::constants::{CALCULATION_SCALE, CONFIG_KEY, RESPONSE_BLOCK_SIZE};
use crate::msg::ProfitDistributorResponseStatus::Success;
use crate::msg::{
    ProfitDistributorHandleAnswer, ProfitDistributorHandleMsg, ProfitDistributorInitMsg,
    ProfitDistributorQueryAnswer, ProfitDistributorQueryMsg, ProfitDistributorReceiveAnswer,
    ProfitDistributorReceiveMsg,
};
use crate::pool_shares_token::InitMsg;
use crate::state::{
    Config, Pool, PoolUser, PoolUserReadonlyStorage, PoolUserStorage, SecretContract, User,
};
use crate::viewing_key::{create_viewing_key, read_viewing_key, set_viewing_key, VIEWING_KEY_SIZE};
use cosmwasm_std::{
    from_binary, to_binary, Api, Binary, CosmosMsg, Env, Extern, HandleResponse, HumanAddr,
    InitResponse, Querier, StdError, StdResult, Storage, Uint128,
};
use secret_toolkit::crypto::sha_256;
use secret_toolkit::snip20;
use secret_toolkit::storage::{TypedStore, TypedStoreMut};
use secret_toolkit::utils::{pad_handle_result, pad_query_result, InitCallback};

pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: ProfitDistributorInitMsg,
) -> StdResult<InitResponse> {
    let prng_seed_hashed = sha_256(&msg.prng_seed.0);
    let mut config_store = TypedStoreMut::attach(&mut deps.storage);
    let config = Config {
        admin: env.message.sender.clone(),
        buttcoin: msg.buttcoin.clone(),
        contract_address: env.contract.address.clone(),
        prng_seed: prng_seed_hashed.to_vec(),
        profit_tokens: vec![],
        pool_shares_token: msg.pool_shares_token.clone(),
        total_shares: 0,
        viewing_key: msg.viewing_key.clone(),
    };
    config_store.store(CONFIG_KEY, &config)?;

    // Initiate pool shares token for this contract
    let pool_shares_token_init_msg = InitMsg { count: 100 };
    // Create contract label, get code id for ontract and the hash. Don't worry about the last input as that's to do with putting Secret tokens in there and there's no need for that.
    let pool_shares_token_init_msg_as_cosmos_msg = pool_shares_token_init_msg.to_cosmos_msg(
        "new_contract_label".to_string(),
        123,
        "CODE_HASH_OF_CONTRACT_YOU_WANT_TO_INSTANTIATE".to_string(),
        None,
    )?;

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
    let response = match msg {
        ProfitDistributorHandleMsg::AddProfitToken { token } => add_profit_token(deps, env, token),
        ProfitDistributorHandleMsg::ChangeAdmin { address, .. } => change_admin(deps, env, address),
        ProfitDistributorHandleMsg::CreateViewingKey { entropy, .. } => {
            let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY)?;
            create_viewing_key(deps, env, entropy, config.prng_seed)
        }
        ProfitDistributorHandleMsg::SetViewingKey { key, .. } => set_viewing_key(deps, env, key),
        ProfitDistributorHandleMsg::Receive {
            from, amount, msg, ..
        } => receive(deps, env, from, amount.u128(), msg),
    };

    pad_handle_result(response, RESPONSE_BLOCK_SIZE)
}

pub fn query<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    msg: ProfitDistributorQueryMsg,
) -> StdResult<Binary> {
    match msg {
        ProfitDistributorQueryMsg::Balance { token } => balance(deps, token),
        ProfitDistributorQueryMsg::Config {} => public_config(deps),
        ProfitDistributorQueryMsg::Pool { token_address } => public_pool(deps, token_address),
        _ => pad_query_result(authenticated_queries(deps, msg), RESPONSE_BLOCK_SIZE),
    }
}

fn authenticated_queries<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    msg: ProfitDistributorQueryMsg,
) -> StdResult<Binary> {
    let (address, key) = msg.get_validation_params();
    let canonical_addr = deps.api.canonical_address(address)?;
    let expected_key = read_viewing_key(&deps.storage, &canonical_addr);

    if expected_key.is_none() {
        // Checking the key will take significant time. We don't want to exit immediately if it isn't set
        // in a way which will allow to time the command and determine if a viewing key doesn't exist
        key.check_viewing_key(&[0u8; VIEWING_KEY_SIZE]);
    } else if key.check_viewing_key(expected_key.unwrap().as_slice()) {
        return match msg {
            ProfitDistributorQueryMsg::ClaimableProfit {
                token_address,
                user_address,
                ..
            } => query_claimable_profit(deps, &token_address, &user_address),
            _ => panic!("This should never happen"),
        };
    }

    Ok(to_binary(&ProfitDistributorQueryAnswer::QueryError {
        msg: "Wrong viewing key for this address or viewing key not set".to_string(),
    })?)
}

fn claimable_profit(pool: Pool, pool_user: PoolUser, user: User) -> u128 {
    if pool.residue > 0 {
        pool.residue
    } else {
        user.shares * pool.per_share_scaled / CALCULATION_SCALE - pool_user.debt
    }
}

fn query_claimable_profit<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    token_address: &HumanAddr,
    user_address: &HumanAddr,
) -> StdResult<Binary> {
    let mut amount: u128 = 0;
    // Load user
    let user = TypedStore::<User, S>::attach(&deps.storage).load(user_address.0.as_bytes())?;
    if user.shares > 0 {
        // Load pool
        let pool: Pool = TypedStore::attach(&deps.storage).load(token_address.0.as_bytes())?;
        // Load pool_user
        let pool_user: PoolUser =
            PoolUserReadonlyStorage::from_storage(&deps.storage, token_address.clone())
                .get(user_address.clone())
                .unwrap_or(PoolUser { debt: 0 });
        amount = claimable_profit(pool, pool_user, user);
    }

    to_binary(&ProfitDistributorQueryAnswer::ClaimableProfit {
        amount: Uint128(amount),
    })
}

fn add_profit<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    amount: u128,
) -> StdResult<HandleResponse> {
    let token_address_as_bytes = env.message.sender.0.as_bytes();
    let mut pool: Pool = TypedStoreMut::attach(&mut deps.storage).load(token_address_as_bytes)?;
    if amount > 0 {
        let config: Config = TypedStoreMut::attach(&mut deps.storage).load(CONFIG_KEY)?;
        if config.total_shares == 0 {
            pool.residue += amount;
        } else {
            pool.per_share_scaled +=
                (amount + pool.residue) * CALCULATION_SCALE / config.total_shares;
            pool.residue = 0;
        };
        pool.total_added += amount;
        TypedStoreMut::attach(&mut deps.storage).store(token_address_as_bytes, &pool)?;
    }

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&ProfitDistributorReceiveAnswer::AddProfit {
            status: Success,
        })?),
    })
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

    // Store token into profit tokens vector
    config.profit_tokens.push(token.clone());
    TypedStoreMut::<Config, S>::attach(&mut deps.storage).store(CONFIG_KEY, &config)?;

    // Store pool into database
    TypedStoreMut::<Pool, S>::attach(&mut deps.storage).store(
        token.address.0.as_bytes(),
        &Pool {
            per_share_scaled: 0,
            residue: 0,
            total_added: 0,
        },
    )?;

    Ok(HandleResponse {
        messages: vec![
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
        ],
        log: vec![],
        data: Some(to_binary(&ProfitDistributorHandleAnswer::AddProfitToken {
            status: Success,
        })?),
    })
}

fn balance<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    token: SecretContract,
) -> StdResult<Binary> {
    let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY)?;
    let balance = snip20::balance_query(
        &deps.querier,
        config.contract_address,
        config.viewing_key,
        RESPONSE_BLOCK_SIZE,
        token.contract_hash,
        token.address,
    )?;

    to_binary(&ProfitDistributorQueryAnswer::Balance {
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
        data: Some(to_binary(&ProfitDistributorHandleAnswer::ChangeAdmin {
            status: Success,
        })?),
    })
}

fn deposit_buttcoin<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    from: HumanAddr,
    amount: u128,
) -> StdResult<HandleResponse> {
    let mut config = TypedStoreMut::<Config, S>::attach(&mut deps.storage).load(CONFIG_KEY)?;
    authorize(config.buttcoin.address.clone(), env.message.sender.clone())?;

    let mut user = TypedStoreMut::<User, S>::attach(&mut deps.storage)
        .load(from.0.as_bytes())
        .unwrap_or(User { shares: 0 });
    let shares_after_transaction: u128 = user.shares + amount;

    let mut messages: Vec<CosmosMsg> = generate_messages_to_claim_profits_and_update_debts(
        &mut deps.storage,
        config.clone(),
        shares_after_transaction,
        from.clone(),
        user.clone(),
    )?;

    // Update user shares
    user.shares = shares_after_transaction;
    TypedStoreMut::<User, S>::attach(&mut deps.storage).store(from.0.as_bytes(), &user)?;

    // Update config shares
    config.total_shares += amount;
    TypedStoreMut::<Config, S>::attach(&mut deps.storage).store(CONFIG_KEY, &config)?;

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
        data: Some(to_binary(
            &ProfitDistributorReceiveAnswer::DepositButtcoin { status: Success },
        )?),
    })
}

fn generate_messages_to_claim_profits_and_update_debts<S: Storage>(
    storage: &mut S,
    config: Config,
    shares_after_transaction: u128,
    user_address: HumanAddr,
    user: User,
) -> StdResult<Vec<CosmosMsg>> {
    let mut messages: Vec<CosmosMsg> = vec![];
    for profit_token in config.profit_tokens {
        let mut pool: Pool = TypedStoreMut::<Pool, S>::attach(storage)
            .load(profit_token.address.0.as_bytes())
            .unwrap();
        let mut pool_user: PoolUser =
            PoolUserStorage::from_storage(storage, profit_token.address.clone())
                .get(user_address.clone())
                .unwrap_or(PoolUser { debt: 0 });
        if user.shares > 0 {
            if pool.residue > 0 {
                pool.per_share_scaled += pool.residue * CALCULATION_SCALE / config.total_shares;
                pool.residue = 0;
                TypedStoreMut::attach(storage)
                    .store(profit_token.address.0.as_bytes(), &pool)
                    .unwrap();
            }

            if pool.per_share_scaled > 0 {
                let claimable_profit: u128 =
                    claimable_profit(pool.clone(), pool_user.clone(), user.clone());
                if claimable_profit > 0 {
                    messages.push(secret_toolkit::snip20::transfer_msg(
                        user_address.clone(),
                        Uint128(claimable_profit),
                        None,
                        RESPONSE_BLOCK_SIZE,
                        profit_token.contract_hash,
                        profit_token.address.clone(),
                    )?);
                }
            }
        }
        pool_user.debt = shares_after_transaction * pool.per_share_scaled / CALCULATION_SCALE;
        PoolUserStorage::from_storage(storage, profit_token.address)
            .set(user_address.clone(), pool_user)
    }
    Ok(messages)
}

fn public_config<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>) -> StdResult<Binary> {
    let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY)?;

    to_binary(&ProfitDistributorQueryAnswer::Config {
        admin: config.admin,
        buttcoin: config.buttcoin,
        contract_address: config.contract_address,
        pool_shares_token: config.pool_shares_token,
        profit_tokens: config.profit_tokens,
    })
}

fn public_pool<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    token_address: HumanAddr,
) -> StdResult<Binary> {
    let pool: Pool = TypedStore::attach(&deps.storage).load(token_address.0.as_bytes())?;

    to_binary(&ProfitDistributorQueryAnswer::Pool {
        total_added: Uint128(pool.total_added),
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
        ProfitDistributorReceiveMsg::AddProfit {} => add_profit(deps, env, amount),
        ProfitDistributorReceiveMsg::DepositButtcoin {} => {
            deposit_buttcoin(deps, env, from, amount)
        }
        ProfitDistributorReceiveMsg::Withdraw {} => withdraw(deps, env, from, amount),
    }
}

fn withdraw<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    from: HumanAddr,
    amount: u128,
) -> StdResult<HandleResponse> {
    let mut config = TypedStoreMut::<Config, S>::attach(&mut deps.storage).load(CONFIG_KEY)?;
    authorize(
        config.pool_shares_token.address.clone(),
        env.message.sender.clone(),
    )?;

    let mut user = TypedStoreMut::<User, S>::attach(&mut deps.storage)
        .load(from.0.as_bytes())
        .unwrap();
    if amount > user.shares {
        return Err(StdError::generic_err(format!(
            "insufficient funds to withdraw: balance={}, required={}",
            user.shares, amount,
        )));
    }

    let shares_after_transaction: u128 = user.shares - amount;

    let mut messages: Vec<CosmosMsg> = generate_messages_to_claim_profits_and_update_debts(
        &mut deps.storage,
        config.clone(),
        shares_after_transaction,
        from.clone(),
        user.clone(),
    )?;

    if amount > 0 {
        // Update user shares
        user.shares = shares_after_transaction;
        TypedStoreMut::<User, S>::attach(&mut deps.storage).store(from.0.as_bytes(), &user)?;

        // Update config shares
        config.total_shares -= amount;
        TypedStoreMut::<Config, S>::attach(&mut deps.storage).store(CONFIG_KEY, &config)?;

        // Burn share tokens
        messages.push(snip20::burn_msg(
            Uint128(amount),
            None,
            RESPONSE_BLOCK_SIZE,
            config.pool_shares_token.contract_hash,
            config.pool_shares_token.address,
        )?);

        // Send buttcoin to user
        messages.push(secret_toolkit::snip20::transfer_msg(
            from,
            Uint128(amount),
            None,
            RESPONSE_BLOCK_SIZE,
            config.buttcoin.contract_hash,
            config.buttcoin.address.clone(),
        )?);
    }

    Ok(HandleResponse {
        messages: messages,
        log: vec![],
        data: Some(to_binary(&ProfitDistributorReceiveAnswer::Withdraw {
            status: Success,
        })?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::ProfitDistributorReceiveMsg;
    use crate::state::SecretContract;
    use cosmwasm_std::from_binary;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, MockApi, MockQuerier, MockStorage};
    use cosmwasm_std::StdError::NotFound;

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
        let value: ProfitDistributorQueryAnswer = from_binary(&res).unwrap();
        match value {
            ProfitDistributorQueryAnswer::Config { admin, .. } => {
                assert_eq!(admin, HumanAddr("bob".to_string()))
            }
            _ => panic!("at the taco bell"),
        }
    }

    #[test]
    fn test_public_config() {
        let (_init_result, deps) = init_helper();
        let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY).unwrap();

        let res = query(&deps, ProfitDistributorQueryMsg::Config {}).unwrap();
        let value: ProfitDistributorQueryAnswer = from_binary(&res).unwrap();
        // Test response does not include viewing key.
        // Test that the desired fields are returned.
        match value {
            ProfitDistributorQueryAnswer::Config {
                admin,
                buttcoin,
                contract_address,
                pool_shares_token,
                profit_tokens,
            } => {
                assert_eq!(admin, config.admin);
                assert_eq!(buttcoin, config.buttcoin);
                assert_eq!(contract_address, config.contract_address);
                assert_eq!(pool_shares_token, config.pool_shares_token);
                assert_eq!(profit_tokens, config.profit_tokens);
            }
            _ => panic!("at the taco bell"),
        }
    }

    #[test]
    fn test_public_pool() {
        let (_init_result, mut deps) = init_helper();
        let add_profit_token_msg = ProfitDistributorHandleMsg::AddProfitToken {
            token: mock_buttcoin(),
        };
        let amount: Uint128 = Uint128(123);

        handle(
            &mut deps,
            mock_env(MOCK_ADMIN, &[]),
            add_profit_token_msg.clone(),
        )
        .unwrap();

        // = When no profit has been added
        // = * It returns a zero value
        let res = query(
            &deps,
            ProfitDistributorQueryMsg::Pool {
                token_address: mock_buttcoin().address,
            },
        )
        .unwrap();
        let value: ProfitDistributorQueryAnswer = from_binary(&res).unwrap();
        match value {
            ProfitDistributorQueryAnswer::Pool { total_added } => {
                assert_eq!(total_added, Uint128(0));
            }
            _ => panic!("at the taco bell"),
        }

        // == When profit has been added
        // == * It returns the total added
        let receive_add_profit_msg = ProfitDistributorHandleMsg::Receive {
            amount: amount,
            from: mock_buttcoin().address,
            sender: mock_buttcoin().address,
            msg: to_binary(&ProfitDistributorReceiveMsg::AddProfit {}).unwrap(),
        };
        handle(
            &mut deps,
            mock_env(mock_buttcoin().address.to_string(), &[]),
            receive_add_profit_msg.clone(),
        )
        .unwrap();
        let res = query(
            &deps,
            ProfitDistributorQueryMsg::Pool {
                token_address: mock_buttcoin().address,
            },
        )
        .unwrap();
        let value: ProfitDistributorQueryAnswer = from_binary(&res).unwrap();
        match value {
            ProfitDistributorQueryAnswer::Pool { total_added } => {
                assert_eq!(total_added, amount);
            }
            _ => panic!("at the taco bell"),
        }

        // === When shares added
        // === * It doesn't affect the total added
        let msg = ProfitDistributorHandleMsg::Receive {
            amount: amount,
            from: mock_pool_shares_token().address,
            sender: mock_pool_shares_token().address,
            msg: to_binary(&ProfitDistributorReceiveMsg::DepositButtcoin {}).unwrap(),
        };
        handle(
            &mut deps,
            mock_env(mock_buttcoin().address.to_string(), &[]),
            msg.clone(),
        )
        .unwrap();
        let res = query(
            &deps,
            ProfitDistributorQueryMsg::Pool {
                token_address: mock_buttcoin().address,
            },
        )
        .unwrap();
        let value: ProfitDistributorQueryAnswer = from_binary(&res).unwrap();
        match value {
            ProfitDistributorQueryAnswer::Pool { total_added } => {
                assert_eq!(total_added, amount);
            }
            _ => panic!("at the taco bell"),
        }
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
        let env = mock_env(MOCK_ADMIN, &[]);
        let handle_response = handle(&mut deps, env.clone(), msg.clone());

        // It registers a receive message for that token for this contract as well as setting a viewing key
        let handle_response_unwrapped = handle_response.unwrap();
        assert_eq!(
            handle_response_unwrapped.messages,
            vec![
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
            ]
        );
        let handle_response_data: ProfitDistributorHandleAnswer =
            from_binary(&handle_response_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_response_data).unwrap(),
            to_binary(&ProfitDistributorHandleAnswer::AddProfitToken { status: Success }).unwrap()
        );

        // It stores the profit token in config as a distributable token
        let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY).unwrap();
        assert_eq!(config.profit_tokens, vec![mock_profit_token()],);

        // It stores a Pool struct for the token
        let mock_profit_token_pool: Pool = TypedStore::attach(&deps.storage)
            .load(mock_profit_token().address.0.as_bytes())
            .unwrap();
        assert_eq!(
            mock_profit_token_pool,
            Pool {
                per_share_scaled: 0,
                residue: 0,
                total_added: 0,
            }
        );

        // When adding a profit token that has already been added
        let handle_response = handle(&mut deps, env.clone(), msg.clone());
        assert_eq!(
            handle_response.unwrap_err(),
            StdError::generic_err(format!("Record not unique"))
        );
    }

    #[test]
    fn test_handle_change_admin() {
        let (_init_result, mut deps) = init_helper();

        // = When called by a non-admin
        // = * It returns an unauthorized error
        let change_admin_msg = ProfitDistributorHandleMsg::ChangeAdmin {
            address: mock_buttcoin().address,
        };
        let handle_response = handle(
            &mut deps,
            mock_env(mock_buttcoin().address, &[]),
            change_admin_msg.clone(),
        );
        assert_eq!(
            handle_response.unwrap_err(),
            StdError::Unauthorized { backtrace: None }
        );

        // = When called by an admin
        // = * It changes the admin
        let handle_response = handle(
            &mut deps,
            mock_env(MOCK_ADMIN, &[]),
            change_admin_msg.clone(),
        );
        handle_response.unwrap();
        let config: Config = TypedStoreMut::attach(&mut deps.storage)
            .load(CONFIG_KEY)
            .unwrap();
        assert_eq!(config.admin, mock_buttcoin().address);
    }

    #[test]
    fn test_handle_receive_add_profit() {
        let (_init_result, mut deps) = init_helper();
        let amount: Uint128 = Uint128(333);
        let buttcoin_deposit_amount: Uint128 = Uint128(3);
        let from: HumanAddr = HumanAddr::from("someuser");

        // = When received token is not an allowed profit token
        // = * It returns an unauthorized error
        let receive_add_profit_msg = ProfitDistributorHandleMsg::Receive {
            amount: amount,
            from: from.clone(),
            sender: from.clone(),
            msg: to_binary(&ProfitDistributorReceiveMsg::AddProfit {}).unwrap(),
        };
        let handle_response = handle(
            &mut deps,
            mock_env(mock_buttcoin().address.to_string(), &[]),
            receive_add_profit_msg.clone(),
        );
        assert_eq!(
            handle_response.unwrap_err(),
            NotFound {
                kind: "cw_profit_distributor::state::Pool".to_string(),
                backtrace: None
            }
        );

        // = When received token is an allowed profit token
        let add_profit_token_msg = ProfitDistributorHandleMsg::AddProfitToken {
            token: mock_buttcoin(),
        };
        let handle_response = handle(
            &mut deps,
            mock_env(MOCK_ADMIN, &[]),
            add_profit_token_msg.clone(),
        );
        handle_response.unwrap();
        // == With an amount of zero
        let receive_add_profit_msg = ProfitDistributorHandleMsg::Receive {
            amount: Uint128(0),
            from: from.clone(),
            sender: from.clone(),
            msg: to_binary(&ProfitDistributorReceiveMsg::AddProfit {}).unwrap(),
        };
        let handle_response = handle(
            &mut deps,
            mock_env(mock_buttcoin().address.to_string(), &[]),
            receive_add_profit_msg.clone(),
        );
        handle_response.unwrap();
        // == * It does not update the token's pool
        let pool: Pool = TypedStoreMut::attach(&mut deps.storage)
            .load(mock_buttcoin().address.0.as_bytes())
            .unwrap();
        assert_eq!(pool.per_share_scaled, 0);
        assert_eq!(pool.residue, 0);
        // == With an amount greater than zero
        let receive_add_profit_msg = ProfitDistributorHandleMsg::Receive {
            amount: amount,
            from: from.clone(),
            sender: from.clone(),
            msg: to_binary(&ProfitDistributorReceiveMsg::AddProfit {}).unwrap(),
        };
        let handle_response = handle(
            &mut deps,
            mock_env(mock_buttcoin().address.to_string(), &[]),
            receive_add_profit_msg.clone(),
        );
        // === When there are no shares
        // === * It adds to the pool's residue
        handle_response.unwrap();
        let pool: Pool = TypedStoreMut::attach(&mut deps.storage)
            .load(mock_buttcoin().address.0.as_bytes())
            .unwrap();
        assert_eq!(pool.per_share_scaled, 0);
        assert_eq!(pool.residue, amount.u128());

        // === When there are shares
        let receive_deposit_buttcoin_msg = ProfitDistributorHandleMsg::Receive {
            amount: buttcoin_deposit_amount,
            from: from.clone(),
            sender: from.clone(),
            msg: to_binary(&ProfitDistributorReceiveMsg::DepositButtcoin {}).unwrap(),
        };
        handle(
            &mut deps,
            mock_env(mock_buttcoin().address.to_string(), &[]),
            receive_deposit_buttcoin_msg.clone(),
        )
        .unwrap();
        // === * It calculates the per_share factoring in the new amount and the residue and resets the residue
        let handle_response = handle(
            &mut deps,
            mock_env(mock_buttcoin().address.to_string(), &[]),
            receive_add_profit_msg.clone(),
        );
        handle_response.unwrap();
        let pool: Pool = TypedStoreMut::attach(&mut deps.storage)
            .load(mock_buttcoin().address.0.as_bytes())
            .unwrap();
        assert_eq!(
            pool.per_share_scaled,
            amount.u128() * 2 * CALCULATION_SCALE / buttcoin_deposit_amount.u128()
        );
        assert_eq!(pool.residue, 0);
        // === When adding profit when shares exist and no residue
        let handle_response = handle(
            &mut deps,
            mock_env(mock_buttcoin().address.to_string(), &[]),
            receive_add_profit_msg.clone(),
        );
        handle_response.unwrap();
        let pool: Pool = TypedStoreMut::attach(&mut deps.storage)
            .load(mock_buttcoin().address.0.as_bytes())
            .unwrap();
        assert_eq!(
            pool.per_share_scaled,
            amount.u128() * 3 * CALCULATION_SCALE / buttcoin_deposit_amount.u128()
        );
        assert_eq!(pool.residue, 0);
    }

    #[test]
    fn test_handle_receive_deposit_buttcoin() {
        let (_init_result, mut deps) = init_helper();
        let amount: Uint128 = Uint128(333);
        let from: HumanAddr = HumanAddr::from("someuser");

        // = When received token is not Buttcoin
        // = * It raises an Unauthorized error
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

        // = When received token is Buttcoin
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
        // = * It mints the shares tokens to the user depositer
        let handle_response_unwrapped = handle_response.unwrap();
        assert_eq!(
            handle_response_unwrapped.messages,
            vec![snip20::mint_msg(
                from.clone(),
                amount,
                None,
                RESPONSE_BLOCK_SIZE,
                mock_pool_shares_token().contract_hash,
                mock_pool_shares_token().address,
            )
            .unwrap(),]
        );
        let handle_response_data: ProfitDistributorReceiveAnswer =
            from_binary(&handle_response_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_response_data).unwrap(),
            to_binary(&ProfitDistributorReceiveAnswer::DepositButtcoin { status: Success })
                .unwrap()
        );

        // = * It adds amount to user and total shares
        let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY).unwrap();
        assert_eq!(config.total_shares, amount.u128());
        let user: User = TypedStore::attach(&deps.storage)
            .load(from.0.as_bytes())
            .unwrap();
        assert_eq!(user.shares, amount.u128());
        // == When profit token is added
        let add_profit_token_msg = ProfitDistributorHandleMsg::AddProfitToken {
            token: mock_buttcoin(),
        };
        handle(
            &mut deps,
            mock_env(MOCK_ADMIN, &[]),
            add_profit_token_msg.clone(),
        )
        .unwrap();
        // === When more Buttcoin is added by the user
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
        // === * It add to user shares, total shares and mints more share tokens for user
        let handle_response_unwrapped = handle_response.unwrap();
        assert_eq!(
            handle_response_unwrapped.messages,
            vec![snip20::mint_msg(
                from.clone(),
                amount,
                None,
                RESPONSE_BLOCK_SIZE,
                mock_pool_shares_token().contract_hash,
                mock_pool_shares_token().address,
            )
            .unwrap(),]
        );
        let handle_response_data: ProfitDistributorReceiveAnswer =
            from_binary(&handle_response_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_response_data).unwrap(),
            to_binary(&ProfitDistributorReceiveAnswer::DepositButtcoin { status: Success })
                .unwrap()
        );

        let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY).unwrap();
        assert_eq!(config.total_shares, 2 * amount.u128());
        let user: User = TypedStore::attach(&deps.storage)
            .load(from.0.as_bytes())
            .unwrap();
        assert_eq!(user.shares, 2 * amount.u128());
        // === When profit is added
        let receive_add_profit_msg = ProfitDistributorHandleMsg::Receive {
            amount: Uint128(amount.u128() * 4),
            from: from.clone(),
            sender: from.clone(),
            msg: to_binary(&ProfitDistributorReceiveMsg::AddProfit {}).unwrap(),
        };
        handle(
            &mut deps,
            mock_env(mock_buttcoin().address, &[]),
            receive_add_profit_msg.clone(),
        )
        .unwrap();
        // ==== When more Buttcoin is added by the user
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
        // ==== * It add to user shares, total shares, mints more share tokens for user and sends reward to user
        let handle_response_unwrapped = handle_response.unwrap();
        assert_eq!(
            handle_response_unwrapped.messages,
            vec![
                secret_toolkit::snip20::transfer_msg(
                    from.clone(),
                    Uint128(amount.u128() * 4),
                    None,
                    RESPONSE_BLOCK_SIZE,
                    mock_buttcoin().contract_hash,
                    mock_buttcoin().address.clone(),
                )
                .unwrap(),
                snip20::mint_msg(
                    from.clone(),
                    amount,
                    None,
                    RESPONSE_BLOCK_SIZE,
                    mock_pool_shares_token().contract_hash,
                    mock_pool_shares_token().address,
                )
                .unwrap(),
            ]
        );
        let handle_response_data: ProfitDistributorReceiveAnswer =
            from_binary(&handle_response_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_response_data).unwrap(),
            to_binary(&ProfitDistributorReceiveAnswer::DepositButtcoin { status: Success })
                .unwrap()
        );

        let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY).unwrap();
        assert_eq!(config.total_shares, 3 * amount.u128());
        let user: User = TypedStore::attach(&deps.storage)
            .load(from.0.as_bytes())
            .unwrap();
        assert_eq!(user.shares, 3 * amount.u128());
        // ==== * It sets the correct PoolUser debt
        let buttcoin_pool_user: PoolUser =
            PoolUserStorage::from_storage(&mut deps.storage, mock_buttcoin().address.clone())
                .get(from.clone())
                .unwrap();
        assert_eq!(
            buttcoin_pool_user.debt,
            user.shares * 4 * 333 * CALCULATION_SCALE / (amount.u128() * 2) / CALCULATION_SCALE
        );
        // ===== When more Buttcoin is added by the user
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
        // ===== * It add to user shares, total shares, mints more share tokens for user (But does not send any reward tokens to user)
        let handle_response_unwrapped = handle_response.unwrap();
        assert_eq!(
            handle_response_unwrapped.messages,
            vec![snip20::mint_msg(
                from.clone(),
                amount,
                None,
                RESPONSE_BLOCK_SIZE,
                mock_pool_shares_token().contract_hash,
                mock_pool_shares_token().address,
            )
            .unwrap(),]
        );
        let handle_response_data: ProfitDistributorReceiveAnswer =
            from_binary(&handle_response_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_response_data).unwrap(),
            to_binary(&ProfitDistributorReceiveAnswer::DepositButtcoin { status: Success })
                .unwrap()
        );

        let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY).unwrap();
        assert_eq!(config.total_shares, 4 * amount.u128());
        let user: User = TypedStore::attach(&deps.storage)
            .load(from.0.as_bytes())
            .unwrap();
        assert_eq!(user.shares, 4 * amount.u128());
        // ===== * It sets the correct PoolUser debt
        let buttcoin_pool_user: PoolUser =
            PoolUserStorage::from_storage(&mut deps.storage, mock_buttcoin().address.clone())
                .get(from.clone())
                .unwrap();
        assert_eq!(
            buttcoin_pool_user.debt,
            user.shares * 4 * 333 * CALCULATION_SCALE / (amount.u128() * 2) / CALCULATION_SCALE
        );
        // ====== When Buttcoin is added by anothe user
        let from: HumanAddr = HumanAddr::from("user-two");
        let amount_two: Uint128 = Uint128(65404);
        let msg = ProfitDistributorHandleMsg::Receive {
            amount: amount_two,
            from: from.clone(),
            sender: from.clone(),
            msg: to_binary(&ProfitDistributorReceiveMsg::DepositButtcoin {}).unwrap(),
        };
        let handle_response = handle(
            &mut deps,
            mock_env(mock_buttcoin().address.to_string(), &[]),
            msg.clone(),
        );
        // ====== * It add to user shares, total shares, mints more share tokens for user (But does not send any reward tokens to user)
        let handle_response_unwrapped = handle_response.unwrap();
        assert_eq!(
            handle_response_unwrapped.messages,
            vec![snip20::mint_msg(
                from.clone(),
                amount_two,
                None,
                RESPONSE_BLOCK_SIZE,
                mock_pool_shares_token().contract_hash,
                mock_pool_shares_token().address,
            )
            .unwrap(),]
        );
        let handle_response_data: ProfitDistributorReceiveAnswer =
            from_binary(&handle_response_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_response_data).unwrap(),
            to_binary(&ProfitDistributorReceiveAnswer::DepositButtcoin { status: Success })
                .unwrap()
        );

        let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY).unwrap();
        assert_eq!(config.total_shares, 4 * amount.u128() + amount_two.u128());
        let user: User = TypedStore::attach(&deps.storage)
            .load(from.0.as_bytes())
            .unwrap();
        assert_eq!(user.shares, amount_two.u128());
    }

    #[test]
    fn test_handle_receive_withdraw() {
        let (_init_result, mut deps) = init_helper();
        let amount: Uint128 = Uint128(333);
        let from: HumanAddr = HumanAddr::from("someuser");

        // = When Buttcoin is deposited
        let msg = ProfitDistributorHandleMsg::Receive {
            amount: amount,
            from: from.clone(),
            sender: from.clone(),
            msg: to_binary(&ProfitDistributorReceiveMsg::DepositButtcoin {}).unwrap(),
        };
        handle(
            &mut deps,
            mock_env(mock_buttcoin().address.to_string(), &[]),
            msg.clone(),
        )
        .unwrap();
        // == When profit token is added
        let add_profit_token_msg = ProfitDistributorHandleMsg::AddProfitToken {
            token: mock_buttcoin(),
        };
        handle(
            &mut deps,
            mock_env(MOCK_ADMIN, &[]),
            add_profit_token_msg.clone(),
        )
        .unwrap();
        // === When more Buttcoin is added by the user
        let msg = ProfitDistributorHandleMsg::Receive {
            amount: amount,
            from: from.clone(),
            sender: from.clone(),
            msg: to_binary(&ProfitDistributorReceiveMsg::DepositButtcoin {}).unwrap(),
        };
        handle(
            &mut deps,
            mock_env(mock_buttcoin().address.to_string(), &[]),
            msg.clone(),
        )
        .unwrap();
        // === When profit is added
        let receive_add_profit_msg = ProfitDistributorHandleMsg::Receive {
            amount: Uint128(amount.u128() * 4),
            from: from.clone(),
            sender: from.clone(),
            msg: to_binary(&ProfitDistributorReceiveMsg::AddProfit {}).unwrap(),
        };
        handle(
            &mut deps,
            mock_env(mock_buttcoin().address, &[]),
            receive_add_profit_msg.clone(),
        )
        .unwrap();
        // ====== When Buttcoin is added by another user
        let from_two: HumanAddr = HumanAddr::from("user-two");
        let amount_two: Uint128 = Uint128(65404);
        let msg = ProfitDistributorHandleMsg::Receive {
            amount: amount_two,
            from: from_two.clone(),
            sender: from_two.clone(),
            msg: to_binary(&ProfitDistributorReceiveMsg::DepositButtcoin {}).unwrap(),
        };
        handle(
            &mut deps,
            mock_env(mock_buttcoin().address.to_string(), &[]),
            msg.clone(),
        )
        .unwrap();

        // === WITHDRAWING BEGINGS ===
        // ======= When user two tries to withdraw using a non pool shares token
        let receive_withdraw_msg = ProfitDistributorHandleMsg::Receive {
            amount: amount_two,
            from: from_two.clone(),
            sender: from_two.clone(),
            msg: to_binary(&ProfitDistributorReceiveMsg::Withdraw {}).unwrap(),
        };
        let env = mock_env(mock_buttcoin().address.to_string(), &[]);
        let handle_response = handle(&mut deps, env, receive_withdraw_msg.clone());
        // ======= * It raises an unauthorized error
        assert_eq!(
            handle_response.unwrap_err(),
            StdError::Unauthorized { backtrace: None }
        );

        // ======= When user two tries to withdraw using pool shares token
        let env = mock_env(mock_pool_shares_token().address.to_string(), &[]);
        let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY).unwrap();
        config.total_shares;
        let total_shares_before_transaction: u128 = config.total_shares;
        let user: User = TypedStore::attach(&deps.storage)
            .load(from_two.0.as_bytes())
            .unwrap();
        let user_shares_before_transaction: u128 = user.shares;
        let handle_response = handle(&mut deps, env, receive_withdraw_msg.clone());
        // ======= * It updates the user shares, total shares, burns the tokens received and sends the equivalent amount of Buttcoin to withdrawer
        let handle_response_unwrapped = handle_response.unwrap();
        assert_eq!(
            handle_response_unwrapped.messages,
            vec![
                snip20::burn_msg(
                    amount_two,
                    None,
                    RESPONSE_BLOCK_SIZE,
                    mock_pool_shares_token().contract_hash,
                    mock_pool_shares_token().address,
                )
                .unwrap(),
                secret_toolkit::snip20::transfer_msg(
                    from_two.clone(),
                    amount_two,
                    None,
                    RESPONSE_BLOCK_SIZE,
                    mock_buttcoin().contract_hash,
                    mock_buttcoin().address.clone(),
                )
                .unwrap()
            ]
        );
        let handle_response_data: ProfitDistributorReceiveAnswer =
            from_binary(&handle_response_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_response_data).unwrap(),
            to_binary(&ProfitDistributorReceiveAnswer::Withdraw { status: Success }).unwrap()
        );
        let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY).unwrap();
        assert_eq!(
            config.total_shares,
            total_shares_before_transaction - amount_two.u128()
        );
        let user: User = TypedStore::attach(&deps.storage)
            .load(from_two.0.as_bytes())
            .unwrap();
        assert_eq!(
            user.shares,
            user_shares_before_transaction - amount_two.u128()
        );

        // ======= When user one withdraws
        let receive_withdraw_msg = ProfitDistributorHandleMsg::Receive {
            amount: amount,
            from: from.clone(),
            sender: from.clone(),
            msg: to_binary(&ProfitDistributorReceiveMsg::Withdraw {}).unwrap(),
        };
        let env = mock_env(mock_pool_shares_token().address.to_string(), &[]);
        let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY).unwrap();
        config.total_shares;
        let total_shares_before_transaction: u128 = config.total_shares;
        let user: User = TypedStore::attach(&deps.storage)
            .load(from.0.as_bytes())
            .unwrap();
        let user_shares_before_transaction: u128 = user.shares;
        let handle_response = handle(&mut deps, env, receive_withdraw_msg.clone());
        // ======= * It updates the user shares, total shares, burns the tokens received, sends the equivalent amount of Buttcoin to withdrawer and sends reward
        let handle_response_unwrapped = handle_response.unwrap();
        assert_eq!(
            handle_response_unwrapped.messages,
            vec![
                secret_toolkit::snip20::transfer_msg(
                    from.clone(),
                    Uint128(amount.u128() * 4),
                    None,
                    RESPONSE_BLOCK_SIZE,
                    mock_buttcoin().contract_hash,
                    mock_buttcoin().address.clone(),
                )
                .unwrap(),
                snip20::burn_msg(
                    amount,
                    None,
                    RESPONSE_BLOCK_SIZE,
                    mock_pool_shares_token().contract_hash,
                    mock_pool_shares_token().address,
                )
                .unwrap(),
                secret_toolkit::snip20::transfer_msg(
                    from.clone(),
                    amount,
                    None,
                    RESPONSE_BLOCK_SIZE,
                    mock_buttcoin().contract_hash,
                    mock_buttcoin().address.clone(),
                )
                .unwrap()
            ]
        );
        let handle_response_data: ProfitDistributorReceiveAnswer =
            from_binary(&handle_response_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_response_data).unwrap(),
            to_binary(&ProfitDistributorReceiveAnswer::Withdraw { status: Success }).unwrap()
        );

        let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY).unwrap();
        assert_eq!(
            config.total_shares,
            total_shares_before_transaction - amount.u128()
        );
        let user: User = TypedStore::attach(&deps.storage)
            .load(from.0.as_bytes())
            .unwrap();
        assert_eq!(user.shares, user_shares_before_transaction - amount.u128());

        // ======== When user one withdraw full balance
        let user: User = TypedStore::attach(&deps.storage)
            .load(from.0.as_bytes())
            .unwrap();
        let receive_withdraw_msg = ProfitDistributorHandleMsg::Receive {
            amount: Uint128(user.shares),
            from: from.clone(),
            sender: from.clone(),
            msg: to_binary(&ProfitDistributorReceiveMsg::Withdraw {}).unwrap(),
        };
        let env = mock_env(mock_pool_shares_token().address.to_string(), &[]);
        let handle_response = handle(&mut deps, env, receive_withdraw_msg.clone());
        // ======= * It updates the user shares, total shares, burns the tokens received, sends the equivalent amount of Buttcoin to withdrawer (No rewards to send)
        let handle_response_unwrapped = handle_response.unwrap();
        assert_eq!(
            handle_response_unwrapped.messages,
            vec![
                snip20::burn_msg(
                    Uint128(user.shares),
                    None,
                    RESPONSE_BLOCK_SIZE,
                    mock_pool_shares_token().contract_hash,
                    mock_pool_shares_token().address,
                )
                .unwrap(),
                secret_toolkit::snip20::transfer_msg(
                    from.clone(),
                    Uint128(user.shares),
                    None,
                    RESPONSE_BLOCK_SIZE,
                    mock_buttcoin().contract_hash,
                    mock_buttcoin().address.clone(),
                )
                .unwrap()
            ]
        );
        let handle_response_data: ProfitDistributorReceiveAnswer =
            from_binary(&handle_response_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_response_data).unwrap(),
            to_binary(&ProfitDistributorReceiveAnswer::Withdraw { status: Success }).unwrap()
        );

        let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY).unwrap();
        assert_eq!(config.total_shares, 0);
        let user: User = TypedStore::attach(&deps.storage)
            .load(from.0.as_bytes())
            .unwrap();
        assert_eq!(user.shares, 0);
        // ======= When user one tries to withdraw more than their balance
        let receive_withdraw_msg = ProfitDistributorHandleMsg::Receive {
            amount: Uint128(1),
            from: from.clone(),
            sender: from.clone(),
            msg: to_binary(&ProfitDistributorReceiveMsg::Withdraw {}).unwrap(),
        };
        let env = mock_env(mock_pool_shares_token().address.to_string(), &[]);
        let handle_response = handle(&mut deps, env, receive_withdraw_msg.clone());
        // ======= * It raises an error
        assert_eq!(
            handle_response.unwrap_err(),
            StdError::generic_err(format!(
                "insufficient funds to withdraw: balance={}, required={}",
                user.shares, 1,
            ))
        );

        // ======== When profit is added when there are no shares
        let receive_add_profit_msg = ProfitDistributorHandleMsg::Receive {
            amount: Uint128(amount.u128() * 4),
            from: from.clone(),
            sender: from.clone(),
            msg: to_binary(&ProfitDistributorReceiveMsg::AddProfit {}).unwrap(),
        };
        handle(
            &mut deps,
            mock_env(mock_buttcoin().address, &[]),
            receive_add_profit_msg.clone(),
        )
        .unwrap();
        // ======== When Buttcoin is added by a user
        let from_two: HumanAddr = HumanAddr::from("user-two");
        let amount_two: Uint128 = Uint128(123);
        let msg = ProfitDistributorHandleMsg::Receive {
            amount: amount_two,
            from: from_two.clone(),
            sender: from_two.clone(),
            msg: to_binary(&ProfitDistributorReceiveMsg::DepositButtcoin {}).unwrap(),
        };
        let handle_response = handle(
            &mut deps,
            mock_env(mock_buttcoin().address.to_string(), &[]),
            msg.clone(),
        );
        // ======= * It updates the user shares, total shares, sends the equivalent amount of pool shares to depositer and sends rewards
        let handle_response_unwrapped = handle_response.unwrap();
        assert_eq!(
            handle_response_unwrapped.messages,
            vec![snip20::mint_msg(
                from_two.clone(),
                amount_two,
                None,
                RESPONSE_BLOCK_SIZE,
                mock_pool_shares_token().contract_hash,
                mock_pool_shares_token().address,
            )
            .unwrap(),]
        );
        let handle_response_data: ProfitDistributorReceiveAnswer =
            from_binary(&handle_response_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_response_data).unwrap(),
            to_binary(&ProfitDistributorReceiveAnswer::DepositButtcoin { status: Success })
                .unwrap()
        );

        let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY).unwrap();
        assert_eq!(config.total_shares, amount_two.u128());
        let user: User = TypedStore::attach(&deps.storage)
            .load(from_two.0.as_bytes())
            .unwrap();
        assert_eq!(user.shares, amount_two.u128());

        // ======== When user withdraws full balance
        let user: User = TypedStore::attach(&deps.storage)
            .load(from_two.0.as_bytes())
            .unwrap();
        let receive_withdraw_msg = ProfitDistributorHandleMsg::Receive {
            amount: Uint128(user.shares),
            from: from_two.clone(),
            sender: from_two.clone(),
            msg: to_binary(&ProfitDistributorReceiveMsg::Withdraw {}).unwrap(),
        };
        let env = mock_env(mock_pool_shares_token().address.to_string(), &[]);
        let handle_response = handle(&mut deps, env, receive_withdraw_msg.clone());
        // ======= * It updates the user shares, total shares, burns the tokens received, sends the equivalent amount of Buttcoin to withdrawer
        let handle_response_unwrapped = handle_response.unwrap();
        assert_eq!(
            handle_response_unwrapped.messages,
            vec![
                secret_toolkit::snip20::transfer_msg(
                    from_two.clone(),
                    Uint128(1331),
                    None,
                    RESPONSE_BLOCK_SIZE,
                    mock_buttcoin().contract_hash,
                    mock_buttcoin().address.clone(),
                )
                .unwrap(),
                snip20::burn_msg(
                    amount_two,
                    None,
                    RESPONSE_BLOCK_SIZE,
                    mock_pool_shares_token().contract_hash,
                    mock_pool_shares_token().address,
                )
                .unwrap(),
                secret_toolkit::snip20::transfer_msg(
                    from_two.clone(),
                    amount_two,
                    None,
                    RESPONSE_BLOCK_SIZE,
                    mock_buttcoin().contract_hash,
                    mock_buttcoin().address.clone(),
                )
                .unwrap()
            ]
        );
        let handle_response_data: ProfitDistributorReceiveAnswer =
            from_binary(&handle_response_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_response_data).unwrap(),
            to_binary(&ProfitDistributorReceiveAnswer::Withdraw { status: Success }).unwrap()
        );

        let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY).unwrap();
        assert_eq!(config.total_shares, 0);
        let user: User = TypedStore::attach(&deps.storage)
            .load(from_two.0.as_bytes())
            .unwrap();
        assert_eq!(user.shares, 0);
    }
}
