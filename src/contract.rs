use crate::constants::{CALCULATION_SCALE, CONFIG_KEY, RESPONSE_BLOCK_SIZE, VIEWING_KEY_KEY};
use crate::msg::{
    ProfitDistributorBalanceResponse, ProfitDistributorConfigResponse, ProfitDistributorHandleMsg,
    ProfitDistributorInitMsg, ProfitDistributorQueryMsg, ProfitDistributorReceiveMsg,
};
use crate::state::{Config, Pool, PoolUser, PoolUserStorage, SecretContract, User};
use crate::viewing_key::ViewingKey;
use cosmwasm_std::{
    from_binary, to_binary, Api, Binary, CosmosMsg, Env, Extern, HandleResponse, HumanAddr,
    InitResponse, Querier, StdError, StdResult, Storage, Uint128,
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
        TypedStoreMut::attach(&mut deps.storage).store(token_address_as_bytes, &pool)?;
    }

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: None,
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
        data: None,
    })
}

fn authorize(expected: HumanAddr, received: HumanAddr) -> StdResult<()> {
    if expected != received {
        return Err(StdError::Unauthorized { backtrace: None });
    }

    Ok(())
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
        data: None,
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
        let pool: Pool = TypedStoreMut::<Pool, S>::attach(storage)
            .load(profit_token.address.0.as_bytes())
            .unwrap();
        let mut pool_user: PoolUser =
            PoolUserStorage::from_storage(storage, profit_token.address.clone())
                .get(user_address.clone())
                .unwrap_or(PoolUser { debt: 0 });
        if user.shares > 0 {
            if pool.per_share_scaled > 0 {
                let pending: u128 =
                    user.shares * pool.per_share_scaled / CALCULATION_SCALE - pool_user.debt;
                if pending > 0 {
                    messages.push(secret_toolkit::snip20::transfer_msg(
                        user_address.clone(),
                        Uint128(pending),
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

fn public_config<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
) -> StdResult<ProfitDistributorConfigResponse> {
    let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY)?;
    Ok(ProfitDistributorConfigResponse {
        admin: config.admin,
        buttcoin: config.buttcoin,
        contract_address: config.contract_address,
        pool_shares_token: config.pool_shares_token,
        profit_tokens: config.profit_tokens,
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
    let shares_after_transaction: u128 = user.shares - amount;

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
    if amount > 0 {
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
        let value: ProfitDistributorConfigResponse = from_binary(&res).unwrap();
        assert_eq!(value.admin, HumanAddr("bob".to_string()));
    }

    #[test]
    fn test_public_config() {
        let (_init_result, deps) = init_helper();
        let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY).unwrap();

        let res = query(&deps, ProfitDistributorQueryMsg::Config {}).unwrap();
        let value: ProfitDistributorConfigResponse = from_binary(&res).unwrap();
        // Test response does not include viewing key.
        // Test that the desired fields are returned.
        assert_eq!(
            ProfitDistributorConfigResponse {
                admin: HumanAddr::from(MOCK_ADMIN),
                buttcoin: mock_buttcoin(),
                contract_address: config.contract_address,
                pool_shares_token: mock_pool_shares_token(),
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
        let env = mock_env(MOCK_ADMIN, &[]);
        let handle_response = handle(&mut deps, env.clone(), msg.clone());

        // It registers a receive message for that token for this contract as well as setting a viewing key
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

        // It stores a Pool struct for the token
        let mock_profit_token_pool: Pool = TypedStore::attach(&deps.storage)
            .load(mock_profit_token().address.0.as_bytes())
            .unwrap();
        assert_eq!(
            mock_profit_token_pool,
            Pool {
                per_share_scaled: 0,
                residue: 0
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
    fn test_receive_add_profit() {
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
        // It add to the balance buttcoin
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
