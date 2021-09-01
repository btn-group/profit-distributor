use crate::authorize::authorize;
use crate::constants::{CALCULATION_SCALE, CONFIG_KEY, POOL_KEY, RESPONSE_BLOCK_SIZE};
use crate::msg::{
    ProfitDistributorHandleAnswer, ProfitDistributorHandleMsg, ProfitDistributorInitMsg,
    ProfitDistributorQueryAnswer, ProfitDistributorQueryMsg, ProfitDistributorReceiveAnswer,
    ProfitDistributorReceiveMsg, ProfitDistributorResponseStatus::Success,
};
use crate::state::{Config, Pool, User};
use cosmwasm_std::{
    from_binary, to_binary, Api, Binary, CosmosMsg, Env, Extern, HandleResponse, HumanAddr,
    InitResponse, Querier, StdError, StdResult, Storage, Uint128,
};
use secret_toolkit::snip20;
use secret_toolkit::storage::{TypedStore, TypedStoreMut};

pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: ProfitDistributorInitMsg,
) -> StdResult<InitResponse> {
    let mut config_store = TypedStoreMut::attach(&mut deps.storage);
    let config = Config {
        buttcoin: msg.buttcoin.clone(),
        profit_token: msg.profit_token.clone(),
        total_shares: 0,
        viewing_key: msg.viewing_key.clone(),
    };
    config_store.store(CONFIG_KEY, &config)?;

    // Store pool into database
    TypedStoreMut::<Pool, S>::attach(&mut deps.storage).store(
        POOL_KEY,
        &Pool {
            per_share_scaled: 0,
            residue: 0,
        },
    )?;

    // https://github.com/enigmampc/secret-toolkit/tree/master/packages/snip20
    let messages = vec![
        snip20::register_receive_msg(
            env.contract_code_hash.clone(),
            None,
            RESPONSE_BLOCK_SIZE,
            msg.buttcoin.contract_hash.clone(),
            msg.buttcoin.address.clone(),
        )?,
        snip20::set_viewing_key_msg(
            msg.viewing_key.clone(),
            None,
            RESPONSE_BLOCK_SIZE,
            msg.buttcoin.contract_hash,
            msg.buttcoin.address,
        )?,
        snip20::register_receive_msg(
            env.contract_code_hash.clone(),
            None,
            RESPONSE_BLOCK_SIZE,
            msg.profit_token.contract_hash.clone(),
            msg.profit_token.address.clone(),
        )?,
        snip20::set_viewing_key_msg(
            msg.viewing_key,
            None,
            RESPONSE_BLOCK_SIZE,
            msg.profit_token.contract_hash,
            msg.profit_token.address,
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
        ProfitDistributorHandleMsg::Receive {
            from, amount, msg, ..
        } => receive(deps, env, from, amount.u128(), msg),
        ProfitDistributorHandleMsg::Withdraw { amount } => withdraw(deps, env, amount),
    }
}

pub fn query<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    msg: ProfitDistributorQueryMsg,
) -> StdResult<Binary> {
    match msg {
        ProfitDistributorQueryMsg::Config {} => config(deps),
        ProfitDistributorQueryMsg::ClaimableProfit { user_address, .. } => {
            query_claimable_profit(deps, &user_address)
        }
    }
}

fn claimable_profit(pool: Pool, user: User) -> u128 {
    if pool.residue > 0 {
        pool.residue
    } else {
        user.shares * pool.per_share_scaled / CALCULATION_SCALE - user.debt
    }
}

fn query_claimable_profit<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    user_address: &HumanAddr,
) -> StdResult<Binary> {
    let mut amount: u128 = 0;
    // Load user
    let user = TypedStore::<User, S>::attach(&deps.storage).load(user_address.0.as_bytes())?;
    if user.shares > 0 {
        // Load pool
        let pool: Pool = TypedStore::attach(&deps.storage).load(POOL_KEY)?;
        amount = claimable_profit(pool, user);
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
    let config: Config = TypedStoreMut::attach(&mut deps.storage).load(CONFIG_KEY)?;
    authorize(config.profit_token.address, env.message.sender)?;

    let mut pool: Pool = TypedStoreMut::attach(&mut deps.storage).load(POOL_KEY)?;
    if amount > 0 {
        if config.total_shares == 0 {
            pool.residue += amount;
        } else {
            pool.per_share_scaled +=
                (amount + pool.residue) * CALCULATION_SCALE / config.total_shares;
            pool.residue = 0;
        };
        TypedStoreMut::attach(&mut deps.storage).store(POOL_KEY, &pool)?;
    }

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&ProfitDistributorReceiveAnswer::AddProfit {
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

    let user = TypedStoreMut::<User, S>::attach(&mut deps.storage)
        .load(from.0.as_bytes())
        .unwrap_or(User { debt: 0, shares: 0 });
    let shares_after_transaction: u128 = user.shares + amount;

    let messages: Vec<CosmosMsg> = generate_message_to_claim_profit_and_update_debt(
        &mut deps.storage,
        config.clone(),
        shares_after_transaction,
        from.clone(),
        user.clone(),
    )?;
    let mut user = TypedStoreMut::<User, S>::attach(&mut deps.storage)
        .load(from.0.as_bytes())
        .unwrap();

    // Update user shares
    user.shares = shares_after_transaction;
    TypedStoreMut::<User, S>::attach(&mut deps.storage).store(from.0.as_bytes(), &user)?;

    // Update config shares
    config.total_shares += amount;
    TypedStoreMut::<Config, S>::attach(&mut deps.storage).store(CONFIG_KEY, &config)?;

    Ok(HandleResponse {
        messages: messages,
        log: vec![],
        data: Some(to_binary(
            &ProfitDistributorReceiveAnswer::DepositButtcoin { status: Success },
        )?),
    })
}

fn generate_message_to_claim_profit_and_update_debt<S: Storage>(
    storage: &mut S,
    config: Config,
    shares_after_transaction: u128,
    user_address: HumanAddr,
    mut user: User,
) -> StdResult<Vec<CosmosMsg>> {
    let mut messages: Vec<CosmosMsg> = vec![];
    let profit_token = config.profit_token;
    let mut pool: Pool = TypedStoreMut::<Pool, S>::attach(storage)
        .load(POOL_KEY)
        .unwrap();
    if user.shares > 0 {
        if pool.residue > 0 {
            pool.per_share_scaled += pool.residue * CALCULATION_SCALE / config.total_shares;
            pool.residue = 0;
            TypedStoreMut::attach(storage)
                .store(POOL_KEY, &pool)
                .unwrap();
        }

        if pool.per_share_scaled > 0 {
            let claimable_profit: u128 = claimable_profit(pool.clone(), user.clone());
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
    user.debt = shares_after_transaction * pool.per_share_scaled / CALCULATION_SCALE;
    TypedStoreMut::<User, S>::attach(storage).store(user_address.0.as_bytes(), &user)?;

    Ok(messages)
}

fn config<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>) -> StdResult<Binary> {
    let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY)?;

    to_binary(&ProfitDistributorQueryAnswer::Config {
        buttcoin: config.buttcoin,
        profit_token: config.profit_token,
        total_shares: Uint128(config.total_shares),
        viewing_key: config.viewing_key,
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
    }
}

fn withdraw<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    amount: Uint128,
) -> StdResult<HandleResponse> {
    let amount: u128 = amount.u128();
    let mut config = TypedStoreMut::<Config, S>::attach(&mut deps.storage).load(CONFIG_KEY)?;

    let user = TypedStoreMut::<User, S>::attach(&mut deps.storage)
        .load(env.message.sender.0.as_bytes())
        .unwrap();
    if amount > user.shares {
        return Err(StdError::generic_err(format!(
            "insufficient funds to withdraw: balance={}, required={}",
            user.shares, amount,
        )));
    }

    let shares_after_transaction: u128 = user.shares - amount;

    let mut messages: Vec<CosmosMsg> = generate_message_to_claim_profit_and_update_debt(
        &mut deps.storage,
        config.clone(),
        shares_after_transaction,
        env.message.sender.clone(),
        user.clone(),
    )?;
    let mut user = TypedStoreMut::<User, S>::attach(&mut deps.storage)
        .load(env.message.sender.0.as_bytes())
        .unwrap();

    if amount > 0 {
        // Update user shares
        user.shares = shares_after_transaction;
        TypedStoreMut::<User, S>::attach(&mut deps.storage)
            .store(env.message.sender.0.as_bytes(), &user)?;

        // Update config shares
        config.total_shares -= amount;
        TypedStoreMut::<Config, S>::attach(&mut deps.storage).store(CONFIG_KEY, &config)?;

        // Send buttcoin to user
        messages.push(secret_toolkit::snip20::transfer_msg(
            env.message.sender,
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
        data: Some(to_binary(&ProfitDistributorHandleAnswer::Withdraw {
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
    use cosmwasm_std::StdError::Unauthorized;

    pub const MOCK_ADMIN: &str = "admin";

    // === HELPERS ===

    fn init_helper() -> (
        StdResult<InitResponse>,
        Extern<MockStorage, MockApi, MockQuerier>,
    ) {
        let env = mock_env(MOCK_ADMIN, &[]);
        let mut deps = mock_dependencies(20, &[]);
        let msg = ProfitDistributorInitMsg {
            buttcoin: mock_buttcoin(),
            profit_token: mock_profit_token(),
            viewing_key: mock_viewing_key(),
        };
        (init(&mut deps, env.clone(), msg), deps)
    }

    fn mock_buttcoin() -> SecretContract {
        SecretContract {
            address: HumanAddr::from("buttcoincontractaddress"),
            contract_hash: "buttcoincontracthash".to_string(),
        }
    }

    fn mock_profit_token() -> SecretContract {
        SecretContract {
            address: HumanAddr::from("profit-token-address"),
            contract_hash: "profit-token-contract-hash".to_string(),
        }
    }

    fn mock_viewing_key() -> String {
        "mock-viewing-key".to_string()
    }

    // === INIT TEST ===

    #[test]
    fn test_init() {
        let (init_result, _deps) = init_helper();
        let env = mock_env(MOCK_ADMIN, &[]);

        let init_result_unwrapped = init_result.unwrap();
        assert_eq!(
            init_result_unwrapped.messages,
            vec![
                snip20::register_receive_msg(
                    env.contract_code_hash.clone(),
                    None,
                    RESPONSE_BLOCK_SIZE,
                    mock_buttcoin().contract_hash.clone(),
                    mock_buttcoin().address.clone(),
                )
                .unwrap(),
                snip20::set_viewing_key_msg(
                    mock_viewing_key(),
                    None,
                    RESPONSE_BLOCK_SIZE,
                    mock_buttcoin().contract_hash,
                    mock_buttcoin().address,
                )
                .unwrap(),
                snip20::register_receive_msg(
                    env.contract_code_hash.clone(),
                    None,
                    RESPONSE_BLOCK_SIZE,
                    mock_profit_token().contract_hash.clone(),
                    mock_profit_token().address.clone(),
                )
                .unwrap(),
                snip20::set_viewing_key_msg(
                    mock_viewing_key(),
                    None,
                    RESPONSE_BLOCK_SIZE,
                    mock_profit_token().contract_hash,
                    mock_profit_token().address,
                )
                .unwrap(),
            ]
        );
    }

    // === QUERY TESTS ===

    #[test]
    fn test_config() {
        let (_init_result, deps) = init_helper();
        let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY).unwrap();

        let res = query(&deps, ProfitDistributorQueryMsg::Config {}).unwrap();
        let value: ProfitDistributorQueryAnswer = from_binary(&res).unwrap();
        // Test response does not include viewing key.
        // Test that the desired fields are returned.
        match value {
            ProfitDistributorQueryAnswer::Config {
                buttcoin,
                profit_token,
                total_shares,
                viewing_key,
            } => {
                assert_eq!(buttcoin, config.buttcoin);
                assert_eq!(profit_token, config.profit_token);
                assert_eq!(total_shares, Uint128(config.total_shares));
                assert_eq!(viewing_key, config.viewing_key);
            }
            _ => panic!("at the taco bell"),
        }
    }

    // === HANDLE TESTS ===

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
            Unauthorized { backtrace: None }
        );

        // = When received token is an allowed profit token
        // == With an amount of zero
        let receive_add_profit_msg = ProfitDistributorHandleMsg::Receive {
            amount: Uint128(0),
            from: from.clone(),
            sender: from.clone(),
            msg: to_binary(&ProfitDistributorReceiveMsg::AddProfit {}).unwrap(),
        };
        let handle_response = handle(
            &mut deps,
            mock_env(mock_profit_token().address.to_string(), &[]),
            receive_add_profit_msg.clone(),
        );
        handle_response.unwrap();
        // == * It does not update the token's pool
        let pool: Pool = TypedStoreMut::attach(&mut deps.storage)
            .load(POOL_KEY)
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
            mock_env(mock_profit_token().address.to_string(), &[]),
            receive_add_profit_msg.clone(),
        );
        // === When there are no shares
        // === * It adds to the pool's residue
        handle_response.unwrap();
        let pool: Pool = TypedStoreMut::attach(&mut deps.storage)
            .load(POOL_KEY)
            .unwrap();
        assert_eq!(pool.per_share_scaled, 0);
        assert_eq!(pool.residue, amount.u128());

        // ==== When there are shares
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
        // ==== * It calculates the per_share factoring in the new amount and the residue and resets the residue
        let handle_response = handle(
            &mut deps,
            mock_env(mock_profit_token().address.to_string(), &[]),
            receive_add_profit_msg.clone(),
        );
        handle_response.unwrap();
        let pool: Pool = TypedStoreMut::attach(&mut deps.storage)
            .load(POOL_KEY)
            .unwrap();
        assert_eq!(
            pool.per_share_scaled,
            amount.u128() * 2 * CALCULATION_SCALE / buttcoin_deposit_amount.u128()
        );
        assert_eq!(pool.residue, 0);
        // ==== When adding profit when shares exist and no residue
        let handle_response = handle(
            &mut deps,
            mock_env(mock_profit_token().address.to_string(), &[]),
            receive_add_profit_msg.clone(),
        );
        handle_response.unwrap();
        let pool: Pool = TypedStoreMut::attach(&mut deps.storage)
            .load(POOL_KEY)
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
            mock_env(mock_profit_token().address.to_string(), &[]),
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
        handle(
            &mut deps,
            mock_env(mock_buttcoin().address.to_string(), &[]),
            msg.clone(),
        )
        .unwrap();

        // = * It adds amount to user and total shares
        let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY).unwrap();
        assert_eq!(config.total_shares, amount.u128());
        let user: User = TypedStore::attach(&deps.storage)
            .load(from.0.as_bytes())
            .unwrap();
        assert_eq!(user.shares, amount.u128());
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
        // === * It add to user shares and total shares
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
            mock_env(mock_profit_token().address, &[]),
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
        // ==== * It add to user shares and total shares tokens for user and sends reward to user
        let handle_response_unwrapped = handle_response.unwrap();
        assert_eq!(
            handle_response_unwrapped.messages,
            vec![secret_toolkit::snip20::transfer_msg(
                from.clone(),
                Uint128(amount.u128() * 4),
                None,
                RESPONSE_BLOCK_SIZE,
                mock_profit_token().contract_hash,
                mock_profit_token().address.clone(),
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
        assert_eq!(config.total_shares, 3 * amount.u128());
        let user: User = TypedStore::attach(&deps.storage)
            .load(from.0.as_bytes())
            .unwrap();
        assert_eq!(user.shares, 3 * amount.u128());
        // ==== * It sets the correct debt
        assert_eq!(
            user.debt,
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
        // ===== * It add to user shares and total shares (But does not send any reward tokens to user)
        let handle_response_unwrapped = handle_response.unwrap();
        assert_eq!(handle_response_unwrapped.messages, vec![]);
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
        // ===== * It sets the correct debt
        assert_eq!(
            user.debt,
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
        // ====== * It add to user shares, total shares and does not send any reward tokens to user
        let handle_response_unwrapped = handle_response.unwrap();
        assert_eq!(handle_response_unwrapped.messages, vec![]);
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
    fn test_handle_withdraw() {
        let (_init_result, mut deps) = init_helper();
        let amount: Uint128 = Uint128(333);
        let from: HumanAddr = HumanAddr::from("someuser");

        // == When Buttcoin is deposited
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
        // ==== When more Buttcoin is added by the user
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
        // ==== When profit is added
        let receive_add_profit_msg = ProfitDistributorHandleMsg::Receive {
            amount: Uint128(amount.u128() * 4),
            from: from.clone(),
            sender: from.clone(),
            msg: to_binary(&ProfitDistributorReceiveMsg::AddProfit {}).unwrap(),
        };
        handle(
            &mut deps,
            mock_env(mock_profit_token().address, &[]),
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
        let withdraw_msg = ProfitDistributorHandleMsg::Withdraw { amount: amount_two };
        let env = mock_env(from_two.to_string(), &[]);
        // let _handle_response = handle(&mut deps, env, withdraw_msg.clone());
        let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY).unwrap();
        let total_shares_before_transaction: u128 = config.total_shares;
        let user: User = TypedStore::attach(&deps.storage)
            .load(from_two.0.as_bytes())
            .unwrap();
        let user_shares_before_transaction: u128 = user.shares;
        let handle_response = handle(&mut deps, env, withdraw_msg.clone());
        // ======= * It updates the user shares, total shares and sends the equivalent amount of Buttcoin to withdrawer
        let handle_response_unwrapped = handle_response.unwrap();
        assert_eq!(
            handle_response_unwrapped.messages,
            vec![secret_toolkit::snip20::transfer_msg(
                from_two.clone(),
                amount_two,
                None,
                RESPONSE_BLOCK_SIZE,
                mock_buttcoin().contract_hash,
                mock_buttcoin().address.clone(),
            )
            .unwrap()]
        );
        let handle_response_data: ProfitDistributorHandleAnswer =
            from_binary(&handle_response_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_response_data).unwrap(),
            to_binary(&ProfitDistributorHandleAnswer::Withdraw { status: Success }).unwrap()
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
        let withdraw_msg = ProfitDistributorHandleMsg::Withdraw { amount: amount };
        let env = mock_env(from.to_string(), &[]);
        let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY).unwrap();
        let total_shares_before_transaction: u128 = config.total_shares;
        let user: User = TypedStore::attach(&deps.storage)
            .load(from.0.as_bytes())
            .unwrap();
        let user_shares_before_transaction: u128 = user.shares;
        let handle_response = handle(&mut deps, env, withdraw_msg.clone());
        // ======= * It updates the user shares, total shares, sends the equivalent amount of Buttcoin to withdrawer and sends reward
        let handle_response_unwrapped = handle_response.unwrap();
        assert_eq!(
            handle_response_unwrapped.messages,
            vec![
                secret_toolkit::snip20::transfer_msg(
                    from.clone(),
                    Uint128(amount.u128() * 4),
                    None,
                    RESPONSE_BLOCK_SIZE,
                    mock_profit_token().contract_hash,
                    mock_profit_token().address.clone(),
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
        let handle_response_data: ProfitDistributorHandleAnswer =
            from_binary(&handle_response_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_response_data).unwrap(),
            to_binary(&ProfitDistributorHandleAnswer::Withdraw { status: Success }).unwrap()
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
        let withdraw_msg = ProfitDistributorHandleMsg::Withdraw {
            amount: Uint128(user.shares),
        };
        let env = mock_env(from.to_string(), &[]);
        let handle_response = handle(&mut deps, env, withdraw_msg.clone());
        // ======= * It updates the user shares, total shares and sends the equivalent amount of Buttcoin to withdrawer (No rewards to send)
        let handle_response_unwrapped = handle_response.unwrap();
        assert_eq!(
            handle_response_unwrapped.messages,
            vec![secret_toolkit::snip20::transfer_msg(
                from.clone(),
                Uint128(user.shares),
                None,
                RESPONSE_BLOCK_SIZE,
                mock_buttcoin().contract_hash,
                mock_buttcoin().address.clone(),
            )
            .unwrap()]
        );
        let handle_response_data: ProfitDistributorHandleAnswer =
            from_binary(&handle_response_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_response_data).unwrap(),
            to_binary(&ProfitDistributorHandleAnswer::Withdraw { status: Success }).unwrap()
        );

        let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY).unwrap();
        assert_eq!(config.total_shares, 0);
        let user: User = TypedStore::attach(&deps.storage)
            .load(from.0.as_bytes())
            .unwrap();
        assert_eq!(user.shares, 0);
        // ======= When user one tries to withdraw more than their balance
        let withdraw_msg = ProfitDistributorHandleMsg::Withdraw {
            amount: Uint128(user.shares + 1),
        };
        let env = mock_env(from.to_string(), &[]);
        let handle_response = handle(&mut deps, env, withdraw_msg.clone());
        // ======= * It raises an error
        assert_eq!(
            handle_response.unwrap_err(),
            StdError::generic_err(format!(
                "insufficient funds to withdraw: balance={}, required={}",
                user.shares, RESPONSE_BLOCK_SIZE,
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
            mock_env(mock_profit_token().address, &[]),
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
        assert_eq!(handle_response_unwrapped.messages, vec![]);
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
        let withdraw_msg = ProfitDistributorHandleMsg::Withdraw {
            amount: Uint128(user.shares),
        };
        let env = mock_env(from_two.to_string(), &[]);
        let handle_response = handle(&mut deps, env, withdraw_msg.clone());
        // ======= * It updates the user shares, total shares, sends Buttcoin and profit token to withdrawer
        let handle_response_unwrapped = handle_response.unwrap();
        assert_eq!(
            handle_response_unwrapped.messages,
            vec![
                secret_toolkit::snip20::transfer_msg(
                    from_two.clone(),
                    Uint128(1331),
                    None,
                    RESPONSE_BLOCK_SIZE,
                    mock_profit_token().contract_hash,
                    mock_profit_token().address.clone(),
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
        let handle_response_data: ProfitDistributorHandleAnswer =
            from_binary(&handle_response_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_response_data).unwrap(),
            to_binary(&ProfitDistributorHandleAnswer::Withdraw { status: Success }).unwrap()
        );

        let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY).unwrap();
        assert_eq!(config.total_shares, 0);
        let user: User = TypedStore::attach(&deps.storage)
            .load(from_two.0.as_bytes())
            .unwrap();
        assert_eq!(user.shares, 0);
    }
}
