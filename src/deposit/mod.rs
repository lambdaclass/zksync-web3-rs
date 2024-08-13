// FIXME: Remove this after finishing the implementation.
#![allow(clippy::unwrap_used)]

use crate::{
    contracts::{
        bridgehub::{Bridgehub, L2TransactionRequestDirect, L2TransactionRequestTwoBridgesOuter},
        erc20::ERC20,
    },
    eip712::Eip712TransactionRequest,
    types::L1TxOverrides,
    utils, ZKMiddleware,
};
use constants::{L1_FEE_ESTIMATION_COEF_DENOMINATOR, L1_FEE_ESTIMATION_COEF_NUMERATOR};
use ethers::{
    abi::{Address, Hash, Tokenizable},
    middleware::SignerMiddleware,
    providers::Middleware,
    signers::Signer,
    types::U256,
};
use std::sync::Arc;

mod constants;

pub async fn deposit<M, S, L2Provider>(
    amount: U256,
    token: impl Into<Address>,
    from: Arc<SignerMiddleware<M, S>>,
    to: Address,
    refund_recipient: Address,
    l2_provider: &L2Provider,
) -> Hash
where
    M: Middleware,
    S: Signer,
    L2Provider: ZKMiddleware + Middleware,
{
    // The type is converted to avoid adding Copy as a constraint bound (Address is Copy).
    let token: Address = token.into();

    let bridgehub_address = l2_provider.get_bridgehub_contract().await.unwrap();
    let bridgehub = Bridgehub::new(
        bridgehub_address,
        Arc::<SignerMiddleware<M, S>>::clone(&from),
    );

    let zk_chain_id = l2_provider.get_chainid().await.unwrap();
    let zk_chain_base_token: Address = bridgehub.base_token(zk_chain_id).call().await.unwrap();

    let token_to_deposit_is_eth = token == utils::L2_ETH_TOKEN_ADDRESS;
    let token_to_deposit_is_zk_chain_base_token = token == zk_chain_base_token;

    match (
        token_to_deposit_is_eth,
        token_to_deposit_is_zk_chain_base_token,
    ) {
        // Depositing base token.
        (_, true) => {
            deposit_base_token(
                amount,
                token,
                from,
                to,
                refund_recipient,
                zk_chain_id,
                l2_provider,
                bridgehub,
                token_to_deposit_is_eth,
            )
            .await
        }
        // Depositing ETH to a ZKChain whose base token is not ETH.
        (true, false) => {
            let erc20 = ERC20::new(token, Arc::<SignerMiddleware<M, S>>::clone(&from));
            deposit_non_base_erc20_token(
                amount,
                token,
                from,
                to,
                refund_recipient,
                l2_provider,
                bridgehub,
                erc20,
                false,
            )
            .await
        }
        // We are depositing an ERC20 to a ZKChain where:
        // 1. ETH is the base token.
        // 2. An ERC20 different than the deposited is the base token.
        (false, false) => {
            let erc20 = ERC20::new(token, Arc::<SignerMiddleware<M, S>>::clone(&from));
            deposit_non_base_erc20_token(
                amount,
                token,
                from,
                to,
                refund_recipient,
                l2_provider,
                bridgehub,
                erc20,
                false,
            )
            .await
        }
    }
}

/// Deposit ETH to a ZKChain whose base token is ETH.
pub async fn deposit_base_token<M, S, L2Provider>(
    amount: U256,
    token: Address,
    from: Arc<SignerMiddleware<M, S>>,
    to: Address,
    refund_recipient: Address,
    zk_chain_id: U256,
    l2_provider: &L2Provider,
    bridgehub: Bridgehub<SignerMiddleware<M, S>>,
    token_is_eth: bool,
) -> Hash
where
    M: Middleware,
    S: Signer,
    L2Provider: ZKMiddleware + Middleware,
{
    let from_addr = from.address();

    // The amount of gas required for executing an L2 tx via L1.
    let estimate_l1_to_l2_gas = l2_provider
        .estimate_gas_l1_to_l2(
            Eip712TransactionRequest::new()
                .chain_id(zk_chain_id)
                .from(from_addr)
                .to(to),
        )
        .await
        .unwrap();
    let l2_gas_per_pubdata_byte_limit = U256::from(utils::REQUIRED_L1_TO_L2_GAS_PER_PUBDATA_LIMIT);
    let l2_costs = {
        let operator_tip = U256::zero();
        let base_cost: U256 = bridgehub
            .l_2_transaction_base_cost(
                zk_chain_id,
                from.get_gas_price().await.unwrap(),
                estimate_l1_to_l2_gas,
                l2_gas_per_pubdata_byte_limit,
            )
            .call()
            .await
            .unwrap();
        base_cost + operator_tip + amount
    };

    // There's no need to override l2_calldata for depositing ETH into an
    // ETH based chain.
    //
    // l2_contract and refund_recipient could be overridden in the future.
    // You might want to deposit ETH into a different account or contract,
    // or you might want to refund the deposit to a different account or
    // L1 contract.
    //
    // factory_deps is empty for depositing ETH into an ETH based chain.
    let request = L2TransactionRequestDirect::new()
        .chain_id(zk_chain_id)
        .mint_value(l2_costs)
        .l2_contract(to)
        .l2_value(amount)
        .l2_calldata(vec![])
        .l2_gas_limit(estimate_l1_to_l2_gas)
        .l2_gas_per_pubdata_byte_limit(l2_gas_per_pubdata_byte_limit)
        .factory_deps(vec![])
        .refund_recipient(refund_recipient);

    let base_token_is_eth = token == utils::L2_ETH_TOKEN_ADDRESS;
    if !base_token_is_eth {
        let l1_shared_bridge_address: Address = bridgehub.shared_bridge().call().await.unwrap();
        let erc20 = ERC20::new(token, Arc::<SignerMiddleware<M, S>>::clone(&from));

        let allowance: U256 = erc20
            .allowance(from.address(), l1_shared_bridge_address)
            .call()
            .await
            .unwrap();
        // ERC20 approval needs to be done before getting the nonce for the
        // overrides.
        if allowance < amount {
            erc20
                .approve(l1_shared_bridge_address, amount)
                .send()
                .await
                .unwrap()
                .await
                .unwrap()
                .unwrap();
        }
    }

    let value = base_token_is_eth.then_some(l2_costs).unwrap_or_default();

    // NOTE: In ETH deposits, the amount of ETH to be deposited into the
    // ETH based chain should be part of the `value` field of the L1 tx
    // which essentially is the call to the `requestL2TransactionDirect`.
    let overrides = L1TxOverrides::default()
        .from(from_addr)
        .value(value)
        .gas_price(from.get_gas_price().await.unwrap())
        .gas(scale_gas_limit(estimate_l1_to_l2_gas))
        .nonce(from.get_transaction_count(from_addr, None).await.unwrap());

    deposit_with_l2_transaction_direct_request(bridgehub, request, overrides).await
}

pub async fn deposit_with_l2_transaction_direct_request<M, S>(
    bridgehub: Bridgehub<SignerMiddleware<M, S>>,
    request: L2TransactionRequestDirect,
    overrides: L1TxOverrides,
) -> Hash
where
    M: Middleware,
    S: Signer,
{
    bridgehub
        .request_l2_transaction_direct(request)
        .from(overrides.from.unwrap_or_default())
        .value(overrides.value.unwrap_or_default())
        .gas_price(overrides.gas_price.unwrap_or_default())
        .gas(overrides.gas.unwrap_or_default())
        .nonce(overrides.nonce.unwrap_or_default())
        .send()
        .await
        .unwrap()
        .await
        .unwrap()
        .unwrap()
        .transaction_hash
}

/// Deposits ERC20 tokens into a ZKChain where the base token
/// is either ETH or a different ERC20 than the deposited.
pub async fn deposit_non_base_erc20_token<M, S, L2Provider>(
    amount: U256,
    token: Address,
    from: Arc<SignerMiddleware<M, S>>,
    to: Address,
    refund_recipient: Address,
    l2_provider: &L2Provider,
    bridgehub: Bridgehub<SignerMiddleware<M, S>>,
    erc20: ERC20<SignerMiddleware<M, S>>,
    token_to_deposit_is_zk_chain_base_token: bool,
) -> Hash
where
    M: Middleware,
    S: Signer,
    L2Provider: ZKMiddleware + Middleware,
{
    let zk_chain_id = l2_provider.get_chainid().await.unwrap();
    // The amount of gas required for executing an L2 tx via L1.
    let estimate_gas_for_l1_to_l2_tx = l2_provider
        .estimate_gas_l1_to_l2(
            Eip712TransactionRequest::new()
                .chain_id(zk_chain_id)
                .from(from.address())
                .to(to),
        )
        .await
        .unwrap();
    let l2_gas_per_pubdata_byte_limit = U256::from(utils::REQUIRED_L1_TO_L2_GAS_PER_PUBDATA_LIMIT);
    let operator_tip = U256::zero();
    let base_cost = l2_tx_base_cost(
        &bridgehub,
        zk_chain_id,
        from.get_gas_price().await.unwrap(),
        estimate_gas_for_l1_to_l2_tx,
        l2_gas_per_pubdata_byte_limit,
    )
    .await;
    let l2_costs = scale_gas_limit(base_cost + operator_tip);

    let l1_shared_bridge_address: Address = bridgehub.shared_bridge().call().await.unwrap();

    let calldata = ethers::abi::encode(&[token.into_token(), amount.into_token(), to.into_token()]);

    let request: L2TransactionRequestTwoBridgesOuter = L2TransactionRequestTwoBridgesOuter::new()
        .chain_id(zk_chain_id)
        .mint_value(l2_costs)
        .l2_value(U256::zero())
        .l2_gas_limit(estimate_gas_for_l1_to_l2_tx)
        .l2_gas_per_pubdata_byte_limit(l2_gas_per_pubdata_byte_limit)
        .refund_recipient(refund_recipient)
        .second_bridge_address(l1_shared_bridge_address)
        .second_bridge_value(U256::zero())
        .second_bridge_calldata(calldata);

    let allowance: U256 = erc20
        .allowance(from.address(), l1_shared_bridge_address)
        .call()
        .await
        .unwrap();
    // ERC20 approval needs to be done before getting the nonce for the
    // overrides.
    if allowance < amount {
        erc20
            .approve(l1_shared_bridge_address, amount)
            .send()
            .await
            .unwrap()
            .await
            .unwrap()
            .unwrap();
    }

    let nonce = from
        .get_transaction_count(from.address(), None)
        .await
        .unwrap();
    let l1_gas_price = from.get_gas_price().await.unwrap();
    // The value should be overridden in the case where the base token is ETH.
    let value = bridgehub
        .base_token(zk_chain_id)
        .call()
        .await
        .unwrap()
        .eq(&utils::L2_ETH_TOKEN_ADDRESS)
        .then_some(l2_costs)
        .unwrap_or_default();

    let overrides = L1TxOverrides::default()
        .from(from.address())
        .gas_price(l1_gas_price)
        .gas(estimate_gas_for_l1_to_l2_tx)
        .nonce(nonce)
        .value(value);

    deposit_with_l2_transaction_two_bridges_request(bridgehub, request, overrides).await
}

pub async fn deposit_with_l2_transaction_two_bridges_request<M, S>(
    bridgehub: Bridgehub<SignerMiddleware<M, S>>,
    request: L2TransactionRequestTwoBridgesOuter,
    overrides: L1TxOverrides,
) -> Hash
where
    M: Middleware,
    S: Signer,
{
    bridgehub
        .request_l2_transaction_two_bridges(request)
        .from(overrides.from.unwrap_or_default())
        .value(overrides.value.unwrap_or_default())
        .gas_price(overrides.gas_price.unwrap_or_default())
        .gas(overrides.gas.unwrap_or_default())
        .nonce(overrides.nonce.unwrap_or_default())
        .send()
        .await
        .unwrap()
        .await
        .unwrap()
        .unwrap()
        .transaction_hash
}

/// Hash corresponding to the L2 priority operation transaction for finalizing a deposit.
pub async fn l2_deposit_tx_hash<L1Provider>(
    l1_deposit_tx_hash: Hash,
    l1_provider: &L1Provider,
) -> Hash
where
    L1Provider: Middleware,
{
    let l1_deposit_tx_receipt = l1_provider
        .get_transaction_receipt(l1_deposit_tx_hash)
        .await
        .unwrap()
        .unwrap();

    l1_deposit_tx_receipt
        .logs
        .into_iter()
        .find(|event| {
            event.topics[0]
                .eq(&ethers::utils::keccak256(
                    "NewPriorityRequest(uint256,bytes32,uint64,(uint256,uint256,uint256,uint256,uint256,uint256,uint256,uint256,uint256,uint256,uint256[4],bytes,bytes,uint256[],bytes,bytes),bytes[])",
                )
                .into())
        })
        .map(|new_priority_request_event| Hash::from_slice(&new_priority_request_event.data.0[32..64]))
        .unwrap()
}

pub async fn l2_tx_base_cost<M, S>(
    bridgehub: &Bridgehub<SignerMiddleware<M, S>>,
    zk_chain_id: U256,
    l1_gas_price: U256,
    estimate_gas_for_l1_to_l2_tx: U256,
    l2_gas_per_pubdata_byte_limit: U256,
) -> U256
where
    M: Middleware,
    S: Signer,
{
    bridgehub
        .l_2_transaction_base_cost(
            zk_chain_id,
            l1_gas_price,
            estimate_gas_for_l1_to_l2_tx,
            l2_gas_per_pubdata_byte_limit,
        )
        .call()
        .await
        .unwrap()
}

/// Scales the provided gas limit using a coefficient to ensure acceptance of L1->L2 transactions.
///
/// This function adjusts the gas limit by multiplying it with a coefficient calculated from the
/// `L1_FEE_ESTIMATION_COEF_NUMERATOR` and `L1_FEE_ESTIMATION_COEF_DENOMINATOR` constants.
pub fn scale_gas_limit(gas_limit: U256) -> U256 {
    gas_limit
        .checked_mul(U256::from(L1_FEE_ESTIMATION_COEF_NUMERATOR))
        .unwrap()
        .checked_div(U256::from(L1_FEE_ESTIMATION_COEF_DENOMINATOR))
        .unwrap()
}

pub async fn wait_for_finalize_deposit<L2Provider>(
    finalize_deposit_tx_hash: Hash,
    l2_provider: &L2Provider,
) where
    L2Provider: ZKMiddleware + Middleware,
{
    loop {
        if l2_provider
            .get_transaction_details(finalize_deposit_tx_hash)
            .await
            .unwrap()
            .unwrap()
            .eth_execute_tx_hash
            .is_some()
        {
            break;
        }
        println!("Finalize deposit request not executed on L1 yet. Retrying in 5 seconds...");
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}
