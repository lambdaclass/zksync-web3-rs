// FIXME: Remove this after finishing the implementation.
#![allow(clippy::unwrap_used)]

use crate::{
    contracts::{
        bridgehub::{Bridgehub, L2TransactionRequestDirect, L2TransactionRequestTwoBridgesOuter},
        erc20::ERC20,
    },
    types::L1TxOverrides,
    utils::{L2_ETH_TOKEN_ADDRESS, REQUIRED_L1_TO_L2_GAS_PER_PUBDATA_LIMIT},
    ZKMiddleware,
};
use ethers::{
    abi::{Address, Hash, Tokenizable},
    middleware::SignerMiddleware,
    providers::Middleware,
    signers::Signer,
    types::U256,
};
use std::sync::Arc;
use utils::{estimate_gas_for_l1_to_l2_tx, l2_tx_base_cost, scale_gas_limit};

mod constants;
mod utils;

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

    let token_to_deposit_is_zk_chain_base_token = token == zk_chain_base_token;

    // The amount of gas required for executing an L2 tx via L1.
    let estimate_gas_for_l1_to_l2_tx =
        estimate_gas_for_l1_to_l2_tx(from.address(), to, zk_chain_id, &l2_provider).await;
    let l2_gas_per_pubdata_byte_limit = U256::from(REQUIRED_L1_TO_L2_GAS_PER_PUBDATA_LIMIT);
    let operator_tip = U256::zero();
    let base_cost = l2_tx_base_cost(
        &bridgehub,
        zk_chain_id,
        from.get_gas_price().await.unwrap(),
        estimate_gas_for_l1_to_l2_tx,
        l2_gas_per_pubdata_byte_limit,
    )
    .await;
    let l2_costs = base_cost + operator_tip + amount;

    let l1_shared_bridge_address: Address = bridgehub.shared_bridge().call().await.unwrap();
    let token_is_eth = token == L2_ETH_TOKEN_ADDRESS;
    if !token_is_eth {
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
                .approve(l1_shared_bridge_address, amount * 2)
                .send()
                .await
                .unwrap()
                .await
                .unwrap()
                .unwrap();
        }
    }

    let overrides = L1TxOverrides::default()
        .from(from.address())
        .value(token_is_eth.then_some(l2_costs).unwrap_or_default())
        .gas_price(from.get_gas_price().await.unwrap())
        .gas(scale_gas_limit(estimate_gas_for_l1_to_l2_tx))
        .nonce(
            from.get_transaction_count(from.address(), None)
                .await
                .unwrap(),
        );

    if token_to_deposit_is_zk_chain_base_token {
        let request = L2TransactionRequestDirect::new()
            .chain_id(zk_chain_id)
            .mint_value(l2_costs)
            .l2_contract(to)
            .l2_value(amount)
            .l2_calldata(vec![])
            .l2_gas_limit(estimate_gas_for_l1_to_l2_tx)
            .l2_gas_per_pubdata_byte_limit(l2_gas_per_pubdata_byte_limit)
            .factory_deps(vec![])
            .refund_recipient(refund_recipient);

        deposit_with_l2_transaction_direct_request(bridgehub, request, overrides).await
    } else {
        let request = L2TransactionRequestTwoBridgesOuter::new()
            .chain_id(zk_chain_id)
            .mint_value(l2_costs)
            .l2_value(U256::zero())
            .l2_gas_limit(estimate_gas_for_l1_to_l2_tx)
            .l2_gas_per_pubdata_byte_limit(l2_gas_per_pubdata_byte_limit)
            .refund_recipient(refund_recipient)
            .second_bridge_address(l1_shared_bridge_address)
            .second_bridge_value(U256::zero())
            .second_bridge_calldata(ethers::abi::encode(&[
                token.into_token(),
                amount.into_token(),
                to.into_token(),
            ]));

        deposit_with_l2_transaction_two_bridges_request(bridgehub, request, overrides).await
    }
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
) -> Option<Hash>
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
