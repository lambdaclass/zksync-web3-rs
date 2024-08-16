// FIXME: Remove this after finishing the implementation.
#![allow(clippy::unwrap_used)]

use ethers::{
    abi::{Address, Hash},
    middleware::SignerMiddleware,
    providers::Middleware,
    signers::Signer,
    types::{transaction::eip2718::TypedTransaction, Eip1559TransactionRequest, U256},
};
use std::{ops::Mul, sync::Arc};
use zksync_types::{L2_BASE_TOKEN_ADDRESS, MAX_L2_TX_GAS_LIMIT};

use crate::{
    contracts::erc20::ERC20,
    utils::{MAX_FEE_PER_GAS, MAX_PRIORITY_FEE_PER_GAS},
};

pub async fn transfer<M, S>(
    amount: U256,
    token: impl Into<Address>,
    from: Arc<SignerMiddleware<M, S>>,
    to: Address,
) -> Hash
where
    M: Middleware,
    S: Signer,
{
    // The type is converted to avoid adding Copy as a constraint bound (Address is Copy).
    let token: Address = token.into();

    let token_to_transfer_is_zk_chain_base_token = token == L2_BASE_TOKEN_ADDRESS;

    if token_to_transfer_is_zk_chain_base_token {
        transfer_base_token(amount, from, to).await
    } else {
        transfer_non_base_token(amount, token, from, to).await
    }
}

pub async fn transfer_base_token<M, S>(
    amount: U256,
    from: Arc<SignerMiddleware<M, S>>,
    to: Address,
) -> Hash
where
    M: Middleware,
    S: Signer,
{
    let mut transfer_tx = Eip1559TransactionRequest::new()
        .from(from.address())
        .to(to)
        .value(amount)
        .nonce(
            from.get_transaction_count(from.address(), None)
                .await
                .unwrap(),
        );
    // let fee = from.estimate_fee(transfer_tx.clone()).await.unwrap();
    transfer_tx = transfer_tx
        .max_fee_per_gas(MAX_FEE_PER_GAS.mul(100))
        .max_priority_fee_per_gas(MAX_PRIORITY_FEE_PER_GAS.mul(100))
        .gas(MAX_L2_TX_GAS_LIMIT.mul(10));

    let tx: TypedTransaction = transfer_tx.into();

    let transfer_receipt = from
        .send_transaction(tx, None)
        .await
        .unwrap()
        .await
        .unwrap()
        .unwrap();

    transfer_receipt.transaction_hash
}

pub async fn transfer_non_base_token<M, S>(
    amount: U256,
    token: Address,
    from: Arc<SignerMiddleware<M, S>>,
    to: Address,
) -> Hash
where
    M: Middleware,
    S: Signer,
{
    let non_base_token_transfer_receipt = ERC20::new(token, Arc::clone(&from))
        .transfer(to, amount)
        .send()
        .await
        .unwrap()
        .await
        .unwrap()
        .unwrap();
    non_base_token_transfer_receipt.transaction_hash
}
