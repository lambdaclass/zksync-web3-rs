// FIXME: Remove this after finishing the implementation.
#![allow(clippy::unwrap_used)]

use ethers::{
    abi::{Address, Hash},
    middleware::SignerMiddleware,
    providers::Middleware,
    signers::Signer,
    types::{transaction::eip2718::TypedTransaction, Eip1559TransactionRequest, U256},
};
use std::sync::Arc;
use zksync_types::L2_BASE_TOKEN_ADDRESS;

use crate::{contracts::erc20::ERC20, types::L2TxOverrides, ZKMiddleware};

pub async fn transfer<M, S>(
    amount: U256,
    token: impl Into<Address>,
    from: Arc<SignerMiddleware<M, S>>,
    to: Address,
    overrides: Option<L2TxOverrides>,
) -> Hash
where
    M: Middleware,
    S: Signer,
{
    // The type is converted to avoid adding Copy as a constraint bound (Address is Copy).
    let token: Address = token.into();

    let token_to_transfer_is_zk_chain_base_token = token == L2_BASE_TOKEN_ADDRESS;

    if token_to_transfer_is_zk_chain_base_token {
        transfer_base_token(amount, from, to, overrides).await
    } else {
        transfer_non_base_token(amount, token, from, to).await
    }
}

///  The fee has to be deducted manually, amount is the exact amount that has to be transferred
pub async fn transfer_base_token<M, S>(
    amount: U256,
    from: Arc<SignerMiddleware<M, S>>,
    to: Address,
    overrides: Option<L2TxOverrides>,
) -> Hash
where
    M: Middleware,
    S: Signer,
{
    let transaction_count = from
        .get_transaction_count(from.address(), None)
        .await
        .unwrap();

    let nonce = if let Some(overrides) = overrides {
        overrides.nonce.unwrap_or(transaction_count)
    } else {
        transaction_count
    };

    let mut transfer_tx = Eip1559TransactionRequest::new()
        .from(from.address())
        .to(to)
        .value(amount)
        .nonce(nonce);
    let fees = from.provider().estimate_fee(&transfer_tx).await.unwrap();
    transfer_tx = transfer_tx
        .max_fee_per_gas(fees.max_fee_per_gas)
        .max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
        .gas(fees.gas_limit);

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
