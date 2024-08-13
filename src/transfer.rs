// FIXME: Remove this after finishing the implementation.
#![allow(clippy::unwrap_used)]

use ethers::{
    abi::{Address, Hash},
    middleware::SignerMiddleware,
    providers::Middleware,
    signers::Signer,
    types::U256,
};
use std::sync::Arc;
use zksync_types::L2_BASE_TOKEN_ADDRESS;

use crate::{
    contracts::{bridgehub::Bridgehub, erc20::ERC20, l2_eth::BaseToken},
    ZKMiddleware,
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

    let bridgehub_address = from.provider().get_bridgehub_contract().await.unwrap();
    let bridgehub = Bridgehub::new(
        bridgehub_address,
        Arc::<SignerMiddleware<M, S>>::clone(&from),
    );

    let zk_chain_id = from.provider().get_chainid().await.unwrap();
    let zk_chain_base_token: Address = bridgehub.base_token(zk_chain_id).call().await.unwrap();

    let token_to_transfer_is_zk_chain_base_token = token == zk_chain_base_token;

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
    let base_token_transfer_receipt = BaseToken::new(L2_BASE_TOKEN_ADDRESS, Arc::clone(&from))
        .transfer_from_to(from.address(), to, amount)
        .send()
        .await
        .unwrap()
        .await
        .unwrap()
        .unwrap();
    base_token_transfer_receipt.transaction_hash
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
