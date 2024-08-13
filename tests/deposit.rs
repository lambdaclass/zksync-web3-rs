use common::{
    assert_tx_succeeded, balance_of, l1_explorer_url, l1_signer, l2_explorer_url, l2_provider,
};
use ethers::{abi::Address, middleware::SignerMiddleware, providers::Middleware, signers::Signer};
use std::{str::FromStr, sync::Arc};
use zksync_ethers_rs::{
    deposit::{deposit, l2_deposit_tx_hash, wait_for_finalize_deposit},
    utils::L2_ETH_TOKEN_ADDRESS,
    ZKMiddleware,
};

mod common;

async fn can_deposit<M, S>(token: Address, from: Arc<SignerMiddleware<M, S>>, to: Address)
where
    M: Middleware,
    S: Signer,
{
    let refund_recipient = from.address();
    let l2_provider = l2_provider().await;
    let amount = ethers::utils::parse_ether("0.001").unwrap().into();

    let receiver_l2_balance_before = balance_of(to, token, &l2_provider).await;

    let l1_tx_hash = deposit(
        amount,
        token,
        Arc::clone(&from),
        to,
        refund_recipient,
        &l2_provider,
    )
    .await;

    println!("{}/tx/{l1_tx_hash:?}", l1_explorer_url());

    assert_tx_succeeded(l1_tx_hash, from.provider(), "L1 transaction failed").await;

    let l2_tx_hash = l2_deposit_tx_hash(l1_tx_hash, from.provider()).await;

    println!("{}/tx/{l2_tx_hash:?}", l2_explorer_url());

    assert_tx_succeeded(l2_tx_hash, &l2_provider, "L2 transaction failed").await;

    wait_for_finalize_deposit(l2_tx_hash, &l2_provider).await;

    let receiver_l2_balance_after = balance_of(to, token, &l2_provider).await;

    assert_eq!(
        receiver_l2_balance_before + amount,
        receiver_l2_balance_after,
        "Receiver's L2 balance has not increased by the deposited amount. Before: {receiver_l2_balance_before}, After: {receiver_l2_balance_after}, Amount: {amount}"
    );
}

#[tokio::test]
async fn can_deposit_eth() {
    let from = l1_signer().await;
    let to = Address::random();
    can_deposit(L2_ETH_TOKEN_ADDRESS, from, to).await;
}

#[tokio::test]
async fn can_deposit_erc20() {
    let some_erc20 = Address::from_str("0x7209EaD3dfe1c3a517B6b730C00bea1E7f319260").unwrap();

    let from = l1_signer().await;
    let to = Address::random();
    can_deposit(some_erc20, from, to).await;
}

#[tokio::test]
async fn can_deposit_base_token() {
    let from = l1_signer().await;
    let to = Address::random();
    let l1_base_token_address = l2_provider()
        .await
        .get_base_token_l1_address()
        .await
        .unwrap();
    can_deposit(l1_base_token_address, from, to).await;
}
