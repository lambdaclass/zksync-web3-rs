use common::{assert_tx_succeeded, l1_explorer_url, l1_signer, l2_explorer_url, l2_signer};
use ethers::{
    abi::Address,
    middleware::SignerMiddleware,
    providers::{Http, Middleware, Provider},
    signers::LocalWallet,
    types::U256,
};
use std::{str::FromStr, sync::Arc};
use zksync_ethers_rs::{
    finalize_withdrawal, utils::L2_ETH_TOKEN_ADDRESS, wait_for_finalize_withdrawal,
    withdraw::withdraw, ZKMiddleware,
};

mod common;

async fn can_withdraw(
    token: Address,
    from: Arc<SignerMiddleware<Provider<Http>, LocalWallet>>,
    to: Arc<SignerMiddleware<Provider<Http>, LocalWallet>>,
) {
    let amount: U256 = ethers::utils::parse_units("0.001", "ether").unwrap().into();

    let receiver_l1_balance_before = to.provider().get_balance(to.address(), None).await.unwrap();

    let l2_tx_hash = withdraw(amount, token, Arc::clone(&from), to.provider()).await;

    println!("{}/tx/{l2_tx_hash:?}", l2_explorer_url());

    assert_tx_succeeded(l2_tx_hash, from.provider(), "L2 transaction failed").await;

    wait_for_finalize_withdrawal(l2_tx_hash, from.provider()).await;

    let l1_tx_hash = finalize_withdrawal(Arc::clone(&to), l2_tx_hash, from.provider()).await;

    println!("{}/tx/{l1_tx_hash}", l1_explorer_url());

    assert_tx_succeeded(l1_tx_hash, to.provider(), "L1 transaction failed").await;

    let receiver_l1_balance_after = to.provider().get_balance(to.address(), None).await.unwrap();

    assert_eq!(
        receiver_l1_balance_after,
        receiver_l1_balance_before + amount,
        "Receiver's L1 balance has not increased by the withdraw amount. Before: {receiver_l1_balance_before}, After: {receiver_l1_balance_after}, Amount: {amount}"
    );
}

#[tokio::test]
async fn can_withdraw_eth() {
    let from = l2_signer().await;
    let to = l1_signer().await;
    can_withdraw(L2_ETH_TOKEN_ADDRESS, from, to).await;
}

#[tokio::test]
async fn can_withdraw_erc20() {
    let some_erc20 = Address::from_str("0x7209EaD3dfe1c3a517B6b730C00bea1E7f319260").unwrap();

    let from = l2_signer().await;
    let to = l1_signer().await;
    can_withdraw(some_erc20, from, to).await;
}

#[tokio::test]
async fn can_withdraw_base_token() {
    let from = l2_signer().await;
    let to = l1_signer().await;
    let l1_base_token_address = from.provider().get_base_token_l1_address().await.unwrap();
    can_withdraw(l1_base_token_address, from, to).await;
}
