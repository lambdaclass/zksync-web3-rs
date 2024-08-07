use common::{assert_tx_succeeded, balance_of, l1_provider, l1_signer, l2_provider};
use ethers::{
    abi::Address, middleware::SignerMiddleware, providers::Middleware, signers::Signer, types::U256,
};
use std::{str::FromStr, sync::Arc};
use zksync_ethers_rs::{
    deposit::{deposit, l2_deposit_tx_hash},
    utils::L2_ETH_TOKEN_ADDRESS,
};

mod common;

async fn can_deposit<M, S>(token: Address, from: Arc<SignerMiddleware<M, S>>, to: Address)
where
    M: Middleware,
    S: Signer,
{
    let refund_recipient = from.address();
    let l2_provider = l2_provider().await;
    let amount: U256 = ethers::utils::parse_units("0.001", "ether").unwrap().into();

    let receiver_l2_balance_before = balance_of(to, token, &l2_provider).await;

    let deposit_tx_hash = deposit(
        amount,
        token,
        Arc::clone(&from),
        to,
        refund_recipient,
        &l2_provider,
    )
    .await;

    println!("https://sepolia.etherscan.io/tx/{deposit_tx_hash:?}",);

    assert_tx_succeeded(deposit_tx_hash, from.provider(), "L1 transaction failed").await;

    let l2_tx_hash = l2_deposit_tx_hash(deposit_tx_hash, from.provider()).await;

    println!("https://explorer.sepolia.shyft.lambdaclass.com/tx/{l2_tx_hash:?}");

    assert_tx_succeeded(l2_tx_hash, &l2_provider, "L2 transaction failed").await;

    let receiver_l2_balance_after = balance_of(to, token, &l2_provider).await;

    assert_eq!(
        receiver_l2_balance_after,
        receiver_l2_balance_before + amount,
        "Receiver's L2 balance has not increased by the deposited amount."
    );
}

#[tokio::test]
async fn can_self_deposit_eth_to_eth_based_zk_chain() {
    let from = l1_signer().await;
    let to = from.address();
    can_deposit(L2_ETH_TOKEN_ADDRESS, from, to).await;
}

#[tokio::test]
async fn can_self_deposit_erc20_to_eth_based_zk_chain() {
    let some_erc20 = Address::from_str("0x7209EaD3dfe1c3a517B6b730C00bea1E7f319260").unwrap();
    let from = l1_signer().await;
    let to = from.address();
    can_deposit(some_erc20, from, to).await;
}

#[tokio::test]
#[ignore = "unimplemented"]
async fn can_self_deposit_eth_to_erc20_based_zk_chain() {}

#[tokio::test]
#[ignore = "unimplemented"]
async fn can_self_deposit_erc20_to_same_erc20_based_zk_chain() {
    let from = l1_signer().await;
    let to = from.address();
    let ihc_token = Address::from_str("0xd0580192e98ea6ceb9c7b6191ed2e27560911697").unwrap();
    can_deposit(ihc_token, from, to).await;
}

#[tokio::test]
#[ignore = "unimplemented"]
async fn can_self_deposit_erc20_to_different_erc20_based_zk_chain() {}

#[tokio::test]
#[ignore = "unimplemented"]
async fn can_deposit_eth_to_eth_based_zk_chain_to_other_account() {
    let from = l1_signer().await;
    let to = Address::from_str("0x01bdD706463BC3A556a7efD8497A5b008D77dc71").unwrap();
    can_deposit(L2_ETH_TOKEN_ADDRESS, from, to).await;
}

#[tokio::test]
#[ignore = "unimplemented"]
async fn can_deposit_erc20_to_eth_based_zk_chain_to_other_account() {
    let some_erc20 = Address::from_str("0x7209EaD3dfe1c3a517B6b730C00bea1E7f319260").unwrap();
    let from = l1_signer().await;
    let to = Address::from_str("0x01bdD706463BC3A556a7efD8497A5b008D77dc71").unwrap();
    can_deposit(some_erc20, from, to).await;
}

#[tokio::test]
#[ignore = "unimplemented"]
async fn can_deposit_eth_to_erc20_based_zk_chain_to_other_account() {}

#[tokio::test]
#[ignore = "unimplemented"]
async fn can_deposit_erc20_to_same_erc20_based_zk_chain_to_other_account() {}

#[tokio::test]
#[ignore = "unimplemented"]
async fn can_deposit_erc20_to_different_erc20_based_zk_chain_to_other_account() {}

#[tokio::test]
async fn testito() {
    let l1_provider = l1_provider().await;
    let l2_provider = l2_provider().await;

    println!(
        "{:?}",
        l2_deposit_tx_hash(
            "0x1ba39e2ca832d5fedaf92d46220bd2582048c7e69c4a20ba74555b9ce94d5485"
                .parse()
                .unwrap(),
            &l1_provider
        )
        .await
    );
}
