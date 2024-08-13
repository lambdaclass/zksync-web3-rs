use std::{str::FromStr, sync::Arc};

use ethers::{
    abi::{Address, Hash},
    prelude::SignerMiddleware,
    providers::{Http, Middleware, Provider, ProviderExt},
    signers::{LocalWallet, Signer},
    types::{U256, U64},
};
use zksync_ethers_rs::{
    utils::{L1_ETH_TOKEN_ADDRESS, L2_ETH_TOKEN_ADDRESS},
    ZKMiddleware,
};

pub const L2_RPC_URL: &str = "http://127.0.0.1:3050";
pub const L2_EXPLORER_URL: &str = "http://127.0.0.1:3010";
pub const L1_EXPLORER_URL: &str = "";
pub const L1_RPC_URL: &str = "http://127.0.0.1:8545";

pub fn l1_explorer_url() -> String {
    std::env::var("L1_EXPLORER_URL").unwrap_or(L1_EXPLORER_URL.to_owned())
}

pub fn l2_explorer_url() -> String {
    std::env::var("L2_EXPLORER_URL").unwrap_or(L2_EXPLORER_URL.to_owned())
}

pub async fn l1_provider() -> Provider<Http> {
    Provider::<Http>::connect(&std::env::var("L1_RPC_URL").unwrap_or(L1_RPC_URL.to_owned())).await
}

pub async fn l2_provider() -> Provider<Http> {
    Provider::<Http>::connect(&std::env::var("L2_RPC_URL").unwrap_or(L2_RPC_URL.to_owned())).await
}

pub async fn signer(
    provider: Provider<Http>,
) -> Arc<SignerMiddleware<Provider<Http>, LocalWallet>> {
    let chain_id = provider.get_chainid().await.unwrap().as_u64();
    Arc::new(SignerMiddleware::<Provider<Http>, LocalWallet>::new(
        provider,
        LocalWallet::from_str(&std::env::var("PRIVATE_KEY").unwrap_or(
            "0x385c546456b6a603a1cfcaa9ec9494ba4832da08dd6bcf4de9a71e4a01b74924".to_owned(),
        ))
        .unwrap()
        .with_chain_id(chain_id),
    ))
}

pub async fn l1_signer() -> Arc<SignerMiddleware<Provider<Http>, LocalWallet>> {
    signer(l1_provider().await).await
}

pub async fn l2_signer() -> Arc<SignerMiddleware<Provider<Http>, LocalWallet>> {
    signer(l2_provider().await).await
}

pub async fn balance_of(of: Address, token: Address, provider: &Provider<Http>) -> U256 {
    let token = if token == L2_ETH_TOKEN_ADDRESS {
        L1_ETH_TOKEN_ADDRESS
    } else {
        token
    };
    *provider
        .get_all_account_balances(of)
        .await
        .unwrap()
        .get(&token)
        .unwrap_or(&U256::zero())
}

pub async fn assert_tx_succeeded<Provider>(tx_hash: Hash, provider: &Provider, panic_message: &str)
where
    Provider: Middleware,
{
    wait_for_tx(tx_hash, provider).await;

    let tx_receipt = provider
        .get_transaction_receipt(tx_hash)
        .await
        .unwrap()
        .unwrap();

    assert!(tx_succeeded(&tx_receipt), "{panic_message}: {tx_receipt:?}");
}

async fn wait_for_tx<M>(tx_hash: Hash, provider: &M)
where
    M: Middleware,
{
    while provider
        .get_transaction_receipt(tx_hash)
        .await
        .unwrap()
        .is_none()
    {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}

fn tx_succeeded(receipt: &ethers::types::TransactionReceipt) -> bool {
    let tx_has_failed = receipt.status.as_ref().is_some_and(U64::is_zero);
    !tx_has_failed
}
