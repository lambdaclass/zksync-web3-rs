use std::env;

use ethers::{
    abi::Abi,
    prelude::{MiddlewareBuilder, SignerMiddleware},
    providers::{Http, Provider},
    signers::{LocalWallet, Signer, Wallet},
    types::Bytes,
};
use ethers_contract::core::k256::ecdsa::SigningKey;
use serde::Deserialize;

use crate::zks_utils::ERA_CHAIN_ID;

pub const TEST_PRIVATE_KEY: &str =
    "0xe131bc3f481277a8f73d680d9ba404cc6f959e64296e0914dded403030d4f705";

#[derive(Deserialize)]
pub(crate) struct CompiledContract {
    pub abi: Abi,
    pub bin: Bytes,
}

pub fn eth_provider() -> Provider<Http> {
    let url: String = env::var("ZKSYNC_WEB3_RS_L1_PROVIDER_URL").unwrap();
    Provider::try_from(url).unwrap()
}

pub fn era_provider() -> Provider<Http> {
    let url: String = env::var("ZKSYNC_WEB3_RS_L2_PROVIDER_URL").unwrap();
    Provider::try_from(url).unwrap()
}

pub fn local_wallet() -> LocalWallet {
    TEST_PRIVATE_KEY
        .parse::<LocalWallet>()
        .unwrap()
        .with_chain_id(ERA_CHAIN_ID)
}

pub fn era_signer() -> SignerMiddleware<Provider<ethers::providers::Http>, Wallet<SigningKey>> {
    let signer = Wallet::with_chain_id(
        TEST_PRIVATE_KEY.parse::<Wallet<SigningKey>>().unwrap(),
        ERA_CHAIN_ID,
    );
    era_provider().with_signer(signer)
}
