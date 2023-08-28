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
    "0x7726827caac94a7f9e1b160f7ea819f172f7b6f9d2a97f992c38edeab82d4110"
        .parse::<LocalWallet>()
        .unwrap()
        .with_chain_id(ERA_CHAIN_ID)
}

pub fn era_signer() -> SignerMiddleware<Provider<ethers::providers::Http>, Wallet<SigningKey>> {
    let signer = Wallet::with_chain_id(
        "0x7726827caac94a7f9e1b160f7ea819f172f7b6f9d2a97f992c38edeab82d4110"
            .parse::<Wallet<SigningKey>>()
            .unwrap(),
        ERA_CHAIN_ID,
    );
    era_provider().with_signer(signer)
}
