use std::env;

use ethers::{
    abi::Abi,
    providers::{Http, Provider},
    types::Bytes,
};
use serde::Deserialize;

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
