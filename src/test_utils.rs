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

static DEFAULT_L1_PROVIDER_URL: &str = "http://65.21.140.36:8545";
static DEFAULT_L2_PROVIDER_URL: &str = "http://65.21.140.36:3050";

pub fn eth_provider() -> Provider<Http> {
    let url: String =
        env::var("ZKSYNC_WEB3_RS_L1_PROVIDER_URL").unwrap_or(DEFAULT_L1_PROVIDER_URL.to_owned());
    Provider::try_from(url).unwrap()
}

pub fn era_provider() -> Provider<Http> {
    let url: String =
        env::var("ZKSYNC_WEB3_RS_L2_PROVIDER_URL").unwrap_or(DEFAULT_L2_PROVIDER_URL.to_owned());
    Provider::try_from(url).unwrap()
}
