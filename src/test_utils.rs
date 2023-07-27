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

/// Helper function that returns the value for an environment variable. Formats an error message
/// when the environment var defined by `key` is unset.
fn get_env_var(key: &str) -> String {
    env::var(key).expect(&format!("Environment variable is unset: {}", key))
}

pub fn eth_provider() -> Provider<Http> {
    let url: String = get_env_var("ZKSYNC_WEB3_RS_L1_PROVIDER_URL");
    Provider::try_from(url).unwrap()
}

pub fn era_provider() -> Provider<Http> {
    let url: String = get_env_var("ZKSYNC_WEB3_RS_L2_PROVIDER_URL");
    Provider::try_from(url).unwrap()
}

pub fn era_provider_chain_id() -> u16 {
    get_env_var("ZKSYNC_WEB3_RS_L2_PROVIDER_CHAIN_ID")
        .parse()
        .expect("Failed to parse ZKSYNC_WEB3_RS_L2_PROVIDER_CHAIN_ID")
}
