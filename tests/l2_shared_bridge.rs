use std::str::FromStr;
mod common;
use common::l2_provider;
use zksync_ethers_rs::contracts::l2_shared_bridge::get_l2_token_from_l1_address;
use zksync_types::H160;

#[tokio::test]
async fn l2_token_address() {
    let l2_provider = l2_provider().await;
    let l2_token = get_l2_token_from_l1_address(
        H160::from_str("0x8E9C82509488eD471A83824d20Dd474b8F534a0b").unwrap(),
        &l2_provider,
    )
    .await;
    assert_eq!(
        l2_token,
        H160::from_str("0xb06fcdb64e4b4c18406e0d5e13ed1c7cec452716").unwrap()
    );
}
