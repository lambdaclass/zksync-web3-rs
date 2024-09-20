// FIXME: Remove this after finishing the implementation.
#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use ethers::{abi::Address, providers::Middleware};
use ethers_contract::abigen;

use crate::ZKMiddleware;

abigen!(L2SharedBridge, "abi/IL2Bridge.json");

/// Gets the L2 token Address, given the L1 token Address.
///
/// # Returns
///
/// L2 token Address.
pub async fn get_l2_token_from_l1_address<L2Provider>(
    token: Address,
    l2_provider: &L2Provider,
) -> Address
where
    L2Provider: ZKMiddleware + Middleware + Clone + 'static,
{
    let bridge_addresses = l2_provider.get_bridge_contracts().await.unwrap();
    let l2_shared_bridge_addr = bridge_addresses.l2_shared_default_bridge.unwrap();

    let l2_shared_bridge =
        L2SharedBridge::new(l2_shared_bridge_addr, Arc::new(l2_provider.clone()));

    l2_shared_bridge.l_2_token_address(token).await.unwrap()
}
