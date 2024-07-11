// FIXME: Remove this after finishing the implementation.
#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use ethers::{
    abi::{Address, Tokenizable},
    middleware::SignerMiddleware,
    providers::Middleware,
    signers::Signer,
    types::U256,
};

use crate::{
    contracts::{
        bridgehub::{Bridgehub, L2TransactionRequestDirect, L2TransactionRequestTwoBridgesOuter},
        erc20::ERC20,
    },
    eip712::Eip712TransactionRequest,
    types::L1TxOverrides,
    utils, ZKMiddleware,
};

pub async fn deposit<M, S, L2Provider>(
    amount: U256,
    token: impl Into<Address>,
    from: Arc<SignerMiddleware<M, S>>,
    to: Address,
    refund_recipient: Address,
    l2_provider: L2Provider,
) -> ethers::types::TransactionReceipt
where
    M: Middleware,
    S: Signer,
    L2Provider: ZKMiddleware + Middleware,
{
    // The type is converted to avoid adding Copy as a constraint bound (Address is Copy).
    let token: Address = token.into();

    let bridgehub_address = l2_provider.get_bridgehub_contract().await.unwrap();
    let bridgehub = Bridgehub::new(
        bridgehub_address,
        Arc::<SignerMiddleware<M, S>>::clone(&from),
    );

    let zk_chain_id = l2_provider.get_chainid().await.unwrap();
    let zk_chain_base_token: Address = bridgehub.base_token(zk_chain_id).call().await.unwrap();

    let token_to_deposit_is_eth = token == utils::L2_ETH_TOKEN_ADDRESS;
    let token_to_deposit_is_zk_chain_base_token = token == zk_chain_base_token;

    match (
        token_to_deposit_is_eth,
        token_to_deposit_is_zk_chain_base_token,
    ) {
        // Depositing ETH to an ETH based ZKChain.
        (true, true) => {
            deposit_eth_to_eth_based_zk_chain(
                amount,
                from,
                to,
                refund_recipient,
                zk_chain_id,
                l2_provider,
                bridgehub,
            )
            .await
        }
        // Depositing ETH to a ZKChain whose base token is not ETH.
        (true, false) => todo!(),
        // Depositing an ERC20 to a ZKChain whose base token is the same ERC20.
        (false, true) => todo!(),
        // We are depositing an ERC20 to a ZKChain where:
        // 1. ETH is the base token.
        // 2. An ERC20 different than the deposited is the base token.
        (false, false) => {
            let erc20 = ERC20::new(token, Arc::<SignerMiddleware<M, S>>::clone(&from));
            deposit_non_base_erc20_token(
                amount,
                token,
                from,
                to,
                refund_recipient,
                l2_provider,
                bridgehub,
                erc20,
            )
            .await
        }
    }
}

/// Deposit ETH to a ZKChain whose base token is ETH.
pub async fn deposit_eth_to_eth_based_zk_chain<M, S, L2Provider>(
    amount: U256,
    from: Arc<SignerMiddleware<M, S>>,
    to: Address,
    refund_recipient: Address,
    zk_chain_id: U256,
    l2_provider: L2Provider,
    bridgehub: Bridgehub<SignerMiddleware<M, S>>,
) -> ethers::types::TransactionReceipt
where
    M: Middleware,
    S: Signer,
    L2Provider: ZKMiddleware + Middleware,
{
    let from_addr = from.address();

    // The amount of gas required for executing an L2 tx via L1.
    let estimate_l1_to_l2_gas = l2_provider
        .estimate_gas_l1_to_l2(
            Eip712TransactionRequest::new()
                .chain_id(zk_chain_id)
                .from(from_addr)
                .to(to),
        )
        .await
        .unwrap();
    let l2_gas_per_pubdata_byte_limit = U256::from(utils::REQUIRED_L1_TO_L2_GAS_PER_PUBDATA_LIMIT);
    let l2_costs = {
        let operator_tip = U256::zero();
        let base_cost: U256 = bridgehub
            .l_2_transaction_base_cost(
                zk_chain_id,
                from.get_gas_price().await.unwrap(),
                estimate_l1_to_l2_gas,
                l2_gas_per_pubdata_byte_limit,
            )
            .call()
            .await
            .unwrap();
        base_cost + operator_tip + amount
    };

    // There's no need to override l2_calldata for depositing ETH into an
    // ETH based chain.
    //
    // l2_contract and refund_recipient could be overridden in the future.
    // You might want to deposit ETH into a different account or contract,
    // or you might want to refund the deposit to a different account or
    // L1 contract.
    //
    // factory_deps is empty for depositing ETH into an ETH based chain.
    let request = L2TransactionRequestDirect::new()
        .chain_id(zk_chain_id)
        .mint_value(l2_costs)
        .l2_contract(to)
        .l2_value(amount)
        .l2_calldata(vec![])
        .l2_gas_limit(estimate_l1_to_l2_gas)
        .l2_gas_per_pubdata_byte_limit(l2_gas_per_pubdata_byte_limit)
        .factory_deps(vec![])
        .refund_recipient(refund_recipient);

    // NOTE: In ETH deposits, the amount of ETH to be deposited into the
    // ETH based chain should be part of the `value` field of the L1 tx
    // which essentially is the call to the `requestL2TransactionDirect`.
    let overrides = L1TxOverrides::default()
        .from(from_addr)
        .value(l2_costs)
        .gas_price(from.get_gas_price().await.unwrap())
        .gas(estimate_l1_to_l2_gas)
        .nonce(from.get_transaction_count(from_addr, None).await.unwrap());

    deposit_with_l2_transaction_direct_request(bridgehub, request, overrides).await
}

pub async fn deposit_with_l2_transaction_direct_request<M, S>(
    bridgehub: Bridgehub<SignerMiddleware<M, S>>,
    request: L2TransactionRequestDirect,
    overrides: L1TxOverrides,
) -> ethers::types::TransactionReceipt
where
    M: Middleware,
    S: Signer,
{
    bridgehub
        .request_l2_transaction_direct(request)
        .from(overrides.from.unwrap_or_default())
        .value(overrides.value.unwrap_or_default())
        .gas_price(overrides.gas_price.unwrap_or_default())
        .gas(overrides.gas.unwrap_or_default())
        .nonce(overrides.nonce.unwrap_or_default())
        .send()
        .await
        .unwrap()
        .await
        .unwrap()
        .unwrap()
}

/// Deposits ERC20 tokens into a ZKChain where the base token
/// is either ETH or a different ERC20 than the deposited.
pub async fn deposit_non_base_erc20_token<M, S, L2Provider>(
    amount: U256,
    token: Address,
    from: Arc<SignerMiddleware<M, S>>,
    to: Address,
    refund_recipient: Address,
    l2_provider: L2Provider,
    bridgehub: Bridgehub<SignerMiddleware<M, S>>,
    erc20: ERC20<SignerMiddleware<M, S>>,
) -> ethers::types::TransactionReceipt
where
    M: Middleware,
    S: Signer,
    L2Provider: ZKMiddleware + Middleware,
{
    let zk_chain_id = l2_provider.get_chainid().await.unwrap();
    // The amount of gas required for executing an L2 tx via L1.
    let estimate_gas_for_l1_to_l2_tx = l2_provider
        .estimate_gas_l1_to_l2(
            Eip712TransactionRequest::new()
                .chain_id(zk_chain_id)
                .from(from.address())
                .to(to),
        )
        .await
        .unwrap();
    let l2_gas_per_pubdata_byte_limit = U256::from(utils::REQUIRED_L1_TO_L2_GAS_PER_PUBDATA_LIMIT);
    let operator_tip = U256::zero();
    let base_cost = l2_tx_base_cost(
        &bridgehub,
        zk_chain_id,
        from.get_gas_price().await.unwrap(),
        estimate_gas_for_l1_to_l2_tx,
        l2_gas_per_pubdata_byte_limit,
    )
    .await;
    let l2_costs = base_cost + operator_tip;

    let l1_shared_bridge_address: Address = bridgehub.shared_bridge().call().await.unwrap();

    let calldata = ethers::abi::encode(&[token.into_token(), amount.into_token(), to.into_token()]);

    let request: L2TransactionRequestTwoBridgesOuter = L2TransactionRequestTwoBridgesOuter::new()
        .chain_id(zk_chain_id)
        .mint_value(l2_costs)
        .l2_value(U256::zero())
        .l2_gas_limit(estimate_gas_for_l1_to_l2_tx)
        .l2_gas_per_pubdata_byte_limit(l2_gas_per_pubdata_byte_limit)
        .refund_recipient(refund_recipient)
        .second_bridge_address(l1_shared_bridge_address)
        .second_bridge_value(U256::zero())
        .second_bridge_calldata(calldata);

    let allowance: U256 = erc20
        .allowance(from.address(), l1_shared_bridge_address)
        .call()
        .await
        .unwrap();
    // ERC20 approval needs to be done before getting the nonce for the
    // overrides.
    if allowance < amount {
        erc20
            .approve(l1_shared_bridge_address, amount)
            .send()
            .await
            .unwrap()
            .await
            .unwrap()
            .unwrap();
    }

    let nonce = from
        .get_transaction_count(from.address(), None)
        .await
        .unwrap();
    let l1_gas_price = from.get_gas_price().await.unwrap();
    // The value should be overridden in the case where the base token is ETH.
    let value = bridgehub
        .base_token(zk_chain_id)
        .call()
        .await
        .unwrap()
        .eq(&utils::L2_ETH_TOKEN_ADDRESS)
        .then_some(l2_costs)
        .unwrap_or_default();

    let overrides = L1TxOverrides::default()
        .from(from.address())
        .gas_price(l1_gas_price)
        .gas(estimate_gas_for_l1_to_l2_tx)
        .nonce(nonce)
        .value(value);

    deposit_with_l2_transaction_two_bridges_request(bridgehub, request, overrides).await
}

async fn deposit_with_l2_transaction_two_bridges_request<M, S>(
    bridgehub: Bridgehub<SignerMiddleware<M, S>>,
    request: L2TransactionRequestTwoBridgesOuter,
    overrides: L1TxOverrides,
) -> ethers::types::TransactionReceipt
where
    M: Middleware,
    S: Signer,
{
    bridgehub
        .request_l2_transaction_two_bridges(request)
        .from(overrides.from.unwrap_or_default())
        .value(overrides.value.unwrap_or_default())
        .gas_price(overrides.gas_price.unwrap_or_default())
        .gas(overrides.gas.unwrap_or_default())
        .nonce(overrides.nonce.unwrap_or_default())
        .send()
        .await
        .unwrap()
        .await
        .unwrap()
        .unwrap()
}

pub async fn l2_tx_base_cost<M, S>(
    bridgehub: &Bridgehub<SignerMiddleware<M, S>>,
    zk_chain_id: U256,
    l1_gas_price: U256,
    estimate_gas_for_l1_to_l2_tx: U256,
    l2_gas_per_pubdata_byte_limit: U256,
) -> U256
where
    M: Middleware,
    S: Signer,
{
    bridgehub
        .l_2_transaction_base_cost(
            zk_chain_id,
            l1_gas_price,
            estimate_gas_for_l1_to_l2_tx,
            l2_gas_per_pubdata_byte_limit,
        )
        .call()
        .await
        .unwrap()
}

#[cfg(test)]
mod deposit_tests {
    use super::deposit;
    use crate::utils::L2_ETH_TOKEN_ADDRESS;
    use ethers::{
        abi::Address,
        middleware::SignerMiddleware,
        providers::{Http, Middleware, Provider, ProviderExt},
        signers::{LocalWallet, Signer},
        types::U256,
    };
    use std::{str::FromStr, sync::Arc};

    #[tokio::test]
    async fn can_deposit_eth_to_eth_based_zk_chain() {
        let l1_provider = Provider::<Http>::connect("http://eth-sepolia").await;
        let l1_chain_id = l1_provider.get_chainid().await.unwrap().as_u64();
        let from = Arc::new(SignerMiddleware::<Provider<Http>, LocalWallet>::new(
            l1_provider,
            LocalWallet::from_str(
                "0x385c546456b6a603a1cfcaa9ec9494ba4832da08dd6bcf4de9a71e4a01b74924",
            )
            .unwrap()
            .with_chain_id(l1_chain_id),
        ));
        let to = from.address();
        let refund_recipient = from.address();
        let l2_provider =
            Provider::<Http>::connect("https://dev.rpc.sepolia.shyft.lambdaclass.com").await;
        let amount: U256 = ethers::utils::parse_units("0.1", "ether").unwrap().into();

        let receipt = deposit(
            amount,
            L2_ETH_TOKEN_ADDRESS,
            from,
            to,
            refund_recipient,
            l2_provider,
        )
        .await;

        println!(
            "https://sepolia.etherscan.io/tx/{:?}",
            receipt.transaction_hash
        );
    }

    #[tokio::test]
    async fn deposit_erc20_to_eth_based_zk_chain() {
        let l1_provider = Provider::<Http>::connect("http://eth-sepolia").await;
        let l1_chain_id = l1_provider.get_chainid().await.unwrap().as_u64();
        let from = Arc::new(SignerMiddleware::<Provider<Http>, LocalWallet>::new(
            l1_provider,
            LocalWallet::from_str(
                "0x385c546456b6a603a1cfcaa9ec9494ba4832da08dd6bcf4de9a71e4a01b74924",
            )
            .unwrap()
            .with_chain_id(l1_chain_id),
        ));
        let to = from.address();
        let refund_recipient = from.address();
        let l2_provider =
            Provider::<Http>::connect("https://dev.rpc.sepolia.shyft.lambdaclass.com").await;
        let amount: U256 = ethers::utils::parse_units("0.1", "ether").unwrap().into();

        let receipt = deposit(
            amount,
            Address::from_str("0x7209EaD3dfe1c3a517B6b730C00bea1E7f319260").unwrap(),
            from,
            to,
            refund_recipient,
            l2_provider,
        )
        .await;

        println!(
            "https://sepolia.etherscan.io/tx/{:?}",
            receipt.transaction_hash
        );
    }
}
