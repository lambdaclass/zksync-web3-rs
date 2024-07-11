// FIXME: Remove this after finishing the implementation.
#![allow(clippy::unwrap_used)]

use ethers::{
    abi::{Hash, ParamType, Token},
    middleware::SignerMiddleware,
    providers::{Http, Middleware, Provider, ProviderExt},
    signers::{LocalWallet, Signer},
    types::{Bytes, U256},
};
use std::{str::FromStr, sync::Arc};
use zksync_types::{api::L2ToL1Log, L1_MESSENGER_ADDRESS};

use crate::{
    contracts::{bridgehub::Bridgehub, l1_shared_bridge::L1SharedBridge},
    ZKMiddleware,
};

pub async fn wait_for_finalize_withdrawal<L2Provider>(
    l2_withdrawal_tx_hash: Hash,
    l2_provider: &L2Provider,
) where
    L2Provider: ZKMiddleware + Middleware,
{
    loop {
        if l2_provider
            .get_transaction_details(l2_withdrawal_tx_hash)
            .await
            .unwrap()
            .unwrap()
            .eth_execute_tx_hash
            .is_some()
        {
            break;
        }
        println!("Withdraw request not executed on L1 yet. Retrying in 5 seconds...");
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

pub async fn finalize_withdrawal(l2_withdrawal_tx_hash: Hash) -> Hash {
    let l1_provider = Provider::<Http>::connect("http://eth-sepolia").await;
    let l1_chain_id = l1_provider.get_chainid().await.unwrap().as_u64();
    let to = Arc::new(SignerMiddleware::<Provider<Http>, LocalWallet>::new(
        l1_provider,
        LocalWallet::from_str("0x385c546456b6a603a1cfcaa9ec9494ba4832da08dd6bcf4de9a71e4a01b74924")
            .unwrap()
            .with_chain_id(l1_chain_id),
    ));

    let l2_provider =
        Provider::<Http>::connect("https://dev.rpc.sepolia.shyft.lambdaclass.com").await;

    let bridgehub_address = l2_provider.get_bridgehub_contract().await.unwrap();
    let bridgehub = Bridgehub::new(bridgehub_address, Arc::clone(&to));
    let l1_shared_bridge_address = bridgehub.shared_bridge().call().await.unwrap();
    let l1_shared_bridge = L1SharedBridge::new(l1_shared_bridge_address, Arc::clone(&to));

    // This is an L2 transaction hash.
    let withdrawal_tx_receipt = l2_provider
        .get_transaction_receipt(l2_withdrawal_tx_hash)
        .await
        .unwrap()
        .unwrap();
    let zk_chain_id = l2_provider.get_chainid().await.unwrap().as_u64();
    let withdrawal_log = withdrawal_tx_receipt
        .logs
        .iter()
        .filter(|log| {
            log.address == L1_MESSENGER_ADDRESS
                && log.topics[0]
                    == ethers::utils::keccak256("L1MessageSent(address,bytes32,bytes)").into()
        })
        .collect::<Vec<_>>()[0];
    let l2_tx_number_in_batch: u16 = U256::from_str(
        &serde_json::from_value::<String>(
            withdrawal_tx_receipt
                .other
                .get("l1BatchTxIndex")
                .unwrap()
                .clone(),
        )
        .unwrap(),
    )
    .unwrap()
    .as_u64()
    .try_into()
    .unwrap();
    let l2_to_l1_logs = withdrawal_tx_receipt
        .other
        .get_deserialized::<Vec<L2ToL1Log>>("l2ToL1Logs")
        .unwrap()
        .unwrap();
    let withdraw_l2_to_l1_logs = l2_to_l1_logs
        .into_iter()
        .filter(|log| log.sender == L1_MESSENGER_ADDRESS)
        .collect::<Vec<_>>();
    let l1_messenger_l2_to_l1_log_index = withdraw_l2_to_l1_logs
        .first()
        .map(|log| &log.log_index)
        .map(U256::as_u64);

    let message = Bytes::from(
        ethers::abi::decode(&[ParamType::Bytes], &withdrawal_log.data)
            .unwrap()
            .first()
            .cloned()
            .map(Token::into_bytes)
            .unwrap()
            .unwrap(),
    );
    let proof = l2_provider
        .get_l2_to_l1_log_proof(l2_withdrawal_tx_hash, l1_messenger_l2_to_l1_log_index)
        .await
        .unwrap()
        .unwrap()
        .proof
        .into_iter()
        .map(Into::into)
        .collect::<Vec<_>>();
    let l2_batch_number = withdraw_l2_to_l1_logs
        .first()
        .map(|log| log.l1_batch_number)
        .unwrap()
        .unwrap();

    let finalize_withdrawal_tx_receipt = l1_shared_bridge
        .finalize_withdrawal(
            zk_chain_id.into(),
            l2_batch_number.as_u64().into(),
            U256::zero(),
            l2_tx_number_in_batch,
            message,
            proof,
        )
        .send()
        .await
        .inspect_err(|err| {
            if let Some(revert) = err.as_revert() {
                println!("{:?}", ethers::abi::decode(&[ParamType::String], revert))
            }
        })
        .unwrap()
        .await
        .unwrap()
        .unwrap();

    finalize_withdrawal_tx_receipt.transaction_hash
}

#[cfg(test)]
mod withdraw_tests {
    use crate::{
        contracts::l2_eth::BaseToken,
        withdraw::{finalize_withdrawal, wait_for_finalize_withdrawal},
    };
    use ethers::{
        abi::Hash,
        middleware::SignerMiddleware,
        providers::{Http, Middleware, Provider, ProviderExt},
        signers::{LocalWallet, Signer},
        types::U256,
    };
    use std::{str::FromStr, sync::Arc};
    use zksync_types::L2_BASE_TOKEN_ADDRESS;

    #[tokio::test]
    async fn can_withdraw_eth_from_eth_based_chain() {
        let l2_provider =
            Provider::<Http>::connect("https://dev.rpc.sepolia.shyft.lambdaclass.com").await;
        let zk_chain_id = l2_provider.get_chainid().await.unwrap().as_u64();
        let from = Arc::new(SignerMiddleware::<Provider<Http>, LocalWallet>::new(
            l2_provider,
            LocalWallet::from_str(
                "0x385c546456b6a603a1cfcaa9ec9494ba4832da08dd6bcf4de9a71e4a01b74924",
            )
            .unwrap()
            .with_chain_id(zk_chain_id),
        ));
        let amount: U256 = ethers::utils::parse_units("0.01", "ether").unwrap().into();

        let withdrawal_tx_receipt = BaseToken::new(L2_BASE_TOKEN_ADDRESS, Arc::clone(&from))
            .withdraw(from.address())
            .value(amount)
            .send()
            .await
            .unwrap()
            .await
            .unwrap()
            .unwrap();

        let withdrawal_tx_hash = withdrawal_tx_receipt.transaction_hash;

        println!("https://dev.explorer.sepolia.shyft.lambdaclass.com/tx/{withdrawal_tx_hash:?}");

        wait_for_finalize_withdrawal(withdrawal_tx_hash, from.provider()).await;

        let finalize_withdrawal_l1_tx_hash = finalize_withdrawal(withdrawal_tx_hash).await;

        println!("https://sepolia.etherscan.io/tx/{finalize_withdrawal_l1_tx_hash:?}",);
    }
}
