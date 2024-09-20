use std::{fs::File, path::PathBuf};

use common::{l1_signer, l2_signer, CompiledContract};
use ethers::utils::parse_ether;
use zksync_ethers_rs::{
    eip712::{DeployRequest, Eip712TransactionRequest},
    zk_wallet::ZKWallet,
};
mod common;

#[tokio::test]
async fn test_deploy() {
    let zk_wallet = ZKWallet::new(l1_signer().await, l2_signer().await);
    zk_wallet
        .deposit_base_token(parse_ether("10").unwrap())
        .await
        .unwrap();
    let mut contract_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    contract_path.push("abi/test_contracts/storage_combined.json");
    let contract: CompiledContract =
        serde_json::from_reader(File::open(contract_path).unwrap()).unwrap();
    let deploy_request =
        DeployRequest::with(contract.abi, contract.bin.to_vec(), vec!["10".to_owned()])
            .from(zk_wallet.l2_address());
    let tx_request: Eip712TransactionRequest = deploy_request.clone().try_into().unwrap();
    let tx_result = zk_wallet.send_transaction_eip712(tx_request).await;
    assert!(tx_result.is_ok());
}
