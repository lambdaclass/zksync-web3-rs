use ethers::abi::Abi;
use std::str::FromStr;
use zksync_web3_rs::providers::{Middleware, Provider};
use zksync_web3_rs::signers::{LocalWallet, Signer};
use zksync_web3_rs::zks_provider::ZKSProvider;
use zksync_web3_rs::zks_wallet::{CallRequest, DeployRequest};
use zksync_web3_rs::ZKSWallet;

// This is the default url for a local `era-test-node` instance.
static ERA_PROVIDER_URL: &str = "http://127.0.0.1:8011";

// This is the private key for one of the rich wallets that come bundled with the era-test-node.
static PRIVATE_KEY: &str = "7726827caac94a7f9e1b160f7ea819f172f7b6f9d2a97f992c38edeab82d4110";

static CONTRACT_BIN: &str = include_str!("./Greeter.bin");
static CONTRACT_ABI: &str = include_str!("./Greeter.abi");

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // Note that for this code example we only need to interface with zkSync Era. We don't care
    // about the Ethereum layer-1 network.
    let zk_wallet = {
        let era_provider = Provider::try_from(ERA_PROVIDER_URL).unwrap();

        let chain_id = era_provider.get_chainid().await.unwrap();
        let l2_wallet = LocalWallet::from_str(PRIVATE_KEY)
            .unwrap()
            .with_chain_id(chain_id.as_u64());
        ZKSWallet::new(l2_wallet, None, Some(era_provider.clone()), None).unwrap()
    };

    // Deploy contract:
    let contract_address = {
        let abi = Abi::load(CONTRACT_ABI.as_bytes()).unwrap();
        let contract_bin = hex::decode(CONTRACT_BIN).unwrap().to_vec();
        let request = DeployRequest::with(abi, contract_bin, vec!["Hey".to_owned()])
            .from(zk_wallet.l2_address());
        let address = zk_wallet.deploy(&request).await.unwrap();

        println!("Contract address: {:#?}", address);

        address
    };

    // Call the greet view method:
    {
        let era_provider = zk_wallet.get_era_provider().unwrap();
        let call_request = CallRequest::new(contract_address, "greet()(string)".to_owned());

        let greet = ZKSProvider::call(era_provider.as_ref(), &call_request)
            .await
            .unwrap();

        println!("greet: {}", greet[0]);
    }

    // Perform a signed transaction calling the setGreeting method
    {
        let receipt = zk_wallet
            .get_era_provider()
            .unwrap()
            .clone()
            .send_eip712(
                &zk_wallet.l2_wallet,
                contract_address,
                "setGreeting(string)",
                Some(["Hello".into()].into()),
                None,
            )
            .await
            .unwrap()
            .await
            .unwrap()
            .unwrap();

        println!(
            "setGreeting transaction hash {:#?}",
            receipt.transaction_hash
        );
    };

    // Call the greet view method:

    {
        let era_provider = zk_wallet.get_era_provider().unwrap();
        let call_request = CallRequest::new(contract_address, "greet()(string)".to_owned());

        let greet = ZKSProvider::call(era_provider.as_ref(), &call_request)
            .await
            .unwrap();

        println!("greet: {}", greet[0]);
    }
}
