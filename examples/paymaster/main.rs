use ethers::abi::Bytes;
use ethers::core::k256::ecdsa::SigningKey;
use ethers::prelude::*;
use ethers::providers::Http;
use ethers::{
    abi::Address,
    providers::Provider,
    signers::{Signer, Wallet},
    types::U256,
};
use std::str::FromStr;
use std::sync::Arc;
use zksync_web3_rs::core::abi::{Contract, Token};
use zksync_web3_rs::eip712::{Eip712Meta, Eip712TransactionRequest, PaymasterParams};
use zksync_web3_rs::ZKSWallet;
use zksync_web3_rs::zks_provider::ZKSProvider;

static ERA_PROVIDER_URL: &str = "http://127.0.0.1:3050";
static PK: &str = "0x27593fea79697e947890ecbecce7901b0008345e5d7259710d0dd5e500d040be";
static PAYMASTER_ADDRESS: &str = "";

const PAYMASTER_ABI: &str = r#"
    [
      {
        "inputs": [
          {
            "internalType": "bytes",
            "name": "input",
            "type": "bytes"
          }
        ],
        "name": "general",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
      }
    ]
    "#;

pub struct PaymasterFlow {
    paymaster: Address,
    amount: U256,
    paymaster_encoded_input: Bytes,
    zk_wallet: ZKSWallet<Provider<Http>, SigningKey>,
    era_provider: Arc<SignerMiddleware<Provider<Http>, Wallet<SigningKey>>>,
}

impl PaymasterFlow {
    pub fn new(private_key: String,
           paymaster_address: H160,
           chain_id: u64,
           provider:Provider<Http>) -> Self {
        let paymaster_contract = Contract::load(PAYMASTER_ABI.as_bytes()).expect("Failed to load the paymaster ABI");
        let paymaster_general_fn = paymaster_contract.function("general").expect("Failed to get the general function");
        let wallet = Wallet::from_str(private_key.as_str()).expect("Failed to create wallet from private key");
        let signer = Wallet::with_chain_id(wallet, chain_id);
        let zk_wallet = ZKSWallet::new(signer, None, Some(provider.clone()), None).unwrap();
        let era_provider = zk_wallet.get_era_provider().expect("Failed to get era provider from zk wallet");
        let paymaster_encoded_input = paymaster_general_fn.encode_input(&[Token::Bytes(vec![])]).expect("Failed to encode paymaster input");
        
        Self {
            paymaster: paymaster_address,
            amount: U256::from_dec_str("1").expect("Failed to parse amount"),
            paymaster_encoded_input,
            zk_wallet,
            era_provider
        }
    }

    fn tx_request(&self) -> Eip712TransactionRequest {
        let address = self.zk_wallet.l1_wallet.address();
        Eip712TransactionRequest::new()
            .from(address)
            .to(address)
            .value(self.amount)
            .custom_data(Eip712Meta::new().paymaster_params(PaymasterParams {
                paymaster: self.paymaster,
                paymaster_input: self.paymaster_encoded_input.clone()
            }))
    }

    async fn send_transaction(&self) -> anyhow::Result<PendingTransaction<Http>> {
        let result = self.era_provider
            .send_transaction_eip712(&self.zk_wallet.l2_wallet, self.tx_request())
            .await?;
        Ok(result)
    }
}

#[tokio::main]
async fn main() {
    let era_provider = Provider::try_from(ERA_PROVIDER_URL).unwrap();
    let paymaster_address = Address::from_str(PAYMASTER_ADDRESS).unwrap();
    let chain_id = era_provider.get_chainid().await.unwrap();
    let flow = PaymasterFlow::new(PK.to_string(), paymaster_address, chain_id.as_u64(), era_provider.clone());
    let tx = flow.send_transaction().await.unwrap().await.unwrap().unwrap();
    println!("Transaction sent: {:#?}", tx);
}
