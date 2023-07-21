use clap::Parser;
use ethers::{
    abi::Address,
    prelude::k256::ecdsa::SigningKey,
    providers::{Middleware, Provider},
    signers::{Signer, Wallet},
    types::{TransactionReceipt, U256},
};
use zksync_web3_rs::ZKSWallet;

// It is set so that the transaction is replay-protected (EIP-155)
// https://era.zksync.io/docs/api/hardhat/testing.html#connect-wallet-to-local-nodes
//const L1_CHAIN_ID: u64 = 9;
const L2_CHAIN_ID: u64 = 270;

#[derive(Parser)]
struct Args {
    #[clap(long)]
    pub host: String,
    #[clap(short, long)]
    pub port: u16,
    #[clap(long, name = "AMOUNT_TO_TRANSFER")]
    pub amount: String,
    #[clap(long, name = "SENDER_ADDRESS")]
    pub from: Address,
    #[clap(long, name = "RECEIVER_ADDRESS")]
    pub to: Address,
    #[clap(long, name = "SENDER_PRIVATE_KEY")]
    pub private_key: Wallet<SigningKey>,
}

#[tokio::main]
async fn main() {
    env_logger::builder()
        .filter_module("reqwest::connect", log::LevelFilter::Off)
        .filter_level(log::LevelFilter::Debug)
        .init();

    let args = Args::parse();

    /* Connecting to the node */
    let amount = U256::from_dec_str(&args.amount).unwrap();
    log::debug!("Amount to transfer: {:?}", amount);
    let signer = Wallet::with_chain_id(args.private_key, L2_CHAIN_ID);

    let provider = Provider::try_from(format!(
        "http://{host}:{port}",
        host = args.host,
        port = args.port
    ))
    .unwrap()
    .interval(std::time::Duration::from_millis(10));

    let zk_wallet = ZKSWallet::new(signer, None, Some(provider.clone()), None).unwrap();

    /* Sending the payment transaction */

    log::debug!(
        "Sender's balance before paying: {:?}",
        provider.clone().get_balance(args.from, None).await.unwrap()
    );
    log::debug!(
        "Receiver's balance before getting payed: {:?}",
        provider.get_balance(args.to, None).await.unwrap()
    );

    let pending_payment_transaction = zk_wallet.transfer(args.to, amount, None).await.unwrap();

    /* Waiting for the payment transaction */
    let payment_response: TransactionReceipt = pending_payment_transaction.await.unwrap().unwrap();
    log::info!("{:?}", payment_response);

    log::debug!(
        "Sender's balance after paying: {:?}",
        provider.get_balance(args.from, None).await.unwrap()
    );
    log::debug!(
        "Receiver's balance after getting payed: {:?}",
        provider.get_balance(args.to, None).await.unwrap()
    );
}
