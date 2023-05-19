use clap::Parser;
use ethers::{
    abi::Address,
    middleware::SignerMiddleware,
    prelude::{k256::ecdsa::SigningKey, MiddlewareBuilder},
    providers::{Middleware, Provider},
    signers::{Signer, Wallet},
    types::{
        transaction::eip2718::TypedTransaction, Eip1559TransactionRequest, TransactionReceipt, U256,
    },
};
use zksync_web3_rs::zks_provider::ZKSProvider;

// It is set so that the transaction is replay-protected (EIP-155)
// https://era.zksync.io/docs/api/hardhat/testing.html#connect-wallet-to-local-nodes
const L1_CHAIN_ID: u64 = 9;
const L2_CHAIN_ID: u64 = 270;

#[derive(Parser)]
struct Args {
    #[clap(long)]
    pub host: String,
    #[clap(short, long)]
    pub port: u16,
    #[clap(long, name = "AMOUNT_TO_TRANSFER")]
    pub amount: U256,
    #[clap(long, name = "SENDER_ADDRESS")]
    pub from: Address,
    #[clap(long, name = "RECEIVER_ADDRESS")]
    pub to: Address,
    #[clap(long, name = "SENDER_PRIVATE_KEY")]
    pub private_key: Wallet<SigningKey>,
    #[clap(long, name = "NETWORK_NAME", help = "Available networks: \"era\" or \"eth\"")]
    pub network: String,
}

#[tokio::main]
async fn main() {
    env_logger::builder()
        .filter_module("reqwest::connect", log::LevelFilter::Off)
        .filter_level(log::LevelFilter::Debug)
        .init();

    let args = Args::parse();

    /* Connecting to the node */

    let signer = Wallet::with_chain_id(
        args.private_key,
        if args.network == "eth" {
            L1_CHAIN_ID
        } else {
            L2_CHAIN_ID
        },
    );
    let provider = Provider::try_from(format!(
        "http://{host}:{port}",
        host = args.host,
        port = args.port
    ))
    .unwrap()
    .interval(std::time::Duration::from_millis(10));
    let signer_middleware = provider.clone().with_signer(signer);

    /* Payment transaction building */

    let mut payment_request = Eip1559TransactionRequest::new()
        .from(args.from)
        .to(args.to)
        .value(args.amount);

    if args.network == "era" {
        let fee = provider
            .estimate_fee(payment_request.clone())
            .await
            .unwrap();
        payment_request = payment_request.max_priority_fee_per_gas(fee.max_priority_fee_per_gas);
        payment_request = payment_request.max_fee_per_gas(fee.max_fee_per_gas);
    }

    let transaction: TypedTransaction = payment_request.into();

    log::debug!("{:?}", transaction);

    /* Sending the payment transaction */

    log::debug!(
        "Sender's balance before paying: {:?}",
        provider.get_balance(args.from, None).await.unwrap()
    );
    log::debug!(
        "Receiver's balance before getting payed: {:?}",
        provider.get_balance(args.to, None).await.unwrap()
    );

    let payment_response: TransactionReceipt =
        SignerMiddleware::send_transaction(&signer_middleware, transaction, None)
            .await
            .unwrap()
            .await
            .unwrap()
            .unwrap();
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
