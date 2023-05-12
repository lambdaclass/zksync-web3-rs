use crate::cli::ZKSyncWeb3Config;
use crate::{
    prelude::{k256::ecdsa::SigningKey, MiddlewareBuilder, SignerMiddleware},
    providers::{Middleware, Provider},
    signers::{Signer, Wallet},
    types::{
        transaction::eip2718::TypedTransaction, Address, Eip1559TransactionRequest,
        TransactionReceipt, U256,
    },
};
use clap::Args;
use eyre::ContextCompat;

use super::CHAIN_ID;

#[derive(Args)]
pub(crate) struct Pay {
    #[clap(short, long, default_value = "0", name = "AMOUNT_TO_TRANSFER")]
    pub amount: U256,
    #[clap(short, long, name = "SENDER_ADDRESS")]
    pub from: Address,
    #[clap(short, long, name = "RECEIVER_ADDRESS")]
    pub to: Address,
    #[clap(short, long, name = "SENDER_PRIVATE_KEY")]
    pub private_key: Wallet<SigningKey>,
}

pub(crate) async fn run(args: Pay, config: ZKSyncWeb3Config) {
    let signer = Wallet::with_chain_id(args.private_key, CHAIN_ID);
    let provider = Provider::try_from(format!(
        "http://{host}:{port}",
        host = config.host,
        port = config.port
    ))
    .unwrap()
    .interval(std::time::Duration::from_millis(10))
    .with_signer(signer);

    let payment_request = Eip1559TransactionRequest::new()
        .from(args.from)
        .to(args.to)
        .value(args.amount);
    let mut transaction: TypedTransaction = payment_request.into();
    provider
        .fill_transaction(&mut transaction, None)
        .await
        .unwrap();

    let payment_response: TransactionReceipt =
        SignerMiddleware::send_transaction(&provider, transaction, None)
            .await
            .unwrap()
            .await
            .unwrap()
            .unwrap();
    log::info!("{:?}", payment_response);
}
