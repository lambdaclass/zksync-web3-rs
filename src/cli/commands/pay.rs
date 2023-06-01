use crate::cli::ZKSyncWeb3Config;
use crate::zks_provider::ZKSProvider;
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

use super::L2_CHAIN_ID;

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

pub(crate) async fn run(args: Pay, config: ZKSyncWeb3Config) -> eyre::Result<()> {
    let signer = Wallet::with_chain_id(args.private_key, L2_CHAIN_ID);
    let provider = Provider::try_from(format!(
        "http://{host}:{port}",
        host = config.host,
        port = config.port
    ))?
    .interval(std::time::Duration::from_millis(10));
    let signer_middleware = provider.clone().with_signer(signer);

    let mut payment_request = Eip1559TransactionRequest::new()
        .from(args.from)
        .to(args.to)
        .value(args.amount);

    // Pre-fill transaction
    let fee = provider.estimate_fee(payment_request.clone()).await?;
    payment_request = payment_request.max_priority_fee_per_gas(fee.max_priority_fee_per_gas);
    payment_request = payment_request.max_fee_per_gas(fee.max_fee_per_gas);

    let mut transaction: TypedTransaction = payment_request.into();
    provider.fill_transaction(&mut transaction, None).await?;
    log::debug!("Transaction request: {:?}", transaction);

    log::debug!(
        "Sender's balance before paying: {:?}",
        provider.get_balance(args.from, None).await?
    );
    log::debug!(
        "Receiver's balance before getting payed: {:?}",
        provider.get_balance(args.to, None).await?
    );

    let payment_response: TransactionReceipt =
        SignerMiddleware::send_transaction(&signer_middleware, transaction, None)
            .await?
            .await?
            .context("No pending transaction")?;

    log::info!("{:#?}", payment_response.transaction_hash);

    log::debug!(
        "Sender's balance after paying: {:?}",
        provider.get_balance(args.from, None).await?
    );
    log::debug!(
        "Receiver's balance after getting payed: {:?}",
        provider.get_balance(args.to, None).await?
    );
    Ok(())
}
