use crate::cli::ZKSyncWeb3Config;
use crate::{
    providers::{Middleware, Provider},
    types::H256,
};
use clap::Args;
use eyre::ContextCompat;

#[derive(Args)]
pub(crate) struct GetTransaction {
    #[clap(short, long, name = "TRANSACTION_HASH")]
    pub transaction: H256,
}

pub(crate) async fn run(args: GetTransaction, config: ZKSyncWeb3Config) -> eyre::Result<()> {
    let provider = Provider::try_from(format!(
        "http://{host}:{port}",
        host = config.host,
        port = config.port
    ))?
    .interval(std::time::Duration::from_millis(10));
    let transaction = provider
        .get_transaction(args.transaction)
        .await?
        .context("No pending transaction")?;
    log::info!("{:#?}", transaction);
    Ok(())
}
