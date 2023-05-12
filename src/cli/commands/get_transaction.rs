use clap::Args;
use ethers::{
    providers::{Middleware, Provider},
    types::H256,
};

use crate::cli::ZKSyncWeb3Config;

#[derive(Args)]
pub(crate) struct GetTransaction {
    #[clap(short, long, name = "TRANSACTION_HASH")]
    pub transaction: H256,
}

pub(crate) async fn run(args: GetTransaction, config: ZKSyncWeb3Config) {
    let provider = Provider::try_from(format!(
        "http://{host}:{port}",
        host = config.host,
        port = config.port
    ))
    .unwrap()
    .interval(std::time::Duration::from_millis(10));
    let transaction = provider
        .get_transaction(args.transaction)
        .await
        .unwrap()
        .unwrap();
    log::info!("{:#?}", transaction);
}
