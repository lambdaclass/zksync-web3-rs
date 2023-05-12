use crate::cli::ZKSyncWeb3Config;
use crate::{
    providers::{Middleware, Provider},
    types::Address,
};
use clap::Args;

#[derive(Args)]
pub(crate) struct GetContract {
    #[clap(short, long, name = "CONTRACT_ADDRESS")]
    pub contract: String,
}

pub(crate) async fn run(args: GetContract, config: ZKSyncWeb3Config) {
    let provider = Provider::try_from(format!(
        "http://{host}:{port}",
        host = config.host,
        port = config.port
    ))
    .unwrap()
    .interval(std::time::Duration::from_millis(10));
    let contract = provider
        .get_code(args.contract.parse::<Address>().unwrap(), None)
        .await
        .unwrap();
    log::info!("{:#?}", contract);
}
