use crate::cli::ZKSyncWeb3Config;
use crate::{
    providers::{Middleware, Provider},
    types::Address,
};
use clap::Args;

#[derive(Args)]
pub(crate) struct AccountBalance {
    #[clap(short, long, name = "ACCOUNT_ADDRESS")]
    pub account: Address,
}

pub(crate) async fn run(args: AccountBalance, config: ZKSyncWeb3Config) {
    let provider = Provider::try_from(format!(
        "http://{host}:{port}",
        host = config.host,
        port = config.port
    ))
    .unwrap()
    .interval(std::time::Duration::from_millis(10));
    let balance = provider.get_balance(args.account, None).await.unwrap();
    log::info!("{:#?}", balance);
}
