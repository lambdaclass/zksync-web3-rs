use crate::ZKSWallet;
use crate::cli::ZKSyncWeb3Config;
use crate::zks_utils::ERA_CHAIN_ID;
use crate::{
    providers::Provider,
    signers::Signer,
    types::Address,
};
use clap::Args;
use ethers::signers::LocalWallet;

// TODO: Optional parameters were omitted, they should be added in the future.
#[derive(Args)]
pub(crate) struct Call {
    #[clap(short, long, name = "CONTRACT_ADDRESS")]
    pub contract: Address,
    #[clap(short, long, name = "FUNCTION_SIGNATURE")]
    pub function: String,
    #[clap(short, long, name = "FUNCTION_ARGS")]
    pub args: Option<Vec<String>>,
    #[clap(short, long, name = "PRIVATE_KEY")]
    pub private_key: LocalWallet,
}

pub(crate) async fn run(args: Call, config: ZKSyncWeb3Config) -> eyre::Result<()> {
    let provider = Provider::try_from(format!(
        "http://{host}:{port}",
        host = config.host,
        port = config.port
    ))?;
    let wallet = args.private_key.with_chain_id(ERA_CHAIN_ID);
    let zk_wallet = ZKSWallet::new(wallet, Some(provider.clone()), None)?;

    // TODO: Figure out how to parse the args correctly.
    let output = zk_wallet
        .call(args.contract, &args.function, args.args)
        .await
        .unwrap();
    println!("{output:?}");
    Ok(())
}
