use crate::cli::ZKSyncWeb3Config;
use crate::zks_provider::ZKSProvider;
use crate::{providers::Provider, types::Address};
use clap::Args;
use ethers::signers::LocalWallet;

// TODO: Optional parameters were omitted, they should be added in the future.
#[derive(Args)]
pub(crate) struct Call {
    #[clap(short, long, name = "CONTRACT_ADDRESS")]
    pub contract: Address,
    #[clap(short, long, name = "FUNCTION_SIGNATURE")]
    pub function: String,
    #[clap(short, long, num_args(1..), name = "FUNCTION_ARGS")]
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

    // Note: CLI syntactic sugar need to be handle in the run() function.
    // If more sugar cases are needed, we should switch to a match statement.
    let function_signature = if args.function.is_empty() {
        "function()"
    } else {
        &args.function
    };

    // TODO: Figure out how to parse the args correctly.
    let output = ZKSProvider::call(&provider, args.contract, function_signature, args.args).await?;
    log::info!("{output:?}");
    Ok(())
}
