use crate::cli::ZKSyncWeb3Config;
use crate::zks_utils::ERA_CHAIN_ID;
use crate::ZKSWallet;
use crate::{providers::Provider, signers::Signer};
use clap::Args;
use ethers::abi::Token;
use ethers::signers::LocalWallet;
use ethers::types::Bytes;
use eyre::ContextCompat;

#[derive(Args)]
pub(crate) struct Deploy {
    #[clap(
        long,
        name = "CONTRACT PATH",
        requires = "contract_name",
        conflicts_with = "bytecode"
    )]
    pub contract: Option<String>,
    #[clap(
        long,
        name = "CONTRACT NAME",
        requires = "contract",
        conflicts_with = "bytecode"
    )]
    pub contract_name: Option<String>,
    #[clap(long, num_args(1..), name = "CONSTRUCTOR_ARGS")]
    constructor_args: Vec<String>,
    #[clap(short, long, name = "PRIVATE KEY")]
    pub private_key: LocalWallet,
    #[clap(long, name = "CONTRACT BYTECODE")]
    pub bytecode: Option<Bytes>,
}

pub(crate) async fn run(args: Deploy, config: ZKSyncWeb3Config) -> eyre::Result<()> {
    let era_provider = Provider::try_from(format!(
        "http://{host}:{port}",
        host = config.host,
        port = config.port
    ))?;
    let wallet = args.private_key.with_chain_id(ERA_CHAIN_ID);
    let zk_wallet = ZKSWallet::new(wallet, None, Some(era_provider.clone()), None)?;
    let contract_address = if let Some(bytecode) = args.bytecode {
        zk_wallet
            .deploy_from_bytecode(&bytecode, None, None::<Token>)
            .await?
    } else {
        zk_wallet
            .deploy(
                args.contract.context("no contract path")?,
                &args.contract_name.context("no contract name")?,
                None,
            )
            .await?
    };
    log::info!("{contract_address:#?}");
    Ok(())
}
