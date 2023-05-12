use crate::cli::{commands::CHAIN_ID, ZKSyncWeb3Config};
use crate::{
    prelude::{k256::ecdsa::SigningKey, ContractFactory, SignerMiddleware},
    providers::Provider,
    signers::Signer,
    signers::Wallet,
    solc::{Artifact, Project, ProjectPathsConfig},
};
use clap::Args;
use eyre::ContextCompat;
use std::{path::PathBuf, sync::Arc};

#[derive(Args)]
pub(crate) struct Deploy {
    #[clap(short, long, name = "CONTRACT PATH")]
    pub contract: PathBuf,
    #[clap(short, long, name = "PRIVATE KEY")]
    pub private_key: String,
}

pub(crate) async fn run(args: Deploy, config: ZKSyncWeb3Config) -> eyre::Result<()> {
    let paths = ProjectPathsConfig::builder().build_with_root(args.contract);
    let project = Project::builder()
        .paths(paths)
        .set_auto_detect(true)
        .no_artifacts()
        .build()?;
    let compilation_output = project.compile()?;
    let contract = compilation_output
        .find_first("Counter")
        .context("contract not found")?
        .clone();
    let (abi, bytecode, _) = contract.into_parts();
    let mut wallet = args.private_key.parse::<Wallet<SigningKey>>()?;
    wallet = Wallet::with_chain_id(wallet, CHAIN_ID);
    let provider = Provider::try_from(format!(
        "http://{host}:{port}",
        host = config.host,
        port = config.port
    ))?
    .interval(std::time::Duration::from_millis(10));
    let client = Arc::new(SignerMiddleware::new(provider, wallet));
    let factory = ContractFactory::new(
        abi.context("contract has no abi")?,
        bytecode.context("contract has no bytecode")?,
        client,
    );
    let deployer = factory.deploy(())?;
    let (deployed_contract, _transaction_receipt) = deployer.clone().send_with_receipt().await?;
    log::info!("{:#?}", deployed_contract.address());
    Ok(())
}
