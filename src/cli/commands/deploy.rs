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

pub(crate) async fn run(args: Deploy, config: ZKSyncWeb3Config) {
    let paths = ProjectPathsConfig::builder().build_with_root(args.contract);
    let project = Project::builder()
        .paths(paths)
        .set_auto_detect(true)
        .no_artifacts()
        .build()
        .unwrap();
    let compilation_output = project.compile().unwrap();
    let contract = compilation_output.find_first("Counter").unwrap().clone();
    let (abi, bytecode, _) = contract.into_parts();
    let mut wallet = args.private_key.parse::<Wallet<SigningKey>>().unwrap();
    wallet = Wallet::with_chain_id(wallet, CHAIN_ID);
    let provider = Provider::try_from(format!(
        "http://{host}:{port}",
        host = config.host,
        port = config.port
    ))
    .unwrap()
    .interval(std::time::Duration::from_millis(10));
    let client = Arc::new(SignerMiddleware::new(provider, wallet));
    let factory = ContractFactory::new(abi.unwrap(), bytecode.unwrap(), client);
    let deployer = factory.deploy(()).unwrap();
    let (deployed_contract, _transaction_receipt) =
        deployer.clone().send_with_receipt().await.unwrap();
    log::info!("{:#?}", deployed_contract.address());
}
