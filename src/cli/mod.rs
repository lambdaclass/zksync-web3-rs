pub(crate) mod commands;
use clap::{command, Args, Parser, Subcommand};
use commands::{
    account_balance, call, compile, deploy, get_contract, get_transaction, pay, AccountBalance,
    Call, CompileArgs, Deploy, GetContract, GetTransaction, Pay,
};

pub const VERSION_STRING: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(name="zksync-web3-cli", author, version=VERSION_STRING, about, long_about = None)]
struct ZKSyncWeb3 {
    #[command(subcommand)]
    command: ZKSyncWeb3Command,
    #[clap(flatten)]
    config: ZKSyncWeb3Config,
}

#[derive(Args)]
pub struct ZKSyncWeb3Config {
    #[clap(long, default_value = "65.108.204.116")]
    pub host: String,
    #[clap(short, long, default_value = "8545")]
    pub port: u16,
}

#[derive(Subcommand)]
enum ZKSyncWeb3Command {
    Deploy(Deploy),
    Call(Call),
    GetContract(GetContract),
    GetTransaction(GetTransaction),
    Balance(AccountBalance),
    Pay(Pay),
    Compile(CompileArgs),
}

pub async fn start() -> eyre::Result<()> {
    let ZKSyncWeb3 { command, config } = ZKSyncWeb3::parse();
    match command {
        ZKSyncWeb3Command::Deploy(args) => deploy::run(args, config).await?,
        ZKSyncWeb3Command::Call(args) => call::run(args, config).await?,
        ZKSyncWeb3Command::GetContract(args) => get_contract::run(args, config).await?,
        ZKSyncWeb3Command::GetTransaction(args) => get_transaction::run(args, config).await?,
        ZKSyncWeb3Command::Balance(args) => account_balance::run(args, config).await?,
        ZKSyncWeb3Command::Pay(args) => pay::run(args, config).await?,
        ZKSyncWeb3Command::Compile(args) => {
            let _ = compile::run(args)?;
        }
    };

    Ok(())
}
