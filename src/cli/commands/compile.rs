use crate::compile::{constants, output::ZKSCompilationOutput, zksolc_manager::{ZkSolcManager, ZkSolcManagerBuilder, ZkSolcManagerOpts}, zksolc::{ZkSolcOpts, ZkSolc}, ZKCompile};
use clap::Parser;
use ethers_solc::{Project, ProjectPathsConfig};
use std::path::PathBuf;

#[derive(Parser)]
pub struct CompileArgs {
    // TODO: Handle this like Foundry does.
    #[clap(long, num_args(1..), name = "CONTRACT_PATH")]
    pub contract_paths: Vec<PathBuf>,
    #[clap(long, name = "PATH_TO_SOLC")]
    pub solc: Option<PathBuf>,
    #[clap(long, name = "COMBINED_JSON")]
    pub combined_json: Option<String>,
    #[clap(long, action)]
    pub standard_json: bool,
}

pub(crate) fn run(args: CompileArgs) -> eyre::Result<ZKSCompilationOutput> {
    let mut command = &mut std::process::Command::new(constants::ZK_SOLC_PATH);
    // if let Some(solc) = args.solc {
    //     command = command.arg("--solc").arg(solc);
    // } else if let Ok(solc) = std::env::var("SOLC_PATH") {
    //     command = command.arg("--solc").arg(solc);
    // } else {
    //     eyre::bail!("no solc path provided");
    // }

    // const VALID_COMBINED_JSON_ARGS: [&str; 10] = [
    //     "abi",
    //     "hashes",
    //     "metadata",
    //     "devdoc",
    //     "userdoc",
    //     "storage-layout",
    //     "ast",
    //     "asm",
    //     "bin",
    //     "bin-runtime",
    // ];

    // if let Some(combined_json_arg) = args.combined_json {
    //     let valid_args = combined_json_arg
    //         .split(',')
    //         .all(|arg| VALID_COMBINED_JSON_ARGS.contains(&arg));
    //     if !valid_args {
    //         eyre::bail!("Invalid combined-json argument: {combined_json_arg}");
    //     }
    //     command = command.arg("--combined-json").arg(combined_json_arg);
    // }

    // if args.standard_json {
    //     command = command.arg("--standard-json");
    // }

    // command = command.arg("--").args(args.contract_paths);

    let root = PathBuf::from("./");
    // let path = args.contract_paths.get(0).unwrap().clone();
    // root.push::<PathBuf>(path);
    let zk_project = 
        Project::builder()
            .paths(ProjectPathsConfig::builder().build_with_root(root))
            .set_auto_detect(true)
            .build()?;

    let zk_compile = ZKCompile {};
    let output = zk_compile.run(zk_project)?;

    // dbg!(&zk_project.base_project);


    // log::info!("Res: {res:?}");

    // let output = res?;

    // let command_output = command.output()?;
 
    // let compilation_output: ZKSCompilationOutput = serde_json::from_slice(b"{}")?;

    log::info!("Output: {output:?}");

    Ok(output)
}
