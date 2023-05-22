use crate::compile::{constants, output::ZKCompilationOutput};
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
pub struct CompileArgs {
    #[clap(long, name = "PATH_TO_SOLC")]
    pub solc: Option<PathBuf>,
    #[clap(long, name = "COMBINED_JSON")]
    pub combined_json: Option<String>,
    #[clap(long, action)]
    pub standard_json: bool,
}

pub(crate) fn run(args: CompileArgs) -> eyre::Result<ZKCompilationOutput> {
    let mut command = &mut std::process::Command::new(constants::ZK_SOLC_PATH);
    if let Some(solc) = args.solc {
        command = command.arg("--solc").arg(solc);
    } else if let Ok(solc) = std::env::var("SOLC_PATH") {
        command = command.arg("--solc").arg(solc);
    } else {
        eyre::bail!("no solc path provided");
    }

    const VALID_COMBINED_JSON_ARGS: [&str; 10] = [
        "abi",
        "hashes",
        "metadata",
        "devdoc",
        "userdoc",
        "storage-layout",
        "ast",
        "asm",
        "bin",
        "bin-runtime",
    ];

    if let Some(combined_json_arg) = args.combined_json {
        let valid_args = combined_json_arg
            .split(',')
            .all(|arg| VALID_COMBINED_JSON_ARGS.contains(&arg));
        if !valid_args {
            eyre::bail!("Invalid combined-json argument: {combined_json_arg}");
        }
        command = command.arg("--combined-json").arg(combined_json_arg);
    }

    if args.standard_json {
        command = command.arg("--standard-json");
    }

    command = command
        .arg("--")
        .arg("src/compile/test_contracts/test/src/Test.sol");

    let command_output = command.output()?;
    let compilation_output: ZKCompilationOutput = serde_json::from_slice(&command_output.stdout)?;

    log::info!("{compilation_output:?}");

    Ok(compilation_output)
}
