use crate::compile;
use clap::Parser;
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
    #[clap(
        long,
        action,
        conflicts_with = "standard-json",
        conflicts_with = "combined-json"
    )]
    pub yul: bool,
    #[clap(long, action)]
    pub system_mode: bool,
    #[clap(long, action)]
    pub bin: bool,
    #[clap(long, action)]
    pub asm: bool,
}

pub(crate) fn run(args: CompileArgs) -> eyre::Result<String> {
    let mut command = &mut std::process::Command::new(compile::constants::ZK_SOLC_PATH);
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

    if args.yul {
        command = command.arg("--yul");
    }

    if args.system_mode {
        command = command.arg("--system-mode");
    }

    if args.bin {
        command = command.arg("--bin");
    }

    if args.asm {
        command = command.arg("--asm");
    }

    command = command.arg("--").args(args.contract_paths);

    let command_output = command.output()?;

    let compilation_output = String::from_utf8_lossy(&command_output.stdout)
        .into_owned()
        .trim()
        .to_owned();

    log::info!("{compilation_output:?}");

    Ok(compilation_output)
}
