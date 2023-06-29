pub mod constants;
pub mod errors;
pub mod output;
pub mod zksolc;
pub mod zksolc_manager;

use ethers::solc::utils::source_files;

use crate::{cli::commands, solc::Project};
use std::{path::{Path, PathBuf}, collections::HashMap};

use self::{output::ZKSCompilationOutput, errors::ZKCompilerError, zksolc::{ZkSolcOpts, ZkSolc}, zksolc_manager::{ZkSolcManager, ZkSolcManagerOpts, ZkSolcManagerBuilder}};

pub struct ZKCompile {
}

// impl From<Project> for ZKCompile {
//     fn from(base_project: Project) -> Self {
//         let mut project = base_project;
//         //set zk out path


//         Self { base_project: project }
//     }
// }

impl ZKCompile {
    pub fn run(&self, mut project: Project) -> Result<ZKSCompilationOutput, ZKCompilerError> {
        // let args = commands::CompileArgs {
        //     contract_paths: source_files(self.base_project.root()),
        //     // TODO find a way to avoid having the solc compiler on this folder
        //     solc: Path::new(constants::SOLC_PATH).canonicalize().ok(),
        //     combined_json: Some(String::from("abi,bin")),
        //     standard_json: false,
        // };

        let zk_out_path = project.paths.root.join("zkout");
        project.paths.artifacts = zk_out_path;

        let zksolc_manager =
            setup_zksolc_manager().map_err(|e| ZKCompilerError::CompilationError(e.to_string()))?;

        let zksolc_opts = ZkSolcOpts {
            compiler_path: zksolc_manager.get_full_compiler_path(),
            is_system: false, // TODO
            force_evmla: false, //TODO
        };


        let zksolc = ZkSolc::new(zksolc_opts, project);

        // let compilation_output = String::from_utf8_lossy(&command_output.stdout)
        //     .into_owned()
        //     .trim()
        //     .to_owned();

        // let command_output = commands::compile::run(args)
        //     .map_err(|e| ZKCompilerError::CompilationError(e.to_string()))?;
        // serde_json::from_str(&command_output)
        //     .map_err(|e| ZKCompilerError::CompilationError(e.to_string()))

        match zksolc.compile() {
            Ok(_) => {
                println!("Compiled Successfully");
                Ok(ZKSCompilationOutput {
                    artifacts: HashMap::new(),
                    version: String::from(""),
                    zk_version: String::from(""),
                })
            }
            Err(err) => Err(ZKCompilerError::CompilationError(err.to_string())),
        }

        // commands::compile::run(args).map_err(|e| ZKCompilerError::CompilationError(e.to_string()))
    }
}

fn setup_zksolc_manager() -> eyre::Result<ZkSolcManager> {
    let zksolc_manager_opts = ZkSolcManagerOpts::new("v1.3.11".into()); // TODO fix hardcoded version
    let zksolc_manager_builder = ZkSolcManagerBuilder::new(zksolc_manager_opts);
    let zksolc_manager = zksolc_manager_builder
        .build()
        .map_err(|e| eyre::eyre!("Error building zksolc_manager: {}", e))?;

    if let Err(err) = zksolc_manager.check_setup_compilers_dir() {
        eyre::bail!("Failed to setup compilers directory: {}", err);
    }

    if !zksolc_manager.exists() {
        println!(
            "Downloading zksolc compiler from {:?}",
            zksolc_manager.get_full_download_url().unwrap().to_string()
        );
        zksolc_manager
            .download()
            .map_err(|err| eyre::eyre!("Failed to download the file: {}", err))?;
    }

    Ok(zksolc_manager)
}
