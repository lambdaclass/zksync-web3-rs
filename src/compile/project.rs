use ethers::solc::utils::source_files;

use super::{errors::ZKCompilerError, output::ZKSCompilationOutput};
use crate::{cli::commands, solc::Project, zks_utils::program_path};

pub struct ZKProject {
    pub base_project: Project,
}

impl From<Project> for ZKProject {
    fn from(base_project: Project) -> Self {
        Self { base_project }
    }
}

impl ZKProject {
    pub fn compile(&self) -> Result<ZKSCompilationOutput, ZKCompilerError> {
        let args = commands::CompileArgs {
            contract_paths: source_files(self.base_project.root()),
            // TODO find a way to avoid having the solc compiler on this folder
            solc: program_path("solc"),
            combined_json: Some(String::from("abi,bin")),
            standard_json: false,
            yul: false,
            system_mode: false,
            bin: false,
            asm: false,
        };
        let command_output = commands::compile::run(args)
            .map_err(|e| ZKCompilerError::CompilationError(e.to_string()))?;
        serde_json::from_str(&command_output)
            .map_err(|e| ZKCompilerError::CompilationError(e.to_string()))
    }
}
