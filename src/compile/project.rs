use std::path::Path;

use super::{errors::ZKCompilerError, output::ZKCompilationOutput};
use crate::{cli::commands, solc::Project};

pub struct ZKProject {
    pub base_project: Project,
}

impl From<Project> for ZKProject {
    fn from(base_project: Project) -> Self {
        Self { base_project }
    }
}

impl ZKProject {
    pub fn compile(&self) -> Result<ZKCompilationOutput, ZKCompilerError> {
        let args = commands::CompileArgs {
            // TODO find a way to avoid having the solc compiler on this folder
            solc: Path::new("./src/compile/solc-macos").canonicalize().ok(),
            combined_json: Some(String::from("abi,bin")),
            standard_json: false,
        };
        commands::compile::run(args)
            .map_err(|e| ZKCompilerError::CompilationError(e.to_string()))
    }
}
