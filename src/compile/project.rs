use ethers::solc::utils::source_files;

use super::{errors::ZKCompilerError, output::ZKSCompilationOutput};
use crate::{solc::Project, zks_utils::program_path};

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
        let zksolc_path = program_path("zksolc").ok_or(ZKCompilerError::CompilationError(
            "zksolc not found".to_owned(),
        ))?;

        let mut command = &mut std::process::Command::new(zksolc_path);

        if let Some(solc) = program_path("solc") {
            command = command.arg("--solc").arg(solc);
        } else if let Ok(solc) = std::env::var("SOLC_PATH") {
            command = command.arg("--solc").arg(solc);
        } else {
            return Err(ZKCompilerError::CompilationError(
                "no solc path provided".to_owned(),
            ));
        }

        command = command
            .arg("--combined-json")
            .arg("abi,bin")
            .arg("--")
            .args(source_files(self.base_project.root()));

        let command_output = command.output().map_err(|e| {
            ZKCompilerError::CompilationError(format!(
                "failed to execute zksolc: {}",
                e.to_string()
            ))
        })?;

        let compilation_output = String::from_utf8_lossy(&command_output.stdout)
            .into_owned()
            .trim()
            .to_owned();

        serde_json::from_str(&compilation_output)
            .map_err(|e| ZKCompilerError::CompilationError(e.to_string()))
    }
}
