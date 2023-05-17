use std::path::{Path};

use super::output::ZKCompilationOutput;
use crate::{cli::commands, compile::traits::ZKProject, solc::Project};

impl ZKProject for Project {
    fn compile_zk(&self) -> ZKCompilationOutput {
        let args = commands::CompileArgs {
            // TODO find a way to avoid having the solc compiler on this folder
            solc: Path::new("./src/compile/solc-macos").canonicalize().ok(),
            combined_json: Some(String::from("abi,bin")),
            standard_json: false,
        };
        commands::compile::run(args).unwrap()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::solc::Project;
    use ethers::solc::{artifacts::StandardJsonCompilerInput, CompilerInput, ProjectPathsConfig, Solc};

    #[test]
    fn test_compile_zk() {
        let project = Project::builder().build().unwrap();
        let output = project.compile_zk();
        println!("{output:?}");
    }

    #[test]
    fn test_standard_json_input() {
        let paths =
            ProjectPathsConfig::builder().build_with_root("./src/compile/test_contracts/test");
        println!("PATHS: {paths:?}");
        let sources = paths.read_input_files().unwrap();
        println!("SOURCES: {sources:?}");
        let binding = CompilerInput::with_sources(sources);
        let compiler_input = binding.first().unwrap();
        println!("COMPILER INPUT: {compiler_input:?}");
        let ret = StandardJsonCompilerInput::from(compiler_input.clone());
        println!(
            "STANDARD JSON COMPILER INPUT: {:?}",
            serde_json::to_vec(&ret).unwrap()
        );
    }

    #[test]
    fn test_compile_files() {
        let solc = Solc::new("./src/compile/solc-macos");
        let project = Project::builder().solc(solc).build().unwrap();
        let output = project.compile_files(vec!["./src/compile/test_contracts/test/src/Test.sol"].into_iter()).unwrap();
        println!("{output:?}");
    }
}
