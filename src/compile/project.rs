use std::path::Path;

use super::output::ZKCompilationOutput;
use crate::{cli::commands, compile::traits::ZKProject, solc::Project};

impl ZKProject for Project {
    fn compile_zk(&self) -> ZKCompilationOutput {
        let args = commands::CompileArgs {
            // TODO find a way to avoid having the solc compiler on this folder
            solc: Path::new("./src/compile/solc-macos").canonicalize().ok(),
            combined_json: Some(String::from("abi")),
            standard_json: None,
        };
        commands::compile::run(args).unwrap()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::solc::Project;

    #[test]
    fn test() {
        let project = Project::builder().build().unwrap();
        let output = project.compile_zk();
        println!("{output:?}");
    }
}
