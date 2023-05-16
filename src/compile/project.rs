use crate::compile::traits::ZkProject;
use crate::solc::Project;
use std::{path::Path, process::Command};

use super::output::ZkCompilationOutput;

impl ZkProject for Project {
    fn compile_zk(&self) -> ZkCompilationOutput {
        let mut compile_command = Command::new("./zksolc");
        let dir = Path::new("./src/compile").canonicalize().unwrap();

        compile_command
            .arg("--solc")
            .arg("./solc-macos")
            .arg("--combined-json")
            .arg("abi")
            .arg("--")
            .arg("test_contracts/Test.sol");
        compile_command.current_dir(dir);
        let compilation_output = compile_command.output().expect("Compilation failed");
        serde_json::from_slice(&compilation_output.stdout).unwrap()
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
        println!("{:?}", output);
    }
}
