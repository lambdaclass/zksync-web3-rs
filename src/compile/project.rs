use super::output::ZkCompilationOutput;
use crate::{compile::traits::ZkProject, cli::commands, solc::Project};

impl ZkProject for Project {
    fn compile_zk(&self) -> ZkCompilationOutput {
        let args = commands::CompileArgs { 
            solc: self.solc.clone().solc, 
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
        println!("{:?}", output);
    }
}
