use super::output::ZKCompilationOutput;
use crate::{compile::traits::ZKProject, cli::commands, solc::Project};

impl ZKProject for Project {
    fn compile_zk(&self) -> ZKCompilationOutput {
        let args = commands::CompileArgs { 
            solc: Some(self.solc.clone().solc), 
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
