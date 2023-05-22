use super::{errors::ZKCompilerError, output::ZKCompilationOutput};

pub trait ZKProject {
    fn compile_zk(&self) -> Result<ZKCompilationOutput, ZKCompilerError>;
}
