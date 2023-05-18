use super::{output::ZKCompilationOutput, errors::ZKCompilerError};

pub trait ZKProject {
    fn compile_zk(&self) -> Result<ZKCompilationOutput, ZKCompilerError>;
}
