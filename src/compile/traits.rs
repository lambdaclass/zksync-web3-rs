use super::output::ZKCompilationOutput;

pub trait ZKProject {
    fn compile_zk(&self) -> ZKCompilationOutput;
}
