use super::output::ZkCompilationOutput;

pub trait ZkProject {
    fn compile_zk(&self) -> ZkCompilationOutput;
}
