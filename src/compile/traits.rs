use std::{process::Output, path::PathBuf};

use serde_json::Value;

pub trait ZkProject {
    fn compile_zk(&self) -> Value;
}
