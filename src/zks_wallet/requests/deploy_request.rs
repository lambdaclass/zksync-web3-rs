use ethers::{abi::Abi, types::Address};
use std::fmt::Debug;

#[derive(Clone, Debug)]
pub struct DeployRequest {
    pub contract_abi: Abi,
    pub contract_bytecode: Vec<u8>,
    pub constructor_parameters: Vec<String>,
    pub from: Address,
    pub factory_deps: Option<Vec<Vec<u8>>>,
    pub deploy_type: String,
}

impl DeployRequest {
    pub fn with(
        contract_abi: Abi,
        contract_bytecode: Vec<u8>,
        constructor_parameters: Vec<String>,
    ) -> Self {
        Self {
            contract_abi,
            contract_bytecode,
            constructor_parameters,
            from: Default::default(),
            factory_deps: None,
            deploy_type: "create".to_string(),
        }
    }

    pub fn from(mut self, from: Address) -> Self {
        self.from = from;
        self
    }

    pub fn factory_deps(mut self, factory_deps: Vec<Vec<u8>>) -> Self {
        self.factory_deps = Some(factory_deps);
        self
    }

    pub fn deploy_type(mut self, deploy_type: &str) -> Self {
        self.deploy_type = deploy_type.to_string();
        self
    }
}
