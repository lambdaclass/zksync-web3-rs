use ethers::{abi::Abi, types::Address};
use std::{fmt::Debug, fmt::Display};

#[derive(Clone, Debug)]
pub enum DeployType {
    Create,
    Create2,
}

impl Display for DeployType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeployType::Create => write!(f, "create"),
            DeployType::Create2 => write!(f, "create2"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DeployRequest {
    pub contract_abi: Abi,
    pub contract_bytecode: Vec<u8>,
    pub constructor_parameters: Vec<String>,
    pub from: Address,
    pub factory_deps: Option<Vec<Vec<u8>>>,
    pub deploy_type: DeployType,
    pub salt: Option<[u8; 32]>,
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
            deploy_type: DeployType::Create,
            salt: None,
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

    pub fn deploy_type(mut self, deploy_type: DeployType) -> Self {
        self.deploy_type = deploy_type;
        self
    }

    pub fn salt(mut self, salt: [u8; 32]) -> Self {
        self.salt = Some(salt);
        self
    }
}
