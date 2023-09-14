use ethers::{abi::Abi, types::Address};
use std::fmt::Debug;

/// Parameters for a contract deployment.
/// *`contract_abi` The contract's interface.
/// *`contract_bytecode`
/// *`constructor_parameters` The parameters for the contract's constructor.
/// *`from`
/// *`factory_deps`
#[derive(Clone, Debug)]
pub struct DeployRequest {
    /// The contract's interface.
    pub contract_abi: Abi,
    /// The compiled contract, as vec of bytes.
    pub contract_bytecode: Vec<u8>,
    /// The parameters for the contract's constructor
    pub constructor_parameters: Vec<String>,
    /// The requester of the deploy.
    pub from: Address,
    /// The list of bytecode hashes that the contract should know
    /// in advance, read more about it [here](https://era.zksync.io/docs/reference/architecture/contract-deployment.html#note-on-factory-deps)
    pub factory_deps: Option<Vec<Vec<u8>>>,
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
}
