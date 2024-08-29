pub mod zksync {
    pub use zksync_prover_interface::*;
    pub use zksync_system_constants::*;
    pub use zksync_types::*;
    pub use zksync_web3_decl::types as web3_decl;
}

pub mod ethers {
    pub use ethers::types::*;
}
pub use ethers::*;

#[derive(Debug, Clone, Default)]
pub struct L1TxOverrides {
    pub from: Option<Address>,
    pub value: Option<U256>,
    pub gas_price: Option<U256>,
    pub gas: Option<U256>,
    pub nonce: Option<U256>,
    pub gas_limit: Option<U256>,
}

impl L1TxOverrides {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from(mut self, from: Address) -> Self {
        self.from = Some(from);
        self
    }

    pub fn value(mut self, value: U256) -> Self {
        self.value = Some(value);
        self
    }

    pub fn gas_price(mut self, gas_price: U256) -> Self {
        self.gas_price = Some(gas_price);
        self
    }

    pub fn gas(mut self, gas: U256) -> Self {
        self.gas = Some(gas);
        self
    }

    pub fn nonce(mut self, nonce: U256) -> Self {
        self.nonce = Some(nonce);
        self
    }
}

#[derive(Debug, Clone, Default)]
pub struct L2TxOverrides {
    pub from: Option<Address>,
    pub value: Option<U256>,
    pub gas_price: Option<U256>,
    pub gas: Option<U256>,
    pub nonce: Option<U256>,
    pub gas_limit: Option<U256>,
}

impl L2TxOverrides {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from(mut self, from: Address) -> Self {
        self.from = Some(from);
        self
    }

    pub fn value(mut self, value: U256) -> Self {
        self.value = Some(value);
        self
    }

    pub fn gas_price(mut self, gas_price: U256) -> Self {
        self.gas_price = Some(gas_price);
        self
    }

    pub fn gas(mut self, gas: U256) -> Self {
        self.gas = Some(gas);
        self
    }

    pub fn nonce(mut self, nonce: U256) -> Self {
        self.nonce = Some(nonce);
        self
    }
}
