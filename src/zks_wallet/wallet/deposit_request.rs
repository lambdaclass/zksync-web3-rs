use crate::types::{Address, U256};

use crate::zks_utils::{
    DEPOSIT_GAS_PER_PUBDATA_LIMIT, RECOMMENDED_DEPOSIT_L1_GAS_LIMIT,
    RECOMMENDED_DEPOSIT_L2_GAS_LIMIT,
};

fn default_gas_limit() -> U256 {
    RECOMMENDED_DEPOSIT_L1_GAS_LIMIT.into()
}

fn default_l2_gas_limit() -> U256 {
    RECOMMENDED_DEPOSIT_L2_GAS_LIMIT.into()
}

fn default_gas_per_pubdata_byte() -> U256 {
    DEPOSIT_GAS_PER_PUBDATA_LIMIT.into()
}
pub struct DepositRequest {
    pub amount: U256,
    pub to: Option<Address>,
    pub l2_gas_limit: U256,
    pub gas_per_pubdata_byte: U256,
    pub operator_tip: U256,
    pub gas_price: Option<U256>,
    pub gas_limit: U256,
}

impl DepositRequest {
    pub fn new(amount: U256) -> Self {
        Self {
            amount,
            to: None,
            l2_gas_limit: default_l2_gas_limit(),
            gas_per_pubdata_byte: default_gas_per_pubdata_byte(),
            operator_tip: 0.into(),
            gas_price: None,
            gas_limit: default_gas_limit(),
        }
    }

    pub fn amount(&self) -> &U256 {
        &self.amount
    }

    pub fn to(mut self, address: Address) -> Self {
        self.to = Some(address);
        self
    }

    pub fn l2_gas_limit(mut self, value: Option<U256>) -> Self {
        self.l2_gas_limit = match value {
            Some(l2_gas_limit) => l2_gas_limit,
            None => default_l2_gas_limit(),
        };
        self
    }

    pub fn gas_per_pubdata_byte(mut self, value: Option<U256>) -> Self {
        self.gas_per_pubdata_byte = match value {
            Some(gas_per_pubdata_byte) => gas_per_pubdata_byte,
            None => default_gas_per_pubdata_byte(),
        };
        self
    }

    pub fn operator_tip(mut self, operator_tip: U256) -> Self {
        self.operator_tip = operator_tip;
        self
    }

    pub fn gas_price(mut self, value: Option<U256>) -> Self {
        self.gas_price = value;
        self
    }

    pub fn gas_limit(mut self, value: Option<U256>) -> Self {
        self.gas_limit = match value {
            Some(gas_limit) => gas_limit,
            _ => default_gas_limit(),
        };
        self
    }
}
