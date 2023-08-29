use std::fmt::Debug;

use ethers::types::{Address, U256};

#[derive(Clone, Debug)]
pub struct WithdrawRequest {
    pub amount: U256,
    pub to: Address,
    pub from: Address,
}

impl WithdrawRequest {
    pub fn new(amount: U256) -> Self {
        Self {
            amount,
            to: Default::default(),
            from: Default::default(),
        }
    }

    pub fn to(mut self, to: Address) -> Self {
        self.to = to;
        self
    }

    pub fn from(mut self, from: Address) -> Self {
        self.from = from;
        self
    }
}
