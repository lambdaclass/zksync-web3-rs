use ethers::types::{Address, U256};
use std::fmt::Debug;

#[derive(Clone, Debug)]
pub struct WithdrawRequest {
    pub amount: U256,
    pub to: Option<Address>,
    pub from: Option<Address>,
}

impl WithdrawRequest {
    pub fn with(amount: U256) -> Self {
        Self {
            amount,
            to: None,
            from: None,
        }
    }

    pub fn to(mut self, to: Address) -> Self {
        self.to = Some(to);
        self
    }

    pub fn from(mut self, from: Address) -> Self {
        self.from = Some(from);
        self
    }
}
