use std::fmt::Debug;

use ethers::types::{Address, U256};

/// Parameters for an L2 -> L1 withdraw.
#[derive(Clone, Debug)]
pub struct WithdrawRequest {
    /// The amount to transfer.
    pub amount: U256,
    /// The L1 recipient address.
    pub to: Address,
    /// The L2 sender address.
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
