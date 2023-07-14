use ethers::types::{Address, Eip1559TransactionRequest, U256};
use std::fmt::Debug;

use crate::zks_utils::ERA_CHAIN_ID;

#[derive(Clone, Debug)]
pub struct TransferRequest {
    pub amount: U256,
    pub to: Address,
    pub from: Address,
}

impl TransferRequest {
    pub fn with(amount: U256, to: Address) -> Self {
        Self {
            amount,
            to,
            from: Default::default(),
        }
    }

    pub fn from(mut self, from: Address) -> Self {
        self.from = from;
        self
    }
}

impl From<TransferRequest> for Eip1559TransactionRequest {
    fn from(request: TransferRequest) -> Eip1559TransactionRequest {
        Eip1559TransactionRequest::new()
            .to(request.to)
            .value(request.amount)
            .from(request.from)
            .chain_id(ERA_CHAIN_ID)
    }
}
