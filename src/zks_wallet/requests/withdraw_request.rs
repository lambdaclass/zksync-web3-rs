use ethers::types::{transaction::eip712::Eip712Error, Address, U256};
use std::fmt::Debug;

use crate::eip712::Eip712TransactionRequest;

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

// impl TryFrom<Eip712TransactionRequest> for WithdrawRequest {
//     type Error = Eip712Error;

//     fn try_from(value: Eip712TransactionRequest) -> Result<Self, Self::Error> {
//         Eip712TransactionRequest {

//         }
//     }
// }
