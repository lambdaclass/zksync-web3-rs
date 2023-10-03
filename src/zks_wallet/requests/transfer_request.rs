use ethers::types::{Address, Eip1559TransactionRequest, U256};
use std::fmt::Debug;

/// Parameters for a transaction.
#[derive(Clone, Debug)]
pub struct TransferRequest {
    /// The amount to transfer
    pub amount: U256,
    /// The account that sends the funds.
    pub to: Address,
    /// The receipient of the funds.
    pub from: Address,
}

impl TransferRequest {
    pub fn new(amount: U256) -> Self {
        Self {
            amount,
            to: Default::default(),
            from: Default::default(),
        }
    }

    pub fn from(mut self, from: Address) -> Self {
        self.from = from;
        self
    }

    pub fn to(mut self, to: Address) -> Self {
        self.to = to;
        self
    }

    pub fn amount(mut self, amount: U256) -> Self {
        self.amount = amount;
        self
    }
}

impl From<TransferRequest> for Eip1559TransactionRequest {
    fn from(request: TransferRequest) -> Eip1559TransactionRequest {
        Eip1559TransactionRequest::new()
            .to(request.to)
            .value(request.amount)
            .from(request.from)
    }
}
