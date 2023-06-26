use ethers::types::{Address, U256};

pub struct DepositRequest {
    pub amount: U256,
    pub to: Option<Address>,
}

impl DepositRequest {
    pub fn new(amount: U256) -> Self {
        Self { amount, to: None }
    }

    pub fn amount(&self) -> &U256 {
        &self.amount
    }

    pub fn to(mut self, address: Address) -> Self {
        self.to = Some(address);
        self
    }
}
