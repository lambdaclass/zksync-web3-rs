use ethers::types::{transaction::eip2930::AccessList, Address, Bytes, U256};

use super::{Eip712Meta, Eip712TransactionRequest};

pub struct Eip712TransactionRequestBuilder {
    transaction: Eip712TransactionRequest,
}

impl Eip712TransactionRequestBuilder {
    pub fn new() -> Self {
        Self {
            transaction: Eip712TransactionRequest::default(),
        }
    }

    pub fn to(mut self, to: Address) -> Self {
        self.transaction.to = Some(to);
        self
    }

    pub fn from(mut self, from: Address) -> Self {
        self.transaction.from = Some(from);
        self
    }

    pub fn nonce(mut self, nonce: U256) -> Self {
        self.transaction.nonce = nonce;
        self
    }

    pub fn gas_limit(mut self, gas_limit: U256) -> Self {
        self.transaction.gas_limit = Some(gas_limit);
        self
    }

    pub fn gas_price(mut self, gas_price: U256) -> Self {
        self.transaction.gas_price = gas_price;
        self
    }

    pub fn data(mut self, data: Bytes) -> Self {
        self.transaction.data = Some(data);
        self
    }

    pub fn value(mut self, value: U256) -> Self {
        self.transaction.value = value;
        self
    }

    pub fn chain_id(mut self, chain_id: U256) -> Self {
        self.transaction.chain_id = chain_id;
        self
    }

    pub fn r#type(mut self, r#type: U256) -> Self {
        self.transaction.r#type = r#type;
        self
    }

    pub fn access_list(mut self, access_list: AccessList) -> Self {
        self.transaction.access_list = Some(access_list);
        self
    }

    pub fn max_priority_fee_per_gas(mut self, max_priority_fee_per_gas: U256) -> Self {
        self.transaction.max_priority_fee_per_gas = Some(max_priority_fee_per_gas);
        self
    }

    pub fn max_fee_per_gas(mut self, max_fee_per_gas: U256) -> Self {
        self.transaction.max_fee_per_gas = Some(max_fee_per_gas);
        self
    }

    pub fn custom_data(mut self, custom_data: Eip712Meta) -> Self {
        self.transaction.custom_data = Some(custom_data);
        self
    }

    pub fn ccip_read_enabled(mut self, ccip_read_enabled: bool) -> Self {
        self.transaction.ccip_read_enabled = Some(ccip_read_enabled);
        self
    }

    pub fn build(self) -> Eip712TransactionRequest {
        self.transaction
    }
}
