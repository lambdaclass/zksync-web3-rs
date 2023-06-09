use super::{rlp_append_option, Eip712Meta};
use crate::{
    zks_utils::{EIP712_TX_TYPE, ERA_CHAIN_ID, MAX_PRIORITY_FEE_PER_GAS},
    zks_wallet::Overrides,
};
use ethers::{
    types::{transaction::eip2930::AccessList, Address, Bytes, Signature, U256, U64},
    utils::rlp::{Encodable, RlpStream},
};
use serde::{Deserialize, Serialize};

// TODO: Not all the fields are optional. This was copied from the JS implementation.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all(serialize = "camelCase", deserialize = "camelCase"))]
pub struct Eip712TransactionRequest {
    /* These need to be filled before estimating the gas */
    pub to: Address,
    pub from: Address,
    pub nonce: U256,
    pub gas: U256,
    pub gas_price: U256,
    pub data: Bytes,
    pub value: U256,
    pub chain_id: U256,
    pub r#type: U256,
    pub max_priority_fee_per_gas: U256,
    #[serde(rename = "eip712Meta")]
    pub custom_data: Eip712Meta,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_list: Option<AccessList>,

    /* Filled after estimating the gas */
    // Unknown until we estimate the gas.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_limit: Option<U256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_fee_per_gas: Option<U256>, // conflicts with gas_price

    pub ccip_read_enabled: bool,
}

impl Eip712TransactionRequest {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_overrides(overrides: Overrides) -> Self {
        let mut tx = Self::default();
        if let Some(value) = overrides.value {
            tx.value = value;
        }
        tx
    }

    pub fn to<T>(mut self, to: T) -> Self
    where
        T: Into<Address>,
    {
        self.to = to.into();
        self
    }

    pub fn from<T>(mut self, from: T) -> Self
    where
        T: Into<Address>,
    {
        self.from = from.into();
        self
    }

    pub fn nonce<T>(mut self, nonce: T) -> Self
    where
        T: Into<U256>,
    {
        self.nonce = nonce.into();
        self
    }

    pub fn gas_limit<T>(mut self, gas_limit: T) -> Self
    where
        T: Into<U256>,
    {
        self.gas_limit = Some(gas_limit.into());
        self
    }

    pub fn gas_price<T>(mut self, gas_price: T) -> Self
    where
        T: Into<U256>,
    {
        self.gas_price = gas_price.into();
        self
    }

    pub fn data<T>(mut self, data: T) -> Self
    where
        T: Into<Bytes>,
    {
        self.data = data.into();
        self
    }

    pub fn value<T>(mut self, value: T) -> Self
    where
        T: Into<U256>,
    {
        self.value = value.into();
        self
    }

    pub fn chain_id<T>(mut self, chain_id: T) -> Self
    where
        T: Into<U256>,
    {
        self.chain_id = chain_id.into();
        self
    }

    pub fn r#type<T>(mut self, r#type: T) -> Self
    where
        T: Into<U256>,
    {
        self.r#type = r#type.into();
        self
    }

    pub fn access_list<T>(mut self, access_list: AccessList) -> Self {
        self.access_list = Some(access_list);
        self
    }

    pub fn max_priority_fee_per_gas<T>(mut self, max_priority_fee_per_gas: T) -> Self
    where
        T: Into<U256>,
    {
        self.max_priority_fee_per_gas = max_priority_fee_per_gas.into();
        self
    }

    pub fn max_fee_per_gas<T>(mut self, max_fee_per_gas: T) -> Self
    where
        T: Into<U256>,
    {
        self.max_fee_per_gas = Some(max_fee_per_gas.into());
        self
    }

    pub fn custom_data(mut self, custom_data: Eip712Meta) -> Self {
        self.custom_data = custom_data;
        self
    }

    pub fn ccip_read_enabled(mut self, ccip_read_enabled: bool) -> Self {
        self.ccip_read_enabled = ccip_read_enabled;
        self
    }

    pub fn rlp_unsigned(&self) -> Bytes {
        self.rlp(None)
    }

    pub fn rlp_signed(&self, signature: Signature) -> Bytes {
        self.rlp(Some(signature))
    }

    pub fn rlp(&self, signature: Option<Signature>) -> Bytes {
        let mut stream = RlpStream::new();
        stream.begin_unbounded_list();

        // 0
        stream.append(&self.nonce);
        // 1
        stream.append(&self.max_priority_fee_per_gas);
        // 2
        rlp_append_option(&mut stream, self.max_fee_per_gas);
        // 3 (supped to be gas)
        rlp_append_option(&mut stream, self.gas_limit);
        // 4
        stream.append(&self.to);
        // 5
        stream.append(&self.value);
        // 6
        stream.append(&self.data.0);
        if let Some(signature) = signature {
            // 7
            stream.append(&U64::from(signature.v));
            // 8
            stream.append(&signature.r);
            // 9
            stream.append(&signature.s);
        } else {
            // 7, 8, 9 must be set even if no signature is provided.
            // This should be the case of transaction that have a
            // custom signature set.
            stream.append(&"");
            stream.append(&"");
            stream.append(&"");
        }
        // 10
        stream.append(&self.chain_id);
        // 11
        stream.append(&self.from);
        // 12, 13, 14, 15
        self.custom_data.rlp_append(&mut stream);

        stream.finalize_unbounded_list();
        stream.out().freeze().into()
    }
}

impl Default for Eip712TransactionRequest {
    fn default() -> Self {
        Self {
            to: Default::default(),
            from: Default::default(),
            nonce: Default::default(),
            gas: Default::default(),
            gas_limit: Default::default(),
            gas_price: Default::default(),
            data: Default::default(),
            value: Default::default(),
            chain_id: ERA_CHAIN_ID.into(),
            r#type: EIP712_TX_TYPE.into(),
            access_list: Default::default(),
            max_priority_fee_per_gas: MAX_PRIORITY_FEE_PER_GAS.into(),
            max_fee_per_gas: Default::default(),
            custom_data: Default::default(),
            ccip_read_enabled: Default::default(),
        }
    }
}
