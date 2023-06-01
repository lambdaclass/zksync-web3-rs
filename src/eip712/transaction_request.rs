use super::{hash_bytecode, rlp_opt, Eip712Meta, Eip712SignInput};
use crate::zks_utils::{DEFAULT_GAS_PER_PUBDATA_LIMIT, EIP712_TX_TYPE, ERA_CHAIN_ID};
use ethers::{
    types::{transaction::eip2930::AccessList, Address, Bytes, Signature, U256, U64},
    utils::rlp::{Encodable, RlpStream},
};
use serde::{Deserialize, Serialize};

// TODO: Not all the fields are optional. This was copied from the JS implementation.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all(serialize = "camelCase", deserialize = "camelCase"))]
pub struct Eip712TransactionRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<Address>,
    pub nonce: U256,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_limit: Option<U256>,
    pub gas_price: U256,
    pub data: Bytes,
    pub value: U256,
    pub chain_id: U256,
    pub r#type: U256,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_list: Option<AccessList>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_priority_fee_per_gas: Option<U256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_fee_per_gas: Option<U256>,
    pub custom_data: Eip712Meta,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ccip_read_enabled: Option<bool>,
}

impl Eip712TransactionRequest {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn to<T>(mut self, to: T) -> Self
    where
        T: Into<Address>,
    {
        self.to = Some(to.into());
        self
    }

    pub fn from<T>(mut self, from: T) -> Self
    where
        T: Into<Address>,
    {
        self.from = Some(from.into());
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
        self.max_priority_fee_per_gas = Some(max_priority_fee_per_gas.into());
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
        self.ccip_read_enabled = Some(ccip_read_enabled);
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
        rlp_opt(&mut stream, &self.max_priority_fee_per_gas);
        // 2
        rlp_opt(&mut stream, &self.max_fee_per_gas);
        // 3 (supped to be gas)
        rlp_opt(&mut stream, &self.gas_limit);
        // 4
        rlp_opt(&mut stream, &self.to);
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
        rlp_opt(&mut stream, &self.from);
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
            gas_limit: Default::default(),
            gas_price: Default::default(),
            data: Default::default(),
            value: Default::default(),
            chain_id: ERA_CHAIN_ID.into(),
            r#type: EIP712_TX_TYPE.into(),
            access_list: Default::default(),
            max_priority_fee_per_gas: Default::default(),
            max_fee_per_gas: Default::default(),
            custom_data: Default::default(),
            ccip_read_enabled: Default::default(),
        }
    }
}

impl Into<Eip712SignInput> for Eip712TransactionRequest {
    fn into(self) -> Eip712SignInput {
        let mut eip712_sign_input = Eip712SignInput::default();

        eip712_sign_input.tx_type = self.r#type;
        eip712_sign_input.from = self.from;
        eip712_sign_input.to = self.to;
        eip712_sign_input.gas_limit = self.gas_limit;
        // TODO create a new constant for default value
        eip712_sign_input.max_fee_per_gas = self.max_fee_per_gas.or(Some(U256::from("0x0ee6b280")));
        // TODO create a new constant for default value
        eip712_sign_input.max_priority_fee_per_gas = self
            .max_priority_fee_per_gas
            .or(Some(U256::from("0x0ee6b280")));
        eip712_sign_input.nonce = self.nonce;
        eip712_sign_input.value = self.value;
        eip712_sign_input.data = self.data;

        if let Some(factory_deps) = self.custom_data.factory_deps {
            eip712_sign_input.factory_deps = Some(
                factory_deps
                    .iter()
                    .map(|dependency_bytecode| hash_bytecode(dependency_bytecode).map(Bytes::from))
                    .collect::<Result<Vec<Bytes>, _>>()
                    .unwrap(),
            );
        }
        eip712_sign_input.gas_per_pubdata_byte_limit =
            Some(U256::from(DEFAULT_GAS_PER_PUBDATA_LIMIT));
        if let Some(paymaster_params) = self.custom_data.paymaster_params {
            eip712_sign_input.paymaster = Some(paymaster_params.paymaster);
            eip712_sign_input.paymaster_input = Some(paymaster_params.paymaster_input);
        } else {
            eip712_sign_input.paymaster = Some(
                "0x0000000000000000000000000000000000000000"
                    .parse()
                    .unwrap(),
            );
            // TODO: This default seems to be wrong.
            eip712_sign_input.paymaster_input = Some(Bytes::default());
        }

        eip712_sign_input
    }
}
