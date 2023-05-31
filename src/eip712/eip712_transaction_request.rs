use crate::zks_utils::DEFAULT_GAS_PER_PUBDATA_LIMIT;

use super::{
    hash_bytecode,
    utils::{self, rlp_opt},
    Eip712SignInput,
};
use ethers::{
    types::{transaction::eip2930::AccessList, Address, Bytes, Signature, U256, U64},
    utils::rlp::{Encodable, RlpStream},
};
use serde::{Deserialize, Serialize};

// TODO: Not all the fields are optional. This was copied from the JS implementation.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Bytes>,
    pub value: U256,
    pub chain_id: U256,
    pub r#type: U256,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_list: Option<AccessList>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_priority_fee_per_gas: Option<U256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_fee_per_gas: Option<U256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_data: Option<Eip712Meta>,
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
        self.data = Some(data.into());
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
        self.custom_data = Some(custom_data);
        self
    }

    pub fn ccip_read_enabled(mut self, ccip_read_enabled: bool) -> Self {
        self.ccip_read_enabled = Some(ccip_read_enabled);
        self
    }

    pub fn custom_signature<T>(mut self, signature: T) -> Self
    where
        T: Into<Bytes>,
    {
        if let Some(mut custom_data) = self.custom_data {
            custom_data.custom_signature = Some(signature.into());
            self.custom_data = Some(custom_data);
        } else {
            self.custom_data = Some(Eip712Meta {
                custom_signature: Some(signature.into()),
                ..Default::default()
            });
        }
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
        rlp_opt(&mut stream, &self.data.clone().map(|d| d.0));
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
        if let Some(meta) = &self.custom_data {
            // 12, 13, 14, 15
            meta.rlp_append(&mut stream);
        }

        stream.finalize_unbounded_list();
        stream.out().freeze().into()
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

        if let Some(custom_data) = self.custom_data {
            if let Some(factory_deps) = custom_data.factory_deps {
                eip712_sign_input.factory_deps = Some(
                    factory_deps
                        .iter()
                        .map(|dependency_bytecode| {
                            hash_bytecode(dependency_bytecode).map(Bytes::from)
                        })
                        .collect::<Result<Vec<Bytes>, _>>()
                        .unwrap(),
                );
            }
            eip712_sign_input.gas_per_pubdata_byte_limit =
                Some(U256::from(utils::DEFAULT_GAS_PER_PUBDATA_LIMIT));
            if let Some(paymaster_params) = custom_data.paymaster_params {
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
        }

        eip712_sign_input
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all(serialize = "camelCase", deserialize = "camelCase"))]
pub struct Eip712Meta {
    pub gas_per_pubdata: U256,
    pub factory_deps: Option<Vec<Bytes>>,
    pub custom_signature: Option<Bytes>,
    pub paymaster_params: Option<PaymasterParams>,
}

impl Eip712Meta {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn gas_per_pubdata<T>(mut self, gas_per_pubdata: T) -> Self
    where
        T: Into<U256>,
    {
        self.gas_per_pubdata = gas_per_pubdata.into();
        self
    }

    pub fn factory_deps<T>(mut self, factory_deps: T) -> Self
    where
        T: Into<Vec<Bytes>>,
    {
        self.factory_deps = Some(factory_deps.into());
        self
    }

    pub fn custom_signature<T>(mut self, custom_signature: T) -> Self
    where
        T: Into<Bytes>,
    {
        self.custom_signature = Some(custom_signature.into());
        self
    }

    pub fn paymaster_params(mut self, paymaster_params: PaymasterParams) -> Self {
        self.paymaster_params = Some(paymaster_params);
        self
    }
}

impl Default for Eip712Meta {
    fn default() -> Self {
        Self {
            gas_per_pubdata: DEFAULT_GAS_PER_PUBDATA_LIMIT.into(),
            factory_deps: Default::default(),
            custom_signature: Default::default(),
            paymaster_params: Default::default(),
        }
    }
}

impl Encodable for Eip712Meta {
    fn rlp_append(&self, stream: &mut ethers::utils::rlp::RlpStream) {
        // 12
        stream.append(&self.gas_per_pubdata);
        // 13
        if let Some(factory_deps) = &self.factory_deps {
            stream.begin_list(factory_deps.len());
            for dep in factory_deps.iter() {
                stream.append(&dep.to_vec());
            }
        } else {
            stream.begin_list(0);
        }
        // 14
        rlp_opt(stream, &self.custom_signature.clone().map(|s| s.to_vec()));
        // 15
        if let Some(paymaster_params) = &self.paymaster_params {
            paymaster_params.rlp_append(stream);
        } else {
            stream.begin_list(0);
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all(serialize = "camelCase", deserialize = "camelCase"))]
pub struct PaymasterParams {
    pub paymaster: Address,
    pub paymaster_input: Bytes,
}

impl Encodable for PaymasterParams {
    fn rlp_append(&self, stream: &mut ethers::utils::rlp::RlpStream) {
        stream.begin_list(2);
        stream.append(&self.paymaster.as_bytes());
        stream.append(&self.paymaster_input.to_vec());
    }
}
