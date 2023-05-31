use super::{rlp_opt, PaymasterParams};
use crate::zks_utils::DEFAULT_GAS_PER_PUBDATA_LIMIT;
use ethers::{
    types::{Bytes, U256},
    utils::rlp::Encodable,
};
use serde::{Deserialize, Serialize};

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
