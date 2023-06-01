use super::PaymasterParams;
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
    pub factory_deps: Vec<Bytes>,
    pub custom_signature: Bytes,
    pub paymaster_params: PaymasterParams,
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
        self.factory_deps = factory_deps.into();
        self
    }

    pub fn custom_signature<T>(mut self, custom_signature: T) -> Self
    where
        T: Into<Bytes>,
    {
        self.custom_signature = custom_signature.into();
        self
    }

    pub fn paymaster_params(mut self, paymaster_params: PaymasterParams) -> Self {
        self.paymaster_params = paymaster_params;
        self
    }
}

impl Default for Eip712Meta {
    fn default() -> Self {
        Self {
            gas_per_pubdata: DEFAULT_GAS_PER_PUBDATA_LIMIT.into(),
            factory_deps: <Vec<Bytes>>::default(),
            custom_signature: Bytes::default(),
            paymaster_params: PaymasterParams::default(),
        }
    }
}

impl Encodable for Eip712Meta {
    fn rlp_append(&self, stream: &mut ethers::utils::rlp::RlpStream) {
        // 12
        stream.append(&self.gas_per_pubdata);
        // 13
        if self.factory_deps.len() > 0 {
            stream.begin_list(self.factory_deps.len());
            for dep in self.factory_deps.iter() {
                stream.append(&dep.to_vec());
            }
        } else {
            stream.begin_list(0);
        }
        // 14
        stream.append(&self.custom_signature.to_vec());
        // 15
        self.paymaster_params.rlp_append(stream);
        // } else {
        //     stream.begin_list(0);
        // }
    }
}
