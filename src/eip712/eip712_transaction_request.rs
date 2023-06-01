use super::rlp_opt;
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

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all(serialize = "camelCase", deserialize = "camelCase"))]
pub struct Eip712Meta {
    pub gas_per_pubdata: U256,
    pub factory_deps: Option<Vec<Bytes>>,
    pub custom_signature: Option<Bytes>,
    pub paymaster_params: Option<PaymasterParams>,
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
