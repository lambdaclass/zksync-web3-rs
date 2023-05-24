use super::{
    hash_bytecode,
    utils::{self, rlp_opt},
    Eip712SignInput,
};
use ethers::{
    types::{transaction::eip2930::AccessList, Address, Bytes, Signature, U256},
    utils::rlp::{Encodable, RlpStream},
};
use serde::{Deserialize, Serialize};

// TODO: Not all the fields are optional. This was copied from the JS implementation.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all(serialize = "camelCase", deserialize = "camelCase"))]
pub struct Eip712TransactionRequest {
    pub to: Option<Address>,
    pub from: Option<Address>,
    pub nonce: U256,
    pub gas_limit: Option<U256>,
    pub gas_price: Option<U256>,
    pub data: Option<Bytes>,
    pub value: Option<U256>,
    pub chain_id: U256,
    pub r#type: U256,
    pub access_list: Option<AccessList>,
    pub max_priority_fee_per_gas: Option<U256>,
    pub max_fee_per_gas: Option<U256>,
    pub custom_data: Option<Eip712Meta>,
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
        rlp_opt(&mut stream, &self.value);
        // 6
        rlp_opt(&mut stream, &self.data.clone().map(|d| d.0));
        if let Some(signature) = signature {
            // 7
            stream.append(&signature.v);
            // 8
            stream.append(&signature.r);
            // 9
            stream.append(&signature.s);
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
            eip712_sign_input.factory_deps =
                Some(hash_bytecode(custom_data.factory_deps).unwrap().to_vec());
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
                eip712_sign_input.paymaster_input = Some(vec![0]);
            }
        }

        eip712_sign_input
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

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all(serialize = "camelCase", deserialize = "camelCase"))]
pub struct PaymasterParams {
    pub paymaster: Address,
    pub paymaster_input: Vec<u8>,
}

impl Encodable for PaymasterParams {
    fn rlp_append(&self, stream: &mut ethers::utils::rlp::RlpStream) {
        stream.begin_list(2);
        stream.append(&self.paymaster.as_bytes());
        stream.append(&self.paymaster_input);
    }
}
