use super::{utils, Eip712SignInput};
use ethers::types::{transaction::eip2930::AccessList, Address, Bytes, U256};
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

// TODO: Implement Default for Eip712TransactionRequest.
// impl Default for Eip712TransactionRequest {}
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all(serialize = "camelCase", deserialize = "camelCase"))]
pub struct Eip712Meta {
    pub gas_per_pubdata: U256,
    pub factory_deps: Option<Vec<Bytes>>,
    // TODO: Is this field optional?
    pub custom_signature: Option<Bytes>,
    // TODO: Is this field optional?
    pub paymaster_params: Option<PaymasterParams>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all(serialize = "camelCase", deserialize = "camelCase"))]
pub struct PaymasterParams {
    pub paymaster: Address,
    pub paymaster_input: Vec<u8>,
}

impl Into<Eip712SignInput> for Eip712TransactionRequest {
    fn into(self) -> Eip712SignInput {
        let mut eip712_sign_input = Eip712SignInput::default();

        eip712_sign_input.tx_type = self.r#type;
        eip712_sign_input.from = self.from;
        eip712_sign_input.to = self.to;
        eip712_sign_input.gas_limit = self.gas_limit;
        eip712_sign_input.max_fee_per_gas = self.max_fee_per_gas;
        eip712_sign_input.max_priority_fee_per_gas = self.max_priority_fee_per_gas;
        eip712_sign_input.nonce = self.nonce;
        eip712_sign_input.value = self.value;
        eip712_sign_input.data = self.data;

        if let Some(custom_data) = self.custom_data {
            eip712_sign_input.factory_deps = custom_data.factory_deps;
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
