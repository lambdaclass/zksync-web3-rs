use super::{hash_bytecode, Eip712TransactionRequest};
use crate::zks_utils::{self, DEFAULT_GAS_PER_PUBDATA_LIMIT};
use ethers::{
    abi::encode,
    types::{
        transaction::eip712::{
            encode_data, encode_type, EIP712Domain, Eip712, Eip712DomainType, Eip712Error, Types,
        },
        Address, Bytes, U256,
    },
    utils::keccak256,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::str::FromStr;

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename_all(serialize = "camelCase", deserialize = "camelCase"))]
pub struct Eip712SignInput {
    pub tx_type: U256,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_limit: Option<U256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_per_pubdata_byte_limit: Option<U256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_fee_per_gas: Option<U256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_priority_fee_per_gas: Option<U256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paymaster: Option<Address>,
    pub nonce: U256,
    pub value: U256,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Bytes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub factory_deps: Option<Vec<Bytes>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paymaster_input: Option<Bytes>,
}

impl Eip712SignInput {
    pub fn new() -> Self {
        Self::default()
    }
}

// FIXME: Cleanup this.
pub fn eip712_sign_input_types() -> Types {
    let mut types = Types::new();

    types.insert(
        "Transaction".to_owned(),
        vec![
            Eip712DomainType {
                name: "txType".to_owned(),
                r#type: "uint256".to_owned(),
            },
            Eip712DomainType {
                name: "from".to_owned(),
                r#type: "uint256".to_owned(),
            },
            Eip712DomainType {
                name: "to".to_owned(),
                r#type: "uint256".to_owned(),
            },
            Eip712DomainType {
                name: "gasLimit".to_owned(),
                r#type: "uint256".to_owned(),
            },
            Eip712DomainType {
                name: "gasPerPubdataByteLimit".to_owned(),
                r#type: "uint256".to_owned(),
            },
            Eip712DomainType {
                name: "maxFeePerGas".to_owned(),
                r#type: "uint256".to_owned(),
            },
            Eip712DomainType {
                name: "maxPriorityFeePerGas".to_owned(),
                r#type: "uint256".to_owned(),
            },
            Eip712DomainType {
                name: "paymaster".to_owned(),
                r#type: "uint256".to_owned(),
            },
            Eip712DomainType {
                name: "nonce".to_owned(),
                r#type: "uint256".to_owned(),
            },
            Eip712DomainType {
                name: "value".to_owned(),
                r#type: "uint256".to_owned(),
            },
            Eip712DomainType {
                name: "data".to_owned(),
                r#type: "bytes".to_owned(),
            },
            Eip712DomainType {
                name: "factoryDeps".to_owned(),
                r#type: "bytes32[]".to_owned(),
            },
            Eip712DomainType {
                name: "paymasterInput".to_owned(),
                r#type: "bytes".to_owned(),
            },
        ],
    );
    types
}

impl Eip712 for Eip712SignInput {
    type Error = Eip712Error;

    fn domain(&self) -> Result<EIP712Domain, Self::Error> {
        Ok(EIP712Domain {
            name: Some(String::from("zkSync")),
            version: Some(String::from("2")),
            chain_id: Some(U256::from(270_i32)),
            verifying_contract: None,
            salt: None,
        })
    }

    fn type_hash() -> Result<[u8; 32], Self::Error> {
        Ok(keccak256(encode_type(
            "Transaction",
            &eip712_sign_input_types(),
        )?))
    }

    fn struct_hash(&self) -> Result<[u8; 32], Self::Error> {
        let hash = keccak256(encode(&encode_data(
            "Transaction",
            &json!(self),
            &eip712_sign_input_types(),
        )?));
        Ok(hash)
    }
}

impl TryFrom<Eip712TransactionRequest> for Eip712SignInput {
    type Error = Eip712Error;

    fn try_from(tx: Eip712TransactionRequest) -> Result<Self, Self::Error> {
        let mut eip712_sign_input = Eip712SignInput::new();

        eip712_sign_input.tx_type = tx.r#type;
        eip712_sign_input.from = tx.from;
        eip712_sign_input.to = tx.to;
        eip712_sign_input.gas_limit = tx.gas_limit;
        // TODO create a new constant for default value
        eip712_sign_input.max_fee_per_gas = tx.max_fee_per_gas.or(Some(U256::from("0x0ee6b280")));
        // TODO create a new constant for default value
        eip712_sign_input.max_priority_fee_per_gas = tx
            .max_priority_fee_per_gas
            .or(Some(U256::from("0x0ee6b280")));
        eip712_sign_input.nonce = tx.nonce;
        eip712_sign_input.value = tx.value;
        eip712_sign_input.data = tx.data;

        if let Some(custom_data) = tx.custom_data {
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
                Some(U256::from(DEFAULT_GAS_PER_PUBDATA_LIMIT));
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

        Ok(eip712_sign_input)
    }
}
