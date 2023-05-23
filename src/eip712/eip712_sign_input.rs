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

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename_all(serialize = "camelCase", deserialize = "camelCase"))]
pub struct Eip712SignInput {
    pub tx_type: U256,
    pub from: Option<Address>,
    pub to: Option<Address>,
    pub gas_limit: Option<U256>,
    // NOTE: this value must be set after calling ZKSProvider::estimate_fee method.
    pub gas_per_pubdata_byte_limit: Option<U256>,
    // TODO: This field has a default value or calculation
    pub max_fee_per_gas: Option<U256>,
    // TODO: This field has a default value or calculation
    pub max_priority_fee_per_gas: Option<U256>,
    pub paymaster: Option<Address>,
    pub nonce: U256,
    pub value: Option<U256>,
    pub data: Option<Bytes>,
    pub factory_deps: Option<Vec<u8>>,
    pub paymaster_input: Option<Vec<u8>>,
}

// FIXME: Cleanup this.
pub fn eip712_sign_input_types() -> Types {
    let mut types = Types::new();

    types.insert(
        "zkSync".to_string(),
        vec![
            Eip712DomainType {
                name: "txType".to_string(),
                r#type: "uint256".to_string(),
            },
            Eip712DomainType {
                name: "from".to_string(),
                r#type: "address".to_string(),
            },
            Eip712DomainType {
                name: "to".to_string(),
                r#type: "address".to_string(),
            },
            Eip712DomainType {
                name: "gasLimit".to_string(),
                r#type: "uint256".to_string(),
            },
            Eip712DomainType {
                name: "gasPerPubdataByteLimit".to_string(),
                r#type: "uint256".to_string(),
            },
            Eip712DomainType {
                name: "maxFeePerGas".to_string(),
                r#type: "uint256".to_string(),
            },
            Eip712DomainType {
                name: "maxPriorityFeePerGas".to_string(),
                r#type: "uint256".to_string(),
            },
            Eip712DomainType {
                name: "paymaster".to_string(),
                r#type: "address".to_string(),
            },
            Eip712DomainType {
                name: "nonce".to_string(),
                r#type: "uint256".to_string(),
            },
            Eip712DomainType {
                name: "value".to_string(),
                r#type: "uint256".to_string(),
            },
            Eip712DomainType {
                name: "data".to_string(),
                r#type: "bytes".to_string(),
            },
            Eip712DomainType {
                name: "factoryDeps".to_string(),
                r#type: "bytes".to_string(),
            },
            Eip712DomainType {
                name: "paymasterInput".to_string(),
                r#type: "bytes".to_string(),
            },
        ],
    );
    types.insert("uint256".to_string(), Vec::new());
    types.insert("bytes".to_string(), Vec::new());

    types
}

impl Eip712 for Eip712SignInput {
    type Error = Eip712Error;

    fn domain(&self) -> Result<EIP712Domain, Self::Error> {
        Ok(EIP712Domain {
            name: Some(String::from("zkSync")),
            version: Some(String::from("2")),
            chain_id: Some(U256::from(270_i32)),
            verifying_contract: "0xDAbb67b676F5b01FcC8997Cc8439846D0d8078ca".parse().ok(),
            salt: Some([0_u8; 32]),
        })
    }

    fn type_hash() -> Result<[u8; 32], Self::Error> {
        todo!()
    }

    fn struct_hash(&self) -> Result<[u8; 32], Self::Error> {
        todo!()
    }
}
