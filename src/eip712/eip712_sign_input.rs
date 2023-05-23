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
        let types = eip712_sign_input_types();
        let type_hash = keccak256(encode_type("zkSync", &types)?);
        Ok(keccak256(
            [
                &type_hash,
                &encode(&encode_data("zkSync", &json!(self), &types)?)[..],
            ]
            .concat(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        eip712::{
            eip712_transaction_request::Eip712Meta,
            utils::{DEFAULT_GAS_PER_PUBDATA_LIMIT, EIP712_TX_TYPE},
            Eip712TransactionRequest,
        },
        zks_provider::ZKSProvider,
        zks_utils::CONTRACT_DEPLOYER_ADDR,
    };
    use ethers::{
        abi::encode,
        providers::{Middleware, Provider},
        utils::keccak256,
    };

    #[tokio::test]
    async fn test_eip712() {
        /* Connect to node */

        let provider = Provider::try_from(format!(
            "http://{host}:{port}",
            host = "65.108.204.116",
            port = 3050
        ))
        .unwrap();

        /* Create Transaction */

        let mut tx = Eip712TransactionRequest::default();

        tx.r#type = EIP712_TX_TYPE.into();
        tx.from = "0xbd29A1B981925B94eEc5c4F1125AF02a2Ec4d1cA".parse().ok();
        tx.to = CONTRACT_DEPLOYER_ADDR.parse().ok();
        tx.chain_id = 270.into();

        // let fee = provider.estimate_fee(tx.clone()).await.unwrap();

        // tx.max_priority_fee_per_gas = Some(fee.max_priority_fee_per_gas);
        // tx.max_fee_per_gas = Some(fee.max_fee_per_gas);
        // tx.gas_limit = Some(fee.gas_limit);

        // Build data
        let build_data = |function_signature: &str| -> eyre::Result<Vec<u8>> {
            // See https://docs.soliditylang.org/en/latest/abi-spec.html#examples
            // TODO: Support all kind of function calls and return cast
            // (nowadays we only support empty function calls).
            Ok(keccak256(function_signature.as_bytes())
                .get(0..4)
                .unwrap()
                .to_vec())
        };

        tx.data = Some(build_data("create()").unwrap().into());

        // Build custom data
        let paymaster_contract = provider.get_testnet_paymaster().await.unwrap();
        let paymaster_contract_bytecode =
            provider.get_code(paymaster_contract, None).await.unwrap();

        let mut custom_data = Eip712Meta::default();
        custom_data.factory_deps = Some(vec![paymaster_contract_bytecode]);
        custom_data.gas_per_pubdata = DEFAULT_GAS_PER_PUBDATA_LIMIT.into();

        tx.custom_data = Some(custom_data);

        /* Create Sign Input */

        let mut tx_sign_input: Eip712SignInput = tx.clone().into();

        tx_sign_input.gas_per_pubdata_byte_limit = Some(DEFAULT_GAS_PER_PUBDATA_LIMIT.into());

        /* Testing */

        let encoded_type = encode_type("zkSync", &eip712_sign_input_types()).unwrap();
        let type_hash = keccak256(&encoded_type);
        println!("{:?}", encoded_type);
        println!("{:?}", type_hash);

        let encoded_data =
            encode_data("zkSync", &json!(tx_sign_input), &eip712_sign_input_types()).unwrap();
        println!("{:?}", encoded_data);
        println!("{:?}", encode(&encoded_data));

        println!("{:?}", tx_sign_input.struct_hash().unwrap());

        println!("{:?}", tx_sign_input.encode_eip712().unwrap());
    }
}
