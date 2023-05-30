use ethers::{
    abi::encode,
    types::{
        transaction::eip712::{
            encode_data, encode_type, EIP712Domain, Eip712, Eip712DomainType,
            Eip712Error, Types,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_limit: Option<U256>,
    // NOTE: this value must be set after calling ZKSProvider::estimate_fee method.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_per_pubdata_byte_limit: Option<U256>,
    // TODO: This field has a default value or calculation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_fee_per_gas: Option<U256>,
    // TODO: This field has a default value or calculation
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

// FIXME: Cleanup this.
pub fn eip712_sign_input_types() -> Types {
    let mut types = Types::new();

    types.insert(
        "Transaction".to_string(),
        vec![
            Eip712DomainType {
                name: "txType".to_string(),
                r#type: "uint256".to_string(),
            },
            Eip712DomainType {
                name: "from".to_string(),
                r#type: "uint256".to_string(),
            },
            Eip712DomainType {
                name: "to".to_string(),
                r#type: "uint256".to_string(),
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
                r#type: "uint256".to_string(),
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
                r#type: "bytes32[]".to_string(),
            },
            Eip712DomainType {
                name: "paymasterInput".to_string(),
                r#type: "bytes".to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        eip712::{
            eip712_transaction_request::{Eip712Meta, PaymasterParams},
            utils::{DEFAULT_GAS_PER_PUBDATA_LIMIT, EIP712_TX_TYPE},
            Eip712TransactionRequest,
        },
        zks_provider::ZKSProvider,
        zks_utils::{CONTRACT_DEPLOYER_ADDR, ERA_CHAIN_ID},
    };
    use ethers::{
        abi::AbiEncode,
        prelude::{k256::ecdsa::SigningKey, MiddlewareBuilder},
        providers::{Middleware, Provider},
        signers::Signer,
        signers::Wallet,
        types::Signature,
        utils::keccak256, solc::{ProjectPathsConfig, Project, Artifact},
    };

    #[tokio::test]
    async fn testito2() {
        let wallet = "0x7726827caac94a7f9e1b160f7ea819f172f7b6f9d2a97f992c38edeab82d4110"
            .parse::<Wallet<SigningKey>>()
            .unwrap();

        let provider = Provider::try_from(format!(
            "http://{host}:{port}",
            // host = "65.108.204.116",
            host = "localhost",
            port = 3050
        ))
        .unwrap()
        .with_signer(wallet.clone());

        let nonce = provider
            .get_transaction_count(
                "0x36615Cf349d7F6344891B1e7CA7C72883F5dc049"
                    .parse::<Address>()
                    .unwrap(),
                None,
            )
            .await
            .unwrap()
            .encode_hex();
        let mut tx: Eip712TransactionRequest = serde_json::from_str(&format!(r#"{{
            "chainId": "0x10E",
            "nonce": "{nonce}",
            "from": "0x36615Cf349d7F6344891B1e7CA7C72883F5dc049",
            "to": "0x0000000000000000000000000000000000008006",
            "gas": "0x0",
            "gasPrice": "0xED4A5100",
            "maxPriorityFeePerGas": "0x5F5E100",
            "value": "0x0",
            "data": "0x9c4d535b00000000000000000000000000000000000000000000000000000000000000000100001bcf3424d9bc67cdb6eca8cfb731cec86df28064283f3c82fb1bf5c8be00000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000000",
            "type": "0x71",
            "customData": {{
                "gasPerPubdata": "0xC350",
                "customSignature": null,
                "factoryDeps": [
                    "0x000200000000000200010000000103550000006001100270000000130010019d0000008001000039000000400010043f0000000101200190000000290000c13d0000000001000031000000040110008c000000420000413d0000000101000367000000000101043b000000e001100270000000150210009c000000310000613d000000160110009c000000420000c13d0000000001000416000000000110004c000000420000c13d000000040100008a00000000011000310000001702000041000000200310008c000000000300001900000000030240190000001701100197000000000410004c000000000200a019000000170110009c00000000010300190000000001026019000000000110004c000000420000c13d00000004010000390000000101100367000000000101043b000000000010041b0000000001000019000000490001042e0000000001000416000000000110004c000000420000c13d0000002001000039000001000010044300000120000004430000001401000041000000490001042e0000000001000416000000000110004c000000420000c13d000000040100008a00000000011000310000001702000041000000000310004c000000000300001900000000030240190000001701100197000000000410004c000000000200a019000000170110009c00000000010300190000000001026019000000000110004c000000440000613d00000000010000190000004a00010430000000000100041a000000800010043f0000001801000041000000490001042e0000004800000432000000490001042e0000004a00010430000000000000000000000000000000000000000000000000000000000000000000000000ffffffff0000000200000000000000000000000000000040000001000000000000000000000000000000000000000000000000000000000000000000000000006d4ce63c0000000000000000000000000000000000000000000000000000000060fe47b1800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000008000000000000000000000000000000000000000000000000000000000000000000000000000000000d5c7d2782d356f4a1a2e458d242d21e07a04810c9f771eed6501083e07288c87"
                ],
                "paymasterParams": {{
                    "paymaster": "0x0000000000000000000000000000000000000000",
                    "paymasterInput": "0x"
                }}
            }}
        }}"#)).unwrap();

        let fee = provider.estimate_fee(tx.clone()).await.unwrap();

        tx.max_fee_per_gas = Some(fee.max_fee_per_gas);
        tx.gas_limit = Some(U256::from("0x2d611"));

        let eip712: Eip712SignInput = tx.clone().into();

        if let Some(custom_data) = &mut tx.custom_data {
            let signature: Signature = Wallet::sign_typed_data(&wallet, &eip712).await.unwrap();
            let signature_bytes = Bytes::from(signature.to_vec());
            custom_data.custom_signature = Some(signature_bytes);
        }

        let eip712: Eip712SignInput = tx.clone().into();
        let signed_msg = wallet.sign_typed_data(&eip712).await.unwrap();
        let unsigned_rlp_encoded = tx.rlp_signed(signed_msg);
        let deployment_transaction_receipt = provider
            .send_raw_transaction(
                [&[EIP712_TX_TYPE], &unsigned_rlp_encoded[..]]
                    .concat()
                    .into(),
            )
            .await
            .unwrap()
            .await
            .unwrap()
            .unwrap();
        println!("TRANSACTION RECEIPT {:?}", deployment_transaction_receipt);
        println!(
            "TRANSACTION HASH {:?}",
            deployment_transaction_receipt.transaction_hash
        );
        println!(
            "CONTRACT ADDRESS {:?}",
            deployment_transaction_receipt.contract_address
        );
    }

    #[tokio::test]
    async fn test_eip712() {
        /* Create Wallet */

        let mut wallet = "0x7726827caac94a7f9e1b160f7ea819f172f7b6f9d2a97f992c38edeab82d4110"
            .parse::<Wallet<SigningKey>>()
            .unwrap();

        /* Connect to node */

        let provider = Provider::try_from(format!(
            "http://{host}:{port}",
            // host = "65.108.204.116",
            host = "localhost",
            port = 3050
        ))
        .unwrap()
        .with_signer(wallet.clone());

        /* Create Transaction */

        let mut tx = Eip712TransactionRequest::default();

        tx.r#type = EIP712_TX_TYPE.into();
        tx.from = "0x36615Cf349d7F6344891B1e7CA7C72883F5dc049".parse().ok();
        tx.to = CONTRACT_DEPLOYER_ADDR.parse().ok();
        tx.chain_id = ERA_CHAIN_ID.into();
        tx.nonce = provider.get_transaction_count(tx.from.unwrap(), None).await.unwrap();
        tx.value = U256::zero();
        tx.gas_price = provider.get_gas_price().await.unwrap();

        let build_data = |function_signature: &str| -> Bytes {
            // See https://docs.soliditylang.org/en/latest/abi-spec.html#examples
            // TODO: Support all kind of function calls and return cast
            // (nowadays we only support empty function calls).
            Bytes::from(keccak256(function_signature.as_bytes())
                .get(0..4)
                .unwrap()
                .to_vec())
        };
        tx.data = Some(build_data("create"));
        tx.data = Some(Bytes::from(hex::decode("9c4d535b00000000000000000000000000000000000000000000000000000000000000000100001bcf3424d9bc67cdb6eca8cfb731cec86df28064283f3c82fb1bf5c8be00000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000000").unwrap()));

        // Build custom data
        let paths = ProjectPathsConfig::builder().build_with_root("./src/compile/test_contracts/test");
        let project = Project::builder()
            .paths(paths)
            .set_auto_detect(true)
            .no_artifacts()
            .build()
            .unwrap();
        let compilation_output = project.compile().unwrap();
        let contract = compilation_output
            .find_first("Test")
            .unwrap()
            .clone();
        let (_, bytecode, _) = contract.into_parts();

        let mut custom_data = Eip712Meta::default();
        custom_data.factory_deps = Some(vec![[bytecode.unwrap().to_vec(), hex::decode("000000000000000000000000000000").unwrap()].concat().into()]);
        custom_data.gas_per_pubdata = DEFAULT_GAS_PER_PUBDATA_LIMIT.into();
        custom_data.paymaster_params = Some(PaymasterParams::default());
        tx.custom_data = Some(custom_data);

        let fee = provider.estimate_fee(tx.clone()).await.unwrap();
        tx.max_priority_fee_per_gas = Some(fee.max_priority_fee_per_gas);
        tx.max_fee_per_gas = Some(fee.max_fee_per_gas);
        tx.gas_limit = Some(fee.gas_limit);

        /* Create Sign Input */

        let mut tx_sign_input: Eip712SignInput = tx.clone().into();

        tx_sign_input.gas_per_pubdata_byte_limit = Some(DEFAULT_GAS_PER_PUBDATA_LIMIT.into());

        /* Update Wallet */

        wallet = Wallet::with_chain_id(
            wallet,
            tx_sign_input.domain().unwrap().chain_id.unwrap().as_u64(),
        );

        if let Some(custom_data) = &mut tx.custom_data {
            let signature: Signature = Wallet::sign_typed_data(&wallet, &tx_sign_input)
                .await
                .unwrap();
            let signature_bytes = Bytes::from(signature.to_vec());
            custom_data.custom_signature = Some(signature_bytes);
        }

        println!("{tx:#?}");

        /* Transaction Signing */
        println!(
            "{:?}",
            provider
                .send_raw_transaction(
                    [&[EIP712_TX_TYPE], &tx.rlp_unsigned()[..]]
                        .concat()
                        .into()
                )
                .await
                .unwrap()
        );
    }
}
