use ethers::{
    abi::encode,
    types::{
        transaction::eip712::{
            encode_data, encode_type, EIP712Domain, EIP712WithDomain, Eip712, Eip712DomainType,
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
        Ok(keccak256(encode_data("Transaction", &json!(self), &eip712_sign_input_types())?))
        // Ok(keccak256(
        //     [
        //         // &Self::type_hash()?,
        //         &encode(&encode_data(
        //             "Transaction",
        //             &json!(self),
        //             &eip712_sign_input_types(),
        //         )?)[..],
        //     ]
        //     .concat(),
        // ))
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
        zks_utils::CONTRACT_DEPLOYER_ADDR,
    };
    use ethers::{
        prelude::{k256::ecdsa::SigningKey, MiddlewareBuilder},
        providers::{Middleware, Provider},
        signers::Signer,
        signers::Wallet,
        types::{transaction::eip712::TypedData, Signature},
        utils::{keccak256, rlp::Rlp},
    };
    use std::collections::BTreeMap;

    #[tokio::test]
    async fn testito2() {
        let mut wallet = "0xf12e28c0eb1ef4ff90478f6805b68d63737b7f33abfa091601140805da450d93"
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

        let mut tx: Eip712TransactionRequest = serde_json::from_str(r#"{
            "chainId": "0x10E",
            "nonce": "0x30",
            "from": "0x36615Cf349d7F6344891B1e7CA7C72883F5dc049",
            "to": "0x0000000000000000000000000000000000008006",
            "gas": "0x0",
            "gasPrice": "0xED4A5100",
            "maxPriorityFeePerGas": "0x5F5E100",
            "value": "0x0",
            "data": "0x9c4d535b00000000000000000000000000000000000000000000000000000000000000000100001bcf3424d9bc67cdb6eca8cfb731cec86df28064283f3c82fb1bf5c8be00000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000000",
            "type": "0x71",
            "customData": {
                "gasPerPubdata": "0xC350",
                "customSignature": null,
                "factoryDeps": [
                    "0x000200000000000200010000000103550000006001100270000000130010019d0000008001000039000000400010043f0000000101200190000000290000c13d0000000001000031000000040110008c000000420000413d0000000101000367000000000101043b000000e001100270000000150210009c000000310000613d000000160110009c000000420000c13d0000000001000416000000000110004c000000420000c13d000000040100008a00000000011000310000001702000041000000200310008c000000000300001900000000030240190000001701100197000000000410004c000000000200a019000000170110009c00000000010300190000000001026019000000000110004c000000420000c13d00000004010000390000000101100367000000000101043b000000000010041b0000000001000019000000490001042e0000000001000416000000000110004c000000420000c13d0000002001000039000001000010044300000120000004430000001401000041000000490001042e0000000001000416000000000110004c000000420000c13d000000040100008a00000000011000310000001702000041000000000310004c000000000300001900000000030240190000001701100197000000000410004c000000000200a019000000170110009c00000000010300190000000001026019000000000110004c000000440000613d00000000010000190000004a00010430000000000100041a000000800010043f0000001801000041000000490001042e0000004800000432000000490001042e0000004a00010430000000000000000000000000000000000000000000000000000000000000000000000000ffffffff0000000200000000000000000000000000000040000001000000000000000000000000000000000000000000000000000000000000000000000000006d4ce63c0000000000000000000000000000000000000000000000000000000060fe47b1800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000008000000000000000000000000000000000000000000000000000000000000000000000000000000000d5c7d2782d356f4a1a2e458d242d21e07a04810c9f771eed6501083e07288c87"
                ],
                "paymasterParams": {
                    "paymaster": "0x0000000000000000000000000000000000000000",
                    "paymasterInput": "0x"
                }
            }
        }"#).unwrap();
        println!("{tx:#?}");

        let fee = provider.estimate_fee(tx.clone()).await.unwrap();
        println!("{fee:#?}");

        tx.max_priority_fee_per_gas = Some(fee.max_priority_fee_per_gas);
        tx.max_fee_per_gas = Some(fee.max_fee_per_gas);
        tx.gas_limit = Some(fee.gas_limit);

        let eip712: Eip712SignInput = tx.clone().into();

        println!("{eip712:#?}");

        fn _encode_data(
            primary_type: &str,
            data: &serde_json::Value,
            types: &Types,
        ) -> Result<Vec<ethers::abi::Token>, Eip712Error> {
            let hash = ethers::types::transaction::eip712::hash_type(primary_type, types)?;
            let mut tokens = vec![ethers::abi::Token::Uint(U256::from(hash))];
        
            if let Some(fields) = types.get(primary_type) {
                for field in fields {
                    // handle recursive types
                    if let Some(value) = data.get(&field.name) {
                        println!("THERE IS SOME VALUE: {:?}", field.name);
                        println!("{:?}", field.r#type);
                        println!("{:?}", value);
                        let field = ethers::types::transaction::eip712::encode_field(types, &field.name, &field.r#type, value)?;
                        println!("FIELD: {field:?}");
                        tokens.push(field);
                    } else if types.contains_key(&field.r#type) {
                        tokens.push(ethers::abi::Token::Uint(U256::zero()));
                    } else {
                        return Err(Eip712Error::Message(format!("No data found for: `{}`", field.name)))
                    }
                }
            }
        
            Ok(tokens)
        }

        println!("STRUCT HASH: {:?}", hex::decode(eip712.struct_hash().unwrap()));
        assert_eq!("Transaction(uint256 txType,uint256 from,uint256 to,uint256 gasLimit,uint256 gasPerPubdataByteLimit,uint256 maxFeePerGas,uint256 maxPriorityFeePerGas,uint256 paymaster,uint256 nonce,uint256 value,bytes data,bytes32[] factoryDeps,bytes paymasterInput)", encode_type("Transaction", &eip712_sign_input_types()).unwrap());

        if let Some(custom_data) = &mut tx.custom_data {
            let signature: Signature = Wallet::sign_typed_data(&wallet, &eip712)
                .await
                .unwrap();
            let signature_bytes = Bytes::from(signature.to_vec());
            custom_data.custom_signature = Some(signature_bytes);
        }

        let unsigned_rlp_encoded = tx.rlp_unsigned();

        println!(
            "{:?}",
            provider
                .send_raw_transaction(
                    [&[EIP712_TX_TYPE], &unsigned_rlp_encoded[..]]
                        .concat()
                        .into()
                )
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_eip712() {
        /* Create Wallet */

        let mut wallet = "0xf12e28c0eb1ef4ff90478f6805b68d63737b7f33abfa091601140805da450d93"
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
        tx.from = "0x8002cD98Cfb563492A6fB3E7C8243b7B9Ad4cc92".parse().ok();
        tx.to = CONTRACT_DEPLOYER_ADDR.parse().ok();
        tx.chain_id = 270.into();

        // let fee = provider.estimate_fee(tx.clone()).await.unwrap();
        // tx.max_priority_fee_per_gas = Some(fee.max_priority_fee_per_gas);
        // tx.max_fee_per_gas = Some(fee.max_fee_per_gas);
        // tx.gas_limit = Some(fee.gas_limit);

        tx.max_priority_fee_per_gas = Some(U256::from(u64::MAX / 2));
        tx.max_fee_per_gas = Some(U256::from(u64::MAX / 2));
        tx.gas_limit = Some(U256::from(100000));
        tx.gas_price = Some(U256::one());

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

        tx.data = Some(build_data("create").unwrap().into());

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

        /* Testing */

        /* Transaction Signing */
        let signature: Signature = Wallet::sign_typed_data(&wallet, &tx_sign_input)
            .await
            .unwrap();

        // let sighash = keccak256([&[EIP712_TX_TYPE], &tx.rlp(None)[..]].concat());
        // let mut signature = wallet.sign_hash(sighash.into()).unwrap();
        println!("V: {}", signature.v);

        let unsigned_rlp_encoded = tx.rlp(None);
        let rlp = Rlp::new(&unsigned_rlp_encoded);
        println!("V: {}", rlp.val_at::<U256>(7).unwrap());

        println!(
            "{:?}",
            provider
                .send_raw_transaction(
                    [&[EIP712_TX_TYPE], &unsigned_rlp_encoded[..]]
                        .concat()
                        .into()
                )
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn testito() {
        /* Create Wallet */

        let mut wallet = "0xf12e28c0eb1ef4ff90478f6805b68d63737b7f33abfa091601140805da450d93"
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
        tx.chain_id = 270.into();
        tx.nonce = 4.into();
        tx.value = Some(0.into());
        tx.max_priority_fee_per_gas = Some(0x0ee6b280.into());
        tx.max_fee_per_gas = Some(0x0ee6b280.into());
        tx.gas_limit = Some(0x02f589.into());
        tx.gas_price = Some(U256::one());
        tx.data = Some(hex::decode("9c4d535b00000000000000000000000000000000000000000000000000000000000000000100008f4ba7acf2a15d4d159ee5f98b53b01ddccc75588290280820b725987100000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000094869207468657265210000000000000000000000000000000000000000000000").unwrap().into());

        // Build custom data
        let mut custom_data = Eip712Meta::default();
        custom_data.factory_deps = Some(vec![Bytes::from([
            1, 0, 0, 143, 75, 167, 172, 242, 161, 93, 77, 21, 158, 229, 249, 139, 83, 176, 29, 220,
            204, 117, 88, 130, 144, 40, 8, 32, 183, 37, 152, 113,
        ])]);
        custom_data.gas_per_pubdata = 0xc350.into();
        let paymaster_params = PaymasterParams {
            paymaster: "0x0000000000000000000000000000000000000000"
                .parse()
                .unwrap(),
            paymaster_input: Bytes::default(),
        };
        custom_data.paymaster_params = Some(paymaster_params);

        tx.custom_data = Some(custom_data);

        /* Create Sign Input */

        let mut tx_sign_input: Eip712SignInput = tx.clone().into();

        tx_sign_input.gas_per_pubdata_byte_limit = Some(DEFAULT_GAS_PER_PUBDATA_LIMIT.into());

        /* Update Wallet */

        wallet = Wallet::with_chain_id(wallet, 270_u64);

        if let Some(custom_data) = &mut tx.custom_data {
            let signature: Signature = Wallet::sign_typed_data(&wallet, &tx_sign_input)
                .await
                .unwrap();
            let signature_bytes = Bytes::from(signature.to_vec());
            custom_data.custom_signature = Some(signature_bytes);
            custom_data.gas_per_pubdata = 0xc350.into();
        }

        /* ----------------------------------------------------------------- */
        // Turn Eip712SignedInput struct to BTreeMap<String, serde_json::Value>

        let custom_sign_input: Eip712SignInput = Eip712SignInput {
            tx_type: EIP712_TX_TYPE.into(),
            from: "0x36615Cf349d7F6344891B1e7CA7C72883F5dc049".parse().ok(),
            to: "0x0000000000000000000000000000000000008006".parse().ok(),
            gas_limit: Some(0x02f589.into()),
            gas_per_pubdata_byte_limit: Some(0xc350.into()),
            max_fee_per_gas: Some(0x0ee6b280.into()),
            max_priority_fee_per_gas: Some(0x0ee6b280.into()),
            paymaster: "0x0000000000000000000000000000000000000000".parse().ok(),
            nonce: 10.into(),
            value: Some(0.into()),
            data: Some(hex::decode("9c4d535b00000000000000000000000000000000000000000000000000000000000000000100008f4ba7acf2a15d4d159ee5f98b53b01ddccc75588290280820b725987100000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000094869207468657265210000000000000000000000000000000000000000000000").unwrap().into()),
            factory_deps: Some(vec![Bytes::from([ 1, 0, 0, 143, 75, 167, 172, 242, 161, 93, 77, 21, 158, 229, 249, 139, 83, 176, 29, 220, 204, 117, 88, 130, 144, 40, 8, 32, 183, 37, 152, 113 ])]),
            paymaster_input: Some(Bytes::default()),
        };

        let eip712 = TypedData {
            domain: tx_sign_input.domain().unwrap(),
            types: eip712_sign_input_types(),
            message: tx_sign_input.clone().into(),
            primary_type: "Transaction".to_string(),
        };

        let custom_eip712 = TypedData {
            domain: custom_sign_input.domain().unwrap(),
            types: eip712_sign_input_types(),
            message: custom_sign_input.clone().into(),
            primary_type: "Transaction".to_string(),
        };

        let expected: [u8; 32] =
            hex::decode("f4bbabfcf7b40908fd63b07a1db08ea2840ddf4defca49369df60f84b942b0fc")
                .unwrap()
                .try_into()
                .unwrap();

        println!("STRUCT HASHES COMPARISON");
        println!("{:?}", eip712.struct_hash().unwrap());
        println!("{:?}", tx_sign_input.struct_hash().unwrap());
        println!("{:?}", custom_sign_input.struct_hash().unwrap());
        println!("{:?}", custom_eip712.struct_hash().unwrap());
        println!();
        println!("EIP712 ENCODING COMPARISON");
        println!("{:?}", eip712.encode_eip712().unwrap());
        println!("{:?}", tx_sign_input.encode_eip712().unwrap());
        println!("{:?}", custom_sign_input.encode_eip712().unwrap());
        println!("{:?}", custom_eip712.encode_eip712().unwrap());

        println!("EIP712 EXPECTED HASH");
        println!("{:?}", expected);

        /* Tx Signing */

        let signature: Signature = Wallet::sign_typed_data(&wallet, &eip712).await.unwrap();

        // let sighash = keccak256([&[EIP712_TX_TYPE], &tx.rlp(None)[..]].concat());
        // let mut signature = wallet.sign_hash(sighash.into()).unwrap();
        println!("V: {}", signature.v);

        let unsigned_rlp_encoded = tx.rlp(None);
        let rlp = Rlp::new(&unsigned_rlp_encoded);
        println!("V: {}", rlp.val_at::<U256>(7).unwrap());

        println!(
            "{:?}",
            provider
                .send_raw_transaction(
                    [&[EIP712_TX_TYPE], &unsigned_rlp_encoded[..]]
                        .concat()
                        .into()
                )
                .await
                .unwrap()
        );
    }

    impl Into<BTreeMap<String, serde_json::Value>> for Eip712SignInput {
        fn into(self) -> BTreeMap<String, serde_json::Value> {
            let mut map = std::collections::BTreeMap::new();
            map.insert(
                "txType".to_string(),
                serde_json::to_value(self.clone().tx_type).unwrap(),
            );
            map.insert(
                "from".to_string(),
                serde_json::to_value(self.clone().from).unwrap(),
            );
            map.insert(
                "to".to_string(),
                serde_json::to_value(self.clone().to).unwrap(),
            );
            map.insert(
                "gasLimit".to_string(),
                serde_json::to_value(self.clone().gas_limit).unwrap(),
            );
            map.insert(
                "gasPerPubdata".to_string(),
                serde_json::to_value(self.clone().gas_per_pubdata_byte_limit).unwrap(),
            );
            map.insert(
                "maxFeePerGas".to_string(),
                serde_json::to_value(self.clone().max_fee_per_gas).unwrap(),
            );
            map.insert(
                "maxPriorityFeePerGas".to_string(),
                serde_json::to_value(self.clone().max_priority_fee_per_gas).unwrap(),
            );
            map.insert(
                "paymaster".to_string(),
                serde_json::to_value(self.clone().paymaster).unwrap(),
            );
            map.insert(
                "nonce".to_string(),
                serde_json::to_value(self.clone().nonce).unwrap(),
            );
            map.insert(
                "value".to_string(),
                serde_json::to_value(self.clone().value).unwrap(),
            );
            map.insert(
                "data".to_string(),
                serde_json::to_value(self.clone().data).unwrap(),
            );
            map.insert(
                "factoryDeps".to_string(),
                serde_json::to_value(self.clone().factory_deps).unwrap(),
            );
            map.insert(
                "paymasterInput".to_string(),
                serde_json::to_value(self.clone().paymaster_input).unwrap(),
            );
            map
        }
    }
}
