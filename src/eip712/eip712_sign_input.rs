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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<U256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Bytes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub factory_deps: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
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
        Ok(keccak256(encode_type(
            "zkSync",
            &eip712_sign_input_types(),
        )?))
    }

    fn struct_hash(&self) -> Result<[u8; 32], Self::Error> {
        let type_hash = <EIP712WithDomain<Self> as Eip712>::type_hash()?;
        Ok(keccak256(
            [
                &type_hash,
                &encode(&encode_data(
                    "zkSync",
                    &json!(self),
                    &eip712_sign_input_types(),
                )?)[..],
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
        types::Signature,
        utils::{
            keccak256,
            rlp::{Encodable, Rlp, RlpStream},
        },
    };

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

        let fee = provider.estimate_fee(tx.clone()).await.unwrap();

        tx.max_priority_fee_per_gas = Some(fee.max_priority_fee_per_gas);
        tx.max_fee_per_gas = Some(fee.max_fee_per_gas);
        tx.gas_limit = Some(fee.gas_limit);

        // tx.max_priority_fee_per_gas = Some(U256::from(500000000));
        // tx.max_fee_per_gas = Some(U256::from(50000));
        // tx.gas_limit = Some(U256::zero());
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

        /* Update Wallet */

        wallet = Wallet::with_chain_id(
            wallet,
            tx_sign_input.domain().unwrap().chain_id.unwrap().as_u64(),
        );

        /* Testing */

        if let Some(custom_data) = &mut tx.custom_data {
            let signature: Signature = Wallet::sign_typed_data(&wallet, &tx_sign_input)
                .await
                .unwrap();
            let signature_bytes = Bytes::from(signature.to_vec());
            custom_data.custom_signature = Some(signature_bytes);

            let mut stream = RlpStream::new();
            stream.begin_unbounded_list();
            tx.rlp_append(&mut stream);
            stream.finalize_unbounded_list();
            let rlp_encoded = stream.out().freeze();

            let rlp = Rlp::new(&rlp_encoded);

            println!("RLP ITEM COUNT: {:?}", rlp.item_count());
            // Print 16 rlp.val_at
            println!("nonce: {:?}", rlp.val_at::<U256>(0).unwrap());
            println!(
                "max_priority_fee_per_gas: {:?}",
                rlp.val_at::<U256>(1).unwrap()
            );
            println!("gas_price: {:?}", rlp.val_at::<U256>(2).unwrap());
            println!("gas_limit: {:?}", rlp.val_at::<U256>(3).unwrap());
            println!("to: {:?}", rlp.val_at::<Address>(4).unwrap());
            println!("value: {:?}", rlp.val_at::<U256>(5).unwrap());
            println!("data: {:?}", rlp.val_at::<U256>(6).unwrap()); // Should be bytes
            println!("v: {:?}", rlp.val_at::<U256>(7).unwrap());
            println!("r: {:?}", rlp.val_at::<U256>(8).unwrap());
            println!("s: {:?}", rlp.val_at::<U256>(9).unwrap());
            println!("chain_id: {:?}", rlp.val_at::<U256>(10).unwrap());
            println!("from: {:?}", rlp.val_at::<Address>(11).unwrap());
            println!("gas_per_pub_data: {:?}", rlp.val_at::<U256>(12).unwrap());
            // println!("factory_deps: {:?}", rlp.list_at(13).unwrap());
            // println!("custom_signature: {:?}", rlp.val_at(14).unwrap());
            // println!("paymaster_params: {:?}", rlp.val_at(15).unwrap());

            println!(
                "{:?}",
                provider
                    .send_raw_transaction(Bytes::from(
                        [&[EIP712_TX_TYPE], &rlp_encoded[..]].concat()
                    ))
                    .await
                    .unwrap()
            );
        }
    }
}
