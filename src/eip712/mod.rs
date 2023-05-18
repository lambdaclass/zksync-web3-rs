use ethers::{
    providers::Middleware,
    types::{
        transaction::eip712::{EIP712Domain, Eip712, Eip712DomainType, Eip712Error},
        Bytes, H160, U256,
    },
};
use serde::{Deserialize, Serialize};

mod utils;

pub struct Eip712TransactionRequest {}

impl Into<Eip712SignInput> for Eip712TransactionRequest {
    fn into(self) -> Eip712SignInput {
        todo!()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all(serialize = "camelCase", deserialize = "camelCase"))]
pub struct Eip712SignInput {
    pub tx_type: U256,
    pub from: Option<U256>,
    pub to: Option<U256>,
    pub gas_limit: Option<U256>,
    pub gas_per_pubdata_byte_limit: U256,
    pub max_fee_per_gas: Option<U256>,
    pub max_priority_fee_per_gas: Option<U256>,
    pub paymaster: Option<U256>,
    pub nonce: Option<U256>,
    pub value: Option<U256>,
    pub data: Option<Bytes>,
    pub factory_deps: Option<Vec<Bytes>>,
    pub paymaster_input: Option<Bytes>,
}

impl Eip712 for Eip712SignInput {
    type Error = Eip712Error;

    fn domain(&self) -> Result<EIP712Domain, Self::Error> {
        Ok(EIP712Domain {
            name: Some(String::from("zkSync")),
            version: Some(String::from("2")),
            chain_id: Some(U256::from(9_i32)),
            // TODO: Get the actual zkSync contract address.
            verifying_contract: None,
            salt: None,
        })
    }

    fn type_hash() -> Result<[u8; 32], Self::Error> {
        todo!()
    }

    /// The 32-byte hash of the bytecode of a zkSync contract is calculated in the following way:
    ///
    /// * The first 2 bytes denote the version of bytecode hash format and are currently equal to [1,0].
    /// * The second 2 bytes denote the length of the bytecode in 32-byte words.
    /// * The rest of the 28-byte (i.e. 28 low big-endian bytes) are equal to the last 28 bytes of the sha256 hash of the contract's bytecode.
    fn struct_hash(&self) -> Result<[u8; 32], Self::Error> {
        let bytecode_hash_format_version;
        let bytecode_length;
        let bytecode_hash;
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::{
        prelude::k256::ecdsa::SigningKey,
        providers::{Middleware, Provider},
        signers::{Signer, Wallet},
    };

    #[tokio::test]
    async fn test_pay_transaction() {
        let mut tx = Eip712TransactionRequest {};
        let mut tx_sign_input = Eip712SignInput {
            tx_type: utils::EIP712_TX_TYPE.into(),
            from: None,
            to: None,
            gas_limit: None,
            gas_per_pubdata_byte_limit: utils::DEFAULT_GAS_PER_PUBDATA_LIMIT.into(),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            paymaster: None,
            nonce: None,
            value: None,
            data: None,
            factory_deps: None,
            paymaster_input: None,
        };

        let mut wallet = "0x28a574ab2de8a00364d5dd4b07c4f2f574ef7fcc2a86a197f65abaec836d1959"
            .parse::<Wallet<SigningKey>>()
            .unwrap();
        wallet = Wallet::with_chain_id(
            wallet,
            tx_sign_input.domain().unwrap().chain_id.unwrap().as_u64(),
        );

        let provider = Provider::try_from(format!(
            "http://{host}:{port}",
            host = "65.108.204.116",
            port = 3050
        ))
        .unwrap();

        let signature = wallet.sign_typed_data(&tx_sign_input).await.unwrap();

        println!(
            "{:?}",
            provider
                .send_raw_transaction(signature.to_vec().into())
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    #[ignore = "not yet implemented"]
    async fn test_call_transaction() {}

    #[tokio::test]
    #[ignore = "not yet implemented"]
    async fn test_deploy_transaction() {}
}
