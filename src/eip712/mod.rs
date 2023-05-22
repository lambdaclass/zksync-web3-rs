use ethers::types::{
    transaction::eip712::{EIP712Domain, Eip712, Eip712Error},
    Address, Bytes, U256,
};
use serde::{Deserialize, Serialize};

mod utils;

// TODO: Not all the fields are optional. This was copied from the JS implementation.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all(serialize = "camelCase", deserialize = "camelCase"))]
pub struct Eip712TransactionRequest {
    pub to: Option<Address>,
    pub from: Option<Address>,
    pub nonce: U256,
    pub gas_limit: Option<U256>,
    pub gas_price: Option<U256>,
    pub data: Option<Bytes>,
    pub value: Option<U256>,
    pub chain_id: u64,
    pub r#type: U256,
    pub access_list: Option<AccessList>,
    pub max_priority_fee_per_gas: Option<U256>,
    pub max_fee_per_gas: Option<U256>,
    pub custom_data: Option<Eip712Meta>,
    pub ccip_read_enabled: Option<bool>,
}

// TODO: Implement Default for Eip712TransactionRequest.
// impl Default for Eip712TransactionRequest {}
#[derive(Serialize, Deserialize, Clone, Debug)]
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
    pub paymaster_input: Bytes,
}

impl Into<Eip712SignInput> for Eip712TransactionRequest {
    fn into(self) -> Eip712SignInput {
        todo!()
    }
}

        eip712_sign_input
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename_all(serialize = "camelCase", deserialize = "camelCase"))]
pub struct Eip712SignInput {
    pub tx_type: U256,
    pub from: Option<Address>,
    pub to: Option<Address>,
    pub gas_limit: Option<U256>,
    // NOTE: this value must be set after calling ZKSProvider::estimate_fee method.
    pub gas_per_pubdata_byte_limit: Option<U256>,
    pub max_fee_per_gas: Option<U256>,
    pub max_priority_fee_per_gas: Option<U256>,
    pub paymaster: Option<Address>,
    pub nonce: U256,
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
        let step_1: [u8; 2] = 0x71_u16.to_be_bytes();
        let step_2: [u8; 2] = ((self
            .factory_deps
            .clone()
            .ok_or_else(|| return Eip712Error::FailedToEncodeStruct)?[0]
            .len()
            / 2
            % 32) as u16)
            .to_be_bytes();
        let step_3: [u8; 28] = sha2::Sha256::digest(
            &self
                .factory_deps
                .clone()
                .ok_or_else(|| return Eip712Error::FailedToEncodeStruct)?[0],
        )
        .into_iter()
        .skip(4)
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();

        let mut contract_hash: [u8; 32] = [0; 32];
        contract_hash[..2].clone_from_slice(&step_1);
        contract_hash[2..4].clone_from_slice(&step_2);
        contract_hash[4..].clone_from_slice(&step_3);

        Ok(contract_hash)
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
