use ethers::types::{
    transaction::eip712::{EIP712Domain, Eip712, Eip712Error},
    Address, Bytes, U256,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;

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
            verifying_contract: "0xDAbb67b676F5b01FcC8997Cc8439846D0d8078ca".parse().ok(),
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
