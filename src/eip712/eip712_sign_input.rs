use ethers::types::{
    transaction::eip712::{EIP712Domain, Eip712, Eip712Error},
    Address, Bytes, U256,
};
use serde::{Deserialize, Serialize};

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

impl Eip712 for Eip712SignInput {
    type Error = Eip712Error;

    fn domain(&self) -> Result<EIP712Domain, Self::Error> {
        Ok(EIP712Domain {
            name: Some(String::from("zkSync")),
            version: Some(String::from("2")),
            chain_id: Some(U256::from(9_i32)),
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
