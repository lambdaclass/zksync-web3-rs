use ethers::{
    types::Address,
    utils::rlp::Encodable,
};
use serde::Serialize;

#[derive(Serialize, serde::Deserialize, Clone, Debug, Default)]
#[serde(rename_all(serialize = "camelCase", deserialize = "camelCase"))]
pub struct PaymasterParams {
    pub paymaster: Address,
    pub paymaster_input: Vec<u8>,
}

impl PaymasterParams {
    pub fn paymaster(mut self, paymaster: Address) -> Self {
        self.paymaster = paymaster;
        self
    }

    pub fn paymaster_input(mut self, paymaster_input: Vec<u8>) -> Self {
        self.paymaster_input = paymaster_input;
        self
    }
}

impl Encodable for PaymasterParams {
    fn rlp_append(&self, stream: &mut ethers::utils::rlp::RlpStream) {
        stream.begin_list(2);
        stream.append(&self.paymaster);
        stream.append(&self.paymaster_input.clone());
    }
}
