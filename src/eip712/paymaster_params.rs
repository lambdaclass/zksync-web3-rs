use ethers::{
    types::{Address, Bytes},
    utils::rlp::Encodable,
};
use serde::Serialize;

#[derive(Serialize, serde::Deserialize, Clone, Debug, Default)]
#[serde(rename_all(serialize = "camelCase", deserialize = "camelCase"))]
pub struct PaymasterParams {
    pub paymaster: Address,
    pub paymaster_input: Bytes,
}

impl PaymasterParams {
    pub fn paymaster(mut self, paymaster: Address) -> Self {
        self.paymaster = paymaster;
        self
    }

    pub fn paymaster_input(mut self, paymaster_input: Bytes) -> Self {
        self.paymaster_input = paymaster_input;
        self
    }
}

impl Encodable for PaymasterParams {
    fn rlp_append(&self, stream: &mut ethers::utils::rlp::RlpStream) {
        stream.begin_list(2);
        stream.append(&self.paymaster.as_bytes());
        stream.append(&self.paymaster_input.to_vec());
    }
}
