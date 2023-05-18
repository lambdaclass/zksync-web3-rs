use ethers::types::U256;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Fee {
    pub gas_limit: U256,
    pub gas_per_pubdata_limit: U256,
    pub max_fee_per_gas: U256,
    pub max_priority_fee_per_gas: U256,
}

impl Copy for Fee {}
