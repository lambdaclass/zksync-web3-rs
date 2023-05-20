use ethers::types::{Address, U256};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Fee {
    pub gas_limit: U256,
    pub gas_per_pubdata_limit: U256,
    pub max_fee_per_gas: U256,
    pub max_priority_fee_per_gas: U256,
}

impl Copy for Fee {}

// TODO: Complete struct.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockDetails;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BridgeContracts {
    pub l1_erc20_default_bridge: Address,
    pub l2_erc20_default_bridge: Address,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TokenInfo {
    decimals: u64,
    l1_address: Address,
    l2_address: Address,
    name: String,
    symbol: String,
}

pub type BlockRange = Vec<String>;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct L1BatchDetails;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Proof;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Transaction;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionDetails;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TracerConfig;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DebugTrace;
