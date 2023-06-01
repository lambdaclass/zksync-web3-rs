use ethers::types::{Address, Bytes, H256, U256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Fee {
    pub gas_limit: U256,
    pub gas_per_pubdata_limit: U256,
    pub max_fee_per_gas: U256,
    pub max_priority_fee_per_gas: U256,
}

impl Copy for Fee {}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BlockDetails {
    pub base_system_contracts_hashes: BaseSystemContractsHashes,
    pub commit_tx_hash: H256,
    pub committed_at: String,
    pub execute_tx_hash: H256,
    pub executed_at: String,
    pub l1_batch_number: u128,
    pub l1_gas_price: u128,
    pub l1_tx_count: u128,
    pub l2_fair_gas_price: u128,
    pub l2_tx_count: u128,
    pub number: u128,
    pub operator_address: Address,
    pub prove_tx_hash: H256,
    pub proven_at: String,
    pub root_hash: H256,
    pub status: String,
    pub timestamp: u128,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BaseSystemContractsHashes {
    pub bootloader: H256,
    pub default_aa: H256,
}

impl Copy for BaseSystemContractsHashes {}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BridgeContracts {
    pub l1_erc20_default_bridge: Address,
    pub l2_erc20_default_bridge: Address,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TokenInfo {
    pub decimals: u64,
    pub l1_address: Address,
    pub l2_address: Address,
    pub name: String,
    pub symbol: String,
}

pub type BlockRange = Vec<String>;

// TODO: Complete struct.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct L1BatchDetails {
    pub base_system_contracts_hashes: BaseSystemContractsHashes,
    pub commit_tx_hash: H256,
    pub committed_at: String,
    pub execute_tx_hash: H256,
    pub executed_at: String,
    pub l1_gas_price: u128,
    pub l1_tx_count: u128,
    pub l2_fair_gas_price: u128,
    pub l2_tx_count: u128,
    pub number: u128,
    pub prove_tx_hash: H256,
    pub proven_at: String,
    pub root_hash: H256,
    pub status: String,
    pub timestamp: u128,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Proof {
    pub id: u64,
    pub proof: Vec<String>,
    pub root: String,
}

// TODO: Complete struct.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Transaction {
    pub common_data: CommonData,
    pub execute: Execute,
    pub received_timestamp_ms: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CommonData {
    #[serde(rename = "L1")]
    pub l1: L1,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct L1 {
    pub canonical_tx_hash: H256,
    pub deadline_block: u64,
    pub eth_block: u64,
    pub eth_hash: H256,
    pub full_fee: U256,
    pub gas_limit: U256,
    pub gas_per_pubdata_limit: U256,
    pub layer2_tip_fee: U256,
    pub max_fee_per_gas: U256,
    pub op_processing_type: String,
    pub priority_queue_type: String,
    pub refund_recipient: Address,
    pub sender: Address,
    pub serial_id: u64,
    pub to_mint: U256,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Execute {
    pub calldata: Bytes,
    pub contract_address: Address,
    pub factory_deps: Vec<Vec<u8>>,
    pub value: U256,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TransactionDetails {
    pub eth_commit_tx_hash: H256,
    pub eth_execute_tx_hash: H256,
    pub eth_prove_tx_hash: H256,
    pub fee: U256,
    pub initiator_address: Address,
    pub is_l1_originated: bool,
    pub received_at: String,
    pub status: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TracerConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_storage: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_stack: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_memory: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_return_data: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracer_config: Option<HashMap<String, bool>>,
}

// TODO: Check correct types for the ones using serde_json::Value.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DebugTrace {
    calls: Vec<serde_json::Value>,
    error: Option<String>,
    from: Address,
    gas: U256,
    gas_used: U256,
    input: Bytes,
    output: Bytes,
    revert_reason: Option<String>,
    to: Address,
    r#type: String,
    value: U256,
}
