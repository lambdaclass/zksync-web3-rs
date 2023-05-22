use ethers::types::{Address, H256, U256};
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
#[derive(Serialize, Deserialize, Debug)]
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

impl Clone for BlockDetails {
    fn clone(&self) -> Self {
        Self {
            base_system_contracts_hashes: self.base_system_contracts_hashes,
            commit_tx_hash: self.commit_tx_hash,
            committed_at: self.committed_at.clone(),
            execute_tx_hash: self.execute_tx_hash,
            executed_at: self.executed_at.clone(),
            l1_batch_number: self.l1_batch_number,
            l1_gas_price: self.l1_gas_price,
            l1_tx_count: self.l1_tx_count,
            l2_fair_gas_price: self.l2_fair_gas_price,
            l2_tx_count: self.l2_tx_count,
            number: self.number,
            operator_address: self.operator_address,
            prove_tx_hash: self.prove_tx_hash,
            proven_at: self.proven_at.clone(),
            root_hash: self.root_hash,
            status: self.status.clone(),
            timestamp: self.timestamp,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BaseSystemContractsHashes {
    pub bootloader: H256,
    pub default_aa: H256,
}

impl Copy for BaseSystemContractsHashes {}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BridgeContracts {
    pub l1_erc20_default_bridge: Address,
    pub l2_erc20_default_bridge: Address,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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
pub struct L1BatchDetails;

// TODO: Complete struct.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Proof;

// TODO: Complete struct.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Transaction;

// TODO: Complete struct.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionDetails;

// TODO: Complete struct.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TracerConfig;

// TODO: Complete struct.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DebugTrace;
