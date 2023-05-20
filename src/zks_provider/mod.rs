use async_trait::async_trait;
use ethers::{
    providers::{JsonRpcClient, Provider, ProviderError},
    types::{Address, H256, U256},
};
use serde::Serialize;
use std::{collections::HashMap, fmt::Debug};

pub mod types;
use types::Fee;

use self::types::{
    BlockDetails, BlockRange, BridgeContracts, DebugTrace, L1BatchDetails, TokenInfo, TracerConfig,
    Transaction, TransactionDetails,
};

/// This trait wraps every JSON-RPC call specified in zkSync Era's documentation
/// https://era.zksync.io/docs/api/api.html#zksync-era-json-rpc-methods
#[async_trait]
pub trait ZKSProvider {
    /// Returns the fee for the transaction.
    async fn estimate_fee<T>(&self, transaction: T) -> Result<Fee, ProviderError>
    where
        T: Debug + Serialize + Send + Sync;

    /// Returns an estimate of the gas required for a L1 to L2 transaction.
    async fn estimate_gas_l1_to_l2<T>(&self, request: T) -> Result<U256, ProviderError>
    where
        T: Debug + Serialize + Send + Sync;

    /// Returns all balances for confirmed tokens given by an account address.
    async fn get_all_account_balances(
        &self,
        address: Address,
    ) -> Result<Vec<HashMap<Address, U256>>, ProviderError>;

    /// Returns additional zkSync-specific information about the L2 block.
    async fn get_block_details(&self, block: u32) -> Result<BlockDetails, ProviderError>;

    /// Returns L1/L2 addresses of default bridges.
    async fn get_bridge_contracts(&self) -> Result<BridgeContracts, ProviderError>;

    /// Returns bytecode of a transaction given by its hash.
    async fn get_bytecode_by_hash(&self, hash: H256) -> Result<Option<Vec<u8>>, ProviderError>;

    /// Returns [address, symbol, name, and decimal] information of all tokens within a range of ids.
    async fn get_confirmed_tokens(
        &self,
        from: u32,
        limit: u8,
    ) -> Result<Vec<TokenInfo>, ProviderError>;

    /// Returns the range of blocks contained within a batch given by batch number.
    async fn get_l1_batch_block_range(&self, batch: U256) -> Result<BlockRange, ProviderError>;

    /// Returns data pertaining to a given batch.
    async fn get_l1_batch_details(&self, batch: U256) -> Result<L1BatchDetails, ProviderError>;

    // /// Returns the proof for the corresponding L2 to L1 log.
    // async fn get_l2_to_l1_log_proof(&self, tx_hash: H256, l2_to_l1_log_index: Option<u64>) -> Result<Option<Proof>, ProviderError>;

    // /// Returns the proof for the message sent via the L1Messenger system contract.
    // async fn get_l2_to_l1_msg_proof(&self, block: u32, sender: Address, msg: H256, l2_log_position: Option<u64>) -> Result<Option<Proof>, ProviderError>;

    /// Returns the address of the zkSync Era contract.
    async fn get_main_contract(&self) -> Result<Address, ProviderError>;

    /// Returns data of transactions in a block.
    async fn get_raw_block_transactions(
        &self,
        block: u32,
    ) -> Result<Vec<Transaction>, ProviderError>;

    /// Returns the address of the testnet paymaster.
    async fn get_testnet_paymaster(&self) -> Result<Address, ProviderError>;

    /// Returns the price of a given token in USD.
    async fn get_token_price(&self, address: Address) -> Result<Option<f64>, ProviderError>;

    /// Returns data from a specific transaction given by the transaction hash.
    async fn get_transaction_details(
        &self,
        hash: H256,
    ) -> Result<Option<TransactionDetails>, ProviderError>;

    /// Returns the latest L1 batch number.
    async fn get_latest_l1_batch_number(&self) -> Result<u32, ProviderError>;

    /// Returns the chain id of the underlying L1.
    async fn get_l1_chain_id(&self) -> Result<u64, ProviderError>;

    // /// Returns debug trace of all executed calls contained in a block given by its L2 hash.
    // async fn debug_trace_block_by_hash(&self, hash: H256, options: TracerConfig) -> Result<DebugTrace, ProviderError>;

    // /// Returns debug trace of all executed calls contained in a block given by its L2 block number.
    // async fn debug_trace_block_by_number(&self, block: U256, options: TracerConfig) -> Result<DebugTrace, ProviderError>;

    // /// Returns debug trace containing information on a specific calls given by the call request.
    // async fn debug_trace_call<T>(&self, request: T, block: U256, options: TracerConfig) -> Result<DebugTrace, ProviderError>
    // where
    //     T: Debug + Serialize + Send + Sync;

    // /// Returns a debug trace of a specific transaction given by its transaction hash.
    // async fn debug_trace_transaction(&self, hash: H256, options: TracerConfig) -> Result<DebugTrace, ProviderError>;
}

#[async_trait]
impl<P: JsonRpcClient> ZKSProvider for Provider<P> {
    async fn estimate_fee<T>(&self, request: T) -> Result<Fee, ProviderError>
    where
        T: Debug + Serialize + Send + Sync,
    {
        self.request("zks_estimateFee", [request]).await
    }

    async fn estimate_gas_l1_to_l2<T>(&self, request: T) -> Result<U256, ProviderError>
    where
        T: Debug + Serialize + Send + Sync,
    {
        self.request("zks_estimateGasL1ToL2", [request]).await
    }

    async fn get_all_account_balances(
        &self,
        address: Address,
    ) -> Result<Vec<HashMap<Address, U256>>, ProviderError> {
        self.request("zks_getAllAccountBalances", [address]).await
    }

    async fn get_block_details(&self, block: u32) -> Result<BlockDetails, ProviderError> {
        self.request("zks_getBlockDetails", [block]).await
    }

    async fn get_bridge_contracts(&self) -> Result<BridgeContracts, ProviderError> {
        self.request("zks_getBridgeContracts", ()).await
    }

    async fn get_bytecode_by_hash(&self, hash: H256) -> Result<Option<Vec<u8>>, ProviderError> {
        self.request("zks_getBytecodeByHash", [hash]).await
    }

    async fn get_confirmed_tokens(
        &self,
        from: u32,
        limit: u8,
    ) -> Result<Vec<TokenInfo>, ProviderError> {
        self.request("zks_getConfirmedTokens", [from, limit.into()])
            .await
    }

    async fn get_l1_batch_block_range(&self, batch: U256) -> Result<BlockRange, ProviderError> {
        self.request("zks_getL1BatchBlockRange", [batch]).await
    }

    async fn get_l1_batch_details(&self, batch: U256) -> Result<L1BatchDetails, ProviderError> {
        self.request("zks_getL1BatchDetails", [batch]).await
    }

    // async fn get_l2_to_l1_log_proof(&self, tx_hash: H256, l2_to_l1_log_index: Option<u64>) -> Result<Option<Proof>, ProviderError> {
    //     self.request("zks_getL2ToL1LogProof", [tx_hash, l2_to_l1_log_index]).await
    // }

    // async fn get_l2_to_l1_msg_proof(&self, block: u32, sender: Address, msg: H256, l2_log_position: Option<u64>) -> Result<Option<Proof>, ProviderError> {
    //     self.request("zks_getL2ToL1MsgProof", [block, sender, msg, l2_log_position]).await
    // }

    async fn get_main_contract(&self) -> Result<Address, ProviderError> {
        self.request("zks_getMainContract", ()).await
    }

    async fn get_raw_block_transactions(
        &self,
        block: u32,
    ) -> Result<Vec<Transaction>, ProviderError> {
        self.request("zks_getRawBlockTransactions", [block]).await
    }

    async fn get_testnet_paymaster(&self) -> Result<Address, ProviderError> {
        self.request("zks_getTestnetPaymaster", ()).await
    }

    async fn get_token_price(&self, address: Address) -> Result<Option<f64>, ProviderError> {
        self.request("zks_getTokenPrice", [address]).await
    }

    async fn get_transaction_details(
        &self,
        hash: H256,
    ) -> Result<Option<TransactionDetails>, ProviderError> {
        self.request("zks_getTransactionDetails", [hash]).await
    }

    async fn get_latest_l1_batch_number(&self) -> Result<u32, ProviderError> {
        self.request("zks_getLatestU256", ()).await
    }

    async fn get_l1_chain_id(&self) -> Result<u64, ProviderError> {
        self.request("zks_L1ChainId", ()).await
    }

    // async fn debug_trace_block_by_hash(&self, hash: H256, options: TracerConfig) -> Result<DebugTrace, ProviderError> {
    //     self.request("debug_traceBlockByHash", [hash, options]).await
    // }

    // async fn debug_trace_block_by_number(&self, block: U256, options: TracerConfig) -> Result<DebugTrace, ProviderError> {
    //     self.request("debug_traceBlockByNumber", [block, options]).await
    // }

    // async fn debug_trace_call<T>(&self, request: T, block: U256, options: TracerConfig) -> Result<DebugTrace, ProviderError>
    // where
    //     T: Debug + Serialize + Send + Sync,
    // {
    //     self.request("debug_traceCall", [request, block, options]).await
    // }

    // async fn debug_trace_transaction(&self, hash: H256, options: TracerConfig) -> Result<DebugTrace, ProviderError> {
    //     self.request("debug_traceTransaction", [hash, options]).await
    // }
}

#[cfg(test)]
mod tests {
    use crate::zks_provider::ZKSProvider;
    use ethers::{providers::Provider, types::Address};
    use serde::{Deserialize, Serialize};

    fn get_local_provider() -> Provider<ethers::providers::Http> {
        Provider::try_from(format!(
            "http://{host}:{port}",
            host = "65.108.204.116",
            port = 3_050_i32
        ))
        .unwrap()
        .interval(std::time::Duration::from_millis(10))
    }

    #[tokio::test]
    async fn test_estimate_fee() {
        let provider = get_local_provider();
        #[derive(Serialize, Deserialize, Debug)]
        struct TestTransaction {
            from: String,
            to: String,
            data: String,
        }

        let transaction = TestTransaction {
            from: "0x1111111111111111111111111111111111111111".to_owned(),
            to: "0x2222222222222222222222222222222222222222".to_owned(),
            data: "0x608060405234801561001057600080fd5b50610228806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c80639146769014610030575b600080fd5b61003861004e565b6040516100459190610170565b60405180910390f35b60606000805461005d906101c1565b80601f0160208091040260200160405190810160405280929190818152602001828054610089906101c1565b80156100d65780601f106100ab576101008083540402835291602001916100d6565b820191906000526020600020905b8154815290600101906020018083116100b957829003601f168201915b5050505050905090565b600081519050919050565b600082825260208201905092915050565b60005b8381101561011a5780820151818401526020810190506100ff565b60008484015250505050565b6000601f19601f8301169050919050565b6000610142826100e0565b61014c81856100eb565b935061015c8185602086016100fc565b61016581610126565b840191505092915050565b6000602082019050818103600083015261018a8184610137565b905092915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b600060028204905060018216806101d957607f821691505b6020821081036101ec576101eb610192565b5b5091905056fea26469706673582212203d7f62ad5ef1f9670aa630c438f1a75844e1d2cfaf92e6985c698b7009e3dfa864736f6c63430008140033".to_owned(),
        };

        let estimated_fee = provider.estimate_fee(transaction).await.unwrap();

        assert_eq!(estimated_fee.gas_limit.as_u64(), 162436);
        assert_eq!(estimated_fee.gas_per_pubdata_limit.as_u64(), 66);
        assert_eq!(estimated_fee.max_fee_per_gas.as_u64(), 250000000);
        assert_eq!(estimated_fee.max_priority_fee_per_gas.as_u64(), 0);
    }

    #[tokio::test]
    async fn test_get_testnet_paymaster() {
        let provider = get_local_provider();
        let expected_address: Address = "0x4cccf49428918845022048757f8c9af961fa9a90"
            .parse()
            .unwrap();
        let testnet_paymaster = provider.get_testnet_paymaster().await.unwrap();
        assert_eq!(testnet_paymaster, expected_address);
    }
}
