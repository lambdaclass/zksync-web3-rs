use async_trait::async_trait;
use ethers::{
    prelude::SignerMiddleware,
    providers::{JsonRpcClient, Middleware, Provider, ProviderError},
    signers::Signer,
    types::{Address, H256, U256},
};
use serde::Serialize;
use serde_json::json;
use std::{collections::HashMap, fmt::Debug};

pub mod types;
use types::Fee;

use self::types::{
    BlockDetails, BlockRange, BridgeContracts, DebugTrace, L1BatchDetails, Proof, TokenInfo,
    TracerConfig, Transaction, TransactionDetails,
};

/// This trait wraps every JSON-RPC call specified in zkSync Era's documentation
/// https://era.zksync.io/docs/api/api.html#zksync-era-json-rpc-methods
#[async_trait]
pub trait ZKSProvider {
    async fn estimate_gas<T>(&self, transaction: T) -> Result<U256, ProviderError>
    where
        T: Debug + Serialize + Send + Sync;

    /// Returns the fee for the transaction.
    async fn estimate_fee<T>(&self, transaction: T) -> Result<Fee, ProviderError>
    where
        T: Debug + Serialize + Send + Sync;

    /// Returns an estimate of the gas required for a L1 to L2 transaction.
    async fn estimate_gas_l1_to_l2<T>(&self, transaction: T) -> Result<U256, ProviderError>
    where
        T: Debug + Serialize + Send + Sync;

    /// Returns all balances for confirmed tokens given by an account address.
    async fn get_all_account_balances(
        &self,
        address: Address,
    ) -> Result<HashMap<Address, U256>, ProviderError>;

    /// Returns additional zkSync-specific information about the L2 block.
    /// * `committed`: The batch is closed and the state transition it creates exists on layer 1.
    /// * `proven`: The batch proof has been created, submitted, and accepted on layer 1.
    /// * `executed`: The batch state transition has been executed on L1; meaning the root state has been updated.
    async fn get_block_details(&self, block: u32) -> Result<BlockDetails, ProviderError>;

    /// Returns L1/L2 addresses of default bridges.
    async fn get_bridge_contracts(&self) -> Result<BridgeContracts, ProviderError>;

    /// Returns bytecode of a transaction given by its hash.
    async fn get_bytecode_by_hash(&self, hash: H256) -> Result<Option<Vec<u8>>, ProviderError>;

    /// Returns [address, symbol, name, and decimal] information of all tokens within a range of ids given by parameters `from` and `limit`.
    ///
    /// **Confirmed** in the method name means the method returns any token bridged to zkSync via the official bridge.
    ///
    /// > This method is mainly used by the zkSync team as it relates to a database query where the primary keys relate to the given ids.
    async fn get_confirmed_tokens(
        &self,
        from: u32,
        limit: u8,
    ) -> Result<Vec<TokenInfo>, ProviderError>;

    /// Returns the range of blocks contained within a batch given by batch number.
    ///
    /// The range is given by beginning/end block numbers in hexadecimal.
    async fn get_l1_batch_block_range(&self, batch: u32) -> Result<BlockRange, ProviderError>;

    /// Returns data pertaining to a given batch.
    async fn get_l1_batch_details(&self, batch: u32) -> Result<L1BatchDetails, ProviderError>;

    /// Given a transaction hash, and an index of the L2 to L1 log produced within the
    /// transaction, it returns the proof for the corresponding L2 to L1 log.
    ///
    /// The index of the log that can be obtained from the transaction receipt (it
    /// includes a list of every log produced by the transaction).
    async fn get_l2_to_l1_log_proof(
        &self,
        tx_hash: H256,
        l2_to_l1_log_index: Option<u64>,
    ) -> Result<Option<Proof>, ProviderError>;

    /// Given a block, a sender, a message, and an optional message log index in the
    /// block containing the L1->L2 message, it returns the proof for the message sent
    /// via the L1Messenger system contract.
    async fn get_l2_to_l1_msg_proof(
        &self,
        block: u32,
        sender: Address,
        msg: H256,
        l2_log_position: Option<u64>,
    ) -> Result<Option<Proof>, ProviderError>;

    /// Returns the address of the zkSync Era contract.
    async fn get_main_contract(&self) -> Result<Address, ProviderError>;

    /// Returns data of transactions in a block.
    async fn get_raw_block_transactions(
        &self,
        block: u32,
    ) -> Result<Vec<Transaction>, ProviderError>;

    /// Returns the address of the [testnet paymaster](https://era.zksync.io/docs/dev/developer-guides/aa.html#testnet-paymaster): the paymaster that is available
    /// on testnets and enables paying fees in ERC-20 compatible tokens.
    async fn get_testnet_paymaster(&self) -> Result<Address, ProviderError>;

    /// Returns the price of a given token in USD.
    async fn get_token_price(&self, address: Address) -> Result<String, ProviderError>;

    /// Returns data from a specific transaction given by the transaction hash.
    async fn get_transaction_details(
        &self,
        hash: H256,
    ) -> Result<Option<TransactionDetails>, ProviderError>;

    /// Returns the latest L1 batch number.
    async fn get_l1_batch_number(&self) -> Result<U256, ProviderError>;

    /// Returns the chain id of the underlying L1.
    async fn get_l1_chain_id(&self) -> Result<U256, ProviderError>;

    /// Returns debug trace of all executed calls contained in a block given by its L2 hash.
    async fn debug_trace_block_by_hash(
        &self,
        hash: H256,
        options: Option<TracerConfig>,
    ) -> Result<DebugTrace, ProviderError>;

    /// Returns debug trace of all executed calls contained in a block given by its L2 block number.
    async fn debug_trace_block_by_number(
        &self,
        block: U256,
        options: Option<TracerConfig>,
    ) -> Result<DebugTrace, ProviderError>;

    /// Returns debug trace containing information on a specific calls given by the call request.
    async fn debug_trace_call<T>(
        &self,
        request: T,
        block: Option<U256>,
        options: Option<TracerConfig>,
    ) -> Result<DebugTrace, ProviderError>
    where
        T: Debug + Serialize + Send + Sync;

    /// Uses the EVM's callTracer to return a debug trace of a specific transaction given by its transaction hash.
    async fn debug_trace_transaction(
        &self,
        hash: H256,
        options: Option<TracerConfig>,
    ) -> Result<DebugTrace, ProviderError>;
}

#[async_trait]
impl<M: Middleware + ZKSProvider, S: Signer> ZKSProvider for SignerMiddleware<M, S> {
    async fn estimate_gas<T>(&self, transaction: T) -> Result<U256, ProviderError>
    where
        T: Debug + Serialize + Send + Sync,
    {
        <M as ZKSProvider>::estimate_gas(self.inner(), transaction).await
    }

    async fn estimate_fee<T>(&self, transaction: T) -> Result<Fee, ProviderError>
    where
        T: Debug + Serialize + Send + Sync,
    {
        self.inner().estimate_fee(transaction).await
    }

    async fn estimate_gas_l1_to_l2<T>(&self, transaction: T) -> Result<U256, ProviderError>
    where
        T: Debug + Serialize + Send + Sync,
    {
        self.inner().estimate_gas_l1_to_l2(transaction).await
    }

    async fn get_all_account_balances(
        &self,
        address: Address,
    ) -> Result<HashMap<Address, U256>, ProviderError> {
        self.inner().get_all_account_balances(address).await
    }

    async fn get_block_details(&self, block: u32) -> Result<BlockDetails, ProviderError> {
        self.inner().get_block_details(block).await
    }

    async fn get_bridge_contracts(&self) -> Result<BridgeContracts, ProviderError> {
        self.inner().get_bridge_contracts().await
    }

    async fn get_bytecode_by_hash(&self, hash: H256) -> Result<Option<Vec<u8>>, ProviderError> {
        self.inner().get_bytecode_by_hash(hash).await
    }

    async fn get_confirmed_tokens(
        &self,
        from: u32,
        limit: u8,
    ) -> Result<Vec<TokenInfo>, ProviderError> {
        self.inner().get_confirmed_tokens(from, limit).await
    }

    async fn get_l1_batch_block_range(&self, batch_id: u32) -> Result<BlockRange, ProviderError> {
        self.inner().get_l1_batch_block_range(batch_id).await
    }

    async fn get_l1_batch_details(&self, batch_id: u32) -> Result<L1BatchDetails, ProviderError> {
        self.inner().get_l1_batch_details(batch_id).await
    }

    async fn get_l2_to_l1_log_proof(
        &self,
        tx_hash: H256,
        l2_to_l1_log_index: Option<u64>,
    ) -> Result<Option<Proof>, ProviderError> {
        self.inner()
            .get_l2_to_l1_log_proof(tx_hash, l2_to_l1_log_index)
            .await
    }

    async fn get_l2_to_l1_msg_proof(
        &self,
        block: u32,
        sender: Address,
        msg: H256,
        l2_log_position: Option<u64>,
    ) -> Result<Option<Proof>, ProviderError> {
        self.inner()
            .get_l2_to_l1_msg_proof(block, sender, msg, l2_log_position)
            .await
    }

    async fn get_main_contract(&self) -> Result<Address, ProviderError> {
        self.inner().get_main_contract().await
    }

    async fn get_raw_block_transactions(
        &self,
        block: u32,
    ) -> Result<Vec<Transaction>, ProviderError> {
        self.inner().get_raw_block_transactions(block).await
    }

    async fn get_testnet_paymaster(&self) -> Result<Address, ProviderError> {
        self.inner().get_testnet_paymaster().await
    }

    async fn get_token_price(&self, address: Address) -> Result<String, ProviderError> {
        self.inner().get_token_price(address).await
    }

    async fn get_transaction_details(
        &self,
        hash: H256,
    ) -> Result<Option<TransactionDetails>, ProviderError> {
        self.inner().get_transaction_details(hash).await
    }

    async fn get_l1_batch_number(&self) -> Result<U256, ProviderError> {
        self.inner().get_l1_batch_number().await
    }

    async fn get_l1_chain_id(&self) -> Result<U256, ProviderError> {
        self.inner().get_l1_chain_id().await
    }

    async fn debug_trace_block_by_hash(
        &self,
        hash: H256,
        options: Option<TracerConfig>,
    ) -> Result<DebugTrace, ProviderError> {
        ZKSProvider::debug_trace_block_by_hash(self.inner(), hash, options).await
    }

    async fn debug_trace_block_by_number(
        &self,
        block: U256,
        options: Option<TracerConfig>,
    ) -> Result<DebugTrace, ProviderError> {
        ZKSProvider::debug_trace_block_by_number(self.inner(), block, options).await
    }

    async fn debug_trace_call<T>(
        &self,
        request: T,
        block: Option<U256>,
        options: Option<TracerConfig>,
    ) -> Result<DebugTrace, ProviderError>
    where
        T: Debug + Serialize + Send + Sync,
    {
        ZKSProvider::debug_trace_call(self.inner(), request, block, options).await
    }

    async fn debug_trace_transaction(
        &self,
        hash: H256,
        options: Option<TracerConfig>,
    ) -> Result<DebugTrace, ProviderError> {
        ZKSProvider::debug_trace_transaction(self.inner(), hash, options).await
    }
}

#[async_trait]
impl<P: JsonRpcClient> ZKSProvider for Provider<P> {
    async fn estimate_gas<T>(&self, transaction: T) -> Result<U256, ProviderError>
    where
        T: Debug + Serialize + Send + Sync,
    {
        self.request("eth_estimateGas", [transaction]).await
    }

    async fn estimate_fee<T>(&self, transaction: T) -> Result<Fee, ProviderError>
    where
        T: Debug + Serialize + Send + Sync,
    {
        self.request("zks_estimateFee", [transaction]).await
    }

    async fn estimate_gas_l1_to_l2<T>(&self, transaction: T) -> Result<U256, ProviderError>
    where
        T: Debug + Serialize + Send + Sync,
    {
        self.request("zks_estimateGasL1ToL2", [transaction]).await
    }

    async fn get_all_account_balances(
        &self,
        address: Address,
    ) -> Result<HashMap<Address, U256>, ProviderError> {
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

    async fn get_l1_batch_block_range(&self, batch: u32) -> Result<BlockRange, ProviderError> {
        self.request("zks_getL1BatchBlockRange", [batch]).await
    }

    async fn get_l1_batch_details(&self, batch: u32) -> Result<L1BatchDetails, ProviderError> {
        self.request("zks_getL1BatchDetails", [batch]).await
    }

    async fn get_l2_to_l1_log_proof(
        &self,
        tx_hash: H256,
        l2_to_l1_log_index: Option<u64>,
    ) -> Result<Option<Proof>, ProviderError> {
        self.request(
            "zks_getL2ToL1LogProof",
            json!([tx_hash, l2_to_l1_log_index]),
        )
        .await
    }

    async fn get_l2_to_l1_msg_proof(
        &self,
        block: u32,
        sender: Address,
        msg: H256,
        l2_log_position: Option<u64>,
    ) -> Result<Option<Proof>, ProviderError> {
        self.request(
            "zks_getL2ToL1MsgProof",
            json!([block, sender, msg, l2_log_position]),
        )
        .await
    }

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

    async fn get_token_price(&self, address: Address) -> Result<String, ProviderError> {
        self.request("zks_getTokenPrice", [address]).await
    }

    async fn get_transaction_details(
        &self,
        hash: H256,
    ) -> Result<Option<TransactionDetails>, ProviderError> {
        self.request("zks_getTransactionDetails", [hash]).await
    }

    async fn get_l1_batch_number(&self) -> Result<U256, ProviderError> {
        self.request("zks_L1BatchNumber", ()).await
    }

    async fn get_l1_chain_id(&self) -> Result<U256, ProviderError> {
        self.request("zks_L1ChainId", ()).await
    }

    async fn debug_trace_block_by_hash(
        &self,
        hash: H256,
        options: Option<TracerConfig>,
    ) -> Result<DebugTrace, ProviderError> {
        let processable_response = self
            .request::<serde_json::Value, serde_json::Value>(
                "debug_traceBlockByHash",
                json!([hash, options]),
            )
            .await?[0]["result"]
            .clone();
        serde_json::from_value(processable_response).map_err(ProviderError::SerdeJson)
    }

    async fn debug_trace_block_by_number(
        &self,
        block: U256,
        options: Option<TracerConfig>,
    ) -> Result<DebugTrace, ProviderError> {
        let processable_response = self
            .request::<serde_json::Value, serde_json::Value>(
                "debug_traceBlockByNumber",
                json!([block, options]),
            )
            .await?[0]["result"]
            .clone();
        serde_json::from_value(processable_response).map_err(ProviderError::SerdeJson)
    }

    async fn debug_trace_call<T>(
        &self,
        request: T,
        block: Option<U256>,
        options: Option<TracerConfig>,
    ) -> Result<DebugTrace, ProviderError>
    where
        T: Debug + Serialize + Send + Sync,
    {
        self.request("debug_traceCall", json!([request, block, options]))
            .await
    }

    async fn debug_trace_transaction(
        &self,
        hash: H256,
        options: Option<TracerConfig>,
    ) -> Result<DebugTrace, ProviderError> {
        self.request("debug_traceTransaction", json!([hash, options]))
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::zks_provider::{types::TracerConfig, ZKSProvider};
    use ethers::{
        prelude::{k256::ecdsa::SigningKey, MiddlewareBuilder, SignerMiddleware},
        providers::{Middleware, Provider},
        signers::{Signer, Wallet},
        types::{Address, H256, U256},
    };
    use serde::{Deserialize, Serialize};

    const L2_CHAIN_ID: u64 = 270;

    fn local_provider() -> Provider<ethers::providers::Http> {
        Provider::try_from(format!(
            "http://{host}:{port}",
            host = "localhost",
            port = 3_050_i32
        ))
        .unwrap()
        .interval(std::time::Duration::from_millis(10))
    }

    fn local_signer() -> SignerMiddleware<Provider<ethers::providers::Http>, Wallet<SigningKey>> {
        let signer = Wallet::with_chain_id(
            "0x7726827caac94a7f9e1b160f7ea819f172f7b6f9d2a97f992c38edeab82d4110"
                .parse::<Wallet<SigningKey>>()
                .unwrap(),
            L2_CHAIN_ID,
        );
        local_provider().with_signer(signer)
    }

    #[tokio::test]
    async fn test_provider_estimate_fee() {
        let provider = local_provider();
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

        assert_eq!(estimated_fee.gas_limit, U256::from(162_436_i32));
        assert_eq!(estimated_fee.gas_per_pubdata_limit, U256::from(66_i32));
        assert_eq!(estimated_fee.max_fee_per_gas, U256::from(250_000_000_i32));
        assert_eq!(estimated_fee.max_priority_fee_per_gas, U256::from(0_i32));
    }

    #[tokio::test]
    async fn test_provider_get_testnet_paymaster() {
        let provider = local_provider();
        let expected_address: Address = "0x4cccf49428918845022048757f8c9af961fa9a90"
            .parse()
            .unwrap();
        let testnet_paymaster = provider.get_testnet_paymaster().await.unwrap();
        assert_eq!(testnet_paymaster, expected_address);
    }

    #[tokio::test]
    async fn test_provider_estimate_gas_l1_to_l2() {
        let provider = local_provider();
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

        let estimated_fee = provider.estimate_gas_l1_to_l2(transaction).await.unwrap();

        assert_eq!(estimated_fee, U256::from(36_768_868_i32));
    }

    #[tokio::test]
    // TODO: This test is flacky. It could fail in the future.
    async fn test_provider_get_all_account_balances() {
        let provider = local_provider();
        let address: Address = "0xbd29a1b981925b94eec5c4f1125af02a2ec4d1ca"
            .parse()
            .unwrap();
        let balance = provider.get_balance(address, None).await.unwrap();

        let balances = provider.get_all_account_balances(address).await.unwrap();

        assert_eq!(
            balances
                .get(
                    &"0x0000000000000000000000000000000000000000"
                        .parse::<Address>()
                        .unwrap()
                )
                .unwrap()
                .clone(),
            balance
        );
    }

    #[tokio::test]
    async fn test_provider_get_block_details() {
        let provider = local_provider();
        let block = 2;

        assert!(provider.get_block_details(block).await.is_ok())
    }

    #[tokio::test]
    async fn test_provider_get_bridge_contracts() {
        let provider = local_provider();

        assert!(provider.get_bridge_contracts().await.is_ok());
    }

    #[tokio::test]
    async fn test_provider_get_bytecode_by_hash() {
        let provider = local_provider();
        let invalid_hash = H256::default();
        let test_block = provider.get_block_details(2).await.unwrap();
        let valid_hash = test_block.root_hash;

        assert!(provider.get_bytecode_by_hash(invalid_hash).await.is_err());
        assert!(provider.get_bytecode_by_hash(valid_hash).await.is_err());
    }

    #[tokio::test]
    #[ignore = "fix"]
    async fn test_provider_get_confirmed_tokens() {
        let provider = local_provider();
        let from = 0;
        let limit = 10;

        assert!(provider.get_confirmed_tokens(from, limit).await.is_ok());
    }

    // TODO: This test is flacky. It could fail in the future.
    #[tokio::test]
    async fn test_provider_get_l1_batch_block_range() {
        let provider = local_provider();
        let batch = 1;

        assert!(provider.get_l1_batch_block_range(batch).await.is_ok());
    }

    #[tokio::test]
    async fn test_provider_get_l1_batch_details() {
        let provider = local_provider();
        let batch = 1;

        assert!(provider.get_l1_batch_details(batch).await.is_ok());
    }

    #[tokio::test]
    async fn test_provider_get_l2_to_l1_log_proof() {
        let provider = local_provider();
        let tx_hash: H256 = "0xac9cf301af3b11760feb9d84283513f993dcd29de6e5fd28a8f41b1c7c0469ed"
            .parse()
            .unwrap();

        assert!(provider.get_l2_to_l1_log_proof(tx_hash, None).await.is_ok());
    }

    // #[tokio::test]
    // async fn test_provider_get_l2_to_l1_msg_proof() {
    //     let provider = local_provider();
    //     let block = 2;
    //     let sender = /* create an address object */;
    //     let msg = /* create a hash object */;

    //     assert!(provider.get_l2_to_l1_msg_proof(block, sender, msg, None).await.is_ok());
    // }

    #[tokio::test]
    async fn test_provider_get_main_contract() {
        let provider = local_provider();
        let expected_address: Address = "0x7e9549ad6911839bd256672ca14cec0760add9fd"
            .parse()
            .unwrap();

        let main_contract = provider.get_main_contract().await.unwrap();

        assert_eq!(main_contract, expected_address);
    }

    // TODO: This test is flacky. It could fail in the future. We should create a
    // transaction, send it, and the assert that the details match.
    #[tokio::test]
    async fn test_provider_get_raw_block_transactions() {
        let provider = local_provider();
        let block = 1;

        assert!(provider.get_raw_block_transactions(block).await.is_ok());
    }

    #[tokio::test]
    async fn test_provider_get_token_price() {
        let provider = local_provider();
        let address: Address = "0x0000000000000000000000000000000000000000"
            .parse()
            .unwrap();

        assert!(provider.get_token_price(address).await.is_ok());
    }

    // TODO: This test is flacky. It could fail in the future. We should create a
    // transaction, send it, and the assert that the details match.
    #[tokio::test]
    async fn test_provider_get_transaction_details() {
        let provider = local_provider();
        let test_block = provider.get_block_details(2).await.unwrap();
        let hash = test_block.root_hash;

        assert!(provider.get_transaction_details(hash).await.is_ok());
    }

    #[tokio::test]
    async fn test_provider_get_l1_batch_number() {
        let provider = local_provider();

        assert!(provider.get_l1_batch_number().await.is_ok());
    }

    #[tokio::test]
    async fn test_provider_get_l1_chain_id() {
        let provider = local_provider();

        assert!(provider.get_l1_chain_id().await.is_ok());
    }

    #[tokio::test]
    async fn test_provider_debug_trace_block_by_hash() {
        let provider = local_provider();
        let test_block = provider.get_block_details(2).await.unwrap();
        let hash = test_block.root_hash;

        let options = Some(TracerConfig {
            disable_storage: None,
            disable_stack: None,
            enable_memory: None,
            enable_return_data: None,
            tracer: Some("callTracer".to_owned()),
            tracer_config: Some(HashMap::from([("onlyTopCall".to_owned(), true)])),
        });

        assert!(
            ZKSProvider::debug_trace_block_by_hash(&provider, hash, None)
                .await
                .is_ok()
        );
        assert!(
            ZKSProvider::debug_trace_block_by_hash(&provider, hash, options)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_provider_debug_trace_block_by_number() {
        let provider = local_provider();
        let block_number = U256::from(2);
        let options = Some(TracerConfig {
            disable_storage: None,
            disable_stack: None,
            enable_memory: None,
            enable_return_data: None,
            tracer: Some("callTracer".to_owned()),
            tracer_config: Some(HashMap::from([("onlyTopCall".to_owned(), true)])),
        });

        assert!(
            ZKSProvider::debug_trace_block_by_number(&provider, block_number, None)
                .await
                .is_ok()
        );
        assert!(
            ZKSProvider::debug_trace_block_by_number(&provider, block_number, options)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_provider_debug_trace_call() {
        let provider = local_provider();
        #[derive(Serialize, Deserialize, Debug)]
        struct TestTransaction {
            from: String,
            to: String,
            data: String,
        }

        let request = TestTransaction {
            from: "0x1111111111111111111111111111111111111111".to_owned(),
            to: "0x2222222222222222222222222222222222222222".to_owned(),
            data: "0x608060405234801561001057600080fd5b50610228806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c80639146769014610030575b600080fd5b61003861004e565b6040516100459190610170565b60405180910390f35b60606000805461005d906101c1565b80601f0160208091040260200160405190810160405280929190818152602001828054610089906101c1565b80156100d65780601f106100ab576101008083540402835291602001916100d6565b820191906000526020600020905b8154815290600101906020018083116100b957829003601f168201915b5050505050905090565b600081519050919050565b600082825260208201905092915050565b60005b8381101561011a5780820151818401526020810190506100ff565b60008484015250505050565b6000601f19601f8301169050919050565b6000610142826100e0565b61014c81856100eb565b935061015c8185602086016100fc565b61016581610126565b840191505092915050565b6000602082019050818103600083015261018a8184610137565b905092915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b600060028204905060018216806101d957607f821691505b6020821081036101ec576101eb610192565b5b5091905056fea26469706673582212203d7f62ad5ef1f9670aa630c438f1a75844e1d2cfaf92e6985c698b7009e3dfa864736f6c63430008140033".to_owned(),
        };

        let block = Some(U256::from(2));
        let options = Some(TracerConfig {
            disable_storage: None,
            disable_stack: None,
            enable_memory: None,
            enable_return_data: None,
            tracer: Some("callTracer".to_owned()),
            tracer_config: Some(HashMap::from([("onlyTopCall".to_owned(), true)])),
        });

        assert!(
            ZKSProvider::debug_trace_call(&provider, &request, None, None)
                .await
                .is_ok()
        );
        assert!(
            ZKSProvider::debug_trace_call(&provider, &request, block, None)
                .await
                .is_ok()
        );
        assert!(
            ZKSProvider::debug_trace_call(&provider, &request, block, options.clone())
                .await
                .is_ok()
        );
        assert!(
            ZKSProvider::debug_trace_call(&provider, request, None, options)
                .await
                .is_ok()
        );
    }

    // TODO: This test is flacky. It could fail in the future.
    #[tokio::test]
    async fn test_provider_debug_trace_transaction() {
        let provider = local_provider();
        let transaction_hash = "0x84472204e445cb3cd5f3ce5e23abcc2892cda5e61b35855a7f0bb1562a6e30e7"
            .parse()
            .unwrap();
        let options = Some(TracerConfig {
            disable_storage: None,
            disable_stack: None,
            enable_memory: None,
            enable_return_data: None,
            tracer: Some("callTracer".to_owned()),
            tracer_config: Some(HashMap::from([("onlyTopCall".to_owned(), true)])),
        });

        assert!(
            ZKSProvider::debug_trace_transaction(&provider, transaction_hash, None)
                .await
                .is_ok()
        );
        assert!(
            ZKSProvider::debug_trace_transaction(&provider, transaction_hash, options)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_signer_estimate_fee() {
        let provider = local_signer();
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

        assert_eq!(estimated_fee.gas_limit, U256::from(162_436_i32));
        assert_eq!(estimated_fee.gas_per_pubdata_limit, U256::from(66_i32));
        assert_eq!(estimated_fee.max_fee_per_gas, U256::from(250_000_000_i32));
        assert_eq!(estimated_fee.max_priority_fee_per_gas, U256::from(0_i32));
    }

    #[tokio::test]
    async fn test_signer_get_testnet_paymaster() {
        let provider = local_signer();
        let expected_address: Address = "0x4cccf49428918845022048757f8c9af961fa9a90"
            .parse()
            .unwrap();
        let testnet_paymaster = provider.get_testnet_paymaster().await.unwrap();
        assert_eq!(testnet_paymaster, expected_address);
    }

    #[tokio::test]
    async fn test_signer_estimate_gas_l1_to_l2() {
        let provider = local_signer();
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

        let estimated_fee = provider.estimate_gas_l1_to_l2(transaction).await.unwrap();

        assert_eq!(estimated_fee, U256::from(36_768_868_i32));
    }

    #[tokio::test]
    // TODO: This test is flacky. It could fail in the future.
    async fn test_signer_get_all_account_balances() {
        let provider = local_signer();
        let address: Address = "0xbd29a1b981925b94eec5c4f1125af02a2ec4d1ca"
            .parse()
            .unwrap();
        let balance = provider.get_balance(address, None).await.unwrap();

        let balances = provider.get_all_account_balances(address).await.unwrap();

        assert_eq!(
            balances
                .get(
                    &"0x0000000000000000000000000000000000000000"
                        .parse::<Address>()
                        .unwrap()
                )
                .unwrap()
                .clone(),
            balance
        );
    }

    #[tokio::test]
    async fn test_signer_get_block_details() {
        let provider = local_signer();
        let block = 2;

        assert!(provider.get_block_details(block).await.is_ok())
    }

    #[tokio::test]
    async fn test_signer_get_bridge_contracts() {
        let provider = local_signer();

        assert!(provider.get_bridge_contracts().await.is_ok());
    }

    #[tokio::test]
    async fn test_signer_get_bytecode_by_hash() {
        let provider = local_signer();
        let invalid_hash = H256::default();
        let valid_hash: H256 = "0x7641711d8997f701a4d5929b6661185aeb5ae1fdff33288b6b5df1c05135cfc9"
            .parse()
            .unwrap();

        assert!(provider.get_bytecode_by_hash(invalid_hash).await.is_err());
        assert!(provider.get_bytecode_by_hash(valid_hash).await.is_err());
    }

    #[tokio::test]
    async fn test_signer_get_confirmed_tokens() {
        let provider = local_signer();
        let from = 0;
        let limit = 10;

        assert!(provider.get_confirmed_tokens(from, limit).await.is_ok());
    }

    // TODO: This test is flacky. It could fail in the future.
    #[tokio::test]
    async fn test_signer_get_l1_batch_block_range() {
        let provider = local_signer();
        let batch = 1;

        assert!(provider.get_l1_batch_block_range(batch).await.is_ok());
    }

    #[tokio::test]
    async fn test_signer_get_l1_batch_details() {
        let provider = local_signer();
        let batch = 1;

        assert!(provider.get_l1_batch_details(batch).await.is_ok());
    }

    #[tokio::test]
    async fn test_signer_get_l2_to_l1_log_proof() {
        let provider = local_signer();
        let tx_hash: H256 = "0xac9cf301af3b11760feb9d84283513f993dcd29de6e5fd28a8f41b1c7c0469ed"
            .parse()
            .unwrap();

        assert!(provider.get_l2_to_l1_log_proof(tx_hash, None).await.is_ok());
    }

    // #[tokio::test]
    // async fn test_signer_get_l2_to_l1_msg_proof() {
    //     let provider = local_signer();
    //     let block = 2;
    //     let sender = /* create an address object */;
    //     let msg = /* create a hash object */;

    //     assert!(provider.get_l2_to_l1_msg_proof(block, sender, msg, None).await.is_ok());
    // }

    #[tokio::test]
    async fn test_signer_get_main_contract() {
        let provider = local_signer();
        let expected_address: Address = "0x7e9549ad6911839bd256672ca14cec0760add9fd"
            .parse()
            .unwrap();

        let main_contract = provider.get_main_contract().await.unwrap();

        assert_eq!(main_contract, expected_address);
    }

    // TODO: This test is flacky. It could fail in the future. We should create a
    // transaction, send it, and the assert that the details match.
    #[tokio::test]
    async fn test_signer_get_raw_block_transactions() {
        let provider = local_signer();
        let block = 1;

        assert!(provider.get_raw_block_transactions(block).await.is_ok());
    }

    #[tokio::test]
    async fn test_signer_get_token_price() {
        let provider = local_signer();
        let address: Address = "0x0000000000000000000000000000000000000000"
            .parse()
            .unwrap();

        assert!(provider.get_token_price(address).await.is_ok());
    }

    // TODO: This test is flacky. It could fail in the future. We should create a
    // transaction, send it, and the assert that the details match.
    #[tokio::test]
    async fn test_signer_get_transaction_details() {
        let provider = local_signer();
        let hash: H256 = "0xac9cf301af3b11760feb9d84283513f993dcd29de6e5fd28a8f41b1c7c0469ed"
            .parse()
            .unwrap();

        assert!(provider.get_transaction_details(hash).await.is_ok());
    }

    #[tokio::test]
    async fn test_signer_get_l1_batch_number() {
        let provider = local_signer();

        assert!(provider.get_l1_batch_number().await.is_ok());
    }

    #[tokio::test]
    async fn test_signer_get_l1_chain_id() {
        let provider = local_signer();

        assert!(provider.get_l1_chain_id().await.is_ok());
    }

    #[tokio::test]
    async fn test_signer_debug_trace_block_by_hash() {
        let provider = local_signer();
        let test_block = provider.get_block_details(2).await.unwrap();
        let hash = test_block.root_hash;

        let options = Some(TracerConfig {
            disable_storage: None,
            disable_stack: None,
            enable_memory: None,
            enable_return_data: None,
            tracer: Some("callTracer".to_owned()),
            tracer_config: Some(HashMap::from([("onlyTopCall".to_owned(), true)])),
        });

        assert!(
            ZKSProvider::debug_trace_block_by_hash(&provider, hash, None)
                .await
                .is_ok()
        );
        assert!(
            ZKSProvider::debug_trace_block_by_hash(&provider, hash, options)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_signer_debug_trace_block_by_number() {
        let provider = local_signer();
        let block_number = U256::from(2);
        let options = Some(TracerConfig {
            disable_storage: None,
            disable_stack: None,
            enable_memory: None,
            enable_return_data: None,
            tracer: Some("callTracer".to_owned()),
            tracer_config: Some(HashMap::from([("onlyTopCall".to_owned(), true)])),
        });

        assert!(
            ZKSProvider::debug_trace_block_by_number(&provider, block_number, None)
                .await
                .is_ok()
        );
        assert!(
            ZKSProvider::debug_trace_block_by_number(&provider, block_number, options)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_signer_debug_trace_call() {
        let provider = local_signer();
        #[derive(Serialize, Deserialize, Debug)]
        struct TestTransaction {
            from: String,
            to: String,
            data: String,
        }

        let request = TestTransaction {
            from: "0x1111111111111111111111111111111111111111".to_owned(),
            to: "0x2222222222222222222222222222222222222222".to_owned(),
            data: "0x608060405234801561001057600080fd5b50610228806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c80639146769014610030575b600080fd5b61003861004e565b6040516100459190610170565b60405180910390f35b60606000805461005d906101c1565b80601f0160208091040260200160405190810160405280929190818152602001828054610089906101c1565b80156100d65780601f106100ab576101008083540402835291602001916100d6565b820191906000526020600020905b8154815290600101906020018083116100b957829003601f168201915b5050505050905090565b600081519050919050565b600082825260208201905092915050565b60005b8381101561011a5780820151818401526020810190506100ff565b60008484015250505050565b6000601f19601f8301169050919050565b6000610142826100e0565b61014c81856100eb565b935061015c8185602086016100fc565b61016581610126565b840191505092915050565b6000602082019050818103600083015261018a8184610137565b905092915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b600060028204905060018216806101d957607f821691505b6020821081036101ec576101eb610192565b5b5091905056fea26469706673582212203d7f62ad5ef1f9670aa630c438f1a75844e1d2cfaf92e6985c698b7009e3dfa864736f6c63430008140033".to_owned(),
        };

        let block = Some(U256::from(2));
        let options = Some(TracerConfig {
            disable_storage: None,
            disable_stack: None,
            enable_memory: None,
            enable_return_data: None,
            tracer: Some("callTracer".to_owned()),
            tracer_config: Some(HashMap::from([("onlyTopCall".to_owned(), true)])),
        });

        assert!(
            ZKSProvider::debug_trace_call(&provider, &request, None, None)
                .await
                .is_ok()
        );
        assert!(
            ZKSProvider::debug_trace_call(&provider, &request, block, None)
                .await
                .is_ok()
        );
        assert!(
            ZKSProvider::debug_trace_call(&provider, &request, block, options.clone())
                .await
                .is_ok()
        );
        assert!(
            ZKSProvider::debug_trace_call(&provider, request, None, options)
                .await
                .is_ok()
        );
    }

    // TODO: This test is flacky. It could fail in the future.
    #[tokio::test]
    async fn test_signer_debug_trace_transaction() {
        let provider = local_signer();
        let transaction_hash = "0x84472204e445cb3cd5f3ce5e23abcc2892cda5e61b35855a7f0bb1562a6e30e7"
            .parse()
            .unwrap();
        let options = Some(TracerConfig {
            disable_storage: None,
            disable_stack: None,
            enable_memory: None,
            enable_return_data: None,
            tracer: Some("callTracer".to_owned()),
            tracer_config: Some(HashMap::from([("onlyTopCall".to_owned(), true)])),
        });

        assert!(
            ZKSProvider::debug_trace_transaction(&provider, transaction_hash, None)
                .await
                .is_ok()
        );
        assert!(
            ZKSProvider::debug_trace_transaction(&provider, transaction_hash, options)
                .await
                .is_ok()
        );
    }
}
