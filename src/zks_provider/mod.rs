use async_trait::async_trait;
use ethers::{
    abi::{encode, HumanReadableParser, Token, Tokenize},
    prelude::{
        k256::{
            ecdsa::{RecoveryId, Signature as RecoverableSignature},
            schnorr::signature::hazmat::PrehashSigner,
        },
        SignerMiddleware,
    },
    providers::{JsonRpcClient, Middleware, Provider, ProviderError},
    signers::{Signer, Wallet},
    types::{
        transaction::{eip2718::TypedTransaction, eip712::Eip712Error},
        Address, BlockNumber, Eip1559TransactionRequest, Signature, TransactionReceipt, H256, U256,
        U64,
    },
};
use ethers_contract::providers::PendingTransaction;
use serde::Serialize;
use serde_json::json;
use std::{collections::HashMap, fmt::Debug, time::Duration};
use tokio::time::Instant;

pub mod types;
use types::Fee;

use crate::{
    eip712::{Eip712Meta, Eip712Transaction, Eip712TransactionRequest},
    zks_utils::{
        self, is_precompile, DEFAULT_GAS, EIP712_TX_TYPE, MAX_FEE_PER_GAS, MAX_PRIORITY_FEE_PER_GAS,
    },
    zks_wallet::Overrides,
};

use self::types::{
    BlockDetails, BlockRange, BridgeContracts, DebugTrace, L1BatchDetails, Proof, TokenInfo,
    TracerConfig, Transaction, TransactionDetails,
};

/// This trait wraps every JSON-RPC call specified in zkSync Era's documentation
/// https://era.zksync.io/docs/api/api.html#zksync-era-json-rpc-methods
#[async_trait]
pub trait ZKSProvider {
    type Provider: JsonRpcClient;
    type ZKProvider: JsonRpcClient;

    async fn zk_estimate_gas<T>(&self, transaction: T) -> Result<U256, ProviderError>
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
    async fn get_block_details<T>(&self, block: T) -> Result<Option<BlockDetails>, ProviderError>
    where
        T: Into<U64> + Send + Sync + Serialize + Debug;

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
    async fn get_l1_batch_block_range<T>(&self, batch: T) -> Result<BlockRange, ProviderError>
    where
        T: Into<U64> + Send + Sync + Serialize + Debug;

    /// Returns data pertaining to a given batch.
    async fn get_l1_batch_details<T>(&self, batch: T) -> Result<L1BatchDetails, ProviderError>
    where
        T: Into<U64> + Send + Sync + Serialize + Debug;

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
    async fn get_l2_to_l1_msg_proof<T>(
        &self,
        block: T,
        sender: Address,
        msg: H256,
        l2_log_position: Option<u64>,
    ) -> Result<Option<Proof>, ProviderError>
    where
        T: Into<U64> + Send + Sync + Serialize + Debug;

    /// Returns the address of the zkSync Era contract.
    async fn get_main_contract(&self) -> Result<Address, ProviderError>;

    /// Returns data of transactions in a block.
    async fn get_raw_block_transactions<T>(
        &self,
        block: T,
    ) -> Result<Vec<Transaction>, ProviderError>
    where
        T: Into<U64> + Send + Sync + Serialize + Debug;

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
    async fn debug_trace_block_by_number<T>(
        &self,
        block: T,
        options: Option<TracerConfig>,
    ) -> Result<DebugTrace, ProviderError>
    where
        T: Into<U64> + Send + Sync + Serialize + Debug;

    /// Returns debug trace containing information on a specific calls given by the call request.
    async fn debug_trace_call<R, T>(
        &self,
        request: R,
        block: Option<T>,
        options: Option<TracerConfig>,
    ) -> Result<DebugTrace, ProviderError>
    where
        R: Debug + Serialize + Send + Sync,
        T: Into<U64> + Send + Sync + Serialize + Debug;

    /// Uses the EVM's callTracer to return a debug trace of a specific transaction given by its transaction hash.
    async fn debug_trace_transaction(
        &self,
        hash: H256,
        options: Option<TracerConfig>,
    ) -> Result<DebugTrace, ProviderError>;

    async fn send_eip712<D>(
        &self,
        wallet: &Wallet<D>,
        contract_address: Address,
        function_signature: &str,
        function_parameters: Option<Vec<String>>,
        overrides: Option<Overrides>,
    ) -> Result<PendingTransaction<Self::ZKProvider>, ProviderError>
    where
        D: PrehashSigner<(RecoverableSignature, RecoveryId)> + Send + Sync;

    async fn send<D>(
        &self,
        wallet: &Wallet<D>,
        contract_address: Address,
        function_signature: &str,
        function_parameters: Option<Vec<String>>,
        overrides: Option<Overrides>,
    ) -> Result<PendingTransaction<Self::Provider>, ProviderError>
    where
        D: PrehashSigner<(RecoverableSignature, RecoveryId)> + Send + Sync;

    async fn wait_for_finalize(
        &self,
        transaction_receipt: TransactionReceipt,
        polling_time_in_seconds: Option<Duration>,
        timeout_in_seconds: Option<Duration>,
    ) -> Result<TransactionReceipt, ProviderError>;

    async fn call(
        &self,
        contract_address: Address,
        function_signature: &str,
        function_parameters: Option<Vec<String>>,
    ) -> Result<Vec<Token>, ProviderError>;
}

#[async_trait]
impl<M: Middleware + ZKSProvider, S: Signer> ZKSProvider for SignerMiddleware<M, S> {
    type Provider = <M as Middleware>::Provider;
    type ZKProvider = <M as ZKSProvider>::ZKProvider;

    async fn zk_estimate_gas<T>(&self, transaction: T) -> Result<U256, ProviderError>
    where
        T: Debug + Serialize + Send + Sync,
    {
        <M as ZKSProvider>::zk_estimate_gas(self.inner(), transaction).await
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

    async fn get_block_details<T>(&self, block: T) -> Result<Option<BlockDetails>, ProviderError>
    where
        T: Into<U64> + Send + Sync + Serialize + Debug,
    {
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

    async fn get_l1_batch_block_range<T>(&self, batch_id: T) -> Result<BlockRange, ProviderError>
    where
        T: Into<U64> + Send + Sync + Serialize + Debug,
    {
        self.inner().get_l1_batch_block_range(batch_id).await
    }

    async fn get_l1_batch_details<T>(&self, batch_id: T) -> Result<L1BatchDetails, ProviderError>
    where
        T: Into<U64> + Send + Sync + Serialize + Debug,
    {
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

    async fn get_l2_to_l1_msg_proof<T>(
        &self,
        block: T,
        sender: Address,
        msg: H256,
        l2_log_position: Option<u64>,
    ) -> Result<Option<Proof>, ProviderError>
    where
        T: Into<U64> + Send + Sync + Serialize + Debug,
    {
        self.inner()
            .get_l2_to_l1_msg_proof(block, sender, msg, l2_log_position)
            .await
    }

    async fn get_main_contract(&self) -> Result<Address, ProviderError> {
        self.inner().get_main_contract().await
    }

    async fn get_raw_block_transactions<T>(
        &self,
        block: T,
    ) -> Result<Vec<Transaction>, ProviderError>
    where
        T: Into<U64> + Send + Sync + Serialize + Debug,
    {
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

    async fn debug_trace_block_by_number<T>(
        &self,
        block: T,
        options: Option<TracerConfig>,
    ) -> Result<DebugTrace, ProviderError>
    where
        T: Into<U64> + Send + Sync + Serialize + Debug,
    {
        ZKSProvider::debug_trace_block_by_number(self.inner(), block, options).await
    }

    async fn debug_trace_call<R, T>(
        &self,
        request: R,
        block: Option<T>,
        options: Option<TracerConfig>,
    ) -> Result<DebugTrace, ProviderError>
    where
        R: Debug + Serialize + Send + Sync,
        T: Into<U64> + Send + Sync + Serialize + Debug,
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

    async fn send_eip712<D>(
        &self,
        wallet: &Wallet<D>,
        contract_address: Address,
        function_signature: &str,
        function_parameters: Option<Vec<String>>,
        overrides: Option<Overrides>,
    ) -> Result<PendingTransaction<Self::ZKProvider>, ProviderError>
    where
        D: PrehashSigner<(RecoverableSignature, RecoveryId)> + Send + Sync,
    {
        self.inner()
            .send_eip712(
                wallet,
                contract_address,
                function_signature,
                function_parameters,
                overrides,
            )
            .await
    }

    async fn send<D>(
        &self,
        wallet: &Wallet<D>,
        contract_address: Address,
        function_signature: &str,
        function_parameters: Option<Vec<String>>,
        _overrides: Option<Overrides>,
    ) -> Result<PendingTransaction<Self::Provider>, ProviderError>
    where
        D: PrehashSigner<(RecoverableSignature, RecoveryId)> + Send + Sync,
    {
        let tx = build_send_tx(
            self,
            wallet,
            contract_address,
            function_signature,
            function_parameters,
            _overrides,
        )
        .await?;
        self.send_transaction(tx, None)
            .await
            .map_err(|e| ProviderError::CustomError(format!("Error sending transaction: {e:?}")))
    }

    async fn wait_for_finalize(
        &self,
        transaction_receipt: TransactionReceipt,
        polling_time_in_seconds: Option<Duration>,
        timeout_in_seconds: Option<Duration>,
    ) -> Result<TransactionReceipt, ProviderError> {
        self.inner()
            .wait_for_finalize(
                transaction_receipt,
                polling_time_in_seconds,
                timeout_in_seconds,
            )
            .await
    }

    async fn call(
        &self,
        contract_address: Address,
        function_signature: &str,
        function_parameters: Option<Vec<String>>,
    ) -> Result<Vec<Token>, ProviderError> {
        ZKSProvider::call(
            self.inner(),
            contract_address,
            function_signature,
            function_parameters,
        )
        .await
    }
}

#[async_trait]
impl<P: JsonRpcClient> ZKSProvider for Provider<P> {
    type Provider = P;
    type ZKProvider = P;

    async fn zk_estimate_gas<T>(&self, transaction: T) -> Result<U256, ProviderError>
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

    async fn get_block_details<T>(&self, block: T) -> Result<Option<BlockDetails>, ProviderError>
    where
        T: Into<U64> + Send + Sync + Serialize + Debug,
    {
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

    async fn get_l1_batch_block_range<T>(&self, batch: T) -> Result<BlockRange, ProviderError>
    where
        T: Into<U64> + Send + Sync + Serialize + Debug,
    {
        self.request("zks_getL1BatchBlockRange", [batch]).await
    }

    async fn get_l1_batch_details<T>(&self, batch: T) -> Result<L1BatchDetails, ProviderError>
    where
        T: Into<U64> + Send + Sync + Serialize + Debug,
    {
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

    async fn get_l2_to_l1_msg_proof<T>(
        &self,
        block: T,
        sender: Address,
        msg: H256,
        l2_log_position: Option<u64>,
    ) -> Result<Option<Proof>, ProviderError>
    where
        T: Into<U64> + Send + Sync + Serialize + Debug,
    {
        self.request(
            "zks_getL2ToL1MsgProof",
            json!([block, sender, msg, l2_log_position]),
        )
        .await
    }

    async fn get_main_contract(&self) -> Result<Address, ProviderError> {
        self.request("zks_getMainContract", ()).await
    }

    async fn get_raw_block_transactions<T>(
        &self,
        block: T,
    ) -> Result<Vec<Transaction>, ProviderError>
    where
        T: Into<U64> + Send + Sync + Serialize + Debug,
    {
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
            .await?
            .get(0)
            .ok_or(ProviderError::CustomError(
                "error on debug_trace_block_by_hash".to_owned(),
            ))?
            .get("result")
            .ok_or(ProviderError::CustomError(
                "error on debug_trace_block_by_hash".to_owned(),
            ))?
            .clone();
        serde_json::from_value(processable_response).map_err(ProviderError::SerdeJson)
    }

    async fn debug_trace_block_by_number<T>(
        &self,
        block: T,
        options: Option<TracerConfig>,
    ) -> Result<DebugTrace, ProviderError>
    where
        T: Into<U64> + Send + Sync + Serialize + Debug,
    {
        let processable_response = self
            .request::<serde_json::Value, serde_json::Value>(
                "debug_traceBlockByNumber",
                json!([block, options]),
            )
            .await?
            .get(0)
            .ok_or(ProviderError::CustomError(
                "error on debug_trace_block_by_hash".to_owned(),
            ))?
            .get("result")
            .ok_or(ProviderError::CustomError(
                "error on debug_trace_block_by_hash".to_owned(),
            ))?
            .clone();
        serde_json::from_value(processable_response).map_err(ProviderError::SerdeJson)
    }

    async fn debug_trace_call<R, T>(
        &self,
        request: R,
        block: Option<T>,
        options: Option<TracerConfig>,
    ) -> Result<DebugTrace, ProviderError>
    where
        R: Debug + Serialize + Send + Sync,
        T: Into<U64> + Send + Sync + Serialize + Debug,
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

    async fn send_eip712<D>(
        &self,
        wallet: &Wallet<D>,
        contract_address: Address,
        function_signature: &str,
        function_parameters: Option<Vec<String>>,
        overrides: Option<Overrides>,
    ) -> Result<PendingTransaction<Self::ZKProvider>, ProviderError>
    where
        D: PrehashSigner<(RecoverableSignature, RecoveryId)> + Send + Sync,
    {
        // Note: We couldn't implement ProviderError::LexerError because ethers-rs's LexerError is not exposed.
        // TODO check for ECADD precompile address to get the function signature.
        let function = HumanReadableParser::parse_function(function_signature)
            .map_err(|e| ProviderError::CustomError(e.to_string()))?;

        let mut send_request = if let Some(overrides) = overrides {
            Eip712TransactionRequest::from_overrides(overrides)
        } else {
            Eip712TransactionRequest::new()
        };

        let function_args = if let Some(function_args) = function_parameters {
            function
                .decode_input(
                    &zks_utils::encode_args(&function, &function_args)
                        .map_err(|e| ProviderError::CustomError(e.to_string()))?,
                )
                .map_err(|e| ProviderError::CustomError(e.to_string()))?
        } else {
            vec![]
        };

        send_request = send_request
            .r#type(EIP712_TX_TYPE)
            .from(wallet.address())
            .to(contract_address)
            .chain_id(wallet.chain_id())
            .nonce(self.get_transaction_count(wallet.address(), None).await?)
            .gas_price(self.get_gas_price().await?)
            .max_fee_per_gas(self.get_gas_price().await?)
            .data(if !function_args.is_empty() {
                function
                    .encode_input(&function_args)
                    .map_err(|e| ProviderError::CustomError(e.to_string()))?
            } else {
                function.short_signature().into()
            });

        let fee = self.estimate_fee(send_request.clone()).await?;
        send_request = send_request
            .max_priority_fee_per_gas(fee.max_priority_fee_per_gas)
            .max_fee_per_gas(fee.max_fee_per_gas)
            .gas_limit(fee.gas_limit);

        let signable_data: Eip712Transaction = send_request
            .clone()
            .try_into()
            .map_err(|e: Eip712Error| ProviderError::CustomError(e.to_string()))?;
        let signature: Signature = wallet
            .sign_typed_data(&signable_data)
            .await
            .map_err(|e| ProviderError::CustomError(format!("error signing transaction: {e}")))?;
        send_request =
            send_request.custom_data(Eip712Meta::new().custom_signature(signature.to_vec()));

        let encoded_rlp = &*send_request
            .rlp_signed(signature)
            .map_err(|e| ProviderError::CustomError(format!("error encoding transaction: {e}")))?;
        self.send_raw_transaction([&[EIP712_TX_TYPE], encoded_rlp].concat().into())
            .await
    }

    async fn send<D>(
        &self,
        wallet: &Wallet<D>,
        contract_address: Address,
        function_signature: &str,
        function_parameters: Option<Vec<String>>,
        _overrides: Option<Overrides>,
    ) -> Result<PendingTransaction<Self::Provider>, ProviderError>
    where
        D: PrehashSigner<(RecoverableSignature, RecoveryId)> + Send + Sync,
    {
        let tx = build_send_tx(
            self,
            wallet,
            contract_address,
            function_signature,
            function_parameters,
            _overrides,
        )
        .await?;
        self.send_transaction(tx, None).await
    }

    async fn wait_for_finalize(
        &self,
        transaction_receipt: TransactionReceipt,
        polling_time_in_seconds: Option<Duration>,
        timeout_in_seconds: Option<Duration>,
    ) -> Result<TransactionReceipt, ProviderError> {
        let polling_time_in_seconds = polling_time_in_seconds.unwrap_or(Duration::from_secs(2));
        let mut timer = tokio::time::interval(polling_time_in_seconds);
        let start = Instant::now();

        loop {
            timer.tick().await;

            if let Some(timeout) = timeout_in_seconds {
                if start.elapsed() >= timeout {
                    return Err(ProviderError::CustomError(
                        "Error waiting for transaction to be included into the finalized block"
                            .to_owned(),
                    ));
                }
            }

            // Wait for transaction to be included into the finalized block.
            let latest_block =
                self.get_block(BlockNumber::Finalized)
                    .await?
                    .ok_or(ProviderError::CustomError(
                        "Error getting finalized block".to_owned(),
                    ))?;

            if transaction_receipt.block_number <= latest_block.number {
                return Ok(transaction_receipt);
            }
        }
    }

    async fn call(
        &self,
        contract_address: Address,
        function_signature: &str,
        function_parameters: Option<Vec<String>>,
    ) -> Result<Vec<Token>, ProviderError> {
        // Note: We couldn't implement ZKSWalletError::LexerError because ethers-rs's LexerError is not exposed.
        let function = if contract_address == zks_utils::ECADD_PRECOMPILE_ADDRESS {
            zks_utils::ec_add_function()
        } else if contract_address == zks_utils::ECMUL_PRECOMPILE_ADDRESS {
            zks_utils::ec_mul_function()
        } else if contract_address == zks_utils::MODEXP_PRECOMPILE_ADDRESS {
            zks_utils::mod_exp_function()
        } else {
            HumanReadableParser::parse_function(function_signature)
                .map_err(|e| ProviderError::CustomError(e.to_string()))?
        };
        let function_args = if let Some(function_args) = function_parameters {
            function
                .decode_input(
                    &zks_utils::encode_args(&function, &function_args)
                        .map_err(|e| ProviderError::CustomError(e.to_string()))?,
                )
                .map_err(|e| ProviderError::CustomError(e.to_string()))?
        } else {
            vec![]
        };

        log::info!("{function_args:?}");

        let request: Eip1559TransactionRequest =
            Eip1559TransactionRequest::new().to(contract_address).data(
                match (!function_args.is_empty(), is_precompile(contract_address)) {
                    // The contract to call is a precompile with arguments.
                    (true, true) => encode(&function_args),
                    // The contract to call is a regular contract with arguments.
                    (true, false) => function
                        .encode_input(&function_args)
                        .map_err(|e| ProviderError::CustomError(e.to_string()))?,
                    // The contract to call is a precompile without arguments.
                    (false, true) => Default::default(),
                    // The contract to call is a regular contract without arguments.
                    (false, false) => function.short_signature().into(),
                },
            );

        let transaction: TypedTransaction = request.into();

        let encoded_output = Middleware::call(self, &transaction, None).await?;
        let decoded_output = function.decode_output(&encoded_output).map_err(|e| {
            ProviderError::CustomError(format!("failed to decode output: {e}\n{encoded_output}"))
        })?;

        Ok(if decoded_output.is_empty() {
            encoded_output.into_tokens()
        } else {
            decoded_output
        })
    }
}

async fn build_send_tx<D>(
    provider: &impl Middleware,
    wallet: &Wallet<D>,
    contract_address: Address,
    function_signature: &str,
    function_parameters: Option<Vec<String>>,
    _overrides: Option<Overrides>,
) -> Result<TypedTransaction, ProviderError>
where
    D: PrehashSigner<(RecoverableSignature, RecoveryId)> + Send + Sync,
{
    let function = HumanReadableParser::parse_function(function_signature)
        .map_err(|e| ProviderError::CustomError(e.to_string()))?;

    let function_args = if let Some(function_args) = function_parameters {
        function
            .decode_input(
                &zks_utils::encode_args(&function, &function_args)
                    .map_err(|e| ProviderError::CustomError(e.to_string()))?,
            )
            .map_err(|e| ProviderError::CustomError(e.to_string()))?
    } else {
        vec![]
    };

    // Sending transaction calling the main contract.
    let send_request = Eip1559TransactionRequest::new()
        .from(wallet.address())
        .to(contract_address)
        .chain_id(wallet.chain_id())
        .nonce(
            provider
                .get_transaction_count(wallet.address(), None)
                .await
                .map_err(|e| ProviderError::CustomError(e.to_string()))?,
        )
        .data(if !function_args.is_empty() {
            function
                .encode_input(&function_args)
                .map_err(|e| ProviderError::CustomError(e.to_string()))?
        } else {
            function.short_signature().into()
        })
        .value(0_u8)
        //FIXME we should use default calculation for gas related fields.
        .gas(DEFAULT_GAS)
        .max_fee_per_gas(MAX_FEE_PER_GAS)
        .max_priority_fee_per_gas(MAX_PRIORITY_FEE_PER_GAS);

    Ok(send_request.into())
}
