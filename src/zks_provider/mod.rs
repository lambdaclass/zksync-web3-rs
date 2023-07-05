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
use serde::Serialize;
use serde_json::json;
use std::{collections::HashMap, fmt::Debug, time::Duration};
use tokio::time::Instant;

pub mod types;
use types::Fee;

use crate::{
    eip712::{Eip712Meta, Eip712Transaction, Eip712TransactionRequest},
    zks_utils::{
        self, is_precompile, DEFAULT_GAS, EIP712_TX_TYPE, ERA_CHAIN_ID, ETH_CHAIN_ID,
        MAX_FEE_PER_GAS, MAX_PRIORITY_FEE_PER_GAS,
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
    ) -> Result<(Vec<Token>, H256), ProviderError>
    where
        D: PrehashSigner<(RecoverableSignature, RecoveryId)> + Send + Sync;

    async fn send<D>(
        &self,
        wallet: &Wallet<D>,
        contract_address: Address,
        function_signature: &str,
        function_parameters: Option<Vec<String>>,
        overrides: Option<Overrides>,
    ) -> Result<(Vec<Token>, H256), ProviderError>
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
    ) -> Result<(Vec<Token>, H256), ProviderError>
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
    ) -> Result<(Vec<Token>, H256), ProviderError>
    where
        D: PrehashSigner<(RecoverableSignature, RecoveryId)> + Send + Sync,
    {
        let tx = build_send_tx(
            self,
            wallet.address(),
            contract_address,
            function_signature,
            function_parameters,
            _overrides,
        )
        .await?;
        let pending_transaction = self
            .send_transaction(tx, None)
            .await
            .map_err(|e| ProviderError::CustomError(format!("Error sending transaction: {e:?}")))?;

        let transaction_receipt = pending_transaction
            .await?
            .ok_or(ProviderError::CustomError(
                "no transaction receipt".to_owned(),
            ))?;

        Ok((Vec::new(), transaction_receipt.transaction_hash))
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
    ) -> Result<(Vec<Token>, H256), ProviderError>
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
            .chain_id(ERA_CHAIN_ID)
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

        let pending_transaction = self
            .send_raw_transaction(
                [&[EIP712_TX_TYPE], &*send_request.rlp_unsigned()]
                    .concat()
                    .into(),
            )
            .await?;

        let transaction_receipt = pending_transaction
            .await?
            .ok_or(ProviderError::CustomError(
                "no transaction receipt".to_owned(),
            ))?;

        // TODO: decode function output.
        Ok((Vec::new(), transaction_receipt.transaction_hash))
    }

    async fn send<D>(
        &self,
        wallet: &Wallet<D>,
        contract_address: Address,
        function_signature: &str,
        function_parameters: Option<Vec<String>>,
        _overrides: Option<Overrides>,
    ) -> Result<(Vec<Token>, H256), ProviderError>
    where
        D: PrehashSigner<(RecoverableSignature, RecoveryId)> + Send + Sync,
    {
        let tx = build_send_tx(
            self,
            wallet.address(),
            contract_address,
            function_signature,
            function_parameters,
            _overrides,
        )
        .await?;
        let pending_transaction = self.send_transaction(tx, None).await?;

        let transaction_receipt = pending_transaction
            .await?
            .ok_or(ProviderError::CustomError(
                "no transaction receipt".to_owned(),
            ))?;

        Ok((Vec::new(), transaction_receipt.transaction_hash))
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

async fn build_send_tx(
    provider: &impl Middleware,
    sender: Address,
    contract_address: Address,
    function_signature: &str,
    function_parameters: Option<Vec<String>>,
    _overrides: Option<Overrides>,
) -> Result<TypedTransaction, ProviderError> {
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
        .from(sender)
        .to(contract_address)
        .chain_id(ETH_CHAIN_ID)
        .nonce(
            provider
                .get_transaction_count(sender, None)
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

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, fs::File, path::PathBuf, str::FromStr};

    use crate::{
        test_utils::*,
        zks_provider::{types::TracerConfig, ZKSProvider},
        zks_utils::ERA_CHAIN_ID,
        zks_wallet::ZKSWallet,
    };
    use ethers::{
        abi::Tokenize,
        prelude::{k256::ecdsa::SigningKey, MiddlewareBuilder, SignerMiddleware},
        providers::{Middleware, Provider},
        signers::{LocalWallet, Signer, Wallet},
        types::{Address, Bytes, H256, U256},
    };
    use serde::{Deserialize, Serialize};

    fn local_wallet() -> LocalWallet {
        "0x7726827caac94a7f9e1b160f7ea819f172f7b6f9d2a97f992c38edeab82d4110"
            .parse::<LocalWallet>()
            .unwrap()
            .with_chain_id(ERA_CHAIN_ID)
    }

    fn era_signer() -> SignerMiddleware<Provider<ethers::providers::Http>, Wallet<SigningKey>> {
        let signer = Wallet::with_chain_id(
            "0x7726827caac94a7f9e1b160f7ea819f172f7b6f9d2a97f992c38edeab82d4110"
                .parse::<Wallet<SigningKey>>()
                .unwrap(),
            ERA_CHAIN_ID,
        );
        era_provider().with_signer(signer)
    }

    #[tokio::test]
    async fn test_provider_estimate_fee() {
        let provider = era_provider();
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

        assert_eq!(estimated_fee.gas_limit, U256::from(162_436_u32));
        assert_eq!(estimated_fee.gas_per_pubdata_limit, U256::from(66_u32));
        assert_eq!(estimated_fee.max_fee_per_gas, U256::from(250_000_000_u32));
        assert_eq!(estimated_fee.max_priority_fee_per_gas, U256::from(0_u32));
    }

    #[tokio::test]
    async fn test_provider_get_testnet_paymaster() {
        let provider = era_provider();

        assert!(provider.get_testnet_paymaster().await.is_ok());
    }

    #[tokio::test]
    async fn test_provider_estimate_gas_l1_to_l2() {
        let provider = era_provider();
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

        assert_eq!(estimated_fee, U256::from(36_768_868_u64));
    }

    #[tokio::test]
    // TODO: This test is flacky. It could fail in the future.
    async fn test_provider_get_all_account_balances() {
        let provider = era_provider();
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
        let provider = era_provider();
        let existing_block = 1_u64;
        let non_existing_block = provider.get_block_number().await.unwrap() + 100_u64;

        let existing_block_details = provider.get_block_details(existing_block).await.unwrap();
        let non_existing_block_details = provider
            .get_block_details(non_existing_block.as_u32())
            .await
            .unwrap();

        assert!(existing_block_details.is_some());
        assert!(non_existing_block_details.is_none())
    }

    #[tokio::test]
    async fn test_provider_get_bridge_contracts() {
        let provider = era_provider();

        assert!(provider.get_bridge_contracts().await.is_ok());
    }

    #[tokio::test]
    async fn test_provider_get_bytecode_by_hash() {
        let provider = era_provider();
        let invalid_hash = "0x7641711d8997f701a4d5929b6661185aeb5ae1fdff33288b6b5df1c05135cfc9"
            .parse()
            .unwrap();
        let test_block = provider.get_block_details(2_u64).await.unwrap().unwrap();
        let valid_hash = test_block.root_hash;

        assert!(provider.get_bytecode_by_hash(invalid_hash).await.is_ok());
        assert!(provider.get_bytecode_by_hash(valid_hash).await.is_ok());
    }

    #[ignore]
    #[tokio::test]
    async fn test_provider_get_confirmed_tokens() {
        let provider = era_provider();
        let from = 0;
        let limit = 10;

        assert!(provider.get_confirmed_tokens(from, limit).await.is_ok());
    }

    // TODO: This test is flacky. It could fail in the future.
    #[tokio::test]
    async fn test_provider_get_l1_batch_block_range() {
        let provider = era_provider();
        let batch = 1_u64;

        assert!(provider.get_l1_batch_block_range(batch).await.is_ok());
    }

    #[tokio::test]
    async fn test_provider_get_l1_batch_details() {
        let provider = era_provider();
        let batch = 1_u64;

        assert!(provider.get_l1_batch_details(batch).await.is_ok());
    }

    #[tokio::test]
    async fn test_provider_get_l2_to_l1_log_proof() {
        let provider = era_provider();
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
        let provider = era_provider();

        assert!(provider.get_main_contract().await.is_ok());
    }

    // TODO: This test is flacky. It could fail in the future. We should create a
    // transaction, send it, and the assert that the details match.
    #[tokio::test]
    async fn test_provider_get_raw_block_transactions() {
        let provider = era_provider();
        let block = 1_u64;

        assert!(provider.get_raw_block_transactions(block).await.is_ok());
    }

    #[tokio::test]
    async fn test_provider_get_token_price() {
        let provider = era_provider();
        let address: Address = "0x0000000000000000000000000000000000000000"
            .parse()
            .unwrap();

        assert!(provider.get_token_price(address).await.is_ok());
    }

    // TODO: This test is flacky. It could fail in the future. We should create a
    // transaction, send it, and the assert that the details match.
    #[tokio::test]
    async fn test_provider_get_transaction_details() {
        let provider = era_provider();
        let test_block = provider.get_block_details(2_u64).await.unwrap().unwrap();
        let hash = test_block.root_hash;

        assert!(provider.get_transaction_details(hash).await.is_ok());
    }

    #[tokio::test]
    async fn test_provider_get_l1_batch_number() {
        let provider = era_provider();

        assert!(provider.get_l1_batch_number().await.is_ok());
    }

    #[tokio::test]
    async fn test_provider_get_l1_chain_id() {
        let provider = era_provider();

        assert!(provider.get_l1_chain_id().await.is_ok());
    }

    #[tokio::test]
    async fn test_provider_debug_trace_block_by_hash() {
        let provider = era_provider();
        let block_number = provider.get_block_number().await.unwrap() - 1_u64;
        let test_block = provider
            .get_block_details(block_number.as_u32())
            .await
            .unwrap()
            .unwrap();
        let hash_block = test_block.root_hash;

        let options = Some(TracerConfig {
            disable_storage: None,
            disable_stack: None,
            enable_memory: None,
            enable_return_data: None,
            tracer: Some("callTracer".to_owned()),
            tracer_config: Some(HashMap::from([("onlyTopCall".to_owned(), true)])),
        });

        assert!(
            ZKSProvider::debug_trace_block_by_hash(&provider, hash_block, None)
                .await
                .is_ok()
        );
        assert!(
            ZKSProvider::debug_trace_block_by_hash(&provider, hash_block, options)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_provider_debug_trace_block_by_number() {
        let provider = era_provider();
        let existing_block_number = provider.get_block_number().await.unwrap() - 1_u64;
        let non_existing_block_number = existing_block_number + 100_u64;
        let options = Some(TracerConfig {
            disable_storage: None,
            disable_stack: None,
            enable_memory: None,
            enable_return_data: None,
            tracer: Some("callTracer".to_owned()),
            tracer_config: Some(HashMap::from([("onlyTopCall".to_owned(), true)])),
        });

        assert!(
            ZKSProvider::debug_trace_block_by_number(&provider, existing_block_number, None)
                .await
                .is_ok()
        );
        assert!(ZKSProvider::debug_trace_block_by_number(
            &provider,
            existing_block_number,
            options.clone()
        )
        .await
        .is_ok());
        assert!(ZKSProvider::debug_trace_block_by_number(
            &provider,
            non_existing_block_number,
            None
        )
        .await
        .is_err());
        assert!(ZKSProvider::debug_trace_block_by_number(
            &provider,
            non_existing_block_number,
            options
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn test_provider_debug_trace_call() {
        let provider = era_provider();
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

        let block = provider.get_block_number().await.ok();
        let options = Some(TracerConfig {
            disable_storage: None,
            disable_stack: None,
            enable_memory: None,
            enable_return_data: None,
            tracer: Some("callTracer".to_owned()),
            tracer_config: Some(HashMap::from([("onlyTopCall".to_owned(), true)])),
        });

        println!(
            "{:?}",
            ZKSProvider::debug_trace_call::<&TestTransaction, u64>(&provider, &request, None, None)
                .await
        );

        assert!(ZKSProvider::debug_trace_call::<&TestTransaction, u64>(
            &provider, &request, None, None
        )
        .await
        .is_ok());
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
            ZKSProvider::debug_trace_call::<_, u64>(&provider, request, None, options)
                .await
                .is_ok()
        );
    }

    // TODO: This test is flacky. It could fail in the future.
    #[tokio::test]
    async fn test_provider_debug_trace_transaction() {
        let era_provider = era_provider();
        let zk_wallet = ZKSWallet::new(local_wallet(), None, Some(era_signer()), None).unwrap();

        let transaction_hash = zk_wallet
            .transfer(
                Address::from_str("0x36615Cf349d7F6344891B1e7CA7C72883F5dc049").unwrap(),
                1_u64.into(),
                None,
            )
            .await
            .unwrap()
            .transaction_hash;
        let invalid_transaction_hash: H256 =
            "0x84472204e445cb3cd5f3ce5e23abcc2892cda5e61b35855a7f0bb1562a6e30e7"
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
            ZKSProvider::debug_trace_transaction(&era_provider, transaction_hash, None)
                .await
                .is_ok()
        );
        assert!(ZKSProvider::debug_trace_transaction(
            &era_provider,
            transaction_hash,
            options.clone()
        )
        .await
        .is_ok());
        assert!(ZKSProvider::debug_trace_transaction(
            &era_provider,
            invalid_transaction_hash,
            None
        )
        .await
        .is_err());
        assert!(ZKSProvider::debug_trace_transaction(
            &era_provider,
            invalid_transaction_hash,
            options
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn test_signer_estimate_fee() {
        let provider = era_signer();
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

        assert_eq!(estimated_fee.gas_limit, U256::from(162_436_u32));
        assert_eq!(estimated_fee.gas_per_pubdata_limit, U256::from(66_u32));
        assert_eq!(estimated_fee.max_fee_per_gas, U256::from(250_000_000_u32));
        assert_eq!(estimated_fee.max_priority_fee_per_gas, U256::from(0_u32));
    }

    #[tokio::test]
    async fn test_signer_get_testnet_paymaster() {
        let provider = era_signer();

        assert!(provider.get_testnet_paymaster().await.is_ok());
    }

    #[tokio::test]
    async fn test_signer_estimate_gas_l1_to_l2() {
        let provider = era_signer();
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

        assert_eq!(estimated_fee, U256::from(36_768_868_u32));
    }

    #[tokio::test]
    // TODO: This test is flacky. It could fail in the future.
    async fn test_signer_get_all_account_balances() {
        let provider = era_signer();
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
        let provider = era_signer();
        let existing_block = 1_u64;
        let non_existing_block = provider.get_block_number().await.unwrap() + 100_u64;

        let existing_block_details = provider.get_block_details(existing_block).await.unwrap();
        let non_existing_block_details = provider
            .get_block_details(non_existing_block.as_u32())
            .await
            .unwrap();

        assert!(existing_block_details.is_some());
        assert!(non_existing_block_details.is_none())
    }

    #[tokio::test]
    async fn test_signer_get_bridge_contracts() {
        let provider = era_signer();

        assert!(provider.get_bridge_contracts().await.is_ok());
    }

    #[tokio::test]
    async fn test_signer_get_bytecode_by_hash() {
        let provider = era_signer();
        let invalid_hash = "0xac9cf301af3b11760feb9d84283513f993dcd29de6e5fd28a8f41b1c7c0469ed"
            .parse()
            .unwrap();
        let valid_hash: H256 = "0x7641711d8997f701a4d5929b6661185aeb5ae1fdff33288b6b5df1c05135cfc9"
            .parse()
            .unwrap();

        assert!(provider.get_bytecode_by_hash(invalid_hash).await.is_ok());
        assert!(provider.get_bytecode_by_hash(valid_hash).await.is_ok());
    }

    #[ignore]
    #[tokio::test]
    async fn test_signer_get_confirmed_tokens() {
        let provider = era_signer();
        let from = 0;
        let limit = 10;

        assert!(provider.get_confirmed_tokens(from, limit).await.is_ok());
    }

    // TODO: This test is flacky. It could fail in the future.
    #[tokio::test]
    async fn test_signer_get_l1_batch_block_range() {
        let provider = era_signer();
        let batch = 1_u64;

        assert!(provider.get_l1_batch_block_range(batch).await.is_ok());
    }

    #[tokio::test]
    async fn test_signer_get_l1_batch_details() {
        let provider = era_signer();
        let batch = 1_u64;

        assert!(provider.get_l1_batch_details(batch).await.is_ok());
    }

    #[tokio::test]
    async fn test_signer_get_l2_to_l1_log_proof() {
        let provider = era_signer();
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
        let provider = era_signer();

        assert!(provider.get_main_contract().await.is_ok());
    }

    // TODO: This test is flacky. It could fail in the future. We should create a
    // transaction, send it, and the assert that the details match.
    #[tokio::test]
    async fn test_signer_get_raw_block_transactions() {
        let provider = era_signer();
        let block = 1_u64;

        assert!(provider.get_raw_block_transactions(block).await.is_ok());
    }

    #[tokio::test]
    async fn test_signer_get_token_price() {
        let provider = era_signer();
        let address: Address = "0x0000000000000000000000000000000000000000"
            .parse()
            .unwrap();

        assert!(provider.get_token_price(address).await.is_ok());
    }

    // TODO: This test is flacky. It could fail in the future. We should create a
    // transaction, send it, and the assert that the details match.
    #[tokio::test]
    async fn test_signer_get_transaction_details() {
        let provider = era_signer();
        let hash: H256 = "0xac9cf301af3b11760feb9d84283513f993dcd29de6e5fd28a8f41b1c7c0469ed"
            .parse()
            .unwrap();

        assert!(provider.get_transaction_details(hash).await.is_ok());
    }

    #[tokio::test]
    async fn test_signer_get_l1_batch_number() {
        let provider = era_signer();

        assert!(provider.get_l1_batch_number().await.is_ok());
    }

    #[tokio::test]
    async fn test_signer_get_l1_chain_id() {
        let provider = era_signer();

        assert!(provider.get_l1_chain_id().await.is_ok());
    }

    #[tokio::test]
    async fn test_signer_debug_trace_block_by_hash() {
        let provider = era_signer();
        let block_number = provider.get_block_number().await.unwrap() - 1_u64;
        let test_block = provider
            .get_block_details(block_number.as_u32())
            .await
            .unwrap()
            .unwrap();
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
        let provider = era_signer();
        let existing_block_number = provider.get_block_number().await.unwrap() - 1_u64;
        let non_existing_block_number = existing_block_number + 100_u64;
        let options = Some(TracerConfig {
            disable_storage: None,
            disable_stack: None,
            enable_memory: None,
            enable_return_data: None,
            tracer: Some("callTracer".to_owned()),
            tracer_config: Some(HashMap::from([("onlyTopCall".to_owned(), true)])),
        });

        assert!(
            ZKSProvider::debug_trace_block_by_number(&provider, existing_block_number, None)
                .await
                .is_ok()
        );
        assert!(ZKSProvider::debug_trace_block_by_number(
            &provider,
            existing_block_number,
            options.clone()
        )
        .await
        .is_ok());
        assert!(ZKSProvider::debug_trace_block_by_number(
            &provider,
            non_existing_block_number,
            None
        )
        .await
        .is_err());
        assert!(ZKSProvider::debug_trace_block_by_number(
            &provider,
            non_existing_block_number,
            options
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn test_signer_debug_trace_call() {
        let provider = era_signer();
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

        let block = provider.get_block_number().await.ok();
        let options = Some(TracerConfig {
            disable_storage: None,
            disable_stack: None,
            enable_memory: None,
            enable_return_data: None,
            tracer: Some("callTracer".to_owned()),
            tracer_config: Some(HashMap::from([("onlyTopCall".to_owned(), true)])),
        });

        assert!(
            ZKSProvider::debug_trace_call::<_, u64>(&provider, &request, None, None)
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
            ZKSProvider::debug_trace_call::<_, u64>(&provider, request, None, options)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_signer_debug_trace_transaction() {
        let era_signer = era_signer();
        let zk_wallet =
            ZKSWallet::new(local_wallet(), None, Some(era_signer.clone()), None).unwrap();

        let transaction_hash = zk_wallet
            .transfer(
                Address::from_str("0x36615Cf349d7F6344891B1e7CA7C72883F5dc049").unwrap(),
                1_i32.into(),
                None,
            )
            .await
            .unwrap()
            .transaction_hash;
        let invalid_transaction_hash: H256 =
            "0x84472204e445cb3cd5f3ce5e23abcc2892cda5e61b35855a7f0bb1562a6e30e7"
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
            ZKSProvider::debug_trace_transaction(&era_signer, transaction_hash, None)
                .await
                .is_ok()
        );
        assert!(
            ZKSProvider::debug_trace_transaction(&era_signer, transaction_hash, options)
                .await
                .is_ok()
        );
        assert!(
            ZKSProvider::debug_trace_transaction(&era_signer, invalid_transaction_hash, None)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_send_function_with_arguments() {
        // Deploying a test contract
        let deployer_private_key =
            "7726827caac94a7f9e1b160f7ea819f172f7b6f9d2a97f992c38edeab82d4110";
        let era_provider = era_provider();
        let wallet = LocalWallet::from_str(deployer_private_key)
            .unwrap()
            .with_chain_id(ERA_CHAIN_ID);
        let zk_wallet = ZKSWallet::new(wallet, None, Some(era_provider.clone()), None).unwrap();
        let mut contract_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        contract_path.push("src/abi/test_contracts/storage_combined.json");
        let contract: CompiledContract =
            serde_json::from_reader(File::open(contract_path).unwrap()).unwrap();

        let transaction_receipt = zk_wallet
            .deploy(
                contract.abi,
                contract.bin.to_vec(),
                None,
                Some(vec!["0".to_owned()]),
            )
            .await
            .unwrap();

        let contract_address = transaction_receipt.contract_address.unwrap();
        let initial_value =
            ZKSProvider::call(&era_provider, contract_address, "getValue()(uint256)", None)
                .await
                .unwrap();

        assert_eq!(initial_value, U256::from(0_i32).into_tokens());

        let value_to_set = String::from("10");
        era_provider
            .send_eip712(
                &zk_wallet.l2_wallet,
                contract_address,
                "setValue(uint256)",
                Some([value_to_set.clone()].into()),
                None,
            )
            .await
            .unwrap();
        let set_value =
            ZKSProvider::call(&era_provider, contract_address, "getValue()(uint256)", None)
                .await
                .unwrap();

        assert_eq!(
            set_value,
            U256::from(value_to_set.parse::<u64>().unwrap()).into_tokens()
        );

        era_provider
            .send_eip712(
                &zk_wallet.l2_wallet,
                contract_address,
                "incrementValue()",
                None,
                None,
            )
            .await
            .unwrap();
        let incremented_value =
            ZKSProvider::call(&era_provider, contract_address, "getValue()(uint256)", None)
                .await
                .unwrap();

        assert_eq!(
            incremented_value,
            (value_to_set.parse::<u64>().unwrap() + 1_u64).into_tokens()
        );
    }

    #[tokio::test]
    async fn test_call_view_function_with_no_parameters() {
        // Deploying a test contract
        let deployer_private_key =
            "7726827caac94a7f9e1b160f7ea819f172f7b6f9d2a97f992c38edeab82d4110";
        let era_provider = era_provider();
        let wallet = LocalWallet::from_str(deployer_private_key).unwrap();
        let zk_wallet = ZKSWallet::new(wallet, None, Some(era_provider.clone()), None).unwrap();
        let mut contract_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        contract_path.push("src/abi/test_contracts/basic_combined.json");
        let contract: CompiledContract =
            serde_json::from_reader(File::open(contract_path).unwrap()).unwrap();

        let transaction_receipt = zk_wallet
            .deploy(contract.abi, contract.bin.to_vec(), None, None)
            .await
            .unwrap();

        let contract_address = transaction_receipt.contract_address.unwrap();
        let output = ZKSProvider::call(&era_provider, contract_address, "str_out()(string)", None)
            .await
            .unwrap();

        assert_eq!(output, String::from("Hello World!").into_tokens());
    }

    #[tokio::test]
    async fn test_call_view_function_with_arguments() {
        // Deploying a test contract
        let deployer_private_key =
            "7726827caac94a7f9e1b160f7ea819f172f7b6f9d2a97f992c38edeab82d4110";
        let era_provider = era_provider();
        let wallet = LocalWallet::from_str(deployer_private_key).unwrap();
        let zk_wallet = ZKSWallet::new(wallet, None, Some(era_provider.clone()), None).unwrap();

        let mut contract_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        contract_path.push("src/abi/test_contracts/basic_combined.json");
        let contract: CompiledContract =
            serde_json::from_reader(File::open(contract_path).unwrap()).unwrap();

        let transaction_receipt = zk_wallet
            .deploy(contract.abi, contract.bin.to_vec(), None, None)
            .await
            .unwrap();

        let contract_address = transaction_receipt.contract_address.unwrap();
        let no_return_type_output = ZKSProvider::call(
            &era_provider,
            contract_address,
            "plus_one(uint256)",
            Some(vec!["1".to_owned()]),
        )
        .await
        .unwrap();

        let known_return_type_output = ZKSProvider::call(
            &era_provider,
            contract_address,
            "plus_one(uint256)(uint256)",
            Some(vec!["1".to_owned()]),
        )
        .await
        .unwrap();

        assert_eq!(
            no_return_type_output,
            Bytes::from([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 2
            ])
            .into_tokens()
        );
        assert_eq!(known_return_type_output, U256::from(2_u64).into_tokens());
    }
}
