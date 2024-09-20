use async_trait::async_trait;
use ethers_contract::providers::PendingTransaction;
use serde::Serialize;
use serde_json::json;
use std::{collections::HashMap, fmt::Debug, time::Duration};
use tokio::time::Instant;
use zksync_types::{
    api::{
        BlockDetails, BridgeAddresses, DebugCall, L1BatchDetails, L2ToL1LogProof, ProtocolVersion,
        ResultDebugCall, TracerConfig, Transaction, TransactionDetailedResult, TransactionDetails,
    },
    fee::Fee,
    fee_model::FeeParams,
    EIP_712_TX_TYPE,
};
use zksync_web3_decl::types::Token;

use ethers::{
    abi::HumanReadableParser,
    prelude::k256::{
        ecdsa::{RecoveryId, Signature as RecoverableSignature},
        schnorr::signature::hazmat::PrehashSigner,
    },
    providers::{JsonRpcClient, Middleware, MiddlewareError, ProviderError},
    signers::{Signer, Wallet},
    types::{
        transaction::{eip2718::TypedTransaction, eip712::Eip712Error},
        Address, BlockNumber, Bytes, Eip1559TransactionRequest, Signature, TransactionReceipt,
        TxHash, H256, U256, U64,
    },
};

use crate::{
    eip712::{Eip712Transaction, Eip712TransactionRequest},
    types::L1TxOverrides,
    utils,
};

/// This trait wraps every JSON-RPC call specified in zkSync Era's documentation
/// https://era.zksync.io/docs/api/api.html#zksync-era-json-rpc-methods
#[async_trait]
pub trait ZKMiddleware {
    /// Error type returned by most operations
    type Error: MiddlewareError<Inner = <<Self as ZKMiddleware>::Inner as ZKMiddleware>::Error>;
    /// The JSON-RPC client type at the bottom of the stack
    type Provider: JsonRpcClient;
    /// The next-lower middleware in the middleware stack
    type Inner: Middleware<Provider = Self::Provider>;

    /// Convert a provider error into the associated error type by successively
    /// converting it to every intermediate middleware error
    fn convert_err(p: ProviderError) -> Self::Error {
        Self::Error::from_provider_err(p)
    }

    async fn zk_estimate_gas<T>(&self, transaction: T) -> Result<U256, Self::Error>
    where
        T: Debug + Serialize + Send + Sync;

    /// Returns the fee for the transaction.
    async fn estimate_fee<T>(&self, transaction: T) -> Result<Fee, Self::Error>
    where
        T: Debug + Serialize + Send + Sync;

    /// Returns an estimate of the gas required for a L1 to L2 transaction.
    async fn estimate_gas_l1_to_l2<T>(&self, transaction: T) -> Result<U256, Self::Error>
    where
        T: Debug + Serialize + Send + Sync;

    /// Retrieves the bridge hub contract address.
    async fn get_bridgehub_contract(&self) -> Result<Address, Self::Error>;

    /// Returns all balances for confirmed tokens given by an account address.
    async fn get_all_account_balances(
        &self,
        address: Address,
    ) -> Result<HashMap<Address, U256>, Self::Error>;

    /// Returns additional zkSync-specific information about the L2 block.
    /// * `committed`: The batch is closed and the state transition it creates exists on layer 1.
    /// * `proven`: The batch proof has been created, submitted, and accepted on layer 1.
    /// * `executed`: The batch state transition has been executed on L1; meaning the root state has been updated.
    async fn get_block_details<T>(&self, block: T) -> Result<Option<BlockDetails>, Self::Error>
    where
        T: Into<U64> + Send + Sync + Serialize + Debug;

    /// Returns L1/L2 addresses of default bridges.
    async fn get_bridge_contracts(&self) -> Result<BridgeAddresses, Self::Error>;

    /// Returns bytecode of a transaction given by its hash.
    async fn get_bytecode_by_hash(&self, hash: H256) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Returns [address, symbol, name, and decimal] information of all tokens within a range of ids given by parameters `from` and `limit`.
    ///
    /// **Confirmed** in the method name means the method returns any token bridged to zkSync via the official bridge.
    ///
    /// > This method is mainly used by the zkSync team as it relates to a database query where the primary keys relate to the given ids.
    async fn get_confirmed_tokens(&self, from: u32, limit: u8) -> Result<Vec<Token>, Self::Error>;

    /// Returns the range of blocks contained within a batch given by batch number.
    ///
    /// The range is given by beginning/end block numbers in hexadecimal.
    async fn get_l1_batch_block_range<T>(
        &self,
        batch: T,
    ) -> Result<Option<(U64, U64)>, Self::Error>
    where
        T: Into<U64> + Send + Sync + Serialize + Debug;

    /// Returns data pertaining to a given batch.
    async fn get_l1_batch_details<T>(&self, batch: T) -> Result<L1BatchDetails, Self::Error>
    where
        T: Into<u32> + Send + Sync + Serialize + Debug;

    /// Given a transaction hash, and an index of the L2 to L1 log produced within the
    /// transaction, it returns the proof for the corresponding L2 to L1 log.
    ///
    /// The index of the log that can be obtained from the transaction receipt (it
    /// includes a list of every log produced by the transaction).
    async fn get_l2_to_l1_log_proof(
        &self,
        tx_hash: H256,
        l2_to_l1_log_index: Option<u64>,
    ) -> Result<Option<L2ToL1LogProof>, Self::Error>;

    /// Given a block, a sender, a message, and an optional message log index in the
    /// block containing the L1->L2 message, it returns the proof for the message sent
    /// via the L1Messenger system contract.
    async fn get_l2_to_l1_msg_proof<T>(
        &self,
        block: T,
        sender: Address,
        msg: H256,
        l2_log_position: Option<u64>,
    ) -> Result<Option<L2ToL1LogProof>, Self::Error>
    where
        T: Into<U64> + Send + Sync + Serialize + Debug;

    /// Returns the address of the zkSync Era contract.
    async fn get_main_contract(&self) -> Result<Address, Self::Error>;

    /// Returns data of transactions in a block.
    async fn get_raw_block_transactions<T>(
        &self,
        block: T,
    ) -> Result<Vec<Transaction>, Self::Error>
    where
        T: Into<U64> + Send + Sync + Serialize + Debug;

    /// Returns the address of the [testnet paymaster](https://era.zksync.io/docs/dev/developer-guides/aa.html#testnet-paymaster): the paymaster that is available
    /// on testnets and enables paying fees in ERC-20 compatible tokens.
    async fn get_testnet_paymaster(&self) -> Result<Address, Self::Error>;

    /// Returns the price of a given token in USD.
    async fn get_token_price(&self, address: Address) -> Result<String, Self::Error>;

    /// Returns data from a specific transaction given by the transaction hash.
    async fn get_transaction_details(
        &self,
        hash: H256,
    ) -> Result<Option<TransactionDetails>, Self::Error>;

    /// Returns the latest L1 batch number.
    async fn get_l1_batch_number(&self) -> Result<U64, Self::Error>;

    /// Returns the chain id of the underlying L1.
    async fn get_l1_chain_id(&self) -> Result<U64, Self::Error>;

    /// Retrieves the L1 base token address.
    async fn get_base_token_l1_address(&self) -> Result<Address, Self::Error>;

    /// Returns the current L1 gas price in hexadecimal format, representing the amount of wei per unit of gas.
    async fn get_l1_gas_price(&self) -> Result<U64, Self::Error>;

    /// Retrieves the current fee parameters.
    async fn get_fee_params(&self) -> Result<FeeParams, Self::Error>;

    /// Gets the protocol version.
    async fn get_protocol_version(
        &self,
        id: Option<u16>,
    ) -> Result<Option<ProtocolVersion>, Self::Error>;

    /// Returns debug trace of all executed calls contained in a block given by its L2 hash.
    async fn debug_trace_block_by_hash(
        &self,
        hash: H256,
        options: Option<TracerConfig>,
    ) -> Result<Vec<ResultDebugCall>, Self::Error>;

    /// Returns debug trace of all executed calls contained in a block given by its L2 block number.
    async fn debug_trace_block_by_number<T>(
        &self,
        block: T,
        options: Option<TracerConfig>,
    ) -> Result<Vec<ResultDebugCall>, Self::Error>
    where
        T: Into<U64> + Send + Sync + Serialize + Debug;

    /// Returns debug trace containing information on a specific calls given by the call request.
    async fn debug_trace_call<R, T>(
        &self,
        request: R,
        block: Option<T>,
        options: Option<TracerConfig>,
    ) -> Result<DebugCall, Self::Error>
    where
        R: Debug + Serialize + Send + Sync,
        T: Into<U64> + Send + Sync + Serialize + Debug;

    /// Uses the EVM's callTracer to return a debug trace of a specific transaction given by its transaction hash.
    async fn debug_trace_transaction(
        &self,
        hash: H256,
        options: Option<TracerConfig>,
    ) -> Result<Option<DebugCall>, Self::Error>;

    async fn send_raw_transaction_with_detailed_output(
        &self,
        tx: Bytes,
    ) -> Result<TransactionDetailedResult, Self::Error>;

    async fn send<D>(
        &self,
        wallet: &Wallet<D>,
        contract_address: Address,
        function_signature: &str,
        function_parameters: Option<Vec<String>>,
        overrides: Option<L1TxOverrides>,
    ) -> Result<PendingTransaction<Self::Provider>, Self::Error>
    where
        D: PrehashSigner<(RecoverableSignature, RecoveryId)> + Send + Sync;

    async fn wait_for_finalize(
        &self,
        transaction_receipt: TxHash,
        polling_time_in_seconds: Option<Duration>,
        timeout_in_seconds: Option<Duration>,
    ) -> Result<TransactionReceipt, Self::Error>;

    async fn send_transaction_eip712<T, D>(
        &self,
        wallet: &Wallet<D>,
        transaction: T,
    ) -> Result<PendingTransaction<Self::Provider>, Self::Error>
    where
        T: TryInto<Eip712TransactionRequest> + Send + Sync + Debug,
        D: PrehashSigner<(RecoverableSignature, RecoveryId)> + Send + Sync;
}

#[async_trait]
impl<M> ZKMiddleware for M
where
    M: Middleware,
{
    type Error = M::Error;
    type Provider = M::Provider;
    type Inner = M::Inner;

    async fn zk_estimate_gas<T>(&self, transaction: T) -> Result<U256, Self::Error>
    where
        T: Debug + Serialize + Send + Sync,
    {
        self.provider()
            .request("eth_estimateGas", [transaction])
            .await
            .map_err(M::convert_err)
    }

    async fn estimate_fee<T>(&self, transaction: T) -> Result<Fee, Self::Error>
    where
        T: Debug + Serialize + Send + Sync,
    {
        self.provider()
            .request("zks_estimateFee", [transaction])
            .await
            .map_err(M::convert_err)
    }

    async fn estimate_gas_l1_to_l2<T>(&self, transaction: T) -> Result<U256, Self::Error>
    where
        T: Debug + Serialize + Send + Sync,
    {
        self.provider()
            .request("zks_estimateGasL1ToL2", [transaction])
            .await
            .map_err(M::convert_err)
    }

    async fn get_bridgehub_contract(&self) -> Result<Address, Self::Error> {
        self.provider()
            .request("zks_getBridgehubContract", ())
            .await
            .map_err(M::convert_err)
    }

    async fn get_all_account_balances(
        &self,
        address: Address,
    ) -> Result<HashMap<Address, U256>, Self::Error> {
        self.provider()
            .request("zks_getAllAccountBalances", [address])
            .await
            .map_err(M::convert_err)
    }

    async fn get_block_details<T>(&self, block: T) -> Result<Option<BlockDetails>, Self::Error>
    where
        T: Into<U64> + Send + Sync + Serialize + Debug,
    {
        self.provider()
            .request("zks_getBlockDetails", [block])
            .await
            .map_err(M::convert_err)
    }

    async fn get_bridge_contracts(&self) -> Result<BridgeAddresses, Self::Error> {
        self.provider()
            .request("zks_getBridgeContracts", ())
            .await
            .map_err(M::convert_err)
    }

    async fn get_bytecode_by_hash(&self, hash: H256) -> Result<Option<Vec<u8>>, Self::Error> {
        self.provider()
            .request("zks_getBytecodeByHash", [hash])
            .await
            .map_err(M::convert_err)
    }

    async fn get_confirmed_tokens(&self, from: u32, limit: u8) -> Result<Vec<Token>, Self::Error> {
        self.provider()
            .request("zks_getConfirmedTokens", [from, limit.into()])
            .await
            .map_err(M::convert_err)
    }

    async fn get_l1_batch_block_range<T>(&self, batch: T) -> Result<Option<(U64, U64)>, Self::Error>
    where
        T: Into<U64> + Send + Sync + Serialize + Debug,
    {
        self.provider()
            .request("zks_getL1BatchBlockRange", [batch])
            .await
            .map_err(M::convert_err)
    }

    async fn get_l1_batch_details<T>(&self, batch: T) -> Result<L1BatchDetails, Self::Error>
    where
        T: Into<u32> + Send + Sync + Serialize + Debug,
    {
        self.provider()
            .request("zks_getL1BatchDetails", [batch])
            .await
            .map_err(M::convert_err)
    }

    async fn get_l2_to_l1_log_proof(
        &self,
        tx_hash: H256,
        l2_to_l1_log_index: Option<u64>,
    ) -> Result<Option<L2ToL1LogProof>, Self::Error> {
        self.provider()
            .request(
                "zks_getL2ToL1LogProof",
                json!([tx_hash, l2_to_l1_log_index]),
            )
            .await
            .map_err(M::convert_err)
    }

    async fn get_l2_to_l1_msg_proof<T>(
        &self,
        block: T,
        sender: Address,
        msg: H256,
        l2_log_position: Option<u64>,
    ) -> Result<Option<L2ToL1LogProof>, Self::Error>
    where
        T: Into<U64> + Send + Sync + Serialize + Debug,
    {
        self.provider()
            .request(
                "zks_getL2ToL1MsgProof",
                json!([block, sender, msg, l2_log_position]),
            )
            .await
            .map_err(M::convert_err)
    }

    async fn get_main_contract(&self) -> Result<Address, Self::Error> {
        self.provider()
            .request("zks_getMainContract", ())
            .await
            .map_err(M::convert_err)
    }

    async fn get_raw_block_transactions<T>(&self, block: T) -> Result<Vec<Transaction>, Self::Error>
    where
        T: Into<U64> + Send + Sync + Serialize + Debug,
    {
        self.provider()
            .request("zks_getRawBlockTransactions", [block])
            .await
            .map_err(M::convert_err)
    }

    async fn get_testnet_paymaster(&self) -> Result<Address, Self::Error> {
        self.provider()
            .request("zks_getTestnetPaymaster", ())
            .await
            .map_err(M::convert_err)
    }

    async fn get_token_price(&self, address: Address) -> Result<String, Self::Error> {
        self.provider()
            .request("zks_getTokenPrice", [address])
            .await
            .map_err(M::convert_err)
    }

    async fn get_transaction_details(
        &self,
        hash: H256,
    ) -> Result<Option<TransactionDetails>, Self::Error> {
        self.provider()
            .request("zks_getTransactionDetails", [hash])
            .await
            .map_err(M::convert_err)
    }

    async fn get_l1_batch_number(&self) -> Result<U64, Self::Error> {
        self.provider()
            .request("zks_L1BatchNumber", ())
            .await
            .map_err(M::convert_err)
    }

    async fn get_l1_chain_id(&self) -> Result<U64, Self::Error> {
        self.provider()
            .request("zks_L1ChainId", ())
            .await
            .map_err(M::convert_err)
    }

    async fn get_base_token_l1_address(&self) -> Result<Address, Self::Error> {
        self.provider()
            .request("zks_getBaseTokenL1Address", ())
            .await
            .map_err(M::convert_err)
    }

    async fn get_l1_gas_price(&self) -> Result<U64, Self::Error> {
        self.provider()
            .request("zks_getL1GasPrice", ())
            .await
            .map_err(M::convert_err)
    }

    async fn get_fee_params(&self) -> Result<FeeParams, Self::Error> {
        self.provider()
            .request("zks_getFeeParams", ())
            .await
            .map_err(M::convert_err)
    }

    async fn get_protocol_version(
        &self,
        id: Option<u16>,
    ) -> Result<Option<ProtocolVersion>, Self::Error> {
        self.provider()
            .request("zks_getProtocolVersion", [id])
            .await
            .map_err(M::convert_err)
    }

    async fn send_raw_transaction_with_detailed_output(
        &self,
        tx: Bytes,
    ) -> Result<TransactionDetailedResult, Self::Error> {
        self.provider()
            .request("zks_sendRawTransactionWithDetailedOutput", [tx])
            .await
            .map_err(M::convert_err)
    }

    async fn debug_trace_block_by_hash(
        &self,
        hash: H256,
        options: Option<TracerConfig>,
    ) -> Result<Vec<ResultDebugCall>, Self::Error> {
        let processable_response = self
            .provider()
            .request::<serde_json::Value, serde_json::Value>(
                "debug_traceBlockByHash",
                json!([hash, options]),
            )
            .await
            .map_err(M::convert_err)?
            .get(0)
            .ok_or(ProviderError::CustomError(
                "error on debug_trace_block_by_hash".to_owned(),
            ))
            .map_err(M::convert_err)?
            .get("result")
            .ok_or(ProviderError::CustomError(
                "error on debug_trace_block_by_hash".to_owned(),
            ))
            .map_err(M::convert_err)?
            .clone();
        serde_json::from_value(processable_response)
            .map_err(ProviderError::SerdeJson)
            .map_err(M::convert_err)
    }

    async fn debug_trace_block_by_number<T>(
        &self,
        block: T,
        options: Option<TracerConfig>,
    ) -> Result<Vec<ResultDebugCall>, Self::Error>
    where
        T: Into<U64> + Send + Sync + Serialize + Debug,
    {
        let processable_response = self
            .provider()
            .request::<serde_json::Value, serde_json::Value>(
                "debug_traceBlockByNumber",
                json!([block, options]),
            )
            .await
            .map_err(M::convert_err)?
            .get(0)
            .ok_or(ProviderError::CustomError(
                "error on debug_trace_block_by_hash".to_owned(),
            ))
            .map_err(M::convert_err)?
            .get("result")
            .ok_or(ProviderError::CustomError(
                "error on debug_trace_block_by_hash".to_owned(),
            ))
            .map_err(M::convert_err)?
            .clone();
        serde_json::from_value(processable_response)
            .map_err(ProviderError::SerdeJson)
            .map_err(M::convert_err)
    }

    async fn debug_trace_call<R, T>(
        &self,
        request: R,
        block: Option<T>,
        options: Option<TracerConfig>,
    ) -> Result<DebugCall, Self::Error>
    where
        R: Debug + Serialize + Send + Sync,
        T: Into<U64> + Send + Sync + Serialize + Debug,
    {
        self.provider()
            .request("debug_traceCall", json!([request, block, options]))
            .await
            .map_err(M::convert_err)
    }

    async fn debug_trace_transaction(
        &self,
        hash: H256,
        options: Option<TracerConfig>,
    ) -> Result<Option<DebugCall>, Self::Error> {
        self.provider()
            .request("debug_traceTransaction", json!([hash, options]))
            .await
            .map_err(M::convert_err)
    }

    async fn send_transaction_eip712<T, D>(
        &self,
        wallet: &Wallet<D>,
        transaction: T,
    ) -> Result<PendingTransaction<Self::Provider>, Self::Error>
    where
        T: TryInto<Eip712TransactionRequest> + Sync + Send + Debug,
        D: PrehashSigner<(RecoverableSignature, RecoveryId)> + Send + Sync,
    {
        let mut request: Eip712TransactionRequest = transaction
            .try_into()
            .map_err(|_e| ProviderError::CustomError("error on send_transaction_eip712".to_owned()))
            .map_err(M::convert_err)?;

        let gas_price = self.get_gas_price().await?;
        request = request
            .from(wallet.address())
            .chain_id(wallet.chain_id())
            .nonce(self.get_transaction_count(wallet.address(), None).await?)
            .gas_price(gas_price)
            .max_fee_per_gas(gas_price);

        let custom_data = request.clone().custom_data;
        let fee = self.estimate_fee(request.clone()).await?;
        request = request
            .max_priority_fee_per_gas(fee.max_priority_fee_per_gas)
            .max_fee_per_gas(fee.max_fee_per_gas)
            .gas_limit(fee.gas_limit);
        let signable_data: Eip712Transaction = request
            .clone()
            .try_into()
            .map_err(|e: Eip712Error| ProviderError::CustomError(e.to_string()))
            .map_err(M::convert_err)?;
        let signature: Signature = wallet
            .sign_typed_data(&signable_data)
            .await
            .map_err(|e| ProviderError::CustomError(format!("error signing transaction: {e}")))
            .map_err(M::convert_err)?;
        request = request.custom_data(custom_data.custom_signature(signature.to_vec()));
        let encoded_rlp = &*request
            .rlp_signed(signature)
            .map_err(|e| ProviderError::CustomError(format!("Error in the rlp encoding {e}")))
            .map_err(M::convert_err)?;

        self.send_raw_transaction([&[EIP_712_TX_TYPE], encoded_rlp].concat().into())
            .await
    }

    async fn send<D>(
        &self,
        wallet: &Wallet<D>,
        contract_address: Address,
        function_signature: &str,
        function_parameters: Option<Vec<String>>,
        _overrides: Option<L1TxOverrides>,
    ) -> Result<PendingTransaction<Self::Provider>, Self::Error>
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
        .await
        .map_err(M::convert_err)?;
        self.send_transaction(tx, None).await
    }

    async fn wait_for_finalize(
        &self,
        tx_hash: TxHash,
        polling_time_in_seconds: Option<Duration>,
        timeout_in_seconds: Option<Duration>,
    ) -> Result<TransactionReceipt, Self::Error> {
        let polling_time_in_seconds = polling_time_in_seconds.unwrap_or(Duration::from_secs(2));
        let mut timer = tokio::time::interval(polling_time_in_seconds);
        let start = Instant::now();

        let transaction_receipt = self
            .get_transaction_receipt(tx_hash)
            .await?
            .ok_or(ProviderError::CustomError(
                "No transaction receipt".to_owned(),
            ))
            .map_err(M::convert_err)?;

        loop {
            timer.tick().await;

            if let Some(timeout) = timeout_in_seconds {
                if start.elapsed() >= timeout {
                    return Err(M::convert_err(ProviderError::CustomError(
                        "Error waiting for transaction to be included into the finalized block"
                            .to_owned(),
                    )));
                }
            }

            // Wait for transaction to be included into the finalized block.
            let latest_block = self
                .get_block(BlockNumber::Finalized)
                .await?
                .ok_or(ProviderError::CustomError(
                    "Error getting finalized block".to_owned(),
                ))
                .map_err(M::convert_err)?;

            if transaction_receipt.block_number <= latest_block.number {
                return Ok(transaction_receipt);
            }
        }
    }
}

async fn build_send_tx<D>(
    provider: &impl Middleware,
    wallet: &Wallet<D>,
    contract_address: Address,
    function_signature: &str,
    function_parameters: Option<Vec<String>>,
    _overrides: Option<L1TxOverrides>,
) -> Result<TypedTransaction, ProviderError>
where
    D: PrehashSigner<(RecoverableSignature, RecoveryId)> + Send + Sync,
{
    let function = HumanReadableParser::parse_function(function_signature)
        .map_err(|e| ProviderError::CustomError(e.to_string()))?;

    let function_args = if let Some(function_args) = function_parameters {
        function
            .decode_input(
                &utils::encode_args(&function, &function_args)
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
        .gas(utils::DEFAULT_GAS)
        .max_fee_per_gas(utils::MAX_FEE_PER_GAS)
        .max_priority_fee_per_gas(utils::MAX_PRIORITY_FEE_PER_GAS);

    Ok(send_request.into())
}
