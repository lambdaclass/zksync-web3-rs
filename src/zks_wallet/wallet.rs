use super::{Overrides, ZKSWalletError};
use crate::{
    contracts::main_contract::{MainContract, MainContractInstance},
    eip712::Eip712Transaction,
    eip712::{hash_bytecode, Eip712Meta, Eip712TransactionRequest},
    zks_provider::ZKSProvider,
    zks_utils::{
        self, CONTRACT_DEPLOYER_ADDR, DEPOSIT_GAS_PER_PUBDATA_LIMIT, EIP712_TX_TYPE, ETH_CHAIN_ID,
        RECOMMENDED_DEPOSIT_L1_GAS_LIMIT, RECOMMENDED_DEPOSIT_L2_GAS_LIMIT,
    },
};
use ethers::{
    abi::{decode, Abi, ParamType, Token, Tokenizable},
    prelude::{
        encode_function_data,
        k256::{
            ecdsa::{RecoveryId, Signature as RecoverableSignature},
            schnorr::signature::hazmat::PrehashSigner,
        },
        ContractError, MiddlewareBuilder, SignerMiddleware,
    },
    providers::Middleware,
    signers::{Signer, Wallet},
    types::{
        transaction::eip2718::TypedTransaction, Address, Bytes, Eip1559TransactionRequest, Log,
        Signature, TransactionReceipt, H160, H256, U256,
    },
};
use serde_json::Value;
use std::{fs::File, io::BufReader, path::PathBuf, str::FromStr, sync::Arc};

pub struct ZKSWallet<M, D>
where
    M: Middleware,
    D: PrehashSigner<(RecoverableSignature, RecoveryId)>,
{
    /// Eth provider
    pub eth_provider: Option<Arc<SignerMiddleware<M, Wallet<D>>>>,
    pub era_provider: Option<Arc<SignerMiddleware<M, Wallet<D>>>>,
    pub l2_wallet: Wallet<D>,
    pub l1_wallet: Wallet<D>,
}

impl<M, D> ZKSWallet<M, D>
where
    M: Middleware + 'static,
    D: PrehashSigner<(RecoverableSignature, RecoveryId)> + Sync + Send + Clone,
{
    pub fn new(
        l2_wallet: Wallet<D>,
        l1_wallet: Option<Wallet<D>>,
        era_provider: Option<M>,
        eth_provider: Option<M>,
    ) -> Result<Self, ZKSWalletError<M, D>> {
        let l1_wallet = match l1_wallet {
            Some(wallet) => wallet,
            None => l2_wallet.clone().with_chain_id(ETH_CHAIN_ID),
        };
        Ok(Self {
            l2_wallet: l2_wallet.clone(),
            l1_wallet: l1_wallet.clone(),
            era_provider: era_provider.map(|p| p.with_signer(l2_wallet).into()),
            eth_provider: eth_provider.map(|p| p.with_signer(l1_wallet).into()),
        })
    }

    pub fn connect_eth_provider(mut self, eth_provider: M) -> Self {
        self.eth_provider = Some(eth_provider.with_signer(self.l1_wallet.clone()).into());
        self
    }

    pub fn connect_era_provider(mut self, era_provider: M) -> Self {
        self.era_provider = Some(era_provider.with_signer(self.l2_wallet.clone()).into());
        self
    }

    pub fn connect_eth_signer(mut self, eth_signer: SignerMiddleware<M, Wallet<D>>) -> Self {
        self.eth_provider = Some(eth_signer.into());
        self
    }

    pub fn connect_era_signer(mut self, era_signer: SignerMiddleware<M, Wallet<D>>) -> Self {
        self.era_provider = Some(era_signer.into());
        self
    }

    // pub fn connect_eth(&mut self, host: &str, port: u16) {
    //     self.eth_provider = Provider::try_from(format!("http://{host}:{port}")).ok().map(|p| p.with_signer(self.wallet));
    // }

    // pub fn connect_era(&mut self, host: &str, port: u16) {
    //     self.era_provider = Provider::try_from(format!("http://{host}:{port}")).ok().map(|p| p.with_signer(self.wallet));
    // }

    pub fn l2_address(&self) -> Address {
        self.l2_wallet.address()
    }

    pub fn l1_address(&self) -> Address {
        self.l1_wallet.address()
    }

    pub fn l2_chain_id(&self) -> u64 {
        self.l2_wallet.chain_id()
    }

    pub fn l1_chain_id(&self) -> u64 {
        self.l1_wallet.chain_id()
    }

    pub fn get_eth_provider(
        &self,
    ) -> Result<Arc<SignerMiddleware<M, Wallet<D>>>, ZKSWalletError<M, D>> {
        match &self.eth_provider {
            Some(eth_provider) => Ok(Arc::clone(eth_provider)),
            None => Err(ZKSWalletError::NoL1ProviderError()),
        }
    }

    pub fn get_era_provider(
        &self,
    ) -> Result<Arc<SignerMiddleware<M, Wallet<D>>>, ZKSWalletError<M, D>> {
        match &self.era_provider {
            Some(era_provider) => Ok(Arc::clone(era_provider)),
            None => Err(ZKSWalletError::NoL2ProviderError()),
        }
    }

    pub async fn eth_balance(&self) -> Result<U256, ZKSWalletError<M, D>>
    where
        M: ZKSProvider,
    {
        match &self.eth_provider {
            // TODO: Should we have a balance_on_block method?
            Some(eth_provider) => Ok(eth_provider.get_balance(self.l1_address(), None).await?),
            None => Err(ZKSWalletError::CustomError("no eth provider".to_owned())),
        }
    }

    pub async fn era_balance(&self) -> Result<U256, ZKSWalletError<M, D>>
    where
        M: ZKSProvider,
    {
        match &self.era_provider {
            // TODO: Should we have a balance_on_block method?
            Some(era_provider) => Ok(era_provider.get_balance(self.l2_address(), None).await?),
            None => Err(ZKSWalletError::CustomError("no era provider".to_owned())),
        }
    }

    pub async fn transfer(
        &self,
        to: Address,
        amount_to_transfer: U256,
        // TODO: Support multiple-token transfers.
        _token: Option<Address>,
    ) -> Result<TransactionReceipt, ZKSWalletError<M, D>>
    where
        M: ZKSProvider,
    {
        let era_provider = match &self.era_provider {
            Some(era_provider) => era_provider,
            None => return Err(ZKSWalletError::CustomError("no era provider".to_owned())),
        };

        let mut transfer_request = Eip1559TransactionRequest::new()
            .from(self.l2_address())
            .to(to)
            .value(amount_to_transfer)
            .chain_id(self.l2_chain_id());

        let fee = era_provider.estimate_fee(transfer_request.clone()).await?;
        transfer_request = transfer_request.max_priority_fee_per_gas(fee.max_priority_fee_per_gas);
        transfer_request = transfer_request.max_fee_per_gas(fee.max_fee_per_gas);

        let transaction: TypedTransaction = transfer_request.into();

        // TODO: add block as an override.
        let pending_transaction = era_provider.send_transaction(transaction, None).await?;

        pending_transaction
            .await?
            .ok_or(ZKSWalletError::CustomError(
                "no transaction receipt".to_owned(),
            ))
    }

    pub async fn transfer_eip712(
        &self,
        to: Address,
        amount_to_transfer: U256,
        // TODO: Support multiple-token transfers.
        _token: Option<Address>,
    ) -> Result<TransactionReceipt, ZKSWalletError<M, D>>
    where
        M: ZKSProvider,
    {
        let era_provider = match &self.era_provider {
            Some(era_provider) => era_provider,
            None => return Err(ZKSWalletError::CustomError("no era provider".to_owned())),
        };

        let mut transfer_request = Eip712TransactionRequest::new()
            .from(self.l2_address())
            .to(to)
            .value(amount_to_transfer)
            .nonce(
                era_provider
                    .get_transaction_count(self.l2_address(), None)
                    .await?,
            )
            .gas_price(era_provider.get_gas_price().await?);

        let fee = era_provider.estimate_fee(transfer_request.clone()).await?;
        transfer_request = transfer_request
            .max_priority_fee_per_gas(fee.max_priority_fee_per_gas)
            .max_fee_per_gas(fee.max_fee_per_gas)
            .gas_limit(fee.gas_limit);

        let signable_data: Eip712Transaction = transfer_request.clone().try_into()?;
        let signature: Signature = self.l2_wallet.sign_typed_data(&signable_data).await?;
        transfer_request =
            transfer_request.custom_data(Eip712Meta::new().custom_signature(signature.to_vec()));

        let pending_transaction = era_provider
            .send_raw_transaction(
                [&[EIP712_TX_TYPE], &*transfer_request.rlp_unsigned()]
                    .concat()
                    .into(),
            )
            .await?;

        let transaction_receipt = pending_transaction
            .await?
            .ok_or(ZKSWalletError::CustomError(
                "no transaction receipt".to_owned(),
            ))?;

        Ok(transaction_receipt)
    }

    pub async fn deposit(&self, amount: U256) -> Result<TransactionReceipt, ZKSWalletError<M, D>>
    where
        M: ZKSProvider,
    {
        let to = self.l2_address();
        let call_data = Bytes::default();
        let l2_gas_limit: U256 = RECOMMENDED_DEPOSIT_L2_GAS_LIMIT.into();
        let l2_value = amount;
        let gas_per_pubdata_byte: U256 = DEPOSIT_GAS_PER_PUBDATA_LIMIT.into();
        let gas_price = self.get_eth_provider()?.get_gas_price().await?;
        let gas_limit: U256 = RECOMMENDED_DEPOSIT_L1_GAS_LIMIT.into();
        let operator_tip: U256 = 0_u8.into();
        let base_cost = self
            .get_base_cost(gas_limit, gas_per_pubdata_byte, gas_price)
            .await?;
        let l1_value = base_cost + operator_tip + amount;
        // let factory_deps = [];
        let refund_recipient = self.l1_address();
        // FIXME check base cost

        // FIXME request l2 transaction

        let main_contract_address = self.get_era_provider()?.get_main_contract().await?;
        let main_contract =
            MainContractInstance::new(main_contract_address, self.get_eth_provider()?);

        let receipt = main_contract
            .request_l2_transaction(
                to,
                l2_value,
                call_data,
                l2_gas_limit,
                gas_per_pubdata_byte,
                Default::default(),
                refund_recipient,
                gas_price,
                gas_limit,
                l1_value,
            )
            .await?;

        Ok(receipt)
    }

    async fn get_base_cost(
        &self,
        gas_limit: U256,
        gas_per_pubdata_byte: U256,
        gas_price: U256,
    ) -> Result<U256, ZKSWalletError<M, D>>
    where
        M: ZKSProvider,
    {
        let main_contract_address = self.get_era_provider()?.get_main_contract().await?;
        let main_contract = MainContract::new(main_contract_address, self.get_eth_provider()?);
        let base_cost: U256 = main_contract
            .l_2_transaction_base_cost(gas_price, gas_limit, gas_per_pubdata_byte)
            .call()
            .await?;

        Ok(base_cost)
    }

    pub async fn deploy_from_bytecode<T>(
        &self,
        contract_bytecode: &[u8],
        contract_dependencies: Option<Vec<Vec<u8>>>,
        _constructor_parameters: Option<T>,
    ) -> Result<H160, ZKSWalletError<M, D>>
    where
        M: ZKSProvider,
        T: Tokenizable,
    {
        let era_provider = match &self.era_provider {
            Some(era_provider) => era_provider,
            None => return Err(ZKSWalletError::CustomError("no era provider".to_owned())),
        };

        let custom_data = Eip712Meta::new().factory_deps({
            let mut factory_deps = Vec::new();
            if let Some(contract_dependencies) = contract_dependencies {
                factory_deps.extend(contract_dependencies);
            }
            factory_deps.push(contract_bytecode.to_vec());
            factory_deps
        });

        let mut contract_deployer_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        contract_deployer_path.push("src/abi/ContractDeployer.json");
        let mut deploy_request = Eip712TransactionRequest::new()
            .r#type(EIP712_TX_TYPE)
            .from(self.l2_address())
            .to(Address::from_str(CONTRACT_DEPLOYER_ADDR).map_err(|e| {
                ZKSWalletError::CustomError(format!("invalid contract deployer address: {e}"))
            })?)
            .chain_id(self.l2_chain_id())
            .nonce(
                era_provider
                    .get_transaction_count(self.l2_address(), None)
                    .await?,
            )
            .gas_price(era_provider.get_gas_price().await?)
            .max_fee_per_gas(era_provider.get_gas_price().await?)
            .data({
                let contract_deployer = Abi::load(BufReader::new(
                    File::open(contract_deployer_path).map_err(|e| {
                        ZKSWalletError::CustomError(format!(
                            "failed to open ContractDeployer abi: {e}"
                        ))
                    })?,
                ))
                .map_err(|e| {
                    ZKSWalletError::CustomError(format!("failed to load ContractDeployer abi: {e}"))
                })?;
                let create = contract_deployer.function("create").map_err(|e| {
                    ZKSWalletError::CustomError(format!("failed to get create function: {e}"))
                })?;
                // TODO: User could provide this instead of defaulting.
                let salt = [0_u8; 32];
                let bytecode_hash = hash_bytecode(contract_bytecode)?;
                let call_data = Bytes::default();

                encode_function_data(create, (salt, bytecode_hash, call_data))?
            })
            .custom_data(custom_data.clone());

        let fee = era_provider.estimate_fee(deploy_request.clone()).await?;
        deploy_request = deploy_request
            .max_priority_fee_per_gas(fee.max_priority_fee_per_gas)
            .max_fee_per_gas(fee.max_fee_per_gas)
            .gas_limit(fee.gas_limit);

        let signable_data: Eip712Transaction = deploy_request.clone().try_into()?;
        let signature: Signature = self.l2_wallet.sign_typed_data(&signable_data).await?;
        deploy_request =
            deploy_request.custom_data(custom_data.custom_signature(signature.to_vec()));

        let pending_transaction = era_provider
            .send_raw_transaction(
                [&[EIP712_TX_TYPE], &*deploy_request.rlp_unsigned()]
                    .concat()
                    .into(),
            )
            .await?;

        // TODO: Should we wait here for the transaction to be confirmed on-chain?

        let transaction_receipt = pending_transaction
            .await?
            .ok_or(ZKSWalletError::CustomError(
                "no transaction receipt".to_owned(),
            ))?;

        let contract_address =
            transaction_receipt
                .contract_address
                .ok_or(ZKSWalletError::CustomError(
                    "no contract address".to_owned(),
                ))?;

        Ok(contract_address)
    }

    pub async fn deploy(
        &self,
        contract_abi: Abi,
        contract_bytecode: Vec<u8>,
        contract_dependencies: Option<Vec<Vec<u8>>>,
        constructor_parameters: Option<Vec<String>>,
    ) -> Result<TransactionReceipt, ZKSWalletError<M, D>>
    where
        M: ZKSProvider,
    {
        let era_provider = match &self.era_provider {
            Some(era_provider) => era_provider,
            None => return Err(ZKSWalletError::CustomError("no era provider".to_owned())),
        };

        let custom_data = Eip712Meta::new().factory_deps({
            let mut factory_deps = Vec::new();
            if let Some(contract_dependencies) = contract_dependencies {
                factory_deps.extend(contract_dependencies);
            }
            factory_deps.push(contract_bytecode.clone());
            factory_deps
        });

        let mut contract_deployer_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        contract_deployer_path.push("src/abi/ContractDeployer.json");
        let mut deploy_request = Eip712TransactionRequest::new()
            .r#type(EIP712_TX_TYPE)
            .from(self.l2_address())
            .to(Address::from_str(CONTRACT_DEPLOYER_ADDR).map_err(|e| {
                ZKSWalletError::CustomError(format!("invalid contract deployer address: {e}"))
            })?)
            .chain_id(self.l2_chain_id())
            .nonce(
                era_provider
                    .get_transaction_count(self.l2_address(), None)
                    .await?,
            )
            .gas_price(era_provider.get_gas_price().await?)
            .max_fee_per_gas(era_provider.get_gas_price().await?)
            .data({
                let contract_deployer = Abi::load(BufReader::new(
                    File::open(contract_deployer_path).map_err(|e| {
                        ZKSWalletError::CustomError(format!(
                            "failed to open ContractDeployer abi: {e}"
                        ))
                    })?,
                ))
                .map_err(|e| {
                    ZKSWalletError::CustomError(format!("failed to load ContractDeployer abi: {e}"))
                })?;
                let create = contract_deployer.function("create").map_err(|e| {
                    ZKSWalletError::CustomError(format!("failed to get create function: {e}"))
                })?;
                // TODO: User could provide this instead of defaulting.
                let salt = [0_u8; 32];
                let bytecode_hash = hash_bytecode(&contract_bytecode)?;
                let call_data: Bytes = match (contract_abi.constructor(), constructor_parameters) {
                    (None, Some(_)) => return Err(ContractError::<M>::ConstructorError.into()),
                    (None, None) | (Some(_), None) => Bytes::default(),
                    (Some(constructor), Some(constructor_parameters)) => {
                        zks_utils::encode_constructor_args(constructor, &constructor_parameters)?
                            .into()
                    }
                };

                encode_function_data(create, (salt, bytecode_hash, call_data))?
            })
            .custom_data(custom_data.clone());

        let fee = era_provider.estimate_fee(deploy_request.clone()).await?;
        deploy_request = deploy_request
            .max_priority_fee_per_gas(fee.max_priority_fee_per_gas)
            .max_fee_per_gas(fee.max_fee_per_gas)
            .gas_limit(fee.gas_limit);

        let signable_data: Eip712Transaction = deploy_request.clone().try_into()?;
        let signature: Signature = self.l2_wallet.sign_typed_data(&signable_data).await?;
        deploy_request =
            deploy_request.custom_data(custom_data.custom_signature(signature.to_vec()));

        let pending_transaction = era_provider
            .send_raw_transaction(
                [&[EIP712_TX_TYPE], &*deploy_request.rlp_unsigned()]
                    .concat()
                    .into(),
            )
            .await?;

        pending_transaction
            .await?
            .ok_or(ZKSWalletError::CustomError(
                "no transaction receipt".to_owned(),
            ))
    }

    pub async fn withdraw(
        &self,
        amount: U256,
        to: Address,
    ) -> Result<TransactionReceipt, ZKSWalletError<M, D>>
    where
        M: ZKSProvider,
    {
        let era_provider = match &self.era_provider {
            Some(era_provider) => era_provider,
            None => return Err(ZKSWalletError::CustomError("no era provider".to_owned())),
        };

        let contract_address =
            Address::from_str(zks_utils::CONTRACTS_L2_ETH_TOKEN_ADDR).map_err(|error| {
                ZKSWalletError::CustomError(format!("failed to parse contract address: {error}"))
            })?;
        let function_signature = "function withdraw(address _l1Receiver) external payable override";
        let response: (Vec<Token>, H256) = era_provider
            .send_eip712(
                &self.l2_wallet,
                contract_address,
                function_signature,
                Some([format!("{to:?}")].into()),
                Some(Overrides {
                    value: Some(amount),
                }),
            )
            .await?;

        let tx_receipt = era_provider
            .get_transaction_receipt(response.1)
            .await?
            .ok_or(ZKSWalletError::CustomError(
                "No transaction receipt for withdraw".to_owned(),
            ))?;

        Ok(era_provider
            .wait_for_finalize(tx_receipt, None, None)
            .await?)
    }

    pub async fn finalize_withdraw(
        &self,
        tx_hash: H256,
    ) -> Result<TransactionReceipt, ZKSWalletError<M, D>>
    where
        M: ZKSProvider,
    {
        let (era_provider, eth_provider) = match (&self.era_provider, &self.eth_provider) {
            (Some(era_provider), Some(eth_provider)) => (era_provider, eth_provider),
            _ => {
                return Err(ZKSWalletError::CustomError(
                    "Both era and eth providers are necessary".to_owned(),
                ))
            }
        };

        let withdrawal_receipt = era_provider.get_transaction_receipt(tx_hash).await?.ok_or(
            ZKSWalletError::CustomError("Error getting transaction receipt of withdraw".to_owned()),
        )?;

        let messenger_contract_address = Address::from_str(zks_utils::CONTRACTS_L1_MESSENGER_ADDR)
            .map_err(|error| {
                ZKSWalletError::CustomError(format!("failed to parse contract address: {error}"))
            })?;

        let logs: Vec<Log> = withdrawal_receipt
            .logs
            .into_iter()
            .filter(|log| {
                //log.topics[0] == topic &&
                log.address == messenger_contract_address
            })
            .collect();

        // Get all the parameters needed to call the finalizeWithdrawal function on the main contract contract.
        let (_, l2_to_l1_log_index) = serde_json::from_value::<Vec<Value>>(
            withdrawal_receipt
                .other
                .get("l2ToL1Logs")
                .ok_or(ZKSWalletError::CustomError(
                    "Field not present in receipt".to_owned(),
                ))?
                .clone(),
        )
        .map_err(|err| {
            ZKSWalletError::CustomError(format!("Error getting logs in receipt: {err:?}"))
        })?
        .iter()
        .zip(0_u64..)
        .find(|(log, _)| {
            if let Some(sender) = log.get("sender") {
                sender == zks_utils::CONTRACTS_L1_MESSENGER_ADDR
            } else {
                false
            }
        })
        .ok_or(ZKSWalletError::CustomError(
            "Error getting log index parameter".to_owned(),
        ))?;

        let filtered_log = logs
            .get(0)
            .ok_or(ZKSWalletError::CustomError(
                "Error getting log in receipt".to_owned(),
            ))?
            .clone();
        let proof = era_provider
            .get_l2_to_l1_log_proof(tx_hash, Some(l2_to_l1_log_index))
            .await?
            .ok_or(ZKSWalletError::CustomError(
                "Error getting proof parameter".to_owned(),
            ))?;
        let main_contract = era_provider.get_main_contract().await?;
        let merkle_proof: Vec<H256> = proof.merkle_proof;
        let l1_batch_number = era_provider.get_l1_batch_number().await?;
        let l2_message_index = U256::from(proof.id);

        let l2_tx_number_in_block: String = serde_json::from_value::<String>(
            withdrawal_receipt
                .other
                .get("l1BatchTxIndex")
                .ok_or(ZKSWalletError::CustomError(
                    "Field not present in receipt".to_owned(),
                ))?
                .clone(),
        )
        .map_err(|err| ZKSWalletError::CustomError(format!("Failed to deserialize field {err}")))?;

        let message: Bytes = decode(&[ParamType::Bytes], &filtered_log.data)
            .map_err(|e| ZKSWalletError::CustomError(format!("failed to decode log data: {e}")))?
            .get(0)
            .ok_or(ZKSWalletError::CustomError(
                "Message not found in decoded data".to_owned(),
            ))?
            .clone()
            .into_bytes()
            .ok_or(ZKSWalletError::CustomError(
                "Could not convert message to bytes".to_owned(),
            ))?
            .into();

        let parameters = [
            format!("{l1_batch_number:?}"),
            format!("{l2_message_index:?}"),
            l2_tx_number_in_block,
            hex::encode(&message),
            format!("{merkle_proof:?}")
                .replace('"', "")
                .replace(' ', ""),
        ];

        let function_signature = "function finalizeEthWithdrawal(uint256 _l2BlockNumber,uint256 _l2MessageIndex,uint16 _l2TxNumberInBlock,bytes calldata _message,bytes32[] calldata _merkleProof) external";
        let response = eth_provider
            .send(
                &self.l1_wallet,
                main_contract,
                function_signature,
                Some(parameters.into()),
                None,
            )
            .await?;

        eth_provider
            .get_transaction_receipt(response.1)
            .await?
            .ok_or(ZKSWalletError::CustomError(
                "No transaction receipt for finalize withdraw".to_owned(),
            ))
    }
}

#[cfg(test)]
mod zks_signer_tests {
    use crate::test_utils::*;
    use crate::zks_utils::{ERA_CHAIN_ID, ETH_CHAIN_ID};
    use crate::zks_wallet::ZKSWallet;
    use ethers::providers::Middleware;
    use ethers::signers::{LocalWallet, Signer};
    use ethers::types::Address;
    use ethers::types::U256;
    use ethers::utils::parse_units;
    use std::fs::File;
    use std::path::PathBuf;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_transfer() {
        let sender_private_key =
            "0x28a574ab2de8a00364d5dd4b07c4f2f574ef7fcc2a86a197f65abaec836d1959";
        let receiver_address: Address = "0xa61464658AfeAf65CccaaFD3a512b69A83B77618"
            .parse()
            .unwrap();
        let amount_to_transfer: U256 = 1_i32.into();

        let era_provider = era_provider();
        let wallet = LocalWallet::from_str(sender_private_key)
            .unwrap()
            .with_chain_id(ERA_CHAIN_ID);
        let zk_wallet = ZKSWallet::new(wallet, None, Some(era_provider.clone()), None).unwrap();

        let sender_balance_before = era_provider
            .get_balance(zk_wallet.l2_address(), None)
            .await
            .unwrap();
        let receiver_balance_before = era_provider
            .get_balance(receiver_address, None)
            .await
            .unwrap();

        println!("Sender balance before: {sender_balance_before}");
        println!("Receiver balance before: {receiver_balance_before}");
        println!("Sender balance before: {sender_balance_before}");
        println!("Receiver balance before: {receiver_balance_before}");

        let receipt = zk_wallet
            .transfer(receiver_address, amount_to_transfer, None)
            .await
            .unwrap();

        assert_eq!(receipt.from, zk_wallet.l2_address());
        assert_eq!(receipt.to.unwrap(), receiver_address);

        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        let sender_balance_after = era_provider
            .get_balance(zk_wallet.l2_address(), None)
            .await
            .unwrap();
        let receiver_balance_after = era_provider
            .get_balance(receiver_address, None)
            .await
            .unwrap();

        println!("Sender balance after: {sender_balance_after}");
        println!("Receiver balance after: {receiver_balance_after}");

        assert_eq!(
            sender_balance_after,
            sender_balance_before
                - (amount_to_transfer
                    + receipt.effective_gas_price.unwrap() * receipt.gas_used.unwrap())
        );
        assert_eq!(
            receiver_balance_after,
            receiver_balance_before + amount_to_transfer
        );
    }

    #[tokio::test]
    async fn test_deposit() {
        let private_key = "0x28a574ab2de8a00364d5dd4b07c4f2f574ef7fcc2a86a197f65abaec836d1959";
        let amount: U256 = parse_units("0.01", "ether").unwrap().into();
        println!("Amount: {amount}");

        let l1_provider = eth_provider();
        let l2_provider = era_provider();
        let wallet = LocalWallet::from_str(private_key)
            .unwrap()
            .with_chain_id(ERA_CHAIN_ID);
        let zk_wallet = ZKSWallet::new(
            wallet,
            None,
            Some(l2_provider.clone()),
            Some(l1_provider.clone()),
        )
        .unwrap();

        let l1_balance_before = zk_wallet.eth_balance().await.unwrap();
        let l2_balance_before = zk_wallet.era_balance().await.unwrap();
        println!("L1 balance before: {l1_balance_before}");
        println!("L2 balance before: {l2_balance_before}");

        let receipt = zk_wallet.deposit(amount).await.unwrap();
        assert_eq!(receipt.status.unwrap(), 1_u8.into());

        let _l2_receipt = l2_provider
            .get_transaction_receipt(receipt.transaction_hash)
            .await
            .unwrap();

        let l1_balance_after = zk_wallet.eth_balance().await.unwrap();
        let l2_balance_after = zk_wallet.era_balance().await.unwrap();
        println!("L1 balance after: {l1_balance_after}");
        println!("L2 balance after: {l2_balance_after}");

        assert!(
            l1_balance_after <= l1_balance_before - amount,
            "Balance on L1 should be decreased"
        );
        assert!(
            l2_balance_after >= l2_balance_before + amount,
            "Balance on L2 should be increased"
        );
    }

    #[tokio::test]
    async fn test_transfer_eip712() {
        let sender_private_key =
            "0x28a574ab2de8a00364d5dd4b07c4f2f574ef7fcc2a86a197f65abaec836d1959";
        let receiver_address: Address = "0xa61464658AfeAf65CccaaFD3a512b69A83B77618"
            .parse()
            .unwrap();
        let amount_to_transfer: U256 = 1_i32.into();

        let era_provider = era_provider();
        let wallet = LocalWallet::from_str(sender_private_key)
            .unwrap()
            .with_chain_id(ERA_CHAIN_ID);
        let zk_wallet = ZKSWallet::new(wallet, None, Some(era_provider.clone()), None).unwrap();

        let sender_balance_before = era_provider
            .get_balance(zk_wallet.l2_address(), None)
            .await
            .unwrap();
        let receiver_balance_before = era_provider
            .get_balance(receiver_address, None)
            .await
            .unwrap();

        println!("Sender balance before: {sender_balance_before}");
        println!("Receiver balance before: {receiver_balance_before}");

        let receipt = zk_wallet
            .transfer_eip712(receiver_address, amount_to_transfer, None)
            .await
            .unwrap();

        assert_eq!(receipt.from, zk_wallet.l2_address());
        assert_eq!(receipt.to.unwrap(), receiver_address);

        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        let sender_balance_after = era_provider
            .get_balance(zk_wallet.l2_address(), None)
            .await
            .unwrap();
        let receiver_balance_after = era_provider
            .get_balance(receiver_address, None)
            .await
            .unwrap();

        println!("Sender balance after: {sender_balance_after}");
        println!("Receiver balance after: {receiver_balance_after}");

        assert_eq!(
            sender_balance_after,
            sender_balance_before
                - (amount_to_transfer
                    + receipt.effective_gas_price.unwrap() * receipt.gas_used.unwrap())
        );
        assert_eq!(
            receiver_balance_after,
            receiver_balance_before + amount_to_transfer
        );
    }

    #[tokio::test]
    async fn test_deploy_contract_with_constructor_arg_uint() {
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
                Some(vec!["10".to_owned()]),
            )
            .await
            .unwrap();

        let contract_address = transaction_receipt.contract_address.unwrap();
        let deploy_result = era_provider.get_code(contract_address, None).await;

        assert!(deploy_result.is_ok());
    }

    #[tokio::test]
    async fn test_deploy_contract_with_constructor_arg_string() {
        let deployer_private_key =
            "7726827caac94a7f9e1b160f7ea819f172f7b6f9d2a97f992c38edeab82d4110";
        let era_provider = era_provider();
        let wallet = LocalWallet::from_str(deployer_private_key).unwrap();
        let zk_wallet = ZKSWallet::new(wallet, None, Some(era_provider.clone()), None).unwrap();

        let mut contract_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        contract_path.push("src/abi/test_contracts/greeter_combined.json");
        let contract: CompiledContract =
            serde_json::from_reader(File::open(contract_path).unwrap()).unwrap();

        let transaction_receipt = zk_wallet
            .deploy(
                contract.abi,
                contract.bin.to_vec(),
                None,
                Some(vec!["Hey".to_owned()]),
            )
            .await
            .unwrap();

        let contract_address = transaction_receipt.contract_address.unwrap();
        let deploy_result = era_provider.get_code(contract_address, None).await;

        assert!(deploy_result.is_ok());
    }

    #[tokio::test]
    async fn test_withdraw_to_same_address() {
        let sender_private_key =
            "0x28a574ab2de8a00364d5dd4b07c4f2f574ef7fcc2a86a197f65abaec836d1959";
        let wallet = LocalWallet::from_str(sender_private_key)
            .unwrap()
            .with_chain_id(ERA_CHAIN_ID);
        let zk_wallet =
            ZKSWallet::new(wallet, None, Some(era_provider()), Some(eth_provider())).unwrap();

        // See balances before withdraw
        let l1_balance_before = zk_wallet.eth_balance().await.unwrap();
        let l2_balance_before = zk_wallet.era_balance().await.unwrap();

        println!("Balance on L1 before withdrawal: {l1_balance_before}");
        println!("Balance on L2 before withdrawal: {l2_balance_before}");

        // Withdraw
        let amount_to_withdraw: U256 = parse_units(1_u8, "ether").unwrap().into();
        let tx_receipt = zk_wallet
            .withdraw(amount_to_withdraw, zk_wallet.l1_address())
            .await
            .unwrap();
        assert_eq!(
            1,
            tx_receipt.status.unwrap().as_u64(),
            "Check that transaction in L2 is successful"
        );

        println!("L2 Transaction hash: {:?}", tx_receipt.transaction_hash);

        let l2_balance_after_withdraw = zk_wallet.era_balance().await.unwrap();
        let l1_balance_after_withdraw = zk_wallet.eth_balance().await.unwrap();

        assert_eq!(
            l2_balance_after_withdraw,
            l2_balance_before
                - (amount_to_withdraw + tx_receipt.effective_gas_price.unwrap() * tx_receipt.gas_used.unwrap()),
            "Check that L2 balance inmediately after withdrawal has decreased by the used gas and amount"
        );

        assert_eq!(
            l1_balance_before, l1_balance_after_withdraw,
            "Check that L1 balance has not changed"
        );

        let tx_finalize_receipt = zk_wallet
            .finalize_withdraw(tx_receipt.transaction_hash)
            .await
            .unwrap();

        println!(
            "L1 Transaction hash: {:?}",
            tx_finalize_receipt.transaction_hash
        );

        assert_eq!(
            1,
            tx_finalize_receipt.status.unwrap().as_u64(),
            "Check that transaction in L1 is successful"
        );

        // See balances after withdraw
        let l1_balance_after_finalize = zk_wallet.eth_balance().await.unwrap();
        let l2_balance_after_finalize = zk_wallet.era_balance().await.unwrap();

        println!("Balance on L1 after finalize withdraw: {l1_balance_after_finalize}");
        println!("Balance on L2 after finalize withdraw: {l2_balance_after_finalize}");

        assert_eq!(
            l2_balance_after_finalize, l2_balance_after_withdraw,
            "Check that L2 balance after finalize has decreased by the used gas"
        );

        assert_ne!(
            l1_balance_after_finalize, l1_balance_before,
            "Check that L1 balance after finalize is not the same"
        );
        assert_eq!(
            l1_balance_after_finalize,
            l1_balance_before
                + (amount_to_withdraw
                    - tx_finalize_receipt.effective_gas_price.unwrap()
                        * tx_finalize_receipt.gas_used.unwrap()),
            "Check that L1 balance after finalize has increased by the amount"
        );
    }

    #[tokio::test]
    async fn test_withdraw_to_other_address() {
        let sender_private_key =
            "0x28a574ab2de8a00364d5dd4b07c4f2f574ef7fcc2a86a197f65abaec836d1959";
        let receiver_private_key =
            "0xe667e57a9b8aaa6709e51ff7d093f1c5b73b63f9987e4ab4aa9a5c699e024ee8";
        let l2_wallet = LocalWallet::from_str(sender_private_key)
            .unwrap()
            .with_chain_id(ERA_CHAIN_ID);

        let l1_wallet = LocalWallet::from_str(receiver_private_key)
            .unwrap()
            .with_chain_id(ETH_CHAIN_ID);
        let zk_wallet = ZKSWallet::new(
            l2_wallet,
            Some(l1_wallet),
            Some(era_provider()),
            Some(eth_provider()),
        )
        .unwrap();

        // See balances before withdraw
        let l1_balance_before = zk_wallet.eth_balance().await.unwrap();
        let l2_balance_before = zk_wallet.era_balance().await.unwrap();

        println!("Balance on L1 before withdrawal: {l1_balance_before}");
        println!("Balance on L2 before withdrawal: {l2_balance_before}");

        // Withdraw
        let amount_to_withdraw: U256 = parse_units(1_u8, "ether").unwrap().into();
        let tx_receipt = zk_wallet
            .withdraw(amount_to_withdraw, zk_wallet.l1_address())
            .await
            .unwrap();
        assert_eq!(
            1,
            tx_receipt.status.unwrap().as_u64(),
            "Check that transaction in L2 is successful"
        );

        println!("L2 Transaction hash: {:?}", tx_receipt.transaction_hash);

        let l2_balance_after_withdraw = zk_wallet.era_balance().await.unwrap();
        let l1_balance_after_withdraw = zk_wallet.eth_balance().await.unwrap();

        assert_eq!(
            l2_balance_after_withdraw,
            l2_balance_before
                - (amount_to_withdraw + tx_receipt.effective_gas_price.unwrap() * tx_receipt.gas_used.unwrap()),
            "Check that L2 balance inmediately after withdrawal has decreased by the used gas and amount"
        );

        assert_eq!(
            l1_balance_before, l1_balance_after_withdraw,
            "Check that L1 balance has not changed"
        );

        let tx_finalize_receipt = zk_wallet
            .finalize_withdraw(tx_receipt.transaction_hash)
            .await
            .unwrap();

        println!(
            "L1 Transaction hash: {:?}",
            tx_finalize_receipt.transaction_hash
        );

        assert_eq!(
            1,
            tx_finalize_receipt.status.unwrap().as_u64(),
            "Check that transaction in L1 is successful"
        );

        // See balances after withdraw
        let l1_balance_after_finalize = zk_wallet.eth_balance().await.unwrap();
        let l2_balance_after_finalize = zk_wallet.era_balance().await.unwrap();

        println!("Balance on L1 after finalize withdraw: {l1_balance_after_finalize}");
        println!("Balance on L2 after finalize withdraw: {l2_balance_after_finalize}");

        assert_eq!(
            l2_balance_after_finalize, l2_balance_after_withdraw,
            "Check that L2 balance after finalize has decreased by the used gas"
        );

        assert_ne!(
            l1_balance_after_finalize, l1_balance_before,
            "Check that L1 balance after finalize is not the same"
        );
        assert_eq!(
            l1_balance_after_finalize,
            l1_balance_before
                + (amount_to_withdraw
                    - tx_finalize_receipt.effective_gas_price.unwrap()
                        * tx_finalize_receipt.gas_used.unwrap()),
            "Check that L1 balance after finalize has increased by the amount"
        );
    }
}
