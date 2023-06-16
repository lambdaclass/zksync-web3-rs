use super::{Overrides, ZKSWalletError};
use crate::{
    compile::project::ZKProject,
    eip712::{hash_bytecode, Eip712Meta, Eip712Transaction, Eip712TransactionRequest},
    zks_provider::ZKSProvider,
    zks_utils::{
        CONTRACTS_L1_MESSENGER_ADDR, CONTRACTS_L2_ETH_TOKEN_ADDR, CONTRACT_DEPLOYER_ADDR,
        EIP712_TX_TYPE, ERA_CHAIN_ID, ETH_CHAIN_ID,
    },
};
use ethers::{
    abi::{decode, Abi, HumanReadableParser, ParamType, Token, Tokenizable, Tokenize},
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
    solc::{info::ContractInfo, Project, ProjectPathsConfig},
    types::{
        transaction::eip2718::TypedTransaction, Address, Bytes, Eip1559TransactionRequest, Log,
        Signature, TransactionReceipt, H256, U256,
    },
};
use serde_json::Value;
use std::{fmt::Display, fs::File, io::BufReader, path::PathBuf, str::FromStr};

pub struct ZKSWallet<M, D>
where
    M: Middleware,
    D: PrehashSigner<(RecoverableSignature, RecoveryId)>,
{
    pub eth_provider: Option<SignerMiddleware<M, Wallet<D>>>,
    pub era_provider: Option<SignerMiddleware<M, Wallet<D>>>,
    pub wallet: Wallet<D>,
}

impl<M, D> ZKSWallet<M, D>
where
    M: Middleware + 'static,
    D: PrehashSigner<(RecoverableSignature, RecoveryId)> + Sync + Send + Clone,
{
    pub fn new(
        wallet: Wallet<D>,
        era_provider: Option<M>,
        eth_provider: Option<M>,
    ) -> Result<Self, ZKSWalletError<M, D>> {
        Ok(Self {
            wallet: wallet.clone().with_chain_id(ERA_CHAIN_ID),
            era_provider: era_provider
                .map(|p| p.with_signer(wallet.clone().with_chain_id(ERA_CHAIN_ID))),
            eth_provider: eth_provider.map(|p| p.with_signer(wallet.with_chain_id(ETH_CHAIN_ID))),
        })
    }

    pub fn connect_eth_provider(mut self, eth_provider: M) -> Self {
        self.eth_provider = Some(eth_provider.with_signer(self.wallet.clone()));
        self
    }

    pub fn connect_era_provider(mut self, era_provider: M) -> Self {
        self.era_provider = Some(era_provider.with_signer(self.wallet.clone()));
        self
    }

    pub fn connect_eth_signer(mut self, eth_signer: SignerMiddleware<M, Wallet<D>>) -> Self {
        self.eth_provider = Some(eth_signer);
        self
    }

    pub fn connect_era_signer(mut self, era_signer: SignerMiddleware<M, Wallet<D>>) -> Self {
        self.era_provider = Some(era_signer);
        self
    }

    // pub fn connect_eth(&mut self, host: &str, port: u16) {
    //     self.eth_provider = Provider::try_from(format!("http://{host}:{port}")).ok().map(|p| p.with_signer(self.wallet));
    // }

    // pub fn connect_era(&mut self, host: &str, port: u16) {
    //     self.era_provider = Provider::try_from(format!("http://{host}:{port}")).ok().map(|p| p.with_signer(self.wallet));
    // }

    pub fn address(&self) -> Address {
        self.wallet.address()
    }

    pub async fn eth_balance(&self) -> Result<U256, ZKSWalletError<M, D>>
    where
        M: ZKSProvider,
    {
        match &self.eth_provider {
            // TODO: Should we have a balance_on_block method?
            Some(eth_provider) => Ok(eth_provider.get_balance(self.address(), None).await?),
            None => Err(ZKSWalletError::CustomError("no era provider".to_owned())),
        }
    }

    pub async fn era_balance(&self) -> Result<U256, ZKSWalletError<M, D>>
    where
        M: ZKSProvider,
    {
        match &self.era_provider {
            // TODO: Should we have a balance_on_block method?
            Some(era_provider) => Ok(era_provider.get_balance(self.address(), None).await?),
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
            .from(self.address())
            .to(to)
            .value(amount_to_transfer)
            .chain_id(ERA_CHAIN_ID);

        let fee = era_provider.estimate_fee(transfer_request.clone()).await?;
        transfer_request = transfer_request.max_priority_fee_per_gas(fee.max_priority_fee_per_gas);
        transfer_request = transfer_request.max_fee_per_gas(fee.max_fee_per_gas);

        let transaction: TypedTransaction = transfer_request.into();

        // TODO: add block as an override.
        let pending_transaction = era_provider.send_transaction(transaction, None).await?;

        // TODO: Should we wait here for the transaction to be confirmed on-chain?

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
            .from(self.address())
            .to(to)
            .value(amount_to_transfer)
            .nonce(
                era_provider
                    .get_transaction_count(self.address(), None)
                    .await?,
            )
            .gas_price(era_provider.get_gas_price().await?);

        let fee = era_provider.estimate_fee(transfer_request.clone()).await?;
        transfer_request = transfer_request
            .max_priority_fee_per_gas(fee.max_priority_fee_per_gas)
            .max_fee_per_gas(fee.max_fee_per_gas)
            .gas_limit(fee.gas_limit);

        let signable_data: Eip712Transaction = transfer_request.clone().try_into()?;
        let signature: Signature = self.wallet.sign_typed_data(&signable_data).await?;
        transfer_request =
            transfer_request.custom_data(Eip712Meta::new().custom_signature(signature.to_vec()));

        let pending_transaction = era_provider
            .send_raw_transaction(
                [&[EIP712_TX_TYPE], &*transfer_request.rlp_unsigned()]
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

        Ok(transaction_receipt)
    }

    pub async fn deploy<T>(
        &self,
        contract_path: impl Into<PathBuf> + Display + Clone,
        contract_name: &str,
        constructor_parameters: Option<T>,
    ) -> Result<Address, ZKSWalletError<M, D>>
    where
        M: ZKSProvider,
        T: Tokenizable,
    {
        let mut root = PathBuf::from("./");
        root.push::<PathBuf>(contract_path.clone().into());
        let zk_project = ZKProject::from(
            Project::builder()
                .paths(ProjectPathsConfig::builder().build_with_root(root))
                .set_auto_detect(true)
                .build()?,
        );
        let compilation_output = zk_project.compile()?;
        let artifact = compilation_output
            .find_contract(ContractInfo::from_str(&format!(
                "{contract_path}:{contract_name}"
            ))?)
            .ok_or(ZKSWalletError::CustomError("no contract abi".to_owned()))?;

        let transaction_receipt = self
            ._deploy(
                artifact
                    .abi
                    .clone()
                    .ok_or(ZKSWalletError::CustomError("no contract abi".to_owned()))?,
                artifact
                    .bin
                    .clone()
                    .ok_or(ZKSWalletError::CustomError("no contract bin".to_owned()))?
                    .to_vec(),
                None,
                constructor_parameters,
            )
            .await?;

        let contract_address =
            transaction_receipt
                .contract_address
                .ok_or(ZKSWalletError::CustomError(
                    "no contract address".to_owned(),
                ))?;

        Ok(contract_address)
    }

    pub async fn deploy_with_receipt<T>(
        &self,
        contract_abi: Abi,
        contract_bytecode: Vec<u8>,
        contract_dependencies: Option<Vec<Vec<u8>>>,
        constructor_parameters: Option<T>,
    ) -> Result<(Address, TransactionReceipt), ZKSWalletError<M, D>>
    where
        M: ZKSProvider,
        T: Tokenizable,
    {
        let transaction_receipt = self
            ._deploy(
                contract_abi,
                contract_bytecode,
                contract_dependencies,
                constructor_parameters,
            )
            .await?;

        let contract_address =
            transaction_receipt
                .contract_address
                .ok_or(ZKSWalletError::CustomError(
                    "no contract address".to_owned(),
                ))?;

        Ok((contract_address, transaction_receipt))
    }

    async fn _deploy<T>(
        &self,
        contract_abi: Abi,
        contract_bytecode: Vec<u8>,
        contract_dependencies: Option<Vec<Vec<u8>>>,
        constructor_parameters: Option<T>,
    ) -> Result<TransactionReceipt, ZKSWalletError<M, D>>
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
            factory_deps.push(contract_bytecode.clone());
            factory_deps
        });

        let mut deploy_request = Eip712TransactionRequest::new()
            .r#type(EIP712_TX_TYPE)
            .from(self.address())
            .to(Address::from_str(CONTRACT_DEPLOYER_ADDR).map_err(|e| {
                ZKSWalletError::CustomError(format!("invalid contract deployer address: {e}"))
            })?)
            .chain_id(ERA_CHAIN_ID)
            .nonce(
                era_provider
                    .get_transaction_count(self.address(), None)
                    .await?,
            )
            .gas_price(era_provider.get_gas_price().await?)
            .max_fee_per_gas(era_provider.get_gas_price().await?)
            .data({
                let contract_deployer = Abi::load(BufReader::new(
                    File::open("./src/abi/ContractDeployer.json").map_err(|e| {
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
                    (None, Some(_)) => return Err(ContractError::ConstructorError.into()),
                    (None, None) | (Some(_), None) => Bytes::default(),
                    (Some(constructor), Some(constructor_parameters)) => constructor
                        .encode_input(
                            contract_bytecode.to_vec(),
                            &constructor_parameters.into_tokens(),
                        )
                        .map_err(|err| ZKSWalletError::CustomError(err.to_string()))?
                        .into(),
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
        let signature: Signature = self.wallet.sign_typed_data(&signable_data).await?;
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

        pending_transaction
            .await?
            .ok_or(ZKSWalletError::CustomError(
                "no transaction receipt".to_owned(),
            ))
    }

    pub async fn call<T>(
        &self,
        address: Address,
        function_signature: &str,
        function_parameters: Option<T>,
    ) -> Result<Vec<Token>, ZKSWalletError<M, D>>
    where
        M: ZKSProvider,
        T: Tokenizable,
    {
        let era_provider = match &self.era_provider {
            Some(era_provider) => era_provider,
            None => return Err(ZKSWalletError::CustomError("no era provider".to_owned())),
        };

        // Note: We couldn't implement ZKSWalletError::LexerError because ethers-rs's LexerError is not exposed.
        let function = HumanReadableParser::parse_function(function_signature)
            .map_err(|e| ZKSWalletError::CustomError(e.to_string()))?;

        let request =
            Eip1559TransactionRequest::new()
                .to(address)
                .data(match function_parameters {
                    Some(parameters) => function
                        .encode_input(&parameters.into_tokens())
                        .map_err(|e| ZKSWalletError::CustomError(e.to_string()))?,
                    None => function.short_signature().into(),
                });

        let transaction: TypedTransaction = request.into();

        let encoded_output = era_provider.call(&transaction, None).await?;
        let decoded_output = function.decode_output(&encoded_output).map_err(|e| {
            ZKSWalletError::CustomError(format!("failed to decode output: {e}\n{encoded_output}"))
        })?;

        Ok(if decoded_output.is_empty() {
            encoded_output.into_tokens()
        } else {
            decoded_output
        })
    }

    pub async fn withdraw(&self, amount: U256) -> Result<TransactionReceipt, ZKSWalletError<M, D>>
    where
        M: ZKSProvider,
    {
        let era_provider = match &self.era_provider {
            Some(era_provider) => era_provider,
            None => return Err(ZKSWalletError::CustomError("no era provider".to_owned())),
        };

        let contract_address = Address::from_str(CONTRACTS_L2_ETH_TOKEN_ADDR).unwrap();
        let function_signature = "function withdraw(address _l1Receiver) external payable override";
        let response: (Vec<Token>, H256) = era_provider
            .send_eip712(
                &self.wallet,
                contract_address,
                function_signature,
                Some(self.wallet.address()),
                Some(Overrides {
                    value: Some(amount),
                }),
            )
            .await?;

        Ok(era_provider
            .get_transaction_receipt(response.1)
            .await
            .unwrap()
            .unwrap())
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

        let withdrawal_receipt = era_provider
            .get_transaction_receipt(tx_hash)
            .await?
            .unwrap();

        let logs: Vec<Log> = withdrawal_receipt
            .logs
            .into_iter()
            .filter(|log| {
                //log.topics[0] == topic &&
                log.address == Address::from_str(CONTRACTS_L1_MESSENGER_ADDR).unwrap()
            })
            .collect();

        // Get all the parameters needed to call the finalizeWithdrawal function on the main contract contract.
        let (l2_to_l1_log_index, _) =
            serde_json::from_value::<Vec<Value>>(withdrawal_receipt.other["l2ToL1Logs"].clone())
                .unwrap()
                .iter()
                .enumerate()
                .find(|(_, log)| log["sender"] == CONTRACTS_L1_MESSENGER_ADDR)
                .unwrap();
        let filtered_log = logs[0].clone();
        let proof = era_provider
            .get_l2_to_l1_log_proof(tx_hash, Some(l2_to_l1_log_index as u64))
            .await?
            .unwrap();
        let main_contract = era_provider.get_main_contract().await?;
        let merkle_proof: Vec<H256> = proof.merkle_proof;
        let l1_batch_number = era_provider.get_l1_batch_number().await?;
        let l2_message_index = U256::from(proof.id);
        let l2_tx_number_in_block: u16 =
            serde_json::from_value::<U256>(withdrawal_receipt.other["l1BatchTxIndex"].clone())
                .unwrap()
                .as_u32() as u16;
        let message: Bytes = decode(&[ParamType::Bytes], &*filtered_log.data).map_err(|e| {
            ZKSWalletError::CustomError(format!("failed to decode log data: {}", e))
        })?[0]
            .clone()
            .into_bytes()
            .unwrap()
            .into();
        let parameters = (
            l1_batch_number,
            l2_message_index,
            l2_tx_number_in_block,
            message,
            merkle_proof,
        );

        let function_signature = "function finalizeEthWithdrawal(uint256 _l2BlockNumber,uint256 _l2MessageIndex,uint16 _l2TxNumberInBlock,bytes calldata _message,bytes32[] calldata _merkleProof) external";
        let response = eth_provider
            .send(
                &self.wallet,
                main_contract,
                function_signature,
                Some(parameters),
                None,
            )
            .await?;

        Ok(era_provider
            .get_transaction_receipt(response.1)
            .await
            .unwrap()
            .unwrap())
    }
}

#[cfg(test)]
mod zks_signer_tests {
    use crate::compile::project::ZKProject;
    use crate::test_utils::*;
    use crate::zks_provider::ZKSProvider;
    use crate::zks_utils::ERA_CHAIN_ID;
    use crate::zks_wallet::ZKSWallet;
    use ethers::abi::{Token, Tokenize};
    use ethers::providers::Middleware;
    use ethers::signers::{LocalWallet, Signer};
    use ethers::solc::info::ContractInfo;
    use ethers::solc::{Project, ProjectPathsConfig};
    use ethers::types::U256;
    use ethers::types::{Address, Bytes};
    use ethers::utils::parse_units;
    use std::str::FromStr;
    use std::thread;
    use std::time::Duration;

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
        let zk_wallet = ZKSWallet::new(wallet, Some(era_provider.clone()), None).unwrap();

        let sender_balance_before = era_provider
            .get_balance(zk_wallet.address(), None)
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

        assert_eq!(receipt.from, zk_wallet.address());
        assert_eq!(receipt.to.unwrap(), receiver_address);

        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        let sender_balance_after = era_provider
            .get_balance(zk_wallet.address(), None)
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
        let zk_wallet = ZKSWallet::new(wallet, Some(era_provider.clone()), None).unwrap();

        let sender_balance_before = era_provider
            .get_balance(zk_wallet.address(), None)
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

        assert_eq!(receipt.from, zk_wallet.address());
        assert_eq!(receipt.to.unwrap(), receiver_address);

        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        let sender_balance_after = era_provider
            .get_balance(zk_wallet.address(), None)
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
    #[ignore = "skipped until the compiler OS version is fixed"]
    async fn test_deploy_contract_with_constructor_args() {
        let deployer_private_key =
            "7726827caac94a7f9e1b160f7ea819f172f7b6f9d2a97f992c38edeab82d4110";
        let era_provider = era_provider();
        let wallet = LocalWallet::from_str(deployer_private_key)
            .unwrap()
            .with_chain_id(ERA_CHAIN_ID);
        let zk_wallet = ZKSWallet::new(wallet, Some(era_provider.clone()), None).unwrap();
        let project_root = "./src/compile/test_contracts/storage";
        let contract_name = "ValueStorage";

        let zk_project = ZKProject::from(
            Project::builder()
                .paths(ProjectPathsConfig::builder().build_with_root(project_root))
                .set_auto_detect(true)
                .build()
                .unwrap(),
        );
        let compilation_output = zk_project.compile().unwrap();
        let artifact = compilation_output
            .find_contract(
                ContractInfo::from_str(&format!(
                    "src/compile/test_contracts/storage/src/ValueStorage.sol:{contract_name}"
                ))
                .unwrap(),
            )
            .unwrap();
        let compiled_bytecode = artifact.bin.clone().unwrap();

        let contract_address = zk_wallet
            .deploy(
                "src/compile/test_contracts/storage/src/ValueStorage.sol",
                contract_name,
                Some(U256::from(10_i32)),
            )
            .await
            .unwrap();

        let recovered_bytecode = era_provider.get_code(contract_address, None).await.unwrap();

        assert_eq!(compiled_bytecode, recovered_bytecode);
    }

    #[tokio::test]
    #[ignore = "skipped until the compiler OS version is fixed"]
    async fn test_call_view_function_with_no_parameters() {
        // Deploying a test contract
        let deployer_private_key =
            "7726827caac94a7f9e1b160f7ea819f172f7b6f9d2a97f992c38edeab82d4110";
        let era_provider = era_provider();
        let wallet = LocalWallet::from_str(deployer_private_key)
            .unwrap()
            .with_chain_id(ERA_CHAIN_ID);
        let zk_wallet = ZKSWallet::new(wallet, Some(era_provider.clone()), None).unwrap();

        let contract_address = zk_wallet
            .deploy::<Token>("src/compile/test_contracts/test/src/Test.sol", "Test", None)
            .await
            .unwrap();

        // Making the call to the contract function
        let deployer_private_key =
            "0x28a574ab2de8a00364d5dd4b07c4f2f574ef7fcc2a86a197f65abaec836d1959";
        let wallet = LocalWallet::from_str(deployer_private_key)
            .unwrap()
            .with_chain_id(ERA_CHAIN_ID);
        let zk_wallet = ZKSWallet::new(wallet, Some(era_provider.clone()), None).unwrap();

        let output = zk_wallet
            .call::<Token>(contract_address, "str_out()(string)", None)
            .await
            .unwrap();

        assert_eq!(output, String::from("Hello World!").into_tokens());
    }

    #[tokio::test]
    #[ignore = "skipped until the compiler OS version is fixed"]
    async fn test_call_view_function_with_arguments() {
        // Deploying a test contract
        let deployer_private_key =
            "7726827caac94a7f9e1b160f7ea819f172f7b6f9d2a97f992c38edeab82d4110";
        let era_provider = era_provider();
        let wallet = LocalWallet::from_str(deployer_private_key)
            .unwrap()
            .with_chain_id(ERA_CHAIN_ID);
        let zk_wallet = ZKSWallet::new(wallet, Some(era_provider.clone()), None).unwrap();

        let contract_address = zk_wallet
            .deploy::<Token>("src/compile/test_contracts/test/src/Test.sol", "Test", None)
            .await
            .unwrap();

        let no_return_type_output = zk_wallet
            .call(contract_address, "plus_one(uint256)", Some(U256::one()))
            .await
            .unwrap();

        let known_return_type_output = zk_wallet
            .call(
                contract_address,
                "plus_one(uint256)(uint256)",
                Some(U256::one()),
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

    #[tokio::test]
    #[ignore = "skipped until the compiler OS version is fixed"]
    async fn test_send_function_with_arguments() {
        // Deploying a test contract
        let deployer_private_key =
            "7726827caac94a7f9e1b160f7ea819f172f7b6f9d2a97f992c38edeab82d4110";
        let era_provider = era_provider();
        let wallet = LocalWallet::from_str(deployer_private_key)
            .unwrap()
            .with_chain_id(ERA_CHAIN_ID);
        let zk_wallet = ZKSWallet::new(wallet, Some(era_provider.clone()), None).unwrap();

        let contract_address = zk_wallet
            .deploy(
                "src/compile/test_contracts/storage/src/ValueStorage.sol",
                "ValueStorage",
                Some(U256::zero()),
            )
            .await
            .unwrap();

        let value_to_set = U256::from(10_u64);
        era_provider
            .send_eip712(
                &zk_wallet.wallet,
                contract_address,
                "setValue(uint256)",
                Some(value_to_set),
                None,
            )
            .await
            .unwrap();
        let set_value = zk_wallet
            .call::<Token>(contract_address, "getValue()(uint256)", None)
            .await
            .unwrap();

        assert_eq!(set_value, value_to_set.into_tokens());

        era_provider
            .send_eip712::<Token, _>(
                &zk_wallet.wallet,
                contract_address,
                "incrementValue()",
                None,
                None,
            )
            .await
            .unwrap();
        let incremented_value = zk_wallet
            .call::<Token>(contract_address, "getValue()(uint256)", None)
            .await
            .unwrap();

        assert_eq!(incremented_value, (value_to_set + 1_u64).into_tokens());
    }

    #[tokio::test]
    async fn test_withdraw() {
        let deployer_private_key =
            "7726827caac94a7f9e1b160f7ea819f172f7b6f9d2a97f992c38edeab82d4110";
        let wallet = LocalWallet::from_str(deployer_private_key)
            .unwrap()
            .with_chain_id(ERA_CHAIN_ID);
        let zk_wallet = ZKSWallet::new(wallet, Some(era_provider()), Some(eth_provider())).unwrap();

        // See balances before withdraw
        let l1_balance_before = zk_wallet.eth_balance().await.unwrap();
        let l2_balance_before = zk_wallet.era_balance().await.unwrap();

        println!("Balance on L1 before withdrawal: {l1_balance_before}");
        println!("Balance on L2 before withdrawal: {l2_balance_before}");

        // Withdraw
        let amount_to_withdraw: U256 = parse_units(1, "ether").unwrap().into();
        let tx_receipt = zk_wallet.withdraw(amount_to_withdraw).await.unwrap();
        assert_eq!(
            1,
            tx_receipt.status.unwrap().as_u64(),
            "Check that transaction in L2 is successful"
        );

        println!("L2 Transaction hash: {:?}", tx_receipt.transaction_hash);

        // TODO cleanup. Make sure the proof is posted on L2.
        thread::sleep(Duration::from_millis(20000));

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
