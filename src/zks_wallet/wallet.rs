use super::ZKSWalletError;
use crate::{
    compile::project::ZKProject,
    contracts::main_contract::{MainContract, MainContractInstance},
    eip712::Eip712Transaction,
    eip712::{hash_bytecode, Eip712Meta, Eip712TransactionRequest},
    zks_provider::ZKSProvider,
    zks_utils::{
        self, is_precompile, CONTRACT_DEPLOYER_ADDR, DEPOSIT_GAS_PER_PUBDATA_LIMIT, EIP712_TX_TYPE,
        ERA_CHAIN_ID, ETH_CHAIN_ID, RECOMMENDED_DEPOSIT_L1_GAS_LIMIT,
        RECOMMENDED_DEPOSIT_L2_GAS_LIMIT,
    },
};
use ethers::{
    abi::{encode, Abi, HumanReadableParser, Token, Tokenizable, Tokenize},
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
        transaction::eip2718::TypedTransaction, Address, Bytes, Eip1559TransactionRequest,
        Signature, TransactionReceipt, H160, H256, U256,
    },
};
use std::{
    fmt::{Debug, Display},
    fs::File,
    io::BufReader,
    path::PathBuf,
    str::FromStr,
    sync::Arc,
};

pub struct ZKSWallet<M, D>
where
    M: Middleware,
    D: PrehashSigner<(RecoverableSignature, RecoveryId)>,
{
    pub eth_provider: Option<Arc<SignerMiddleware<M, Wallet<D>>>>,
    pub era_provider: Option<Arc<SignerMiddleware<M, Wallet<D>>>>,
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
            era_provider: era_provider.map(|p| {
                p.with_signer(wallet.clone().with_chain_id(ERA_CHAIN_ID))
                    .into()
            }),
            eth_provider: eth_provider
                .map(|p| p.with_signer(wallet.with_chain_id(ETH_CHAIN_ID)).into()),
        })
    }

    pub fn connect_eth_provider(mut self, eth_provider: M) -> Self {
        self.eth_provider = Some(eth_provider.with_signer(self.wallet.clone()).into());
        self
    }

    pub fn connect_era_provider(mut self, era_provider: M) -> Self {
        self.era_provider = Some(era_provider.with_signer(self.wallet.clone()).into());
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

    pub fn get_eth_provider(
        &self,
    ) -> Result<Arc<SignerMiddleware<M, Wallet<D>>>, ZKSWalletError<M, D>> {
        match &self.eth_provider {
            Some(eth_provider) => Ok(eth_provider.clone()),
            None => Err(ZKSWalletError::NoL1ProviderError()),
        }
    }

    pub fn get_era_provider(
        &self,
    ) -> Result<Arc<SignerMiddleware<M, Wallet<D>>>, ZKSWalletError<M, D>> {
        match &self.era_provider {
            Some(era_provider) => Ok(era_provider.clone()),
            None => Err(ZKSWalletError::NoL2ProviderError()),
        }
    }

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
            None => Err(ZKSWalletError::CustomError("no eth provider".to_owned())),
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

    pub async fn deposit(&self, amount: U256) -> Result<TransactionReceipt, ZKSWalletError<M, D>>
    where
        M: ZKSProvider,
    {
        let to = self.address();
        let call_data = Bytes::default();
        let l2_gas_limit: U256 = RECOMMENDED_DEPOSIT_L2_GAS_LIMIT.into();
        let l2_value = amount;
        let gas_per_pubdata_byte: U256 = DEPOSIT_GAS_PER_PUBDATA_LIMIT.into();
        let gas_price = self.get_eth_provider()?.get_gas_price().await?;
        let gas_limit: U256 = RECOMMENDED_DEPOSIT_L1_GAS_LIMIT.into();
        let operator_tip: U256 = 0.into();
        let base_cost = self
            .get_base_cost(gas_limit, gas_per_pubdata_byte, gas_price)
            .await?;
        let l1_value = base_cost + operator_tip + amount;
        // let factory_deps = [];
        let refund_recipient = self.address();
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
            factory_deps.push(contract_bytecode.clone().to_vec());
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
                    (None, Some(_)) => return Err(ContractError::<M>::ConstructorError.into()),
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

    pub async fn call(
        &self,
        contract_address: Address,
        function_signature: &str,
        function_parameters: Option<Vec<String>>,
    ) -> Result<Vec<Token>, ZKSWalletError<M, D>>
    where
        M: ZKSProvider,
    {
        let era_provider = match &self.era_provider {
            Some(era_provider) => era_provider,
            None => return Err(ZKSWalletError::CustomError("no era provider".to_owned())),
        };

        // Note: We couldn't implement ZKSWalletError::LexerError because ethers-rs's LexerError is not exposed.
        let function = if contract_address == zks_utils::ECADD_PRECOMPILE_ADDRESS {
            zks_utils::ec_add_function()
        } else {
            HumanReadableParser::parse_function(function_signature)
                .map_err(|e| ZKSWalletError::CustomError(e.to_string()))?
        };
        let function_args = if let Some(function_args) = function_parameters {
            function
                .decode_input(&*zks_utils::encode_args(&function, &function_args)?)
                .map_err(|e| ZKSWalletError::CustomError(e.to_string()))?
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
                        .map_err(|e| ZKSWalletError::CustomError(e.to_string()))?,
                    // The contract to call is a precompile without arguments.
                    (false, true) => Default::default(),
                    // The contract to call is a regular contract without arguments.
                    (false, false) => function.short_signature().into(),
                },
            );

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

    pub async fn send<T>(
        &self,
        contract_address: Address,
        function_signature: &str,
        function_parameters: Option<T>,
    ) -> Result<(Vec<Token>, H256), ZKSWalletError<M, D>>
    where
        M: ZKSProvider,
        T: Tokenizable + Debug + Clone,
    {
        let era_provider = match &self.era_provider {
            Some(era_provider) => era_provider,
            None => return Err(ZKSWalletError::CustomError("no era provider".to_owned())),
        };

        // Note: We couldn't implement ZKSWalletError::LexerError because ethers-rs's LexerError is not exposed.
        let function = HumanReadableParser::parse_function(function_signature)
            .map_err(|e| ZKSWalletError::CustomError(e.to_string()))?;

        let mut send_request = Eip712TransactionRequest::new()
            .r#type(EIP712_TX_TYPE)
            .from(self.address())
            .to(contract_address)
            .chain_id(ERA_CHAIN_ID)
            .nonce(
                era_provider
                    .get_transaction_count(self.address(), None)
                    .await?,
            )
            .gas_price(era_provider.get_gas_price().await?)
            .max_fee_per_gas(era_provider.get_gas_price().await?)
            .data(match function_parameters {
                Some(parameters) => function
                    .encode_input(&parameters.into_tokens())
                    .map_err(|e| ZKSWalletError::CustomError(e.to_string()))?,
                None => function.short_signature().into(),
            });

        let fee = era_provider.estimate_fee(send_request.clone()).await?;
        send_request = send_request
            .max_priority_fee_per_gas(fee.max_priority_fee_per_gas)
            .max_fee_per_gas(fee.max_fee_per_gas)
            .gas_limit(fee.gas_limit);

        let signable_data: Eip712Transaction = send_request.clone().try_into()?;
        let signature: Signature = self.wallet.sign_typed_data(&signable_data).await?;
        send_request =
            send_request.custom_data(Eip712Meta::new().custom_signature(signature.to_vec()));

        let pending_transaction = era_provider
            .send_raw_transaction(
                [&[EIP712_TX_TYPE], &*send_request.rlp_unsigned()]
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

        // TODO: decode function output.
        Ok((Vec::new(), transaction_receipt.transaction_hash))
    }
}

#[cfg(test)]
mod zks_signer_tests {
    use crate::compile::project::ZKProject;
    use crate::test_utils::*;
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
    async fn test_deposit() {
        let private_key = "0x28a574ab2de8a00364d5dd4b07c4f2f574ef7fcc2a86a197f65abaec836d1959";
        let amount: U256 = parse_units("0.01", "ether").unwrap().into();
        println!("Amount: {}", amount);

        let l1_provider = eth_provider();
        let l2_provider = era_provider();
        let wallet = LocalWallet::from_str(private_key)
            .unwrap()
            .with_chain_id(ERA_CHAIN_ID);
        let zk_wallet =
            ZKSWallet::new(wallet, Some(l2_provider.clone()), Some(l1_provider.clone())).unwrap();

        let l1_balance_before = zk_wallet.eth_balance().await.unwrap();
        let l2_balance_before = zk_wallet.era_balance().await.unwrap();
        println!("L1 balance before: {}", l1_balance_before);
        println!("L2 balance before: {}", l2_balance_before);

        let receipt = zk_wallet.deposit(amount).await.unwrap();
        assert_eq!(receipt.status.unwrap(), 1.into());

        let l2_receipt = l2_provider
            .get_transaction_receipt(receipt.transaction_hash)
            .await
            .unwrap();

        let l1_balance_after = zk_wallet.eth_balance().await.unwrap();
        let l2_balance_after = zk_wallet.era_balance().await.unwrap();
        println!("L1 balance after: {}", l1_balance_after);
        println!("L2 balance after: {}", l2_balance_after);

        assert!(
            l1_balance_after <= l1_balance_before - amount,
            "Balance on L1 should be decreased"
        );
        assert!(
            l2_balance_after >= l2_balance_before + amount,
            "Balance on L2 should be increased"
        );
    }

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

        println!("CONTRACT ADDRESS: {contract_address:?}");
        let recovered_bytecode = era_provider.get_code(contract_address, None).await.unwrap();

        assert_eq!(compiled_bytecode, recovered_bytecode);
    }

    #[tokio::test]
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
            .call(contract_address, "str_out()(string)", None)
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
        let wallet = LocalWallet::from_str(deployer_private_key)
            .unwrap()
            .with_chain_id(ERA_CHAIN_ID);
        let zk_wallet = ZKSWallet::new(wallet, Some(era_provider.clone()), None).unwrap();

        let contract_address = zk_wallet
            .deploy::<Token>("src/compile/test_contracts/test/src/Test.sol", "Test", None)
            .await
            .unwrap();

        let no_return_type_output = zk_wallet
            .call(
                contract_address,
                "plus_one(uint256)",
                Some(vec!["1".to_owned()]),
            )
            .await
            .unwrap();

        let known_return_type_output = zk_wallet
            .call(
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

    #[tokio::test]
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
        zk_wallet
            .send(contract_address, "setValue(uint256)", Some(value_to_set))
            .await
            .unwrap();
        let set_value = zk_wallet
            .call(contract_address, "getValue()(uint256)", None)
            .await
            .unwrap();

        assert_eq!(set_value, value_to_set.into_tokens());

        zk_wallet
            .send::<Token>(contract_address, "incrementValue()", None)
            .await
            .unwrap();
        let incremented_value = zk_wallet
            .call(contract_address, "getValue()(uint256)", None)
            .await
            .unwrap();

        assert_eq!(incremented_value, (value_to_set + 1_u64).into_tokens());
    }
}
