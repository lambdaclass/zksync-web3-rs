pub mod deposit_request;

use self::deposit_request::DepositRequest;

use super::{Overrides, ZKSWalletError};
use crate::zks_utils::DEPOSIT_GAS_PER_PUBDATA_LIMIT;
use crate::{
    abi,
    contracts::main_contract::{MainContract, MainContractInstance},
    eip712::Eip712Transaction,
    eip712::{hash_bytecode, Eip712Meta, Eip712TransactionRequest},
    zks_provider::ZKSProvider,
    zks_utils::{self, CONTRACT_DEPLOYER_ADDR, EIP712_TX_TYPE, ETHER_L1_ADDRESS, ETH_CHAIN_ID},
};
use ethers::{
    abi::{decode, Abi, ParamType, Tokenizable},
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
use ethers_contract::providers::PendingTransaction;
use lazy_static::lazy_static;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::{fs::File, io::BufReader, path::PathBuf, str::FromStr, sync::Arc};
use zksync_web3_rs::core::abi::Tokenize;

const RAW_ERC20_DEPOSIT_GAS_LIMIT: &str = include_str!("DepositERC20GasLimit.json");

lazy_static! {
    static ref ERC20_DEPOSIT_GAS_LIMITS: HashMap<String, u64> = {
        #![allow(clippy::expect_used)]
        let mut m = HashMap::new();
        let raw: Map<String, Value> = serde_json::from_str(RAW_ERC20_DEPOSIT_GAS_LIMIT)
            .expect("Failed to parse DepositERC20GasLimit.json");
        for (address, value) in raw.iter() {
            m.insert(
                address.to_owned(),
                value
                    .as_u64()
                    .expect("Failed to ERC20 deposit gas limit for address {address:?}"),
            );
        }
        m
    };
}

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
    ) -> Result<PendingTransaction<<M as Middleware>::Provider>, ZKSWalletError<M, D>>
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
        Ok(pending_transaction)
    }

    pub async fn transfer_eip712(
        &self,
        to: Address,
        amount_to_transfer: U256,
        // TODO: Support multiple-token transfers.
        _token: Option<Address>,
    ) -> Result<PendingTransaction<<M as Middleware>::Provider>, ZKSWalletError<M, D>>
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

        Ok(pending_transaction)
    }

    pub async fn deposit(
        &self,
        request: &DepositRequest,
    ) -> Result<TransactionReceipt, ZKSWalletError<M, D>>
    where
        M: ZKSProvider,
    {
        println!("IN DEPOSIT");
        let to = request.to.unwrap_or(self.l2_address());
        let call_data = Bytes::default();
        let l2_gas_limit: U256 = request.l2_gas_limit;
        let l2_value = request.amount;
        let gas_per_pubdata_byte: U256 = request.gas_per_pubdata_byte;
        let gas_price = request
            .gas_price
            .unwrap_or(self.get_eth_provider()?.get_gas_price().await?);
        let gas_limit: U256 = request.gas_limit;
        let operator_tip: U256 = request.operator_tip;
        let base_cost = self
            .get_base_cost(gas_limit, gas_per_pubdata_byte, gas_price)
            .await?;
        let l1_value = base_cost + operator_tip + request.amount;
        // let factory_deps = [];
        let refund_recipient = self.l1_address();
        // FIXME check base cost

        // FIXME Set this default on the DepositRequest builder struct.
        let l1_token = request.token.unwrap_or(ETHER_L1_ADDRESS);

        println!("request.bridge_address: {:?}", request.bridge_address);
        let receipt = if l1_token == ETHER_L1_ADDRESS {
            let main_contract_address = self.get_era_provider()?.get_main_contract().await?;
            let main_contract =
                MainContractInstance::new(main_contract_address, self.get_eth_provider()?);

            main_contract
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
                .await?
        } else {
            self.deposit_erc20_token(
                l1_token,
                request.amount().to_owned(),
                to,
                operator_tip,
                request.bridge_address,
                None,
                Some(gas_price),
            )
            .await?
        };

        Ok(receipt)
    }

    async fn deposit_erc20_token(
        &self,
        l1_token_address: Address,
        amount: U256,
        to: Address,
        operator_tip: U256,
        bridge_address: Option<Address>,
        max_fee_per_gas: Option<U256>,
        gas_price: Option<U256>,
    ) -> Result<TransactionReceipt, ZKSWalletError<M, D>>
    where
        M: ZKSProvider,
    {
        let eth_provider = self.get_eth_provider()?;
        let era_provider = self.get_era_provider()?;

        let gas_limit: U256 = {
            let address_str = format!("{l1_token_address:?}");
            let default_erc20_deposit_gas_limit = 300000_u64; // FIXME make it a constant.
            let is_mainnet = self.get_era_provider()?.get_chainid().await? == 324_i32.into();
            if is_mainnet {
                (*ERC20_DEPOSIT_GAS_LIMITS)
                    .get(&address_str)
                    .unwrap_or(&default_erc20_deposit_gas_limit)
                    .to_owned() // FIXME fix unwrap
            } else {
                default_erc20_deposit_gas_limit
            }
        }
        .into();

        // If the user has already provided max_fee_per_gas or gas_price, we will use
        // it to calculate the base cost for the transaction
        let gas_price = if let Some(max_fee_per_gas) = max_fee_per_gas {
            max_fee_per_gas
        } else if let Some(gas_price) = gas_price {
            gas_price
        } else {
            era_provider.get_gas_price().await?
        };

        let l2_gas_limit = U256::from(3_000_000_u32);

        let base_cost: U256 = self
            .get_base_cost(
                l2_gas_limit,
                DEPOSIT_GAS_PER_PUBDATA_LIMIT.into(),
                gas_price,
            )
            .await?;

        // ERC20 token, `msg.value` is used only for the fee.
        let value = base_cost + operator_tip;

        let data: Bytes = {
            let bridge_contract = abi::l1_bridge_contract();

            #[allow(clippy::expect_used)]
            let contract_function = bridge_contract
                .function("deposit")
                .expect("failed to get deposit function parameters");

            let params = (
                to,
                l1_token_address,
                amount,
                l2_gas_limit,
                U256::from(DEPOSIT_GAS_PER_PUBDATA_LIMIT),
            );

            #[allow(clippy::expect_used)]
            contract_function
                .encode_input(&params.into_tokens())
                .expect("failed to encode deposit function parameters")
                .into()
        };

        let chain_id = eth_provider.get_chainid().await?.as_u64();

        println!("bridge_address: {bridge_address:?}");
        let bridge_address: Address = match bridge_address {
            Some(address) => address,
            None => {
                let bridge_contracts = era_provider.get_bridge_contracts().await?;
                bridge_contracts.l1_erc20_default_bridge
            }
        };
        println!("bridge_address: {bridge_address:?}");

        // FIXME where do I set the nonce?
        let deposit_transaction = Eip1559TransactionRequest {
            from: Some(self.get_eth_provider()?.address()),
            to: Some(bridge_address.into()),
            gas: Some(gas_limit),
            value: Some(value),
            data: Some(data),
            nonce: None, // FIXME
            access_list: Default::default(),
            max_priority_fee_per_gas: None, // FIXME
            max_fee_per_gas: None,          // FIXME
            chain_id: Some(chain_id.into()),
        };

        let _approve_tx_receipt = self
            .approve_erc20(bridge_address, amount, l1_token_address)
            .await?;
        let pending_transaction = eth_provider
            .send_transaction(deposit_transaction, None)
            .await?;

        pending_transaction
            .await?
            .ok_or(ZKSWalletError::CustomError(
                "no transaction receipt".to_owned(),
            ))
    }

    async fn approve_erc20(
        &self,
        bridge: Address,
        amount: U256,
        token: Address,
    ) -> Result<TransactionReceipt, ZKSWalletError<M, D>>
    where
        M: ZKSProvider,
    {
        let provider = self.get_eth_provider()?;
        let function_signature =
            "function approve(address spender,uint256 amount) public virtual returns (bool)";
        let parameters = [format!("{bridge:?}"), format!("{amount:?}")];
        let response = provider
            .send(
                &self.l1_wallet,
                token,
                function_signature,
                Some(parameters.into()),
                None,
            )
            .await?;

        response
            .confirmations(1)
            .await?
            .ok_or(ZKSWalletError::CustomError(
                "No transaction receipt for erc20 approval".to_owned(),
            ))
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
        constructor_parameters: Vec<String>,
        factory_dependencies: Option<Vec<Vec<u8>>>,
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
            if let Some(factory_dependencies) = factory_dependencies {
                factory_deps.extend(factory_dependencies);
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
                let call_data: Bytes = match (
                    contract_abi.constructor(),
                    constructor_parameters.is_empty(),
                ) {
                    (None, false) => return Err(ContractError::<M>::ConstructorError.into()),
                    (None, true) | (Some(_), true) => Bytes::default(),
                    (Some(constructor), false) => {
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
    ) -> Result<PendingTransaction<<M as ZKSProvider>::ZKProvider>, ZKSWalletError<M, D>>
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
        let response = era_provider
            .send_eip712(
                &self.l2_wallet,
                contract_address,
                function_signature,
                Some([format!("{to:?}")].into()),
                Some(Overrides {
                    value: Some(amount),
                }),
            )
            .await;

        response.map_err(|e| ZKSWalletError::CustomError(format!("Error calling withdraw: {e}")))
    }

    pub async fn finalize_withdraw(
        &self,
        tx_hash: H256,
    ) -> Result<PendingTransaction<<M as Middleware>::Provider>, ZKSWalletError<M, D>>
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
            .await;
        response.map_err(|e| {
            ZKSWalletError::CustomError(format!("Error calling finalizeWithdrawal: {e}"))
        })
    }
}

#[cfg(test)]
mod zks_signer_tests {
    use crate::test_utils::*;
    use crate::zks_provider::ZKSProvider;
    use crate::zks_utils::{ERA_CHAIN_ID, ETH_CHAIN_ID};
    use crate::zks_wallet::wallet::deposit_request::DepositRequest;
    use crate::zks_wallet::ZKSWallet;
    use ethers::abi::Tokenize;
    use ethers::contract::abigen;
    use ethers::providers::Middleware;
    use ethers::signers::{LocalWallet, Signer};
    use ethers::types::Address;
    use ethers::types::U256;
    use ethers::utils::parse_units;
    use std::fs::File;
    use std::path::PathBuf;
    use std::str::FromStr;
    use std::sync::Arc;

    // abigen!(ERC20Token, "resources/testing/erc20/MyToken.json");
    abigen!(
        ERC20Token,
        r#"[
            balanceOf(address)(uint256)
        ]"#
    );

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
            .unwrap()
            .await
            .unwrap()
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
        let request = DepositRequest::new(parse_units("0.01", "ether").unwrap().into());
        println!("Amount: {}", request.amount);

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

        let receipt = zk_wallet.deposit(&request).await.unwrap();
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
            l1_balance_after <= l1_balance_before - request.amount(),
            "Balance on L1 should be decreased"
        );
        assert!(
            l2_balance_after >= l2_balance_before + request.amount(),
            "Balance on L2 should be increased"
        );
    }

    #[tokio::test]
    async fn test_deposit_to_another_address() {
        let private_key = "0x28a574ab2de8a00364d5dd4b07c4f2f574ef7fcc2a86a197f65abaec836d1959";
        let to: Address = "0xa61464658AfeAf65CccaaFD3a512b69A83B77618"
            .parse()
            .unwrap();
        let amount = parse_units("0.01", "ether").unwrap().into();
        println!("Amount: {amount}");

        let request = DepositRequest::new(amount).to(to);

        let l1_provider = eth_provider();
        let l2_provider = era_provider();
        let wallet = LocalWallet::from_str(private_key).unwrap();
        let zk_wallet = ZKSWallet::new(
            wallet,
            None,
            Some(l2_provider.clone()),
            Some(l1_provider.clone()),
        )
        .unwrap();

        let l1_balance_before = zk_wallet.eth_balance().await.unwrap();
        let l2_balance_before = era_provider().get_balance(to, None).await.unwrap();
        println!("L1 balance before: {l1_balance_before}");
        println!("L2 balance before: {l2_balance_before}");

        let receipt = zk_wallet.deposit(&request).await.unwrap();
        assert_eq!(receipt.status.unwrap(), 1_u8.into());

        let _l2_receipt = l2_provider
            .get_transaction_receipt(receipt.transaction_hash)
            .await
            .unwrap();

        let l1_balance_after = zk_wallet.eth_balance().await.unwrap();
        let l2_balance_after = era_provider().get_balance(to, None).await.unwrap();
        println!("L1 balance after: {l1_balance_after}");
        println!("L2 balance after: {l2_balance_after}");

        assert!(
            l1_balance_after <= l1_balance_before - request.amount(),
            "Balance on L1 should be decreased"
        );
        assert!(
            l2_balance_after >= l2_balance_before + request.amount(),
            "Balance on L2 should be increased"
        );
    }

    // #[ignore]
    #[tokio::test]
    async fn test_deposit_erc20_token() {
        let amount: U256 = 1_i32.into();
        let private_key = "0x7726827caac94a7f9e1b160f7ea819f172f7b6f9d2a97f992c38edeab82d4110";
        let l1_provider = eth_provider();
        let l2_provider = era_provider();
        let wallet = LocalWallet::from_str(private_key).unwrap();
        let zk_wallet = ZKSWallet::new(
            wallet,
            None,
            Some(l2_provider.clone()),
            Some(l1_provider.clone()),
        )
        .unwrap();

        // Deploys an ERC20 token to conduct the test.
        let token_l1_address: Address = "0x5C9b194733b9D6A93c51B3F313A2029873426740"
            .parse()
            .unwrap();

        let contract_l1 = ERC20Token::new(token_l1_address, Arc::new(l1_provider.clone()));

        let balance_erc20_l1_before: U256 = contract_l1
            .balance_of(zk_wallet.l1_address())
            .call()
            .await
            .unwrap();

        let request = DepositRequest::new(amount).token(Some(token_l1_address));

        let l1_receipt = zk_wallet.deposit(&request).await.unwrap();
        assert_eq!(l1_receipt.status.unwrap(), 1_i32.into());

        let balance_erc20_l1_after: U256 = contract_l1
            .balance_of(zk_wallet.l1_address())
            .call()
            .await
            .unwrap();

        assert_eq!(balance_erc20_l1_after, balance_erc20_l1_before - amount);
        // FIXME check balance on l2.
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
            .unwrap()
            .await
            .unwrap()
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
                vec!["10".to_owned()],
                None,
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
        let wallet = LocalWallet::from_str(deployer_private_key)
            .unwrap()
            .with_chain_id(ERA_CHAIN_ID);
        let zk_wallet = ZKSWallet::new(wallet, None, Some(era_provider.clone()), None).unwrap();

        let mut contract_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        contract_path.push("src/abi/test_contracts/greeter_combined.json");
        let contract: CompiledContract =
            serde_json::from_reader(File::open(contract_path).unwrap()).unwrap();

        let transaction_receipt = zk_wallet
            .deploy(
                contract.abi,
                contract.bin.to_vec(),
                vec!["Hey".to_owned()],
                None,
            )
            .await
            .unwrap();

        let contract_address = transaction_receipt.contract_address.unwrap();
        let deploy_result = era_provider.get_code(contract_address, None).await;

        assert!(deploy_result.is_ok());
    }

    #[tokio::test]
    async fn test_deploy_contract_with_import() {
        let deployer_private_key =
            "7726827caac94a7f9e1b160f7ea819f172f7b6f9d2a97f992c38edeab82d4110";
        let era_provider = era_provider();
        let wallet = LocalWallet::from_str(deployer_private_key)
            .unwrap()
            .with_chain_id(ERA_CHAIN_ID);
        let zk_wallet = ZKSWallet::new(wallet, None, Some(era_provider.clone()), None).unwrap();

        // Deploy imported contract first.
        let mut contract_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        contract_path.push("src/abi/test_contracts/counter_combined.json");
        let counter_contract: CompiledContract =
            serde_json::from_reader(File::open(contract_path).unwrap()).unwrap();

        let transaction_receipt = zk_wallet
            .deploy(
                counter_contract.abi,
                counter_contract.bin.to_vec(),
                vec![],
                None,
            )
            .await
            .unwrap();

        let counter_contract_address = transaction_receipt.contract_address.unwrap();
        let deploy_result = era_provider.get_code(counter_contract_address, None).await;

        assert!(deploy_result.is_ok());

        // Deploy another contract that imports the previous one.
        let mut contract_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        contract_path.push("src/abi/test_contracts/import_combined.json");

        let import_contract: CompiledContract =
            serde_json::from_reader(File::open(contract_path).unwrap()).unwrap();

        let transaction_receipt = zk_wallet
            .deploy(
                import_contract.abi,
                import_contract.bin.to_vec(),
                vec![format!("{counter_contract_address:?}")],
                None,
            )
            .await
            .unwrap();

        let import_contract_address = transaction_receipt.contract_address.unwrap();
        let value = ZKSProvider::call(
            &era_provider,
            import_contract_address,
            "getCounterValue()(uint256)",
            None,
        )
        .await
        .unwrap();

        assert_eq!(value, U256::from(0_u64).into_tokens());
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
            .unwrap()
            .await
            .unwrap()
            .unwrap();
        let tx_receipt = zk_wallet
            .get_era_provider()
            .unwrap()
            .wait_for_finalize(tx_receipt.clone(), None, None)
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
            .unwrap()
            .await
            .unwrap()
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
            .unwrap()
            .await
            .unwrap()
            .unwrap();
        let tx_receipt = zk_wallet
            .get_era_provider()
            .unwrap()
            .wait_for_finalize(tx_receipt, None, None)
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
            .unwrap()
            .await
            .unwrap()
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
