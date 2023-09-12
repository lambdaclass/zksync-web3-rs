use super::ZKSWalletError;
use super::{
    requests::transfer_request::TransferRequest, DeployRequest, DepositRequest, WithdrawRequest,
};
use crate::zks_utils::{
    DEFAULT_ERC20_DEPOSIT_GAS_LIMIT, DEPOSIT_GAS_PER_PUBDATA_LIMIT, ERA_MAINNET_CHAIN_ID,
};
use crate::{
    abi,
    contracts::main_contract::{MainContract, MainContractInstance},
    eip712::Eip712Transaction,
    eip712::{hash_bytecode, Eip712Meta, Eip712TransactionRequest},
    types::TransactionReceipt,
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
        MiddlewareBuilder, SignerMiddleware,
    },
    providers::Middleware,
    signers::{Signer, Wallet},
    types::{
        transaction::eip2718::TypedTransaction, Address, Bytes, Eip1559TransactionRequest, Log,
        Signature, H160, H256, U256,
    },
};
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

/// A zkSync wallet with chain interaction abstracted.
#[derive(Clone, Debug)]
pub struct ZKSWallet<M, D>
where
    M: Middleware + Clone,
    D: PrehashSigner<(RecoverableSignature, RecoveryId)> + Clone,
{
    /// Eth provider
    pub eth_provider: Option<Arc<SignerMiddleware<M, Wallet<D>>>>,
    /// zkSync-era provider
    pub era_provider: Option<Arc<SignerMiddleware<M, Wallet<D>>>>,
    /// L2 wallet 
    pub l2_wallet: Wallet<D>,
    /// L1 wallet 
    pub l1_wallet: Wallet<D>,
}

impl<M, D> ZKSWallet<M, D>
where
    M: Middleware + 'static + Clone,
    D: PrehashSigner<(RecoverableSignature, RecoveryId)> + Sync + Send + Clone,
{
    /// Instance a new zk wallet.
    /// # Arguments
    /// * `l1_wallet`. An l1 [Wallet].
    /// * `l2_wallet`. An l2 [Wallet].
    /// * `era_provider`. An optional era provider, must implement [Middleware].
    /// * `eth_provider`. An optional ethereum provider, must implement [Middleware].
    /// # Example
    /// ```no_run
    ///  # use zksync_web3_rs::prelude::{k256::ecdsa::SigningKey, Wallet};
    ///  # use zksync_web3_rs::signers::Signer;
    ///  let provider = zksync_web3_rs::prelude::Provider::try_from("url_to_provider").unwrap();
    ///  let private_key: Wallet<SigningKey> =
    ///       "0x7726827caac94a7f9e1b160f7ea819f172f7b6f9d2a97f992c38edeab82d4110"
    ///           .parse()
    ///           .unwrap();
    ///   let zksync_era_chain_id: u64 = 270;
    ///   let wallet = Wallet::with_chain_id(private_key, zksync_era_chain_id);
    ///   let zk_wallet = zksync_web3_rs::ZKSWallet::new(wallet, None, Some(provider), None).unwrap();
    /// ```
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

    /// Connect an instance of a wallet to an Ethereum Provider.
    /// # Arguments
    /// * `eth_provider`. An ethereum provider implementing [Middleware].
    /// # Example
    /// ```no_run
    ///  # use zksync_web3_rs::prelude::{k256::ecdsa::SigningKey, Wallet};
    ///  # use zksync_web3_rs::signers::Signer;
    ///  # let private_key: Wallet<SigningKey> =
    ///  #     "0x7726827caac94a7f9e1b160f7ea819f172f7b6f9d2a97f992c38edeab82d4110"
    ///  #         .parse()
    ///  #         .unwrap();
    ///  # let zksync_era_chain_id: u64 = 270;
    ///  # let wallet = Wallet::with_chain_id(private_key, zksync_era_chain_id);
    ///  let ethereum_provider = zksync_web3_rs::prelude::Provider::try_from("http://localhost:8545").unwrap();
    ///  let zk_wallet =
    ///   zksync_web3_rs::ZKSWallet::new(wallet, None, None, None)
    ///   .unwrap()
    ///   .connect_eth_provider(ethereum_provider);
    ///  assert!(zk_wallet.eth_provider.is_some());
    /// ```
    pub fn connect_eth_provider(mut self, eth_provider: M) -> Self {
        self.eth_provider = Some(eth_provider.with_signer(self.l1_wallet.clone()).into());
        self
    }

    /// Connect an instance of a wallet to a zkSync Era provider.
    /// # Arguments.
    /// * `era_provider`. A zkSync provider implementing [Middleware].
    /// # Example 
    /// ```no_run
    ///  # use zksync_web3_rs::prelude::{k256::ecdsa::SigningKey, Wallet};
    ///  # use zksync_web3_rs::signers::Signer;
    ///  # let private_key: Wallet<SigningKey> =
    ///  #     "0x7726827caac94a7f9e1b160f7ea819f172f7b6f9d2a97f992c38edeab82d4110"
    ///  #         .parse()
    ///  #         .unwrap();
    ///  # let zksync_era_chain_id: u64 = 270;
    ///  # let wallet = Wallet::with_chain_id(private_key, zksync_era_chain_id);
    ///  let era_provider = zksync_web3_rs::prelude::Provider::try_from("http://localhost:3050").unwrap();
    ///  let zk_wallet =
    ///   zksync_web3_rs::ZKSWallet::new(wallet, None, None, None)
    ///   .unwrap()
    ///   .connect_eth_provider(era_provider);
    ///  assert!(zk_wallet.eth_provider.is_some());
    /// ```
    pub fn connect_era_provider(mut self, era_provider: M) -> Self {
        self.era_provider = Some(era_provider.with_signer(self.l2_wallet.clone()).into());
        self
    }

    /// Connect an instance of a wallet to an ethereum signer.
    pub fn connect_eth_signer(mut self, eth_signer: SignerMiddleware<M, Wallet<D>>) -> Self {
        self.eth_provider = Some(eth_signer.into());
        self
    }

    /// Connect an instance of a wallet to a zksync era signer.
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

    /// Retrieve the address of the set l2 wallet.
    pub fn l2_address(&self) -> Address {
        self.l2_wallet.address()
    }

    /// Returns the address of the set l2 wallet.
    pub fn l1_address(&self) -> Address {
        self.l1_wallet.address()
    }

    /// Retrieve the set l2 chain id.
    pub fn l2_chain_id(&self) -> u64 {
        self.l2_wallet.chain_id()
    }

    /// Returns the set l1 chain id.
    pub fn l1_chain_id(&self) -> u64 {
        self.l1_wallet.chain_id()
    }

    /// Returns the set ethereum provider.
    pub fn get_eth_provider(
        &self,
    ) -> Result<Arc<SignerMiddleware<M, Wallet<D>>>, ZKSWalletError<M, D>> {
        match &self.eth_provider {
            Some(eth_provider) => Ok(Arc::clone(eth_provider)),
            None => Err(ZKSWalletError::NoL1ProviderError()),
        }
    }

    /// Returns the set zksync era provider.
    pub fn get_era_provider(
        &self,
    ) -> Result<Arc<SignerMiddleware<M, Wallet<D>>>, ZKSWalletError<M, D>> {
        match &self.era_provider {
            Some(era_provider) => Ok(Arc::clone(era_provider)),
            None => Err(ZKSWalletError::NoL2ProviderError()),
        }
    }

    /// Returns the ethereum balance of this wallet, in wei.
    /// # Example
    /// ```no_run
    /// # async fn eth_balance_test() {
    /// # let private_key: Wallet<SigningKey> =
    /// # "0x7726827caac94a7f9e1b160f7ea819f172f7b6f9d2a97f992c38edeab82d4110"
    /// # .parse()
    /// # .unwrap();
    /// # let zksync_era_chain_id: u64 = 270;
    /// # let wallet = Wallet::with_chain_id(private_key, zksync_era_chain_id);
    /// let ethereum_provider = zksync_web3_rs::prelude::Provider::try_from("http://localhost:8545").unwrap();
    /// let zk_wallet = zksync_web3_rs::ZKSWallet::new(wallet, Some(ethereum_provider), None, None).unwrap();
    /// assert_eq!(zk_wallet.eth_balance(), Ok(1000))
    /// # }
    /// ```
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

    /// Returns the zksync era balance of this wallet.
    /// See the [`Self::eth_balance`] example.
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

    /// Create a payment transaction and send it using this wallet through the Era net.
    /// # Arguments
    /// * `request`. A [TransferRequest]
    /// # Returns
    /// The transaction's hash.
    /// # Example 
    /// ```no_run
    ///  # use zksync_web3_rs::prelude::{k256::ecdsa::SigningKey, Wallet};
    ///  # use zksync_web3_rs::signers::Signer;
    ///  # let eth_provider = zksync_web3_rs::prelude::Provider::try_from("url_to_eth_provider").unwrap();
    ///  # let zk_provider = zksync_web3_rs::prelude::Provider::try_from("url_to_zksync_provider").unwrap();
    ///  # let private_key: Wallet<SigningKey> =
    ///  #    "0x7726827caac94a7f9e1b160f7ea819f172f7b6f9d2a97f992c38edeab82d4110"
    ///  #         .parse()
    ///  #         .unwrap();
    ///  # let zksync_era_chain_id: u64 = 270;
    ///  # let wallet = Wallet::with_chain_id(private_key, zksync_era_chain_id);
    /// let zk_wallet = zksync_web3_rs::ZKSWallet::new(wallet, Some(eth_provider), Some(zk_provider), None).unwrap();
    /// /// Transfer 1000 wei to myself.
    /// let req = TransferRequest {
    ///    amount: U256::from(1000_u64),
    ///    to: zk_wallet.l2_address(),
    ///    from: zk_wallet.l2_address(),
    /// };
    /// let tx_hash = zk_wallet.transfer(&req, None).await.unwrap();
    /// assert!(tx_hash.is_ok());
    ///```
    pub async fn transfer(
        &self,
        request: &TransferRequest,
        // TODO: Support multiple-token transfers.
        _token: Option<Address>,
    ) -> Result<H256, ZKSWalletError<M, D>>
    where
        M: ZKSProvider,
    {
        let era_provider = self.get_era_provider()?;

        let mut transfer_request: Eip1559TransactionRequest = request.clone().into();

        let fee = era_provider.estimate_fee(transfer_request.clone()).await?;
        transfer_request = transfer_request.max_priority_fee_per_gas(fee.max_priority_fee_per_gas);
        transfer_request = transfer_request.max_fee_per_gas(fee.max_fee_per_gas);

        let transaction: TypedTransaction = transfer_request.into();

        // TODO: add block as an override.
        let transaction_receipt = era_provider
            .send_transaction(transaction, None)
            .await?
            .await?
            .ok_or(ZKSWalletError::CustomError(
                "No transaction receipt".to_owned(),
            ))?;

        Ok(transaction_receipt.transaction_hash)
    }


    /// Create a payment transaction and send it using this wallet.
    /// # Arguments
    /// * `request`. A [TransferRequest]
    /// # Returns
    /// The transaction's hash.
    /// See [Self::transfer]
    pub async fn transfer_eip712(
        &self,
        request: &TransferRequest,
        // TODO: Support multiple-token transfers.
        _token: Option<Address>,
    ) -> Result<H256, ZKSWalletError<M, D>>
    where
        M: ZKSProvider,
    {
        let era_provider = self.get_era_provider()?;

        let transaction_receipt = era_provider
            .send_transaction_eip712(&self.l2_wallet, request.clone())
            .await?
            .await?
            .ok_or(ZKSWalletError::CustomError(
                "No transaction receipt".to_owned(),
            ))?;

        Ok(transaction_receipt.transaction_hash)
    }

    /// L1 -> L2
    /// Deposit from Ethereum Network to the zkSync era network.
    /// # Arguments:
    /// *`request`. A [DepositRequest]
    /// # Returns
    /// The transaction hash.
    /// # Example
    /// ```no_run
    /// # use zksync_web3_rs::prelude::{k256::ecdsa::SigningKey, Wallet};
    /// # use zksync_web3_rs::types::Address;
    /// # use zksync_web3_rs::zks_wallet::DepositRequest;
    /// # async fn deposit_doc_test() -> () {
    /// # let ethereum_provider =
    /// # zksync_web3_rs::prelude::Provider::try_from("http://localhost:8545").unwrap();
    /// # 
    /// #   let private_key: Wallet<SigningKey> =
    /// #       "0x7726827caac94a7f9e1b160f7ea819f172f7b6f9d2a97f992c38edeab82d4110"
    /// #           .parse()
    /// #          .unwrap();
    /// #  let zksync_era_chain_id: u64 = 270;
    /// #  let wallet = Wallet::with_chain_id(private_key, zksync_era_chain_id);
    /// #  let zk_wallet = zksync_web3_rs::ZKSWallet::new(wallet, None, None, None).unwrap();
    /// # let zk_provider = zksync_web3_rs::prelude::Provider::try_from("http://localhost:3050").unwrap();
    /// # let zk_wallet = zk_wallet
    /// #   .connect_eth_provider(ethereum_provider)
    /// #    .connect_era_provider(zk_provider);
    /// use zksync_web3_rs::signers::Signer;
    /// let to: Address = "0xa61464658AfeAf65CccaaFD3a512b69A83B77618"
    ///     .parse()
    ///     .unwrap();
    /// let amount = zksync_web3_rs::utils::parse_units("0.01", "ether").unwrap().into();
    /// let request = DepositRequest::new(amount).to(to);
    /// let l1_balance_before = dbg!(zk_wallet.eth_balance().await.unwrap());
    /// zk_wallet.deposit(&request).await.unwrap();
    /// let l1_new_balance = dbg!(zk_wallet.eth_balance().await.unwrap());
    /// assert!(l1_balance_before > l1_new_balance);
    /// # }
    /// ```
    pub async fn deposit(&self, request: &DepositRequest) -> Result<H256, ZKSWalletError<M, D>>
    where
        M: ZKSProvider,
    {
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

        let receipt = if request.token == ETHER_L1_ADDRESS {
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
                request.token,
                request.amount().to_owned(),
                to,
                operator_tip,
                request.bridge_address,
                None,
                Some(gas_price),
            )
            .await?
        };

        Ok(receipt.transaction_hash)
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
            let is_mainnet =
                self.get_era_provider()?.get_chainid().await? == ERA_MAINNET_CHAIN_ID.into();
            if is_mainnet {
                (*ERC20_DEPOSIT_GAS_LIMITS)
                    .get(&address_str)
                    .unwrap_or(&DEFAULT_ERC20_DEPOSIT_GAS_LIMIT)
                    .to_owned()
            } else {
                DEFAULT_ERC20_DEPOSIT_GAS_LIMIT
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

        let bridge_address: Address = match bridge_address {
            Some(address) => address,
            None => {
                let bridge_contracts = era_provider.get_bridge_contracts().await?;
                bridge_contracts.l1_erc20_default_bridge
            }
        };

        let deposit_transaction = Eip1559TransactionRequest {
            from: Some(self.get_eth_provider()?.address()),
            to: Some(bridge_address.into()),
            gas: Some(gas_limit),
            value: Some(value),
            data: Some(data),
            nonce: None,
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

        response.await?.ok_or(ZKSWalletError::CustomError(
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
        // TODO: accept constructor parameters.
        _constructor_parameters: Option<T>,
    ) -> Result<H160, ZKSWalletError<M, D>>
    where
        M: ZKSProvider,
        T: Tokenizable,
    {
        let era_provider = self.get_era_provider()?;

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

        let encoded_rlp = &*deploy_request.rlp_signed(signature)?;
        let pending_transaction = era_provider
            .send_raw_transaction([&[EIP712_TX_TYPE], encoded_rlp].concat().into())
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

    pub async fn deploy(&self, request: &DeployRequest) -> Result<H160, ZKSWalletError<M, D>>
    where
        M: ZKSProvider,
    {
        let era_provider = self.get_era_provider()?;

        let eip712_request: Eip712TransactionRequest = request.clone().try_into()?;

        let transaction_receipt = era_provider
            .send_transaction_eip712(&self.l2_wallet, eip712_request)
            .await?
            .await?
            .ok_or(ZKSWalletError::CustomError(
                "No transaction receipt".to_owned(),
            ))?;

        transaction_receipt
            .contract_address
            .ok_or(ZKSWalletError::CustomError(
                "No contract address".to_owned(),
            ))
    }

    // L2 -> L1
    pub async fn withdraw(&self, request: &WithdrawRequest) -> Result<H256, ZKSWalletError<M, D>>
    where
        M: ZKSProvider,
    {
        let era_provider = self.get_era_provider()?;
        let transaction_receipt = era_provider
            .send_transaction_eip712(&self.l2_wallet, request.clone())
            .await?
            .await?
            .ok_or(ZKSWalletError::CustomError(
                "No transaction receipt".to_owned(),
            ))?;

        Ok(transaction_receipt.transaction_hash)
    }

    pub async fn finalize_withdraw(&self, tx_hash: H256) -> Result<H256, ZKSWalletError<M, D>>
    where
        M: ZKSProvider,
    {
        let era_provider = self.get_era_provider()?;
        let eth_provider = self.get_eth_provider()?;

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
        let transaction_receipt = eth_provider
            .send(
                &self.l1_wallet,
                main_contract,
                function_signature,
                Some(parameters.into()),
                None,
            )
            .await?
            .await?
            .ok_or(ZKSWalletError::CustomError(
                "No transaction receipt".to_owned(),
            ))?;

        Ok(transaction_receipt.transaction_hash)
    }
}
