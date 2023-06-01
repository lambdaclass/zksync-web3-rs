use super::ZKSWalletError;
use crate::{
    eip712::{hash_bytecode, Eip712Meta, Eip712SignInput, Eip712TransactionRequest},
    zks_provider::ZKSProvider,
    zks_utils::{
        CONTRACT_DEPLOYER_ADDR, DEFAULT_GAS_PER_PUBDATA_LIMIT, EIP712_TX_TYPE, ERA_CHAIN_ID,
        ETH_CHAIN_ID,
    },
};
use ethers::{
    abi::{Param, ParamType},
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
        transaction::eip2718::TypedTransaction, Address, Bytes, Eip1559TransactionRequest,
        Signature, TransactionReceipt, H256, U256,
    },
};
use std::str::FromStr;

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
            None => Err(ZKSWalletError::CustomError("no era provider".to_string())),
        }
    }

    pub async fn era_balance(&self) -> Result<U256, ZKSWalletError<M, D>>
    where
        M: ZKSProvider,
    {
        match &self.era_provider {
            // TODO: Should we have a balance_on_block method?
            Some(era_provider) => Ok(era_provider.get_balance(self.address(), None).await?),
            None => Err(ZKSWalletError::CustomError("no era provider".to_string())),
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
            None => return Err(ZKSWalletError::CustomError("no era provider".to_string())),
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
                "no transaction receipt".to_string(),
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
        // EIP712 Transfers
        let era_provider = match &self.era_provider {
            Some(era_provider) => era_provider,
            None => return Err(ZKSWalletError::CustomError("no era provider".to_string())),
        };

        let mut transfer_request = Eip712TransactionRequest::new()
            .r#type(EIP712_TX_TYPE)
            .from(self.address())
            .to(to)
            .value(amount_to_transfer)
            .nonce(
                era_provider
                    .get_transaction_count(self.address(), None)
                    .await?,
            )
            .chain_id(ERA_CHAIN_ID)
            .data(Bytes::default())
            .custom_data(Eip712Meta::new());

        let fee = era_provider.estimate_fee(transfer_request.clone()).await?;
        transfer_request = transfer_request
            .max_priority_fee_per_gas(fee.max_priority_fee_per_gas)
            .max_fee_per_gas(fee.max_fee_per_gas)
            .gas_limit(fee.gas_limit);

        let signable_data: Eip712SignInput = transfer_request.clone().into();
        let signature: Signature = self.wallet.sign_typed_data(&signable_data).await?;
        transfer_request =
            transfer_request.custom_data(Eip712Meta::new().custom_signature(signature.to_vec()));

        let pending_transaction = era_provider
            .send_raw_transaction(
                [&[EIP712_TX_TYPE], &transfer_request.rlp_unsigned()[..]]
                    .concat()
                    .into(),
            )
            .await?;

        // TODO: Should we wait here for the transaction to be confirmed on-chain?

        let transaction_receipt = pending_transaction
            .await?
            .ok_or(ZKSWalletError::CustomError(
                "no transaction receipt".to_string(),
            ))?;

        Ok(transaction_receipt)
    }

    pub async fn deploy(
        &self,
        contract_bytecode: Bytes,
        contract_dependencies: Option<Vec<Bytes>>,
    ) -> Result<Address, ZKSWalletError<M, D>>
    where
        M: ZKSProvider,
    {
        let era_provider = match &self.era_provider {
            Some(era_provider) => era_provider,
            None => return Err(ZKSWalletError::CustomError("no era provider".to_string())),
        };

        let custom_data = Eip712Meta::new().factory_deps({
            let mut factory_deps = vec![contract_bytecode.clone()];
            if let Some(contract_dependencies) = contract_dependencies {
                factory_deps.extend(contract_dependencies);
            }
            factory_deps
        });

        let mut deploy_request = Eip712TransactionRequest::new()
            .r#type(EIP712_TX_TYPE)
            .from(self.address())
            .to(Address::from_str(CONTRACT_DEPLOYER_ADDR).unwrap())
            .chain_id(ERA_CHAIN_ID)
            .nonce(
                era_provider
                    .get_transaction_count(self.address(), None)
                    .await?,
            )
            .gas_price(era_provider.get_gas_price().await?)
            .data({
                let create = ethers::abi::Function {
                    name: "create".to_owned(),
                    inputs: vec![
                        Param {
                            name: "_salt".to_owned(),
                            kind: ParamType::FixedBytes(32),
                            internal_type: None,
                        },
                        Param {
                            name: "_bytecodeHash".to_owned(),
                            kind: ParamType::FixedBytes(32),
                            internal_type: None,
                        },
                        Param {
                            name: "_input".to_owned(),
                            kind: ParamType::Bytes,
                            internal_type: None,
                        },
                    ],
                    outputs: vec![],
                    state_mutability: ethers::abi::StateMutability::Payable,
                    constant: None,
                };

                // TODO: User could provide this instead of defaulting.
                let salt = [0_u8; 32];
                let bytecode_hash = hash_bytecode(&contract_bytecode)?;
                // TODO: User could provide this instead of defaulting.
                let call_data = Bytes::default();

                encode_function_data(&create, (salt, bytecode_hash, call_data))?
            })
            .custom_data(custom_data.clone());

        let fee = era_provider.estimate_fee(deploy_request.clone()).await?;
        deploy_request = deploy_request
            .max_priority_fee_per_gas(fee.max_priority_fee_per_gas)
            .max_fee_per_gas(fee.max_fee_per_gas)
            .gas_limit(fee.gas_limit);

        let signable_data: Eip712SignInput = deploy_request.clone().into();
        let signature: Signature = self.wallet.sign_typed_data(&signable_data).await?;
        deploy_request =
            deploy_request.custom_data(custom_data.custom_signature(signature.to_vec()));

        let pending_transaction = era_provider
            .send_raw_transaction(
                [&[EIP712_TX_TYPE], &deploy_request.rlp_unsigned()[..]]
                    .concat()
                    .into(),
            )
            .await?;

        // TODO: Should we wait here for the transaction to be confirmed on-chain?

        let transaction_receipt = pending_transaction
            .await?
            .ok_or(ZKSWalletError::CustomError(
                "no transaction receipt".to_string(),
            ))?;

        let contract_address =
            transaction_receipt
                .contract_address
                .ok_or(ZKSWalletError::CustomError(
                    "no contract address".to_string(),
                ))?;

        Ok(contract_address)
    }

    pub async fn deploy_with_receipt(
        &self,
        contract_bytecode: Bytes,
        contract_dependencies: Option<Vec<Bytes>>,
    ) -> Result<(Address, TransactionReceipt), ZKSWalletError<M, D>>
    where
        M: ZKSProvider,
    {
        let era_provider = match &self.era_provider {
            Some(era_provider) => era_provider,
            None => return Err(ZKSWalletError::CustomError("no era provider".to_string())),
        };

        let custom_data = Eip712Meta::new().factory_deps({
            let mut factory_deps = vec![contract_bytecode.clone()];
            if let Some(contract_dependencies) = contract_dependencies {
                factory_deps.extend(contract_dependencies);
            }
            factory_deps
        });

        let mut deploy_request = Eip712TransactionRequest::new()
            .r#type(EIP712_TX_TYPE)
            .from(self.address())
            .to(Address::from_str(CONTRACT_DEPLOYER_ADDR).unwrap())
            .chain_id(ERA_CHAIN_ID)
            .nonce(
                era_provider
                    .get_transaction_count(self.address(), None)
                    .await?,
            )
            .gas_price(era_provider.get_gas_price().await?)
            .data({
                let create = ethers::abi::Function {
                    name: "create".to_owned(),
                    inputs: vec![
                        Param {
                            name: "_salt".to_owned(),
                            kind: ParamType::FixedBytes(32),
                            internal_type: None,
                        },
                        Param {
                            name: "_bytecodeHash".to_owned(),
                            kind: ParamType::FixedBytes(32),
                            internal_type: None,
                        },
                        Param {
                            name: "_input".to_owned(),
                            kind: ParamType::Bytes,
                            internal_type: None,
                        },
                    ],
                    outputs: vec![],
                    state_mutability: ethers::abi::StateMutability::Payable,
                    constant: None,
                };

                // TODO: User could provide this instead of defaulting.
                let salt = [0_u8; 32];
                let bytecode_hash = hash_bytecode(&contract_bytecode)?;
                // TODO: User could provide this instead of defaulting.
                let call_data = Bytes::default();

                encode_function_data(&create, (salt, bytecode_hash, call_data))?
            })
            .custom_data(custom_data.clone());

        let fee = era_provider.estimate_fee(deploy_request.clone()).await?;
        deploy_request = deploy_request
            .max_priority_fee_per_gas(fee.max_priority_fee_per_gas)
            .max_fee_per_gas(fee.max_fee_per_gas)
            .gas_limit(fee.gas_limit);

        let signable_data: Eip712SignInput = deploy_request.clone().into();
        let signature: Signature = self.wallet.sign_typed_data(&signable_data).await?;
        deploy_request =
            deploy_request.custom_data(custom_data.custom_signature(signature.to_vec()));

        let pending_transaction = era_provider
            .send_raw_transaction(
                [&[EIP712_TX_TYPE], &deploy_request.rlp_unsigned()[..]]
                    .concat()
                    .into(),
            )
            .await?;

        // TODO: Should we wait here for the transaction to be confirmed on-chain?

        let transaction_receipt = pending_transaction
            .await?
            .ok_or(ZKSWalletError::CustomError(
                "no transaction receipt".to_string(),
            ))?;

        let contract_address =
            transaction_receipt
                .contract_address
                .ok_or(ZKSWalletError::CustomError(
                    "no contract address".to_string(),
                ))?;

        Ok((contract_address, transaction_receipt))
    }
}

#[cfg(test)]
mod zks_signer_tests {
    use crate::zks_utils::ERA_CHAIN_ID;
    use crate::zks_wallet::ZKSWallet;
    use ethers::providers::Middleware;
    use ethers::providers::{Http, Provider};
    use ethers::signers::{LocalWallet, Signer};
    use ethers::types::Address;
    use ethers::types::Bytes;
    use ethers::types::U256;
    use std::str::FromStr;

    fn era_provider() -> Provider<Http> {
        Provider::try_from(format!("http://localhost:3050")).unwrap()
    }

    #[tokio::test]
    async fn test_transfer() {
        let sender_private_key =
            "0x28a574ab2de8a00364d5dd4b07c4f2f574ef7fcc2a86a197f65abaec836d1959";
        let receiver_address: Address = "0xa61464658AfeAf65CccaaFD3a512b69A83B77618"
            .parse()
            .unwrap();
        let amount_to_transfer: U256 = 1.into();

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

        println!("Sender balance before: {}", sender_balance_before);
        println!("Receiver balance before: {}", receiver_balance_before);

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

        println!("Sender balance after: {}", sender_balance_after);
        println!("Receiver balance after: {}", receiver_balance_after);

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
        let amount_to_transfer: U256 = 1.into();

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

        println!("Sender balance before: {}", sender_balance_before);
        println!("Receiver balance before: {}", receiver_balance_before);

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

        println!("Sender balance after: {}", sender_balance_after);
        println!("Receiver balance after: {}", receiver_balance_after);

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
    async fn test_deploy() {
        let deployer_private_key =
            "0x28a574ab2de8a00364d5dd4b07c4f2f574ef7fcc2a86a197f65abaec836d1959";
        let era_provider = era_provider();
        let wallet = LocalWallet::from_str(deployer_private_key)
            .unwrap()
            .with_chain_id(ERA_CHAIN_ID);
        let zk_wallet = ZKSWallet::new(wallet, Some(era_provider.clone()), None).unwrap();
        let contract_bytecode = Bytes::from(hex::decode("000200000000000200010000000103550000006001100270000000130010019d0000008001000039000000400010043f0000000101200190000000290000c13d0000000001000031000000040110008c000000420000413d0000000101000367000000000101043b000000e001100270000000150210009c000000310000613d000000160110009c000000420000c13d0000000001000416000000000110004c000000420000c13d000000040100008a00000000011000310000001702000041000000200310008c000000000300001900000000030240190000001701100197000000000410004c000000000200a019000000170110009c00000000010300190000000001026019000000000110004c000000420000c13d00000004010000390000000101100367000000000101043b000000000010041b0000000001000019000000490001042e0000000001000416000000000110004c000000420000c13d0000002001000039000001000010044300000120000004430000001401000041000000490001042e0000000001000416000000000110004c000000420000c13d000000040100008a00000000011000310000001702000041000000000310004c000000000300001900000000030240190000001701100197000000000410004c000000000200a019000000170110009c00000000010300190000000001026019000000000110004c000000440000613d00000000010000190000004a00010430000000000100041a000000800010043f0000001801000041000000490001042e0000004800000432000000490001042e0000004a00010430000000000000000000000000000000000000000000000000000000000000000000000000ffffffff0000000200000000000000000000000000000040000001000000000000000000000000000000000000000000000000000000000000000000000000006d4ce63c0000000000000000000000000000000000000000000000000000000060fe47b1800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000008000000000000000000000000000000000000000000000000000000000000000000000000000000000d5c7d2782d356f4a1a2e458d242d21e07a04810c9f771eed6501083e07288c87").unwrap());

        let (_contract_address, deploy_receipt) = zk_wallet
            .deploy_with_receipt(contract_bytecode, None)
            .await
            .unwrap();

        assert_eq!(deploy_receipt.from, zk_wallet.address());
        assert!(era_provider
            .get_transaction(deploy_receipt.transaction_hash)
            .await
            .is_ok());
    }
}
