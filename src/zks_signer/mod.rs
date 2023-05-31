use crate::{
    eip712::{
        hash_bytecode, Eip712Meta, Eip712SignInput, Eip712TransactionRequest, PaymasterParams,
    },
    zks_provider::ZKSProvider,
    zks_utils::{
        CONTRACT_DEPLOYER_ADDR, DEFAULT_GAS_PER_PUBDATA_LIMIT, EIP712_TX_TYPE, ERA_CHAIN_ID,
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
        signer::SignerMiddlewareError,
        AbiError, SignerMiddleware,
    },
    providers::{Middleware, ProviderError},
    signers::{Signer, Wallet, WalletError},
    types::{
        transaction::{eip2718::TypedTransaction, eip712::Eip712Error},
        Address, Bytes, Eip1559TransactionRequest, Signature, TransactionReceipt, U256,
    },
};

#[derive(thiserror::Error, Debug)]
pub enum ZKSSignerError<M, S>
where
    M: Middleware,
    S: Signer,
{
    #[error("Provider error: {0}")]
    ProviderError(#[from] ProviderError),
    #[error("Middleware error: {0}")]
    MiddlewareError(#[from] SignerMiddlewareError<M, S>),
    #[error("Wallet error: {0}")]
    WalletError(#[from] WalletError),
    #[error("ABI error: {0}")]
    AbiError(#[from] AbiError),
    #[error("EIP712 error: {0}")]
    Eip712Error(#[from] Eip712Error),
    #[error("{0}")]
    CustomError(String),
}

pub struct ZKSSigner<M, S, D>
where
    M: Middleware,
    S: Signer,
    D: PrehashSigner<(RecoverableSignature, RecoveryId)> + Sync + Send,
{
    pub eth_provider: Option<SignerMiddleware<M, S>>,
    pub era_provider: Option<SignerMiddleware<M, S>>,
    pub wallet: Wallet<D>,
}

impl<M, S, D> ZKSSigner<M, S, D>
where
    M: Middleware,
    S: Signer,
    D: PrehashSigner<(RecoverableSignature, RecoveryId)> + Sync + Send,
{
    // TODO: A user could use different wallets for the providers, we should not let that happen.
    pub fn new(
        wallet: Wallet<D>,
        era_provider: Option<SignerMiddleware<M, S>>,
        eth_provider: Option<SignerMiddleware<M, S>>,
    ) -> Self {
        Self {
            wallet,
            era_provider,
            eth_provider,
        }
    }

    pub fn connect_eth_provider(&mut self, eth_provider: SignerMiddleware<M, S>) {
        self.eth_provider = Some(eth_provider);
    }

    pub fn connect_era_provider(&mut self, era_provider: SignerMiddleware<M, S>) {
        self.era_provider = Some(era_provider);
    }

    // pub fn connect_eth(&mut self, host: &str, port: u16) {
    //     self.eth_provider = Provider::try_from(format!("http://{host}:{port}")).ok().map(|p| p.with_signer(self.wallet));
    // }

    // pub fn connect_era(&mut self, era_provider: SignerMiddleware<M, S>) {
    //     self.era_provider = Provider::try_from(format!("http://{host}:{port}")).ok().map(|p| p.with_signer(self.wallet));
    // }

    pub fn address(&self) -> Address {
        self.wallet.address()
    }

    pub async fn balance(&self) -> Result<U256, ZKSSignerError<M>>
    where
        M: ZKSProvider,
    {
        match &self.era_provider {
            // TODO: Should we have a balance_on_block method?
            Some(era_provider) => Ok(era_provider
                .get_balance(self.address(), None)
                .await?),
            None => Err(ZKSSignerError::CustomError("no eth provider".to_string())),
        }
    }

    pub async fn transfer(
        &self,
        to: Address,
        amount_to_transfer: U256,
        // TODO: Support multiple-token transfers.
        _token: Option<Address>,
    ) -> Result<TransactionReceipt, ZKSSignerError<M, S>>
    where
        M: ZKSProvider,
    {
        let era_provider = match &self.era_provider {
            Some(era_provider) => era_provider,
            None => return Err(ZKSSignerError::CustomError("no era provider".to_string())),
        };

        let mut transfer_request = Eip1559TransactionRequest::new()
            .from(era_provider.default_sender().ok_or_else(|| {
                return ZKSSignerError::CustomError("no default sender".to_string());
            })?)
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
            .ok_or(ZKSSignerError::CustomError(
                "no transaction receipt".to_string(),
            ))
    }

    pub async fn deploy(
        &self,
        contract_bytecode: Bytes,
        contract_dependencies: Option<Vec<Bytes>>,
    ) -> Result<TransactionReceipt, ZKSSignerError<M, S>>
    where
        M: ZKSProvider,
    {
        let era_provider = match &self.era_provider {
            Some(era_provider) => era_provider,
            None => return Err(ZKSSignerError::CustomError("no era provider".to_string())),
        };

        let mut deploy_request = Eip712TransactionRequest::default();

        deploy_request.r#type = EIP712_TX_TYPE.into();
        deploy_request.from = era_provider.default_sender();
        deploy_request.to = CONTRACT_DEPLOYER_ADDR.parse().ok();
        deploy_request.chain_id = ERA_CHAIN_ID.into();
        deploy_request.nonce = era_provider
            .get_transaction_count(deploy_request.from.unwrap(), None)
            .await
            .unwrap();
        deploy_request.gas_price = era_provider.get_gas_price().await.unwrap();

        deploy_request.data = {
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

            encode_function_data(&create, (salt, bytecode_hash, call_data)).ok()
        };

        deploy_request.custom_data = {
            let mut custom_data = Eip712Meta::default();
            custom_data.factory_deps = {
                let mut factory_deps = vec![contract_bytecode];
                if let Some(contract_dependencies) = contract_dependencies {
                    factory_deps.extend(contract_dependencies);
                }
                Some(factory_deps)
            };
            // TODO: User could provide this instead of defaulting.
            custom_data.gas_per_pubdata = DEFAULT_GAS_PER_PUBDATA_LIMIT.into();
            // TODO: User could provide this instead of defaulting.
            custom_data.paymaster_params = Some(PaymasterParams::default());
            Some(custom_data)
        };

        let fee = era_provider
            .estimate_fee(deploy_request.clone())
            .await
            .unwrap();
        deploy_request.max_priority_fee_per_gas = Some(fee.max_priority_fee_per_gas);
        deploy_request.max_fee_per_gas = Some(fee.max_fee_per_gas);
        deploy_request.gas_limit = Some(fee.gas_limit);

        /* Create Sign Input */

        let signable_data: Eip712SignInput = deploy_request.clone().into();

        if let Some(custom_data) = &mut deploy_request.custom_data {
            let signature: Signature = self.wallet.sign_typed_data(&signable_data).await?;
            custom_data.custom_signature = Some(Bytes::from(signature.to_vec()));
        }

        let pending_transaction = era_provider
            .send_raw_transaction(
                [&[EIP712_TX_TYPE], &deploy_request.rlp_unsigned()[..]]
                    .concat()
                    .into(),
            )
            .await?;

        // TODO: Should we wait here for the transaction to be confirmed on-chain?

        pending_transaction
            .await?
            .ok_or(ZKSSignerError::CustomError(
                "no transaction receipt".to_string(),
            ))
    }
}

#[cfg(test)]
mod zks_signer_tests {
    use ethers::prelude::k256::ecdsa::{RecoveryId, Signature as RecoverableSignature};
    use ethers::prelude::k256::schnorr::signature::hazmat::PrehashSigner;
    use ethers::prelude::MiddlewareBuilder;
    use ethers::prelude::SignerMiddleware;
    use ethers::providers::Middleware;
    use ethers::providers::{Http, Provider};
    use ethers::signers::Signer;
    use ethers::signers::Wallet;
    use ethers::types::Address;
    use ethers::types::Bytes;
    use ethers::types::U256;

    use crate::zks_signer::ZKSSigner;

    fn provider(host: &str, port: &str) -> Provider<Http> {
        Provider::try_from(format!("http://{host}:{port}")).unwrap()
    }

    fn eth_provider<D>(wallet: Wallet<D>) -> SignerMiddleware<Provider<Http>, Wallet<D>>
    where
        D: PrehashSigner<(RecoverableSignature, RecoveryId)> + Sync + Send,
    {
        provider("localhost", "8545").with_signer(wallet)
    }

    fn era_provider<D>(wallet: Wallet<D>) -> SignerMiddleware<Provider<Http>, Wallet<D>>
    where
        D: PrehashSigner<(RecoverableSignature, RecoveryId)> + Sync + Send,
    {
        provider("localhost", "3050").with_signer(wallet)
    }

    #[tokio::test]
    async fn test_transfer() {
        let sender_private_key =
            "0x28a574ab2de8a00364d5dd4b07c4f2f574ef7fcc2a86a197f65abaec836d1959";
        let receiver_address: Address = "0xa61464658AfeAf65CccaaFD3a512b69A83B77618"
            .parse()
            .unwrap();
        let amount_to_transfer: U256 = 1.into();

        let wallet = Wallet::with_chain_id(sender_private_key.parse().unwrap(), 270_u64);
        let era_provider = era_provider(wallet.clone());
        let zk_wallet = ZKSSigner::new(wallet.clone(), Some(era_provider.clone()), None);

        let sender_balance_before = era_provider
            .get_balance(wallet.address(), None)
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

        assert_eq!(receipt.from, wallet.address());
        assert_eq!(receipt.to.unwrap(), receiver_address);

        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        let sender_balance_after = era_provider
            .get_balance(wallet.address(), None)
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
        let deployer_wallet = Wallet::with_chain_id(deployer_private_key.parse().unwrap(), 270_u64);
        let era_provider = era_provider(deployer_wallet.clone());
        let zk_wallet = ZKSSigner::new(deployer_wallet.clone(), Some(era_provider.clone()), None);
        let contract_bytecode = Bytes::from(hex::decode("000200000000000200010000000103550000006001100270000000130010019d0000008001000039000000400010043f0000000101200190000000290000c13d0000000001000031000000040110008c000000420000413d0000000101000367000000000101043b000000e001100270000000150210009c000000310000613d000000160110009c000000420000c13d0000000001000416000000000110004c000000420000c13d000000040100008a00000000011000310000001702000041000000200310008c000000000300001900000000030240190000001701100197000000000410004c000000000200a019000000170110009c00000000010300190000000001026019000000000110004c000000420000c13d00000004010000390000000101100367000000000101043b000000000010041b0000000001000019000000490001042e0000000001000416000000000110004c000000420000c13d0000002001000039000001000010044300000120000004430000001401000041000000490001042e0000000001000416000000000110004c000000420000c13d000000040100008a00000000011000310000001702000041000000000310004c000000000300001900000000030240190000001701100197000000000410004c000000000200a019000000170110009c00000000010300190000000001026019000000000110004c000000440000613d00000000010000190000004a00010430000000000100041a000000800010043f0000001801000041000000490001042e0000004800000432000000490001042e0000004a00010430000000000000000000000000000000000000000000000000000000000000000000000000ffffffff0000000200000000000000000000000000000040000001000000000000000000000000000000000000000000000000000000000000000000000000006d4ce63c0000000000000000000000000000000000000000000000000000000060fe47b1800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000008000000000000000000000000000000000000000000000000000000000000000000000000000000000d5c7d2782d356f4a1a2e458d242d21e07a04810c9f771eed6501083e07288c87").unwrap());

        let deploy_receipt = zk_wallet.deploy(contract_bytecode, None).await.unwrap();

        assert_eq!(deploy_receipt.from, deployer_wallet.address());
        assert!(era_provider
            .get_transaction(deploy_receipt.transaction_hash)
            .await
            .is_ok());
    }
}
