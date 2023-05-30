use crate::{
    eip712::{
        hash_bytecode, Eip712Meta, Eip712SignInput, Eip712TransactionRequest, PaymasterParams,
    },
    zks_provider::ZKSProvider,
    zks_utils::{
        CONTRACT_DEPLOYER_ADDR, DEFAULT_GAS_PER_PUBDATA_LIMIT, EIP712_TX_TYPE, ERA_CHAIN_ID,
    },
};
use async_trait::async_trait;
use ethers::{
    abi::{Param, ParamType, Tokenizable},
    prelude::{encode_function_data, signer::SignerMiddlewareError, AbiError, SignerMiddleware},
    providers::{Middleware, ProviderError},
    signers::{Signer, WalletError},
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

#[async_trait]
pub trait ZKSSigner<M, S>
where
    M: Middleware,
    S: Signer,
{
    async fn transfer(
        &self,
        to: Address,
        amount_to_transfer: U256,
        // TODO: Support multiple-token transfers.
        _token: Option<Address>,
    ) -> Result<TransactionReceipt, ZKSSignerError<M, S>>
    where
        Self: Middleware + ZKSProvider + Sized,
        ZKSSignerError<M, S>: From<<Self as Middleware>::Error>,
    {
        let mut transfer_request = Eip1559TransactionRequest::new()
            .from(self.default_sender().ok_or_else(|| {
                return ZKSSignerError::CustomError("no default sender".to_string());
            })?)
            .to(to)
            .value(amount_to_transfer)
            .chain_id(270);

        let fee = self.estimate_fee(transfer_request.clone()).await?;
        transfer_request = transfer_request.max_priority_fee_per_gas(fee.max_priority_fee_per_gas);
        transfer_request = transfer_request.max_fee_per_gas(fee.max_fee_per_gas);

        let transaction: TypedTransaction = transfer_request.into();

        // TODO: add block as an override.
        let pending_transaction = self.send_transaction(transaction, None).await?;

        // TODO: Should we wait here for the transaction to be confirmed on-chain?

        pending_transaction
            .await?
            .ok_or(ZKSSignerError::CustomError(
                "no transaction receipt".to_string(),
            ))
    }

    async fn deploy(
        &self,
        contract_bytecode: Bytes,
        contract_dependencies: Vec<Bytes>,
    ) -> Result<TransactionReceipt, ZKSSignerError<M, S>>
    where
        Self: Middleware + Signer + ZKSProvider + Sized,
        ZKSSignerError<M, S>: From<<Self as Signer>::Error> + From<<Self as Middleware>::Error>,
    {
        let mut deploy_request = Eip712TransactionRequest::default();

        deploy_request.r#type = EIP712_TX_TYPE.into();
        deploy_request.from = Some(self.default_sender().ok_or_else(|| {
            return ZKSSignerError::CustomError("no default sender".to_string());
        })?);
        deploy_request.to = CONTRACT_DEPLOYER_ADDR.parse().ok();
        deploy_request.chain_id = ERA_CHAIN_ID.into();
        deploy_request.nonce = self
            .get_transaction_count(deploy_request.from.unwrap(), None)
            .await
            .unwrap();
        deploy_request.gas_price = self.get_gas_price().await.unwrap();

        deploy_request.data = {
            let create = ethers::abi::Function {
                name: "create".to_owned(),
                inputs: vec![
                    Param {
                        name: "salt".to_owned(),
                        kind: ParamType::FixedBytes(32),
                        internal_type: None,
                    },
                    Param {
                        name: "bytecode".to_owned(),
                        kind: ParamType::Bytes,
                        internal_type: None,
                    },
                    Param {
                        name: "call_data".to_owned(),
                        kind: ParamType::Bytes,
                        internal_type: None,
                    },
                ],
                outputs: vec![],
                state_mutability: ethers::abi::StateMutability::View,
                constant: None,
            };

            // TODO: User could provide this instead of defaulting.
            let salt = [0_u8; 32].into_token();
            let bytecode_hash = hash_bytecode(&contract_bytecode)?.into_token();
            // TODO: User could provide this instead of defaulting.
            let call_data = Bytes::default().into_token();

            encode_function_data(&create, [salt, bytecode_hash, call_data]).ok()
        };

        deploy_request.custom_data = {
            let mut custom_data = Eip712Meta::default();
            custom_data.factory_deps = {
                let mut factory_deps = vec![contract_bytecode];
                factory_deps.extend(contract_dependencies);
                Some(factory_deps)
            };
            // TODO: User could provide this instead of defaulting.
            custom_data.gas_per_pubdata = DEFAULT_GAS_PER_PUBDATA_LIMIT.into();
            // TODO: User could provide this instead of defaulting.
            custom_data.paymaster_params = Some(PaymasterParams::default());
            Some(custom_data)
        };

        let fee = self.estimate_fee(deploy_request.clone()).await.unwrap();
        deploy_request.max_priority_fee_per_gas = Some(fee.max_priority_fee_per_gas);
        deploy_request.max_fee_per_gas = Some(fee.max_fee_per_gas);
        deploy_request.gas_limit = Some(fee.gas_limit);

        /* Create Sign Input */

        let signable_data: Eip712SignInput = deploy_request.clone().into();

        if let Some(custom_data) = &mut deploy_request.custom_data {
            let signature: Signature = self.sign_typed_data(&signable_data).await?;
            custom_data.custom_signature = Some(Bytes::from(signature.to_vec()));
        }

        let pending_transaction = self
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

#[async_trait]
impl<M, S> ZKSSigner<M, S> for SignerMiddleware<M, S>
where
    M: Middleware,
    S: Signer,
{
}

#[cfg(test)]
mod tests {
    use crate::zks_signer::ZKSSigner;
    use ethers::prelude::MiddlewareBuilder;
    use ethers::providers::Middleware;
    use ethers::providers::Provider;
    use ethers::signers::Signer;
    use ethers::signers::Wallet;
    use ethers::types::Address;
    use ethers::types::U256;

    #[tokio::test]
    async fn test_transfer() {
        let sender_private_key =
            "0x28a574ab2de8a00364d5dd4b07c4f2f574ef7fcc2a86a197f65abaec836d1959";
        let receiver_address: Address = "0xa61464658AfeAf65CccaaFD3a512b69A83B77618"
            .parse()
            .unwrap();
        let amount_to_transfer: U256 = 1.into();
        let wallet = Wallet::with_chain_id(sender_private_key.parse().unwrap(), 270_u64);
        let signer = Provider::try_from(format!(
            "http://{host}:{port}",
            host = "65.108.204.116",
            port = 3050
        ))
        .unwrap()
        .with_signer(wallet.clone());

        let sender_balance_before = signer.get_balance(wallet.address(), None).await.unwrap();
        let receiver_balance_before = signer.get_balance(receiver_address, None).await.unwrap();

        println!("Sender balance before: {}", sender_balance_before);
        println!("Receiver balance before: {}", receiver_balance_before);

        let receipt = signer
            .transfer(receiver_address, amount_to_transfer, None)
            .await
            .unwrap();

        assert_eq!(receipt.from, wallet.address());
        assert_eq!(receipt.to.unwrap(), receiver_address);

        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        let sender_balance_after = signer.get_balance(wallet.address(), None).await.unwrap();
        let receiver_balance_after = signer.get_balance(receiver_address, None).await.unwrap();

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
}
