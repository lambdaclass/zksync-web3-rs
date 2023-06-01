use crate::zks_provider::ZKSProvider;
use async_trait::async_trait;
use ethers::{
    prelude::{signer::SignerMiddlewareError, SignerMiddleware},
    providers::{Middleware, ProviderError},
    signers::Signer,
    types::{
        transaction::eip2718::TypedTransaction, Address, Eip1559TransactionRequest,
        TransactionReceipt, U256,
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
