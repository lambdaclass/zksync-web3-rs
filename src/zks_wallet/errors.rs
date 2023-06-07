use ethers::{
    prelude::{
        k256::{
            ecdsa::{RecoveryId, Signature as RecoverableSignature},
            schnorr::signature::hazmat::PrehashSigner,
        },
        signer::SignerMiddlewareError,
        AbiError, ContractError,
    },
    providers::{Middleware, ProviderError},
    signers::{Wallet, WalletError},
    types::transaction::eip712::Eip712Error,
};

#[derive(thiserror::Error, Debug)]
pub enum ZKSWalletError<M, D>
where
    M: Middleware,
    D: PrehashSigner<(RecoverableSignature, RecoveryId)> + Sync + Send,
{
    #[error("Provider error: {0}")]
    ProviderError(#[from] ProviderError),
    #[error("Middleware error: {0}")]
    MiddlewareError(#[from] SignerMiddlewareError<M, Wallet<D>>),
    #[error("Wallet error: {0}")]
    EthWalletError(#[from] WalletError),
    #[error("ABI error: {0}")]
    AbiError(#[from] AbiError),
    #[error("EIP712 error: {0}")]
    Eip712Error(#[from] Eip712Error),
    #[error("Contract error: {0}")]
    ContractError(#[from] ContractError<M>),
    #[error("{0}")]
    CustomError(String),
}
