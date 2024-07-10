use ethers::{
    abi::{Address, Hash},
    providers::{Middleware, MiddlewareError},
    signers::Signer,
    types::U256,
};

use crate::ZKMiddleware;

#[async_trait::async_trait]
pub trait ZKWallet {
    type L1Error: MiddlewareError<
        Inner = <<Self::L1Signer as Middleware>::Inner as Middleware>::Error,
    >;
    type L2Error: MiddlewareError<
        Inner = <<Self::L2Signer as ZKMiddleware>::Inner as ZKMiddleware>::Error,
    >;
    type L1Signer: Middleware + Signer;
    type L2Signer: ZKMiddleware + Signer;

    async fn deposit(&self, amount: U256) -> Result<Hash, Self::L1Error>;

    async fn finalize_deposit(&self) -> Result<Hash, Self::L2Error>;

    async fn withdraw(&self, amount: U256) -> Result<(), Self::L2Error>;

    async fn finalize_withdraw(&self) -> Result<Hash, Self::L1Error>;

    async fn transfer(&self, to: Address, amount: U256) -> Result<Hash, Self::L2Error>;

    /* L1 Signer Getters */

    async fn l1_nonce(&self) -> Result<U256, Self::L1Error>;

    async fn l1_balance(&self) -> Result<U256, Self::L1Error>;

    async fn l1_address(&self) -> Result<Address, Self::L1Error>;

    /* L2 Signer Getters */

    async fn l2_nonce(&self) -> Result<U256, Self::L2Error>;

    async fn l2_balance(&self) -> Result<U256, Self::L2Error>;

    async fn l2_address(&self) -> Result<Address, Self::L2Error>;
}
