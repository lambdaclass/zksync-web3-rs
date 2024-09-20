use ethers::{
    abi::{Address, Hash},
    middleware::SignerMiddleware,
    providers::{Middleware, Provider},
    signers::Signer,
    types::{Signature, TransactionReceipt, U256},
};
use std::sync::Arc;
use zksync_types::{EIP_712_TX_TYPE, L2_BASE_TOKEN_ADDRESS};

use crate::{
    deposit,
    eip712::{Eip712Transaction, Eip712TransactionRequest},
    transfer,
    types::L2TxOverrides,
    utils::L2_ETH_TOKEN_ADDRESS,
    withdraw, ZKMiddleware,
};

#[derive(thiserror::Error, Debug)]
pub enum ZKWalletError {
    #[error("Provider error: {0}")]
    ProviderError(#[from] ethers::providers::ProviderError),
    #[error("Deploy error: {0}")]
    SendEIP712(String),
}

/// A ZKsync wallet
pub struct ZKWallet<M, S> {
    l1_signer: Arc<SignerMiddleware<M, S>>,
    l2_signer: Arc<SignerMiddleware<M, S>>,
}

impl<M, S> ZKWallet<M, S>
where
    M: Middleware,
    S: Signer,
{
    pub fn new(
        l1_signer: Arc<SignerMiddleware<M, S>>,
        l2_signer: Arc<SignerMiddleware<M, S>>,
    ) -> Self {
        Self {
            l1_signer,
            l2_signer,
        }
    }

    /// Deposits ETH to the wallet's L2 address.
    ///
    /// # Arguments
    ///
    /// * `amount` - The amount of ETH to deposit.
    ///
    /// # Returns
    ///
    /// The hash of the L1 deposit transaction.
    ///
    /// # Errors
    ///
    /// If the deposit transaction fails.
    pub async fn deposit_eth(&self, amount: U256) -> Result<Hash, ZKWalletError> {
        self._deposit(amount, L2_ETH_TOKEN_ADDRESS, self.l2_address())
            .await
    }

    /// Deposits ETH to a specified address.
    ///
    /// # Arguments
    ///
    /// * `amount` - The amount of ETH to deposit.
    /// * `to` - The address to deposit the ETH to.
    ///
    /// # Returns
    ///
    /// The hash of the L1 deposit transaction.
    ///
    /// # Errors
    ///
    /// If the deposit transaction fails.
    pub async fn deposit_eth_to(&self, amount: U256, to: Address) -> Result<Hash, ZKWalletError> {
        self._deposit(amount, L2_ETH_TOKEN_ADDRESS, to).await
    }

    /// Deposits an ERC20 token to the wallet's L2 address.
    ///
    /// # Arguments
    ///
    /// * `amount` - The amount of the ERC20 token to deposit.
    /// * `token` - The address of the ERC20 token to deposit.
    ///
    /// # Returns
    ///
    /// The hash of the L1 deposit transaction.
    ///
    /// # Errors
    ///
    /// If the deposit transaction fails.
    pub async fn deposit_erc20(&self, amount: U256, token: Address) -> Result<Hash, ZKWalletError> {
        self._deposit(amount, token, self.l2_address()).await
    }

    /// Deposits an ERC20 token to a specified address.
    ///
    /// # Arguments
    ///
    /// * `amount` - The amount of the ERC20 token to deposit.
    /// * `token` - The address of the ERC20 token to deposit.
    /// * `to` - The address to deposit the ERC20 token to.
    ///
    /// # Returns
    ///
    /// The hash of the L1 deposit transaction.
    ///
    /// # Errors
    ///
    /// If the deposit transaction fails.
    pub async fn deposit_erc20_to(
        &self,
        amount: U256,
        token: Address,
        to: Address,
    ) -> Result<Hash, ZKWalletError> {
        self._deposit(amount, token, to).await
    }

    /// Deposits the L2's base token from the L1 account.
    ///
    /// # Arguments
    ///
    /// * `amount` - The amount of the base token to deposit.
    ///
    /// # Returns
    ///
    /// The hash of the L1 deposit transaction.
    ///
    /// # Errors
    ///
    /// * If the deposit transaction fails.
    /// * If the base token L1 address cannot be retrieved.
    pub async fn deposit_base_token(&self, amount: U256) -> Result<Hash, ZKWalletError> {
        self._deposit(
            amount,
            self._l1_base_token_address().await?,
            self.l2_address(),
        )
        .await
    }

    /// Deposits the L2's base token to a specified address.
    ///
    /// # Arguments
    ///
    /// * `amount` - The amount of the base token to deposit.
    /// * `to` - The address to deposit the base token to.
    ///
    /// # Returns
    ///
    /// The hash of the L1 deposit transaction.
    ///
    /// # Errors
    ///
    /// * If the deposit transaction fails.
    /// * If the base token L1 address cannot be retrieved.
    pub async fn deposit_base_token_to(
        &self,
        amount: U256,
        to: Address,
    ) -> Result<Hash, ZKWalletError> {
        self._deposit(amount, self._l1_base_token_address().await?, to)
            .await
    }

    /// Withdraws ETH from the wallet's L2 address.
    ///
    /// # Arguments
    ///
    /// * `amount` - The amount of ETH to withdraw.
    ///
    /// # Returns
    ///
    /// The hash of the L2 withdrawal transaction.
    ///
    /// # Errors
    ///
    /// If the withdrawal transaction fails.
    ///
    /// # Note
    ///
    /// The withdrawal must be finalized before the funds are available on L1.
    /// Use `finalize_withdraw` to finalize the withdrawal.
    pub async fn withdraw_eth(&self, amount: U256) -> Result<Hash, ZKWalletError> {
        self._withdraw(amount, L2_ETH_TOKEN_ADDRESS).await
    }

    /// Withdraws an ERC20 token from the wallet's L2 address.
    ///
    /// # Arguments
    ///
    /// * `amount` - The amount of the ERC20 token to withdraw.
    /// * `token` - The address of the ERC20 token to withdraw.
    ///
    /// # Returns
    ///
    /// The hash of the L2 withdrawal transaction.
    ///
    /// # Errors
    ///
    /// If the withdrawal transaction fails.
    ///
    /// # Note
    ///
    /// The withdrawal must be finalized before the funds are available on L1.
    /// Use `finalize_withdraw` to finalize the withdrawal.
    pub async fn withdraw_erc20(
        &self,
        amount: U256,
        token: Address,
    ) -> Result<Hash, ZKWalletError> {
        self._withdraw(amount, token).await
    }

    /// Withdraws the L2's base token to the L1 account.
    ///
    /// # Arguments
    ///
    /// * `amount` - The amount of the base token to withdraw.
    ///
    /// # Returns
    ///
    /// The hash of the L2 withdrawal transaction.
    ///
    /// # Errors
    ///
    /// * If the withdrawal transaction fails.
    /// * If the base token L1 address cannot be retrieved.
    pub async fn withdraw_base_token(&self, amount: U256) -> Result<Hash, ZKWalletError> {
        self._withdraw(amount, self._l1_base_token_address().await?)
            .await
    }

    /// Finalizes a withdrawal.
    ///
    /// # Arguments
    ///
    /// * `l2_withdrawal_tx_hash` - The hash of the L2 withdrawal transaction.
    ///
    /// # Returns
    ///
    /// The hash of the L1 withdrawal transaction.
    ///
    /// # Errors
    ///
    /// If the finalization transaction fails.
    ///
    /// # Note
    ///
    /// The withdrawal must be initiated before finalization.
    /// Use any of the available withdraw methods to initiate the withdrawal.
    pub async fn finalize_withdraw(
        &self,
        l2_withdrawal_tx_hash: Hash,
    ) -> Result<Hash, ZKWalletError> {
        let l1_withdrawal_hash = withdraw::finalize_withdrawal(
            self.l1_signer(),
            l2_withdrawal_tx_hash,
            self.l2_provider(),
        )
        .await;
        Ok(l1_withdrawal_hash)
    }

    /// Transfers ETH to a specified address.
    /// The ETH is transferred from the wallet's L2 address.
    /// The transfer is done using the wallet's L2 signer.
    ///
    /// The fee has to be deducted manually, amount is the exact amount that has to be transferred.
    ///
    /// # Arguments
    ///
    /// * `amount` - The amount of ETH to transfer.
    /// * `to` - The address to transfer the ETH to.
    /// * `overrides` - Override parameters, such as nonce and gas
    ///
    /// # Returns
    ///
    /// The hash of the transfer transaction.
    ///
    /// # Errors
    ///
    /// If the transfer transaction fails.
    pub async fn transfer_eth(
        &self,
        amount: U256,
        to: Address,
        overrides: Option<L2TxOverrides>,
    ) -> Result<Hash, ZKWalletError> {
        self._transfer(amount, L2_ETH_TOKEN_ADDRESS, to, overrides)
            .await
    }

    /// Transfers an ERC20 token to a specified address.
    /// The ERC20 token is transferred from the wallet's L2 address.
    /// The transfer is done using the wallet's L2 signer.
    ///
    /// # Arguments
    ///
    /// * `amount` - The amount of the ERC20 token to transfer.
    /// * `token` - The address of the ERC20 token to transfer.
    /// * `to` - The address to transfer the ERC20 token to.
    /// * `overrides` - Override parameters, such as nonce and gas
    ///
    /// # Returns
    ///
    /// The hash of the transfer transaction.
    ///
    /// # Errors
    ///
    /// If the transfer transaction fails.
    pub async fn transfer_erc20(
        &self,
        amount: U256,
        token: Address,
        to: Address,
        overrides: Option<L2TxOverrides>,
    ) -> Result<Hash, ZKWalletError> {
        self._transfer(amount, token, to, overrides).await
    }

    /// Transfers the L2's base token to a specified address.
    ///
    /// The fee has to be deducted manually, amount is the exact amount that has to be transferred.
    /// # Arguments
    ///
    /// * `amount` - The amount of the base token to transfer.
    /// * `to` - The address to transfer the base token to.
    ///
    /// # Returns
    ///
    /// The hash of the transfer transaction.
    ///
    /// # Errors
    ///
    /// * If the transfer transaction fails.
    /// * If the base token L1 address cannot be retrieved.
    pub async fn transfer_base_token(
        &self,
        amount: U256,
        to: Address,
        overrides: Option<L2TxOverrides>,
    ) -> Result<Hash, ZKWalletError> {
        self._transfer(amount, L2_BASE_TOKEN_ADDRESS, to, overrides)
            .await
    }

    /* L1 Signer Getters */

    /// Gets the nonce of the wallet's L1 address.
    ///
    /// # Returns
    ///
    /// The nonce of the wallet's L1 address.
    ///
    /// # Errors
    ///
    /// If the nonce cannot be retrieved.
    pub async fn l1_nonce(&self) -> Result<U256, ZKWalletError> {
        let nonce = self
            .l1_provider()
            .get_transaction_count(self.l1_address(), None)
            .await?;
        Ok(nonce)
    }

    /// Gets the balance of the wallet's L1 address.
    ///
    /// # Returns
    ///
    /// The balance of the wallet's L1 address.
    ///
    /// # Errors
    ///
    /// If the balance cannot be retrieved.
    pub async fn l1_balance(&self) -> Result<U256, ZKWalletError> {
        unimplemented!()
    }

    /// Gets the wallet's L1 address.
    ///
    /// # Returns
    ///
    /// The wallet's L1 address.
    pub fn l1_address(&self) -> Address {
        self.l1_signer.address()
    }

    /* L2 Signer Getters */

    /// Gets the nonce of the wallet's L2 address.
    ///
    /// # Returns
    ///
    /// The nonce of the wallet's L2 address.
    ///
    /// # Errors
    ///
    /// If the nonce cannot be retrieved.
    pub async fn l2_nonce(&self) -> Result<U256, ZKWalletError> {
        let nonce = self
            .l2_provider()
            .get_transaction_count(self.l2_address(), None)
            .await?;
        Ok(nonce)
    }

    /// Gets the balance of the wallet's L2 address.
    ///
    /// # Returns
    ///
    /// The balance of the wallet's L2 address.
    ///
    /// # Errors
    ///
    /// If the balance cannot be retrieved.
    pub async fn l2_balance(&self) -> Result<U256, ZKWalletError> {
        unimplemented!()
    }

    /// Gets the wallet's L2 address.
    ///
    /// # Returns
    ///
    /// The wallet's L2 address.
    pub fn l2_address(&self) -> Address {
        self.l2_signer.address()
    }

    /* Providers */

    /// Gets the wallet's L1 provider.
    ///
    /// # Returns
    ///
    /// A reference to the wallet's L1 provider.
    pub fn l1_provider(&self) -> &Provider<<M as Middleware>::Provider> {
        self.l1_signer.provider()
    }

    /// Gets the wallet's L2 provider.
    ///
    /// # Returns
    ///
    /// A reference to the wallet's L2 provider.
    pub fn l2_provider(&self) -> &Provider<<M as Middleware>::Provider> {
        self.l2_signer.provider()
    }

    /* Signers */

    /// Gets the wallet's L1 signer.
    ///
    /// # Returns
    ///
    /// An ARC reference to the wallet's L1 signer.
    pub fn l1_signer(&self) -> Arc<SignerMiddleware<M, S>> {
        Arc::clone(&self.l1_signer)
    }

    /// Gets the wallet's L2 signer.
    ///
    /// # Returns
    ///
    /// An ARC reference to the wallet's L2 signer.
    pub fn l2_signer(&self) -> Arc<SignerMiddleware<M, S>> {
        Arc::clone(&self.l2_signer)
    }

    /* Internals */

    async fn _deposit(
        &self,
        amount: U256,
        token: Address,
        to: Address,
    ) -> Result<Hash, ZKWalletError> {
        let l1_deposit_hash = deposit::deposit(
            amount,
            token,
            self.l1_signer(),
            to,
            self.l1_address(),
            self.l2_provider(),
        )
        .await;
        Ok(l1_deposit_hash)
    }

    async fn _withdraw(&self, amount: U256, token: Address) -> Result<Hash, ZKWalletError> {
        let l2_withdraw_hash =
            withdraw::withdraw(amount, token, self.l2_signer(), self.l1_provider()).await;
        Ok(l2_withdraw_hash)
    }

    pub async fn _transfer(
        &self,
        amount: U256,
        token: Address,
        to: Address,
        overrides: Option<L2TxOverrides>,
    ) -> Result<Hash, ZKWalletError> {
        let transfer_hash =
            transfer::transfer(amount, token, self.l2_signer(), to, overrides).await;
        Ok(transfer_hash)
    }

    pub async fn _l1_base_token_address(&self) -> Result<Address, ZKWalletError> {
        self.l2_provider()
            .get_base_token_l1_address()
            .await
            .map_err(Into::into)
    }

    pub async fn send_transaction_eip712(
        &self,
        transaction: Eip712TransactionRequest,
    ) -> Result<TransactionReceipt, ZKWalletError> {
        let mut request: Eip712TransactionRequest = transaction;

        request = request
            .from(self.l2_address())
            .chain_id(self.l2_provider().get_chainid().await?)
            .nonce(
                self.l2_provider()
                    .get_transaction_count(self.l2_address(), None)
                    .await?,
            );

        let custom_data = request.clone().custom_data;
        let fee = self.l2_provider().estimate_fee(request.clone()).await?;
        let gas = self.l2_provider().zk_estimate_gas(request.clone()).await?;
        let gas_price = self.l2_provider().get_gas_price().await?;
        request = request
            .max_priority_fee_per_gas(fee.max_priority_fee_per_gas)
            .gas_limit(gas)
            .max_fee_per_gas(fee.max_fee_per_gas)
            .gas_price(gas_price);
        let signable_data: Eip712Transaction = request.clone().try_into().map_err(|e| {
            ZKWalletError::SendEIP712(format!("error converting deploy to eip 712 {e}"))
        })?;

        let signature: Signature = self
            .l2_signer()
            .signer()
            .sign_typed_data(&signable_data)
            .await
            .map_err(|e| {
                ZKWalletError::SendEIP712(format!("error signing deploy transaction: {e}"))
            })?;

        request = request.custom_data(custom_data.custom_signature(signature.to_vec()));
        let encoded_rlp = &*request
            .rlp_signed(signature)
            .map_err(|e| ZKWalletError::SendEIP712(format!("Error in the rlp encoding {e}")))?;

        self.l2_provider()
            .send_raw_transaction([&[EIP_712_TX_TYPE], encoded_rlp].concat().into())
            .await?
            .await?
            .ok_or(ZKWalletError::SendEIP712(
                "Error sending the deploy transaction".to_string(),
            ))
    }
}
