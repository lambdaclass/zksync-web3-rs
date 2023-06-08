use std::sync::Arc;

use ethers::prelude::k256::ecdsa::{RecoveryId, Signature};
use ethers::prelude::k256::schnorr::signature::hazmat::PrehashSigner;
use ethers::prelude::signer::SignerMiddlewareError;
use ethers::prelude::SignerMiddleware;
use ethers::providers::Middleware;
use ethers::signers::{Signer, Wallet};
use ethers::types::{Address, Bytes, TransactionReceipt, U256};
use ethers_contract::providers::MiddlewareError;
use ethers_contract::{abigen, ContractError};
use sha2::digest::consts::{U2, U25};

use thiserror::Error as ThisError;

abigen!(MainContract, "./resources/abi/IZkSync.json");

type SM<M, D> = SignerMiddleware<M, Wallet<D>>;

pub struct MainContractInstance<M, D>
where
    M: Middleware,
    D: PrehashSigner<(Signature, RecoveryId)> + Sync + Send,
{
    provider: Arc<SM<M, D>>,
    contract: MainContract<SM<M, D>>,
}

impl<M, D> MainContractInstance<M, D>
where
    M: Middleware,
    D: PrehashSigner<(Signature, RecoveryId)> + Sync + Send,
{
    pub fn new(address: Address, provider: Arc<SignerMiddleware<M, Wallet<D>>>) -> Self {
        let contract = MainContract::new(address, provider.clone());
        Self {
            provider: provider,
            contract,
        }
    }

    pub async fn get_base_cost(
        &self,
        gas_price: U256,
        l2_gas_limit: U256,
        l2_gas_per_pubdata_byte_limit: U256,
    ) -> Result<U256, ContractError<SM<M, D>>> {
        self.contract
            .l_2_transaction_base_cost(gas_price, l2_gas_limit, l2_gas_per_pubdata_byte_limit)
            .call()
            .await
    }

    async fn nonce(&self) -> Result<U256, SignerMiddlewareError<M, Wallet<D>>> {
        let signer_address = self.provider.address();
        self.provider
            .get_transaction_count(signer_address, None)
            .await
    }

    pub async fn request_l2_transaction(
        &self,
        contract_l2: Address,
        l2_value: U256,
        call_data: Bytes,
        l2_gas_limit: U256,
        l2_gas_per_pubdata_byte_limit: U256,
        factory_deps: Vec<Bytes>,
        refund_recipient: Address,
        gas_price: U256,
        gas_limit: U256,
        l1_value: U256,
    ) -> Result<TransactionReceipt, ()> // FIXME error type
    {
        let nonce = self.nonce().await.expect("FIXME");
        let function_call = self
            .contract
            .request_l2_transaction(
                contract_l2,
                l2_value,
                call_data,
                l2_gas_limit,
                l2_gas_per_pubdata_byte_limit,
                factory_deps,
                refund_recipient,
            )
            .nonce(nonce)
            .from(self.provider.address())
            .gas_price(gas_price)
            .gas(gas_limit)
            .value(l1_value);
        let receipt = function_call
            .send()
            .await
            .expect("FIXME")
            .await
            .expect("FIXME")
            .expect("FIXME");

        Ok(receipt)
    }
}
