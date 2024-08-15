use super::constants::{L1_FEE_ESTIMATION_COEF_DENOMINATOR, L1_FEE_ESTIMATION_COEF_NUMERATOR};
use crate::{contracts::bridgehub::Bridgehub, eip712::Eip712TransactionRequest, ZKMiddleware};
use ethers::{middleware::SignerMiddleware, providers::Middleware, signers::Signer};
use zksync_types::{Address, U256};

pub async fn l2_tx_base_cost<M, S>(
    bridgehub: &Bridgehub<SignerMiddleware<M, S>>,
    zk_chain_id: U256,
    l1_gas_price: U256,
    estimate_gas_for_l1_to_l2_tx: U256,
    l2_gas_per_pubdata_byte_limit: U256,
) -> U256
where
    M: Middleware,
    S: Signer,
{
    bridgehub
        .l_2_transaction_base_cost(
            zk_chain_id,
            l1_gas_price,
            estimate_gas_for_l1_to_l2_tx,
            l2_gas_per_pubdata_byte_limit,
        )
        .call()
        .await
        .unwrap()
}

/// Scales the provided gas limit using a coefficient to ensure acceptance of L1->L2 transactions.
///
/// This function adjusts the gas limit by multiplying it with a coefficient calculated from the
/// `L1_FEE_ESTIMATION_COEF_NUMERATOR` and `L1_FEE_ESTIMATION_COEF_DENOMINATOR` constants.
pub fn scale_gas_limit(gas_limit: U256) -> U256 {
    gas_limit
        .checked_mul(U256::from(L1_FEE_ESTIMATION_COEF_NUMERATOR))
        .unwrap()
        .checked_div(U256::from(L1_FEE_ESTIMATION_COEF_DENOMINATOR))
        .unwrap()
}

pub async fn estimate_gas_for_l1_to_l2_tx<L2Provider>(
    from: Address,
    to: Address,
    zk_chain_id: U256,
    l2_provider: &L2Provider,
) -> U256
where
    L2Provider: ZKMiddleware + Middleware,
{
    l2_provider
        .estimate_gas_l1_to_l2(
            Eip712TransactionRequest::new()
                .chain_id(zk_chain_id)
                .from(from)
                .to(to),
        )
        .await
        .unwrap()
}
