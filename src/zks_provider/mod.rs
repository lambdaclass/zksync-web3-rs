use async_trait::async_trait;
use ethers::{
    providers::{JsonRpcClient, Provider, ProviderError},
    types::Address,
};
use serde::Serialize;
use std::fmt::Debug;

pub mod types;
use types::Fee;

/// This trait wraps every JSON-RPC call specified in zkSync Era's documentation
/// https://era.zksync.io/docs/api/api.html#zksync-era-json-rpc-methods
#[async_trait]
pub trait ZKSProvider {
    /// Returns the fee for the transaction.
    async fn estimate_fee<T>(&self, transaction: T) -> Result<Fee, ProviderError>
    where
        T: Debug + Serialize + Send + Sync;

    /// Returns the address where the paymaster contract is deployed.
    async fn get_testnet_paymaster(&self) -> Result<Address, ProviderError>;
}

#[async_trait]
impl<P: JsonRpcClient> ZKSProvider for Provider<P> {
    async fn estimate_fee<T>(&self, transaction: T) -> Result<Fee, ProviderError>
    where
        T: Debug + Serialize + Send + Sync,
    {
        self.request("zks_estimateFee", [transaction]).await
    }

    async fn get_testnet_paymaster(&self) -> Result<Address, ProviderError> {
        self.request("zks_getTestnetPaymaster", ()).await
    }
}

#[cfg(test)]
mod tests {
    use crate::zks_provider::ZKSProvider;
    use ethers::{providers::Provider, types::Address};
    use serde::{Deserialize, Serialize};

    fn get_local_provider() -> Provider<ethers::providers::Http> {
        Provider::try_from(format!(
            "http://{host}:{port}",
            host = "65.108.204.116",
            port = 3_050_i32
        ))
        .unwrap()
        .interval(std::time::Duration::from_millis(10))
    }

    #[tokio::test]
    async fn test_estimate_fee() {
        let provider = get_local_provider();
        #[derive(Serialize, Deserialize, Debug)]
        struct TestTransaction {
            from: String,
            to: String,
            data: String,
        }

        let transaction = TestTransaction {
            from: "0x1111111111111111111111111111111111111111".to_owned(),
            to: "0x2222222222222222222222222222222222222222".to_owned(),
            data: "0x608060405234801561001057600080fd5b50610228806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c80639146769014610030575b600080fd5b61003861004e565b6040516100459190610170565b60405180910390f35b60606000805461005d906101c1565b80601f0160208091040260200160405190810160405280929190818152602001828054610089906101c1565b80156100d65780601f106100ab576101008083540402835291602001916100d6565b820191906000526020600020905b8154815290600101906020018083116100b957829003601f168201915b5050505050905090565b600081519050919050565b600082825260208201905092915050565b60005b8381101561011a5780820151818401526020810190506100ff565b60008484015250505050565b6000601f19601f8301169050919050565b6000610142826100e0565b61014c81856100eb565b935061015c8185602086016100fc565b61016581610126565b840191505092915050565b6000602082019050818103600083015261018a8184610137565b905092915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b600060028204905060018216806101d957607f821691505b6020821081036101ec576101eb610192565b5b5091905056fea26469706673582212203d7f62ad5ef1f9670aa630c438f1a75844e1d2cfaf92e6985c698b7009e3dfa864736f6c63430008140033".to_owned(),
        };

        let estimated_fee = provider.estimate_fee(transaction).await.unwrap();

        assert_eq!(estimated_fee.gas_limit.as_u64(), 162436);
        assert_eq!(estimated_fee.gas_per_pubdata_limit.as_u64(), 66);
        assert_eq!(estimated_fee.max_fee_per_gas.as_u64(), 250000000);
        assert_eq!(estimated_fee.max_priority_fee_per_gas.as_u64(), 0);
    }

    #[tokio::test]
    async fn test_get_testnet_paymaster() {
        let provider = get_local_provider();
        let expected_address: Address = "0x4cccf49428918845022048757f8c9af961fa9a90"
            .parse()
            .unwrap();
        let testnet_paymaster = provider.get_testnet_paymaster().await.unwrap();
        assert_eq!(testnet_paymaster, expected_address);
    }
}
