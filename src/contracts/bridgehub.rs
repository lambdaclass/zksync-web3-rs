use ethers::types::{Address, Bytes, U256};
use ethers_contract::abigen;

abigen!(Bridgehub, "abi/Bridgehub.json");

/// struct L2TransactionRequestDirect {
///     uint256 chainId;
///     uint256 mintValue;
///     address l2Contract;
///     uint256 l2Value;
///     bytes l2Calldata;
///     uint256 l2GasLimit;
///     uint256 l2GasPerPubdataByteLimit;
///     bytes[] factoryDeps;
///     address refundRecipient;
/// }
impl L2TransactionRequestDirect {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn chain_id(mut self, chain_id: impl Into<U256>) -> Self {
        self.chain_id = chain_id.into();
        self
    }

    pub fn mint_value(mut self, mint_value: impl Into<U256>) -> Self {
        self.mint_value = mint_value.into();
        self
    }

    pub fn l2_contract(mut self, l2_contract: impl Into<Address>) -> Self {
        self.l_2_contract = l2_contract.into();
        self
    }

    pub fn l2_value(mut self, l2_value: impl Into<U256>) -> Self {
        self.l_2_value = l2_value.into();
        self
    }

    pub fn l2_calldata(mut self, l2_calldata: impl Into<Bytes>) -> Self {
        self.l_2_calldata = l2_calldata.into();
        self
    }

    pub fn l2_gas_limit(mut self, l2_gas_limit: impl Into<U256>) -> Self {
        self.l_2_gas_limit = l2_gas_limit.into();
        self
    }

    pub fn l2_gas_per_pubdata_byte_limit(
        mut self,
        l2_gas_per_pubdata_byte_limit: impl Into<U256>,
    ) -> Self {
        self.l_2_gas_per_pubdata_byte_limit = l2_gas_per_pubdata_byte_limit.into();
        self
    }

    pub fn factory_deps(mut self, factory_deps: Vec<Bytes>) -> Self {
        self.factory_deps = factory_deps;
        self
    }

    pub fn refund_recipient(mut self, refund_recipient: impl Into<Address>) -> Self {
        self.refund_recipient = refund_recipient.into();
        self
    }
}

/// struct L2TransactionRequestTwoBridgesOuter {
///     uint256 chainId;
///     uint256 mintValue;
///     uint256 l2Value;
///     uint256 l2GasLimit;
///     uint256 l2GasPerPubdataByteLimit;
///     address refundRecipient;
///     address secondBridgeAddress;
///     uint256 secondBridgeValue;
///     bytes secondBridgeCalldata;
/// }
impl L2TransactionRequestTwoBridgesOuter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn chain_id(mut self, chain_id: impl Into<U256>) -> Self {
        self.chain_id = chain_id.into();
        self
    }

    pub fn mint_value(mut self, mint_value: impl Into<U256>) -> Self {
        self.mint_value = mint_value.into();
        self
    }

    pub fn l2_value(mut self, l2_value: impl Into<U256>) -> Self {
        self.l_2_value = l2_value.into();
        self
    }

    pub fn l2_gas_limit(mut self, l2_gas_limit: impl Into<U256>) -> Self {
        self.l_2_gas_limit = l2_gas_limit.into();
        self
    }

    pub fn l2_gas_per_pubdata_byte_limit(
        mut self,
        l2_gas_per_pubdata_byte_limit: impl Into<U256>,
    ) -> Self {
        self.l_2_gas_per_pubdata_byte_limit = l2_gas_per_pubdata_byte_limit.into();
        self
    }

    pub fn refund_recipient(mut self, refund_recipient: Address) -> Self {
        self.refund_recipient = refund_recipient;
        self
    }

    pub fn second_bridge_address(mut self, address: impl Into<Address>) -> Self {
        self.second_bridge_address = address.into();
        self
    }

    pub fn second_bridge_value(mut self, value: impl Into<U256>) -> Self {
        self.second_bridge_value = value.into();
        self
    }

    pub fn second_bridge_calldata(mut self, calldata: impl Into<Bytes>) -> Self {
        self.second_bridge_calldata = calldata.into();
        self
    }
}
