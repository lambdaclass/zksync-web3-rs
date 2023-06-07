use super::{hash_bytecode, Eip712TransactionRequest};
use crate::zks_utils::{DEFAULT_GAS_PER_PUBDATA_LIMIT, EIP712_TX_TYPE};
use ethers::{
    abi::encode,
    types::{
        transaction::eip712::{
            encode_data, encode_type, EIP712Domain, Eip712, Eip712DomainType, Eip712Error, Types,
        },
        Address, Bytes, U256,
    },
    utils::keccak256,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all(serialize = "camelCase", deserialize = "camelCase"))]
pub struct Eip712Transaction {
    pub tx_type: U256,
    pub from: Address,
    pub to: Address,
    pub gas_limit: U256,
    pub gas_per_pubdata_byte_limit: U256,
    pub max_fee_per_gas: U256,
    pub max_priority_fee_per_gas: U256,
    pub paymaster: Address,
    pub nonce: U256,
    pub value: U256,
    pub data: Bytes,
    pub factory_deps: Vec<Bytes>,
    pub paymaster_input: Bytes,
}

impl Eip712Transaction {
    // Check if this is necessary or if we can always use the default.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn tx_type<T>(mut self, tx_type: T) -> Self
    where
        T: Into<U256>,
    {
        self.tx_type = tx_type.into();
        self
    }

    pub fn to<T>(mut self, to: T) -> Self
    where
        T: Into<Address>,
    {
        self.to = to.into();
        self
    }

    pub fn from<T>(mut self, from: T) -> Self
    where
        T: Into<Address>,
    {
        self.from = from.into();
        self
    }

    pub fn nonce<T>(mut self, nonce: T) -> Self
    where
        T: Into<U256>,
    {
        self.nonce = nonce.into();
        self
    }

    pub fn gas_limit<T>(mut self, gas_limit: T) -> Self
    where
        T: Into<U256>,
    {
        self.gas_limit = gas_limit.into();
        self
    }

    pub fn gas_per_pubdata_byte_limit<T>(mut self, gas_per_pubdata_byte_limit: T) -> Self
    where
        T: Into<U256>,
    {
        self.gas_per_pubdata_byte_limit = gas_per_pubdata_byte_limit.into();
        self
    }

    pub fn max_fee_per_gas<T>(mut self, max_fee_per_gas: T) -> Self
    where
        T: Into<U256>,
    {
        self.max_fee_per_gas = max_fee_per_gas.into();
        self
    }

    pub fn max_priority_fee_per_gas<T>(mut self, max_priority_fee_per_gas: T) -> Self
    where
        T: Into<U256>,
    {
        self.max_priority_fee_per_gas = max_priority_fee_per_gas.into();
        self
    }

    pub fn paymaster<T>(mut self, paymaster: T) -> Self
    where
        T: Into<Address>,
    {
        self.paymaster = paymaster.into();
        self
    }

    pub fn value<T>(mut self, value: T) -> Self
    where
        T: Into<U256>,
    {
        self.value = value.into();
        self
    }

    pub fn data<T>(mut self, data: T) -> Self
    where
        T: Into<Bytes>,
    {
        self.data = data.into();
        self
    }

    pub fn factory_deps<T>(mut self, factory_deps: T) -> Self
    where
        T: Into<Vec<Bytes>>,
    {
        self.factory_deps = factory_deps.into();
        self
    }

    pub fn paymaster_input<T>(mut self, paymaster_input: T) -> Self
    where
        T: Into<Bytes>,
    {
        self.paymaster_input = paymaster_input.into();
        self
    }
}

impl Default for Eip712Transaction {
    fn default() -> Self {
        Self {
            tx_type: EIP712_TX_TYPE.into(),
            from: Default::default(),
            to: Default::default(),
            gas_limit: Default::default(),
            gas_per_pubdata_byte_limit: DEFAULT_GAS_PER_PUBDATA_LIMIT.into(),
            max_fee_per_gas: Default::default(),
            max_priority_fee_per_gas: Default::default(),
            paymaster: Default::default(),
            nonce: Default::default(),
            value: Default::default(),
            data: Default::default(),
            factory_deps: <Vec<Bytes>>::default(),
            paymaster_input: Default::default(),
        }
    }
}

// FIXME: Cleanup this.
pub fn eip712_transaction_types() -> Types {
    let mut types = Types::new();

    types.insert(
        "Transaction".to_owned(),
        vec![
            Eip712DomainType {
                name: "txType".to_owned(),
                r#type: "uint256".to_owned(),
            },
            Eip712DomainType {
                name: "from".to_owned(),
                r#type: "uint256".to_owned(),
            },
            Eip712DomainType {
                name: "to".to_owned(),
                r#type: "uint256".to_owned(),
            },
            Eip712DomainType {
                name: "gasLimit".to_owned(),
                r#type: "uint256".to_owned(),
            },
            Eip712DomainType {
                name: "gasPerPubdataByteLimit".to_owned(),
                r#type: "uint256".to_owned(),
            },
            Eip712DomainType {
                name: "maxFeePerGas".to_owned(),
                r#type: "uint256".to_owned(),
            },
            Eip712DomainType {
                name: "maxPriorityFeePerGas".to_owned(),
                r#type: "uint256".to_owned(),
            },
            Eip712DomainType {
                name: "paymaster".to_owned(),
                r#type: "uint256".to_owned(),
            },
            Eip712DomainType {
                name: "nonce".to_owned(),
                r#type: "uint256".to_owned(),
            },
            Eip712DomainType {
                name: "value".to_owned(),
                r#type: "uint256".to_owned(),
            },
            Eip712DomainType {
                name: "data".to_owned(),
                r#type: "bytes".to_owned(),
            },
            Eip712DomainType {
                name: "factoryDeps".to_owned(),
                r#type: "bytes32[]".to_owned(),
            },
            Eip712DomainType {
                name: "paymasterInput".to_owned(),
                r#type: "bytes".to_owned(),
            },
        ],
    );
    types
}

impl Eip712 for Eip712Transaction {
    type Error = Eip712Error;

    fn domain(&self) -> Result<EIP712Domain, Self::Error> {
        Ok(EIP712Domain {
            name: Some(String::from("zkSync")),
            version: Some(String::from("2")),
            chain_id: Some(U256::from(270_i32)),
            verifying_contract: None,
            salt: None,
        })
    }

    fn type_hash() -> Result<[u8; 32], Self::Error> {
        Ok(keccak256(encode_type(
            "Transaction",
            &eip712_transaction_types(),
        )?))
    }

    fn struct_hash(&self) -> Result<[u8; 32], Self::Error> {
        let hash = keccak256(encode(&encode_data(
            "Transaction",
            &json!(self),
            &eip712_transaction_types(),
        )?));
        Ok(hash)
    }
}

impl TryFrom<Eip712TransactionRequest> for Eip712Transaction {
    type Error = Eip712Error;

    fn try_from(tx: Eip712TransactionRequest) -> Result<Self, Self::Error> {
        let eip712_transaction = Eip712Transaction::default()
            .tx_type(tx.r#type)
            .from(tx.from)
            .to(tx.to)
            .gas_limit(tx.gas_limit)
            .max_fee_per_gas(tx.max_fee_per_gas)
            .max_priority_fee_per_gas(tx.max_priority_fee_per_gas)
            .nonce(tx.nonce)
            .value(tx.value)
            .data(tx.data)
            .factory_deps(
                tx.custom_data
                    .factory_deps
                    .iter()
                    .map(|dependency_bytecode| hash_bytecode(dependency_bytecode).map(Bytes::from))
                    .collect::<Result<Vec<Bytes>, _>>()?,
            )
            .paymaster(tx.custom_data.paymaster_params.paymaster)
            .paymaster_input(tx.custom_data.paymaster_params.paymaster_input);

        Ok(eip712_transaction)
    }
}
