use ethers::abi::Contract;
use std::str::FromStr;

const L1_DEFAULT_BRIDGE_INTERFACE: &str = include_str!("./IL1Bridge.json");

// FIXME this was taken from
pub fn load_contract(raw_abi_string: &str) -> Contract {
    // Note that using `.expect` here is acceptable because we expect the value of
    // `L1_DEFAULT_BRIDGE_INTERFACE` to be correct. In the future, we should refactor this piece of
    // code to run in compile time.
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    let abi_string = serde_json::Value::from_str(raw_abi_string)
        .expect("Malformed contract abi file")
        .get("abi")
        .expect("Malformed contract abi file")
        .to_string();
    Contract::load(abi_string.as_bytes()).unwrap()
}

pub fn l1_bridge_contract() -> Contract {
    load_contract(L1_DEFAULT_BRIDGE_INTERFACE)
}
