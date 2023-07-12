use ethers::abi::Contract;
use std::str::FromStr;

const L1_DEFAULT_BRIDGE_INTERFACE: &str = include_str!("./IL1Bridge.json");

// FIXME this was taken from
pub fn load_contract(raw_abi_string: &str) -> Contract {
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
