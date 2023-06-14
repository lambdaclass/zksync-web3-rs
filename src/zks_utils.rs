use std::{env, path::PathBuf};

/* Misc */

pub const ETH_CHAIN_ID: u16 = 0x9;
pub const ERA_CHAIN_ID: u16 = 0x10E;
pub const EIP712_TX_TYPE: u8 = 0x71;
// The large L2 gas per pubdata to sign. This gas is enough to ensure that
// any reasonable limit will be accepted. Note, that the operator is NOT required to
// use the honest value of gas per pubdata and it can use any value up to the one signed by the user.
// In the future releases, we will provide a way to estimate the current gasPerPubdata.
pub const DEFAULT_GAS_PER_PUBDATA_LIMIT: u64 = 50000;
pub const MAX_PRIORITY_FEE_PER_GAS: u64 = 100000000;
/// This the number of pubdata such that it should be always possible to publish
/// from a single transaction. Note, that these pubdata bytes include only bytes that are
/// to be published inside the body of transaction (i.e. excluding of factory deps).
pub const GUARANTEED_PUBDATA_PER_L1_BATCH: u64 = 4000;
pub const MAX_L2_TX_GAS_LIMIT: u64 = 80000000;
// The users should always be able to provide `MAX_GAS_PER_PUBDATA_BYTE` gas per pubdata in their
// transactions so that they are able to send at least GUARANTEED_PUBDATA_PER_L1_BATCH bytes per
// transaction.
pub const MAX_GAS_PER_PUBDATA_BYTE: u64 = MAX_L2_TX_GAS_LIMIT / GUARANTEED_PUBDATA_PER_L1_BATCH;

pub const RECOMMENDED_DEPOSIT_L1_GAS_LIMIT: u64 = 10000000;
pub const RECOMMENDED_DEPOSIT_L2_GAS_LIMIT: u64 = 10000000;
pub const DEPOSIT_GAS_PER_PUBDATA_LIMIT: u64 = 800;

/* Contracts */

pub const CHAIN_STATE_KEEPER_BOOTLOADER_HASH: &str =
    "0x0100038581be3d0e201b3cc45d151ef5cc59eb3a0f146ad44f0f72abf00b594c";
pub const CHAIN_STATE_KEEPER_DEFAULT_AA_HASH: &str =
    "0x0100038dc66b69be75ec31653c64cb931678299b9b659472772b2550b703f41c";

pub const CONTRACT_DEPLOYER_ADDR: &str = "0x0000000000000000000000000000000000008006";
pub const CONTRACTS_DIAMOND_INIT_ADDR: &str = "0x5E6D086F5eC079ADFF4FB3774CDf3e8D6a34F7E9";
pub const CONTRACTS_DIAMOND_UPGRADE_INIT_ADDR: &str = "0x5E6D086F5eC079ADFF4FB3774CDf3e8D6a34F7E9";
pub const CONTRACTS_MAILBOX_FACET_ADDR: &str = "0x5E6D086F5eC079ADFF4FB3774CDf3e8D6a34F7E9";
pub const CONTRACTS_DIAMOND_CUT_FACET_ADDR: &str = "0x5E6D086F5eC079ADFF4FB3774CDf3e8D6a34F7E9";
pub const CONTRACTS_EXECUTOR_FACET_ADDR: &str = "0x5E6D086F5eC079ADFF4FB3774CDf3e8D6a34F7E9";
pub const CONTRACTS_GOVERNANCE_FACET_ADDR: &str = "0x5E6D086F5eC079ADFF4FB3774CDf3e8D6a34F7E9";
pub const CONTRACTS_GETTERS_FACET_ADDR: &str = "0x5E6D086F5eC079ADFF4FB3774CDf3e8D6a34F7E9";
pub const CONTRACTS_VERIFIER_ADDR: &str = "0xDAbb67b676F5b01FcC8997Cc8439846D0d8078ca";
pub const CONTRACTS_DIAMOND_PROXY_ADDR: &str = "0xFC073319977e314F251EAE6ae6bE76B0B3BAeeCF";
pub const CONTRACTS_L1_ERC20_BRIDGE_PROXY_ADDR: &str = "0xFC073319977e314F251EAE6ae6bE76B0B3BAeeCF";
pub const CONTRACTS_L1_ERC20_BRIDGE_IMPL_ADDR: &str = "0xFC073319977e314F251EAE6ae6bE76B0B3BAeeCF";
pub const CONTRACTS_L2_ERC20_BRIDGE_ADDR: &str = "0xFC073319977e314F251EAE6ae6bE76B0B3BAeeCF";
pub const CONTRACTS_L2_TESTNET_PAYMASTER_ADDR: &str = "0xFC073319977e314F251EAE6ae6bE76B0B3BAeeCF";
pub const CONTRACTS_L1_ALLOW_LIST_ADDR: &str = "0xFC073319977e314F251EAE6ae6bE76B0B3BAeeCF";
pub const CONTRACTS_CREATE2_FACTORY_ADDR: &str = "0xce0042B868300000d44A59004Da54A005ffdcf9f";
pub const CONTRACTS_VALIDATOR_TIMELOCK_ADDR: &str = "0xFC073319977e314F251EAE6ae6bE76B0B3BAeeCF";
pub const CONTRACTS_L1_WETH_BRIDGE_IMPL_ADDR: &str = "0x5E6D086F5eC079ADFF4FB3774CDf3e8D6a34F7E9";
pub const CONTRACTS_L1_WETH_BRIDGE_PROXY_ADDR: &str = "0x5E6D086F5eC079ADFF4FB3774CDf3e8D6a34F7E9";
pub const CONTRACTS_L1_WETH_TOKEN_ADDR: &str = "0x5E6D086F5eC079ADFF4FB3774CDf3e8D6a34F7E9";

/// Returns the location for a program in the $PATH.
pub fn program_path(program_name: &str) -> Option<PathBuf> {
    if let Ok(path_env) = env::var("PATH") {
        let paths: Vec<PathBuf> = env::split_paths(&path_env).collect();

        for path in paths {
            let program_path = path.join(program_name);

            if program_path.is_file() {
                return Some(program_path);
            }
        }
    }

    None
}
