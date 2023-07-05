use ethers::{
    abi::{
        encode,
        token::{LenientTokenizer, StrictTokenizer, Tokenizer},
        Constructor, Function, Param, ParamType, Token,
    },
    types::{Address, H160, U256},
};
use ethers_contract::AbiError;
use std::{env, path::PathBuf, str::FromStr};

/* Misc */

pub const ETH_CHAIN_ID: u16 = 0x9;
pub const ERA_CHAIN_ID: u16 = 0x10E;
pub const EIP712_TX_TYPE: u8 = 0x71;
// The large L2 gas per pubdata to sign. This gas is enough to ensure that
// any reasonable limit will be accepted. Note, that the operator is NOT required to
// use the honest value of gas per pubdata and it can use any value up to the one signed by the user.
// In the future releases, we will provide a way to estimate the current gasPerPubdata.
pub const DEFAULT_GAS_PER_PUBDATA_LIMIT: u64 = 50000;
pub const MAX_PRIORITY_FEE_PER_GAS: u64 = 1063439364;
pub const MAX_FEE_PER_GAS: u64 = 1063439378;
pub const DEFAULT_GAS: u64 = 91435;
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
pub const CONTRACTS_L2_ETH_TOKEN_ADDR: &str = "0x000000000000000000000000000000000000800a";
pub const CONTRACTS_L1_MESSENGER_ADDR: &str = "0x0000000000000000000000000000000000008008";

/* Precompiles */

pub const ECRECOVER_PRECOMPILE_ADDRESS: Address = H160([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01,
]);

pub const SHA256_PRECOMPILE_ADDRESS: Address = H160([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x02,
]);

pub const RIPEMD_160_PRECOMPILE_ADDRESS: Address = H160([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x03,
]);

pub const IDENTITY_PRECOMPILE_ADDRESS: Address = H160([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x04,
]);

pub const MODEXP_PRECOMPILE_ADDRESS: Address = H160([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x05,
]);

pub const ECADD_PRECOMPILE_ADDRESS: Address = H160([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x06,
]);

pub const ECMUL_PRECOMPILE_ADDRESS: Address = H160([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x07,
]);

pub const ECPAIRING_PRECOMPILE_ADDRESS: Address = H160([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x08,
]);

pub const BLAKE2F_PRECOMPILE_ADDRESS: Address = H160([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x09,
]);

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

pub fn is_precompile(address: Address) -> bool {
    address == ECRECOVER_PRECOMPILE_ADDRESS
        || address == SHA256_PRECOMPILE_ADDRESS
        || address == RIPEMD_160_PRECOMPILE_ADDRESS
        || address == IDENTITY_PRECOMPILE_ADDRESS
        || address == MODEXP_PRECOMPILE_ADDRESS
        || address == ECADD_PRECOMPILE_ADDRESS
        || address == ECMUL_PRECOMPILE_ADDRESS
        || address == ECPAIRING_PRECOMPILE_ADDRESS
        || address == BLAKE2F_PRECOMPILE_ADDRESS
}

/// Given a function and a vector of string arguments, it proceeds to convert the args to ethabi
/// Tokens and then ABI encode them.
/// > This function was taken from foundry.
pub fn encode_args(func: &Function, args: &[impl AsRef<str>]) -> Result<Vec<u8>, AbiError> {
    let params = func
        .inputs
        .iter()
        .zip(args)
        .map(|(input, arg)| (&input.kind, arg.as_ref()))
        .collect::<Vec<_>>();
    let tokens = parse_tokens(params, true)?;
    Ok(encode(&tokens))
}

/// Given a constructor and a vector of string arguments, it proceeds to convert the args to ethabi
/// Tokens and then ABI encode them.
pub fn encode_constructor_args(
    constructor: &Constructor,
    args: &[impl AsRef<str>],
) -> Result<Vec<u8>, AbiError> {
    let params = constructor
        .inputs
        .iter()
        .zip(args)
        .map(|(input, arg)| (&input.kind, arg.as_ref()))
        .collect::<Vec<_>>();
    let tokens = parse_tokens(params, true)?;
    Ok(encode(&tokens))
}

/// Parses string input as Token against the expected ParamType
/// > This function was taken from foundry.
pub fn parse_tokens<'a, I: IntoIterator<Item = (&'a ParamType, &'a str)>>(
    params: I,
    lenient: bool,
) -> Result<Vec<Token>, AbiError> {
    let mut tokens = Vec::new();

    for (param, value) in params.into_iter() {
        let mut token = if lenient {
            LenientTokenizer::tokenize(param, value)
        } else {
            StrictTokenizer::tokenize(param, value)
        };
        if token.is_err() && value.starts_with("0x") {
            match param {
                ParamType::FixedBytes(32) => {
                    if value.len() < 66 {
                        let padded_value = [value, &"0".repeat(66 - value.len())].concat();
                        token = if lenient {
                            LenientTokenizer::tokenize(param, &padded_value)
                        } else {
                            StrictTokenizer::tokenize(param, &padded_value)
                        };
                    }
                }
                ParamType::Uint(_) => {
                    // try again if value is hex
                    if let Ok(value) = U256::from_str(value).map(|v| v.to_string()) {
                        token = if lenient {
                            LenientTokenizer::tokenize(param, &value)
                        } else {
                            StrictTokenizer::tokenize(param, &value)
                        };
                    }
                }
                // TODO: Not sure what to do here. Put the no effect in for now, but that is not
                // ideal. We could attempt massage for every value type?
                _ => {}
            }
        }

        let token = token.map(sanitize_token)?;
        tokens.push(token);
    }
    Ok(tokens)
}

/// Cleans up potential shortcomings of the ethabi Tokenizer.
///
/// For example: parsing a string array with a single empty string: `[""]`, is returned as
///
/// ```text
///     [
///        String(
///            "\"\"",
///        ),
///    ],
/// ```
///
/// But should just be
///
/// ```text
///     [
///        String(
///            "",
///        ),
///    ],
/// ```
///
/// This will handle this edge case
/// > This function was taken from foundry.
pub fn sanitize_token(token: Token) -> Token {
    match token {
        Token::Array(tokens) => {
            let mut sanitized = Vec::with_capacity(tokens.len());
            for token in tokens {
                let token = match token {
                    Token::String(val) => {
                        let val = match val.as_str() {
                            // this is supposed to be an empty string
                            "\"\"" | "''" => "".to_owned(),
                            _ => val,
                        };
                        Token::String(val)
                    }
                    _ => sanitize_token(token),
                };
                sanitized.push(token)
            }
            Token::Array(sanitized)
        }
        _ => token,
    }
}

pub fn ec_add_function() -> Function {
    Function {
        name: "".to_owned(),
        inputs: vec![
            Param {
                name: "".to_owned(),
                kind: ParamType::Int(256),
                internal_type: Some("sint256".to_owned()),
            },
            Param {
                name: "".to_owned(),
                kind: ParamType::Int(256),
                internal_type: Some("sint256".to_owned()),
            },
            Param {
                name: "".to_owned(),
                kind: ParamType::Int(256),
                internal_type: Some("sint256".to_owned()),
            },
            Param {
                name: "".to_owned(),
                kind: ParamType::Int(256),
                internal_type: Some("sint256".to_owned()),
            },
        ],
        outputs: vec![
            Param {
                name: "".to_owned(),
                kind: ParamType::Int(256),
                internal_type: Some("sint256".to_owned()),
            },
            Param {
                name: "".to_owned(),
                kind: ParamType::Int(256),
                internal_type: Some("sint256".to_owned()),
            },
        ],
        state_mutability: ethers::abi::StateMutability::Payable,
        constant: None,
    }
}

pub fn ec_mul_function() -> Function {
    Function {
        name: "".to_string(),
        inputs: vec![
            Param {
                name: "".to_string(),
                kind: ParamType::Int(256),
                internal_type: Some("sint256".to_owned()),
            },
            Param {
                name: "".to_string(),
                kind: ParamType::Int(256),
                internal_type: Some("sint256".to_owned()),
            },
            Param {
                name: "".to_string(),
                kind: ParamType::Uint(256),
                internal_type: Some("uint256".to_owned()),
            },
        ],
        outputs: vec![
            Param {
                name: "".to_string(),
                kind: ParamType::Int(256),
                internal_type: Some("sint256".to_owned()),
            },
            Param {
                name: "".to_string(),
                kind: ParamType::Int(256),
                internal_type: Some("sint256".to_owned()),
            },
        ],
        state_mutability: ethers::abi::StateMutability::Payable,
        constant: None,
    }
}

pub fn mod_exp_function() -> Function {
    Function {
        name: "".to_string(),
        inputs: vec![
            Param {
                name: "".to_string(),
                kind: ParamType::Int(256),
                internal_type: Some("sint256".to_owned()),
            },
            Param {
                name: "".to_string(),
                kind: ParamType::Int(256),
                internal_type: Some("sint256".to_owned()),
            },
            Param {
                name: "".to_string(),
                kind: ParamType::Int(256),
                internal_type: Some("sint256".to_owned()),
            },
            Param {
                name: "".to_string(),
                kind: ParamType::Uint(256),
                internal_type: Some("uint256".to_owned()),
            },
            Param {
                name: "".to_string(),
                kind: ParamType::Uint(256),
                internal_type: Some("uint256".to_owned()),
            },
            Param {
                name: "".to_string(),
                kind: ParamType::Uint(256),
                internal_type: Some("uint256".to_owned()),
            },
        ],
        outputs: vec![Param {
            name: "".to_string(),
            kind: ParamType::Uint(256),
            internal_type: Some("uint256".to_owned()),
        }],
        state_mutability: ethers::abi::StateMutability::Payable,
        constant: None,
    }
}
