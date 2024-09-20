use ethers::{
    abi::{
        encode,
        token::{LenientTokenizer, StrictTokenizer, Tokenizer},
        Address, Constructor, Function, Param, ParamType, Token,
    },
    types::U256,
};
use ethers_contract::AbiError;
use std::str::FromStr;
use zksync_types::H160;

pub const L1_ETH_TOKEN_ADDRESS: Address = H160([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
]);
pub const L2_ETH_TOKEN_ADDRESS: Address = H160([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01,
]);
pub const ETH_CHAIN_ID: u16 = 0x9;

/// The `L1->L2` transactions are required to have the following gas per pubdata byte.
pub const REQUIRED_L1_TO_L2_GAS_PER_PUBDATA_LIMIT: u64 = 800;
/// Gas limit used for displaying the error messages when the
/// users do not have enough fee when depositing `ETH` token from L1 to L2
pub const L1_RECOMMENDED_MIN_ETH_DEPOSIT_GAS_LIMIT: u64 = 200_000;
// The large L2 gas per pubdata to sign. This gas is enough to ensure that
// any reasonable limit will be accepted. Note, that the operator is NOT required to
// use the honest value of gas per pubdata and it can use any value up to the one signed by the user.
// In the future releases, we will provide a way to estimate the current gasPerPubdata.
pub const DEFAULT_GAS_PER_PUBDATA_LIMIT: u64 = 50000;
pub const MAX_PRIORITY_FEE_PER_GAS: u64 = 1063439364;
pub const MAX_FEE_PER_GAS: u64 = 1063439378;
pub const DEFAULT_GAS: u64 = 91435;

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
    #[allow(deprecated)]
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
    #[allow(deprecated)]
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
                kind: ParamType::Uint(256),
                internal_type: Some("uint256".to_owned()),
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

pub fn mod_exp_function() -> Function {
    #[allow(deprecated)]
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
                kind: ParamType::Bytes,
                internal_type: Some("bytes".to_owned()),
            },
            Param {
                name: "".to_owned(),
                kind: ParamType::Bytes,
                internal_type: Some("bytes".to_owned()),
            },
            Param {
                name: "".to_owned(),
                kind: ParamType::Bytes,
                internal_type: Some("bytes".to_owned()),
            },
        ],
        outputs: vec![Param {
            name: "".to_owned(),
            kind: ParamType::Bytes,
            internal_type: Some("bytes".to_owned()),
        }],
        state_mutability: ethers::abi::StateMutability::Payable,
        constant: None,
    }
}
