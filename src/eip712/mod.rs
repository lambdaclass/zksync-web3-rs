use ethers::{
    types::transaction::eip712::Eip712Error,
    utils::rlp::{Encodable, RlpStream},
};
use sha2::Digest;
use std::num::TryFromIntError;

mod meta;
pub use meta::Eip712Meta;

mod transaction_request;
pub use transaction_request::Eip712TransactionRequest;

mod transaction;
pub use transaction::Eip712Transaction;

mod paymaster_params;
pub use paymaster_params::PaymasterParams;

/// The 32-byte hash of the bytecode of a zkSync contract is calculated in the following way:
///
/// * The first 2 bytes denote the version of bytecode hash format and are currently equal to [1,0].
/// * The second 2 bytes denote the length of the bytecode in 32-byte words.
/// * The rest of the 28-byte (i.e. 28 low big-endian bytes) are equal to the last 28 bytes of the sha256 hash of the contract's bytecode.
pub fn hash_bytecode(bytecode: &[u8]) -> Result<[u8; 32], Eip712Error> {
    let step_1: [u8; 2] = 0x0100_u16.to_be_bytes();
    let bytecode_length: u16 = (bytecode.len() / 32)
        .try_into()
        .map_err(|e: TryFromIntError| Eip712Error::Message(e.to_string()))?;
    let step_2: [u8; 2] = bytecode_length.to_be_bytes();
    let step_3: [u8; 28] = sha2::Sha256::digest(bytecode)
        .into_iter()
        .skip(4)
        .collect::<Vec<u8>>()
        .try_into()
        .map_err(|e| {
            Eip712Error::Message(format!(
                "Failed to digest last 28 bytes of bytecode's sha256 hash: {e:?}"
            ))
        })?;

    let contract_hash: [u8; 32] = [&step_1, &step_2, &step_3[..]]
        .concat()
        .try_into()
        .map_err(|e| {
            Eip712Error::Message(format!("Algorithm's steps concatenation failed: {e:?}"))
        })?;

    Ok(contract_hash)
}

pub(crate) fn rlp_append_option<T>(stream: &mut RlpStream, value: Option<T>)
where
    T: Encodable,
{
    if let Some(v) = value {
        stream.append(&v);
    } else {
        stream.append(&"");
    }
}
