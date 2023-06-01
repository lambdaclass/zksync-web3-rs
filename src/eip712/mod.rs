use ethers::types::{transaction::eip712::Eip712Error, Bytes};
use sha2::Digest;
use std::num::TryFromIntError;

mod eip712_transaction_request;
pub use eip712_transaction_request::Eip712TransactionRequest;

mod eip712_sign_input;
pub use eip712_sign_input::Eip712SignInput;

/// The 32-byte hash of the bytecode of a zkSync contract is calculated in the following way:
///
/// * The first 2 bytes denote the version of bytecode hash format and are currently equal to [1,0].
/// * The second 2 bytes denote the length of the bytecode in 32-byte words.
/// * The rest of the 28-byte (i.e. 28 low big-endian bytes) are equal to the last 28 bytes of the sha256 hash of the contract's bytecode.
pub fn hash_bytecode(bytecode: Option<Vec<Bytes>>) -> Result<[u8; 32], Eip712Error> {
    let step_1: [u8; 2] = 0x100_u16.to_be_bytes();
    let bytecode_length: u16 = (bytecode
        .clone()
        .ok_or_else(|| Eip712Error::FailedToEncodeStruct)?
        .get(0)
        .ok_or_else(|| Eip712Error::FailedToEncodeStruct)?
        .len()
        / 32)
        .try_into()
        .map_err(|e: TryFromIntError| Eip712Error::Message(e.to_string()))?;
    let step_2: [u8; 2] = bytecode_length.to_be_bytes();
    let step_3: [u8; 28] = sha2::Sha256::digest(
        bytecode
            .ok_or_else(|| Eip712Error::FailedToEncodeStruct)?
            .get(0)
            .ok_or_else(|| Eip712Error::FailedToEncodeStruct)?,
    )
    .into_iter()
    .skip(4)
    .collect::<Vec<u8>>()
    .try_into()
    .map_err(|e: Vec<u8>| Eip712Error::Message(format!("{e:?}")))?;

    let contract_hash: [u8; 32] = [&step_1, &step_2, &step_3[..]]
        .concat()
        .to_vec()
        .try_into()
        .map_err(|e: Vec<u8>| Eip712Error::Message(format!("{e:?}")))?;

    Ok(contract_hash)
}

pub(crate) fn rlp_opt<T: ethers::utils::rlp::Encodable>(
    stream: &mut ethers::utils::rlp::RlpStream,
    opt: &Option<T>,
) {
    if let Some(inner) = opt {
        stream.append(inner);
    } else {
        stream.append(&"");
    }
}
