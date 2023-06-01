use ethers::types::{transaction::eip712::Eip712Error, Bytes};
use sha2::Digest;

mod eip712_transaction_request;
pub use eip712_transaction_request::Eip712TransactionRequest;

mod eip712_sign_input;
pub use eip712_sign_input::Eip712SignInput;

mod utils;

/// The 32-byte hash of the bytecode of a zkSync contract is calculated in the following way:
///
/// * The first 2 bytes denote the version of bytecode hash format and are currently equal to [1,0].
/// * The second 2 bytes denote the length of the bytecode in 32-byte words.
/// * The rest of the 28-byte (i.e. 28 low big-endian bytes) are equal to the last 28 bytes of the sha256 hash of the contract's bytecode.
pub fn hash_bytecode(bytecode: Option<Vec<Bytes>>) -> Result<[u8; 32], Eip712Error> {
    let step_1: [u8; 2] = 0x100_u16.to_be_bytes();
    let step_2: [u8; 2] = ((bytecode
        .clone()
        .ok_or_else(|| return Eip712Error::FailedToEncodeStruct)?[0]
        .len()
        / 32) as u16)
        .to_be_bytes();
    let step_3: [u8; 28] = sha2::Sha256::digest(
        &bytecode
            .clone()
            .ok_or_else(|| return Eip712Error::FailedToEncodeStruct)?[0],
    )
    .into_iter()
    .skip(4)
    .collect::<Vec<u8>>()
    .try_into()
    .unwrap();

    let contract_hash: [u8; 32] = [&step_1, &step_2, &step_3[..]]
        .concat()
        .to_vec()
        .try_into()
        .unwrap();

    Ok(contract_hash)
}
