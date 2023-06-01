use ethers::types::{transaction::eip712::Eip712Error, Bytes};
use sha2::Digest;

mod transaction_request;
pub use transaction_request::Eip712TransactionRequest;

mod sign_input;
pub use sign_input::Eip712SignInput;

mod meta;
pub use meta::Eip712Meta;

mod paymaster_params;
pub use paymaster_params::PaymasterParams;

/// The 32-byte hash of the bytecode of a zkSync contract is calculated in the following way:
///
/// * The first 2 bytes denote the version of bytecode hash format and are currently equal to [1,0].
/// * The second 2 bytes denote the length of the bytecode in 32-byte words.
/// * The rest of the 28-byte (i.e. 28 low big-endian bytes) are equal to the last 28 bytes of the sha256 hash of the contract's bytecode.
pub fn hash_bytecode(bytecode: &Bytes) -> Result<[u8; 32], Eip712Error> {
    let step_1: [u8; 2] = 0x0100_u16.to_be_bytes();
    let step_2: [u8; 2] = ((bytecode.len() / 32) as u16).to_be_bytes();
    let step_3: [u8; 28] = sha2::Sha256::digest(bytecode)
        .iter()
        .skip(4)
        .copied()
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
