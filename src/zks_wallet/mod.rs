mod errors;
pub use errors::ZKSWalletError;

mod wallet;
use ethers::types::U256;
pub use wallet::deposit_request::DepositRequest;
pub use wallet::ZKSWallet;

pub struct Overrides {
    pub value: Option<U256>,
}
