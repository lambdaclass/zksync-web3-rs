mod errors;
pub use errors::ZKSWalletError;

mod requests;
pub use requests::{deposit_request::DepositRequest, withdraw_request::WithdrawRequest};

mod wallet;
pub use wallet::ZKSWallet;

use ethers::types::U256;
pub struct Overrides {
    pub value: Option<U256>,
}
