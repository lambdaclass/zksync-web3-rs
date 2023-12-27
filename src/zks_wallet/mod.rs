mod errors;
pub use errors::{ZKRequestError, ZKSWalletError};

mod requests;
pub use requests::{
    call_request::CallRequest,
    deploy_request::{DeployRequest, DeployType},
    deposit_request::DepositRequest,
    transfer_request::TransferRequest,
    withdraw_request::WithdrawRequest,
};

mod wallet;
pub use wallet::ZKSWallet;

use ethers::types::U256;
pub struct Overrides {
    pub value: Option<U256>,
}
