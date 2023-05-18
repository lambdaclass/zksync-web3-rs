pub(crate) mod deploy;
pub(crate) use deploy::Deploy;

pub(crate) mod call;
pub(crate) use call::Call;

pub(crate) mod get_contract;
pub(crate) use get_contract::GetContract;

pub(crate) mod get_transaction;
pub(crate) use get_transaction::GetTransaction;

pub(crate) mod account_balance;
pub(crate) use account_balance::AccountBalance;

pub(crate) mod pay;
pub(crate) use pay::Pay;

// It is set so that the transaction is replay-protected (EIP-155)
// https://era.zksync.io/docs/api/hardhat/testing.html#connect-wallet-to-local-nodes
const CHAIN_ID: u64 = 9;
