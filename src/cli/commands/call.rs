use crate::cli::{commands::CHAIN_ID, ZKSyncWeb3Config};
use crate::{
    prelude::{k256::ecdsa::SigningKey, MiddlewareBuilder, SignerMiddleware},
    providers::{Middleware, Provider},
    signers::Signer,
    signers::Wallet,
    types::{
        transaction::eip2718::TypedTransaction, Address, Eip1559TransactionRequest,
        TransactionReceipt,
    },
    utils::keccak256,
};
use clap::Args;
use eyre::ContextCompat;

// TODO: Optional parameters were omitted, they should be added in the future.
#[derive(Args)]
pub(crate) struct Call {
    #[clap(short, long, name = "CONTRACT_ADDRESS")]
    pub contract: Address,
    #[clap(short, long, name = "FUNCTION_SIGNATURE")]
    pub function: String,
    #[clap(short, long, name = "FUNCTION_ARGS")]
    pub args: Option<Vec<String>>,
    #[clap(short, long, name = "PRIVATE_KEY")]
    pub private_key: Option<String>,
}

pub(crate) async fn run(args: Call, config: ZKSyncWeb3Config) {
    let build_data = |function_signature: &str| -> Vec<u8> {
        // See https://docs.soliditylang.org/en/latest/abi-spec.html#examples
        // TODO: Support all kind of function calls and return cast
        // (nowadays we only support empty function calls).
        keccak256(function_signature.as_bytes())
            .get(0..4)
            .unwrap()
            .to_vec()
    };

    let request = Eip1559TransactionRequest::new()
        .to(args.contract)
        .data(build_data(&args.function));
    let mut transaction: TypedTransaction = request.into();
    let provider = Provider::try_from(format!(
        "http://{host}:{port}",
        host = config.host,
        port = config.port
    ))
    .unwrap()
    .interval(std::time::Duration::from_millis(10));
    if let Some(pk) = args.private_key {
        let mut signer = pk.parse::<Wallet<SigningKey>>().unwrap();
        signer = Wallet::with_chain_id(signer, CHAIN_ID);
        let provider = provider.clone().with_signer(signer);
        provider
            .fill_transaction(&mut transaction, None)
            .await
            .unwrap();
        let response: TransactionReceipt =
            SignerMiddleware::send_transaction(&provider, transaction, None)
                .await
                .unwrap()
                .await
                .unwrap()
                .unwrap();
        log::info!("{:?}", response);
    } else {
        // provider.fill_transaction(&mut transaction, None).await.unwrap();
        log::info!("Transaction: {:#?}", transaction);
        let response = provider.call(&transaction, None).await.unwrap();
        log::info!("{:?}", response);
    };
}
