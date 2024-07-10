// use ethers::{
//     abi::Tokenize,
//     types::{Address, Bytes, H256, U256},
// };
// use serde::{Deserialize, Serialize};
// use std::{fs::File, path::PathBuf, str::FromStr};
// use zksync_ethers_rs::{
//     types::zksync::api::{CallTracerConfig, SupportedTracers, TracerConfig},
//     zk_middleware::ZKMiddleware,
// };

// #[tokio::test]
// async fn test_provider_estimate_fee() {
//     let provider = era_provider();
//     #[derive(Serialize, Deserialize, Debug)]
//     struct TestTransaction {
//         from: String,
//         to: String,
//         data: String,
//     }

//     let transaction = TestTransaction {
//         from: "0x1111111111111111111111111111111111111111".to_owned(),
//         to: "0x2222222222222222222222222222222222222222".to_owned(),
//         data: "0x608060405234801561001057600080fd5b50610228806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c80639146769014610030575b600080fd5b61003861004e565b6040516100459190610170565b60405180910390f35b60606000805461005d906101c1565b80601f0160208091040260200160405190810160405280929190818152602001828054610089906101c1565b80156100d65780601f106100ab576101008083540402835291602001916100d6565b820191906000526020600020905b8154815290600101906020018083116100b957829003601f168201915b5050505050905090565b600081519050919050565b600082825260208201905092915050565b60005b8381101561011a5780820151818401526020810190506100ff565b60008484015250505050565b6000601f19601f8301169050919050565b6000610142826100e0565b61014c81856100eb565b935061015c8185602086016100fc565b61016581610126565b840191505092915050565b6000602082019050818103600083015261018a8184610137565b905092915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b600060028204905060018216806101d957607f821691505b6020821081036101ec576101eb610192565b5b5091905056fea26469706673582212203d7f62ad5ef1f9670aa630c438f1a75844e1d2cfaf92e6985c698b7009e3dfa864736f6c63430008140033".to_owned(),
//     };

//     let estimated_fee = provider.estimate_fee(transaction).await.unwrap();

//     assert_eq!(estimated_fee.gas_limit, U256::from(162_436_u32));
//     assert_eq!(estimated_fee.gas_per_pubdata_limit, U256::from(66_u32));
//     assert_eq!(estimated_fee.max_fee_per_gas, U256::from(250_000_000_u32));
//     assert_eq!(estimated_fee.max_priority_fee_per_gas, U256::from(0_u32));
// }

// #[tokio::test]
// async fn test_provider_get_testnet_paymaster() {
//     let provider = era_provider();

//     assert!(provider.get_testnet_paymaster().await.is_ok());
// }

// #[tokio::test]
// async fn test_provider_estimate_gas_l1_to_l2() {
//     let provider = era_provider();
//     #[derive(Serialize, Deserialize, Debug)]
//     struct TestTransaction {
//         from: String,
//         to: String,
//         data: String,
//     }

//     let transaction = TestTransaction {
//         from: "0x1111111111111111111111111111111111111111".to_owned(),
//         to: "0x2222222222222222222222222222222222222222".to_owned(),
//         data: "0x608060405234801561001057600080fd5b50610228806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c80639146769014610030575b600080fd5b61003861004e565b6040516100459190610170565b60405180910390f35b60606000805461005d906101c1565b80601f0160208091040260200160405190810160405280929190818152602001828054610089906101c1565b80156100d65780601f106100ab576101008083540402835291602001916100d6565b820191906000526020600020905b8154815290600101906020018083116100b957829003601f168201915b5050505050905090565b600081519050919050565b600082825260208201905092915050565b60005b8381101561011a5780820151818401526020810190506100ff565b60008484015250505050565b6000601f19601f8301169050919050565b6000610142826100e0565b61014c81856100eb565b935061015c8185602086016100fc565b61016581610126565b840191505092915050565b6000602082019050818103600083015261018a8184610137565b905092915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b600060028204905060018216806101d957607f821691505b6020821081036101ec576101eb610192565b5b5091905056fea26469706673582212203d7f62ad5ef1f9670aa630c438f1a75844e1d2cfaf92e6985c698b7009e3dfa864736f6c63430008140033".to_owned(),
//     };

//     let estimated_fee = provider.estimate_gas_l1_to_l2(transaction).await.unwrap();

//     assert_eq!(estimated_fee, U256::from(36_768_868_u64));
// }

// #[tokio::test]
// // TODO: This test is flacky. It could fail in the future.
// async fn test_provider_get_all_account_balances() {
//     let provider = era_provider();
//     let address: Address = "0xbd29a1b981925b94eec5c4f1125af02a2ec4d1ca"
//         .parse()
//         .unwrap();
//     let balance = provider.get_balance(address, None).await.unwrap();

//     let balances = provider.get_all_account_balances(address).await.unwrap();

//     assert_eq!(
//         balances
//             .get(
//                 &"0x0000000000000000000000000000000000000000"
//                     .parse::<Address>()
//                     .unwrap()
//             )
//             .unwrap()
//             .clone(),
//         balance
//     );
// }

// #[tokio::test]
// async fn test_provider_get_block_details() {
//     let provider = era_provider();
//     let existing_block = 1_u64;
//     let non_existing_block = provider.get_block_number().await.unwrap() + 100_u64;

//     let existing_block_details = provider.get_block_details(existing_block).await.unwrap();
//     let non_existing_block_details = provider
//         .get_block_details(non_existing_block.as_u32())
//         .await
//         .unwrap();

//     assert!(existing_block_details.is_some());
//     assert!(non_existing_block_details.is_none())
// }

// #[tokio::test]
// async fn test_provider_get_bridge_contracts() {
//     let provider = era_provider();

//     assert!(provider.get_bridge_contracts().await.is_ok());
// }

// #[tokio::test]
// async fn test_provider_get_bytecode_by_hash() {
//     let provider = era_provider();
//     let invalid_hash = "0x7641711d8997f701a4d5929b6661185aeb5ae1fdff33288b6b5df1c05135cfc9"
//         .parse()
//         .unwrap();
//     let test_block = provider.get_block_details(2_u64).await.unwrap().unwrap();
//     let valid_hash = test_block.base.root_hash.unwrap();

//     assert!(provider.get_bytecode_by_hash(invalid_hash).await.is_ok());
//     assert!(provider.get_bytecode_by_hash(valid_hash).await.is_ok());
// }

// #[ignore]
// #[tokio::test]
// async fn test_provider_get_confirmed_tokens() {
//     let provider = era_provider();
//     let from = 0;
//     let limit = 10;

//     assert!(provider.get_confirmed_tokens(from, limit).await.is_ok());
// }

// // TODO: This test is flacky. It could fail in the future.
// #[tokio::test]
// async fn test_provider_get_l1_batch_block_range() {
//     let provider = era_provider();
//     let batch = 1_u64;

//     assert!(provider.get_l1_batch_block_range(batch).await.is_ok());
// }

// #[tokio::test]
// async fn test_provider_get_l1_batch_details() {
//     let provider = era_provider();
//     let batch = 1_u64;

//     assert!(provider.get_l1_batch_details(batch).await.is_ok());
// }

// #[tokio::test]
// async fn test_provider_get_l2_to_l1_log_proof() {
//     let provider = era_provider();
//     let tx_hash: H256 = "0xac9cf301af3b11760feb9d84283513f993dcd29de6e5fd28a8f41b1c7c0469ed"
//         .parse()
//         .unwrap();

//     assert!(provider.get_l2_to_l1_log_proof(tx_hash, None).await.is_ok());
// }

// // #[tokio::test]
// // async fn test_provider_get_l2_to_l1_msg_proof() {
// //     let provider = local_provider();
// //     let block = 2;
// //     let sender = /* create an address object */;
// //     let msg = /* create a hash object */;

// //     assert!(provider.get_l2_to_l1_msg_proof(block, sender, msg, None).await.is_ok());
// // }

// #[tokio::test]
// async fn test_provider_get_main_contract() {
//     let provider = era_provider();

//     assert!(provider.get_main_contract().await.is_ok());
// }

// // TODO: This test is flacky. It could fail in the future. We should create a
// // transaction, send it, and the assert that the details match.
// #[tokio::test]
// async fn test_provider_get_raw_block_transactions() {
//     let provider = era_provider();
//     let block = 1_u64;

//     assert!(provider.get_raw_block_transactions(block).await.is_ok());
// }

// #[tokio::test]
// async fn test_provider_get_token_price() {
//     let provider = era_provider();
//     let address: Address = "0x0000000000000000000000000000000000000000"
//         .parse()
//         .unwrap();

//     assert!(provider.get_token_price(address).await.is_ok());
// }

// // TODO: This test is flacky. It could fail in the future. We should create a
// // transaction, send it, and the assert that the details match.
// #[tokio::test]
// async fn test_provider_get_transaction_details() {
//     let provider = era_provider();
//     let test_block = provider.get_block_details(2_u64).await.unwrap().unwrap();
//     let hash = test_block.base.root_hash.unwrap();

//     assert!(provider.get_transaction_details(hash).await.is_ok());
// }

// #[tokio::test]
// async fn test_provider_get_l1_batch_number() {
//     let provider = era_provider();

//     assert!(provider.get_l1_batch_number().await.is_ok());
// }

// #[tokio::test]
// async fn test_provider_get_l1_chain_id() {
//     let provider = era_provider();

//     assert!(provider.get_l1_chain_id().await.is_ok());
// }

// #[tokio::test]
// async fn test_provider_debug_trace_block_by_hash() {
//     let provider = era_provider();
//     let block_number = provider.get_block_number().await.unwrap() - 1_u64;
//     let test_block = provider
//         .get_block_details(block_number.as_u32())
//         .await
//         .unwrap()
//         .unwrap();
//     let hash_block = test_block.base.root_hash.unwrap();

//     let options = Some(TracerConfig {
//         tracer: SupportedTracers::CallTracer,
//         tracer_config: CallTracerConfig {
//             only_top_call: true,
//         },
//     });

//     assert!(
//         ZKMiddleware::debug_trace_block_by_hash(&provider, hash_block, None)
//             .await
//             .is_ok()
//     );
//     assert!(
//         ZKMiddleware::debug_trace_block_by_hash(&provider, hash_block, options)
//             .await
//             .is_ok()
//     );
// }

// #[tokio::test]
// async fn test_provider_debug_trace_block_by_number() {
//     let provider = era_provider();
//     let existing_block_number = provider.get_block_number().await.unwrap() - 1_u64;
//     let non_existing_block_number = existing_block_number + 100_u64;
//     let options = Some(TracerConfig {
//         tracer: SupportedTracers::CallTracer,
//         tracer_config: CallTracerConfig {
//             only_top_call: true,
//         },
//     });

//     assert!(
//         ZKMiddleware::debug_trace_block_by_number(&provider, existing_block_number, None)
//             .await
//             .is_ok()
//     );
//     assert!(ZKMiddleware::debug_trace_block_by_number(
//         &provider,
//         existing_block_number,
//         options.clone()
//     )
//     .await
//     .is_ok());
//     assert!(
//         ZKMiddleware::debug_trace_block_by_number(&provider, non_existing_block_number, None)
//             .await
//             .is_err()
//     );
//     assert!(ZKMiddleware::debug_trace_block_by_number(
//         &provider,
//         non_existing_block_number,
//         options
//     )
//     .await
//     .is_err());
// }

// #[tokio::test]
// async fn test_provider_debug_trace_call() {
//     let provider = era_provider();
//     #[derive(Serialize, Deserialize, Debug)]
//     struct TestTransaction {
//         from: String,
//         to: String,
//         data: String,
//     }

//     let request = TestTransaction {
//         from: "0x1111111111111111111111111111111111111111".to_owned(),
//         to: "0x2222222222222222222222222222222222222222".to_owned(),
//         data: "0x608060405234801561001057600080fd5b50610228806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c80639146769014610030575b600080fd5b61003861004e565b6040516100459190610170565b60405180910390f35b60606000805461005d906101c1565b80601f0160208091040260200160405190810160405280929190818152602001828054610089906101c1565b80156100d65780601f106100ab576101008083540402835291602001916100d6565b820191906000526020600020905b8154815290600101906020018083116100b957829003601f168201915b5050505050905090565b600081519050919050565b600082825260208201905092915050565b60005b8381101561011a5780820151818401526020810190506100ff565b60008484015250505050565b6000601f19601f8301169050919050565b6000610142826100e0565b61014c81856100eb565b935061015c8185602086016100fc565b61016581610126565b840191505092915050565b6000602082019050818103600083015261018a8184610137565b905092915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b600060028204905060018216806101d957607f821691505b6020821081036101ec576101eb610192565b5b5091905056fea26469706673582212203d7f62ad5ef1f9670aa630c438f1a75844e1d2cfaf92e6985c698b7009e3dfa864736f6c63430008140033".to_owned(),
//     };

//     let block = provider.get_block_number().await.ok();
//     let options = Some(TracerConfig {
//         tracer: SupportedTracers::CallTracer,
//         tracer_config: CallTracerConfig {
//             only_top_call: true,
//         },
//     });

//     println!(
//         "{:?}",
//         ZKMiddleware::debug_trace_call::<&TestTransaction, u64>(&provider, &request, None, None)
//             .await
//     );

//     assert!(ZKMiddleware::debug_trace_call::<&TestTransaction, u64>(
//         &provider, &request, None, None
//     )
//     .await
//     .is_ok());
//     assert!(
//         ZKMiddleware::debug_trace_call(&provider, &request, block, None)
//             .await
//             .is_ok()
//     );
//     assert!(
//         ZKMiddleware::debug_trace_call(&provider, &request, block, options.clone())
//             .await
//             .is_ok()
//     );
//     assert!(
//         ZKMiddleware::debug_trace_call::<_, u64>(&provider, request, None, options)
//             .await
//             .is_ok()
//     );
// }

// // TODO: This test is flacky. It could fail in the future.
// #[tokio::test]
// async fn test_provider_debug_trace_transaction() {
//     let era_provider = era_provider();
//     let zk_wallet = ZKSWallet::new(local_wallet(), None, Some(era_provider.clone()), None).unwrap();

//     let transfer_request = TransferRequest::new(1_u64.into())
//         .to(Address::from_str("0x36615Cf349d7F6344891B1e7CA7C72883F5dc049").unwrap())
//         .from(zk_wallet.l2_address());
//     let transaction_hash = zk_wallet.transfer(&transfer_request, None).await.unwrap();
//     let invalid_transaction_hash: H256 =
//         "0x84472204e445cb3cd5f3ce5e23abcc2892cda5e61b35855a7f0bb1562a6e30e7"
//             .parse()
//             .unwrap();

//     let options = Some(TracerConfig {
//         tracer: SupportedTracers::CallTracer,
//         tracer_config: CallTracerConfig {
//             only_top_call: true,
//         },
//     });

//     assert!(
//         ZKMiddleware::debug_trace_transaction(&era_provider, transaction_hash, None)
//             .await
//             .is_ok()
//     );
//     assert!(ZKMiddleware::debug_trace_transaction(
//         &era_provider,
//         transaction_hash,
//         options.clone()
//     )
//     .await
//     .is_ok());
//     assert!(
//         ZKMiddleware::debug_trace_transaction(&era_provider, invalid_transaction_hash, None)
//             .await
//             .is_err()
//     );
//     assert!(ZKMiddleware::debug_trace_transaction(
//         &era_provider,
//         invalid_transaction_hash,
//         options
//     )
//     .await
//     .is_err());
// }

// #[tokio::test]
// async fn test_signer_estimate_fee() {
//     let provider = era_signer();
//     #[derive(Serialize, Deserialize, Debug)]
//     struct TestTransaction {
//         from: String,
//         to: String,
//         data: String,
//     }

//     let transaction = TestTransaction {
//         from: "0x1111111111111111111111111111111111111111".to_owned(),
//         to: "0x2222222222222222222222222222222222222222".to_owned(),
//         data: "0x608060405234801561001057600080fd5b50610228806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c80639146769014610030575b600080fd5b61003861004e565b6040516100459190610170565b60405180910390f35b60606000805461005d906101c1565b80601f0160208091040260200160405190810160405280929190818152602001828054610089906101c1565b80156100d65780601f106100ab576101008083540402835291602001916100d6565b820191906000526020600020905b8154815290600101906020018083116100b957829003601f168201915b5050505050905090565b600081519050919050565b600082825260208201905092915050565b60005b8381101561011a5780820151818401526020810190506100ff565b60008484015250505050565b6000601f19601f8301169050919050565b6000610142826100e0565b61014c81856100eb565b935061015c8185602086016100fc565b61016581610126565b840191505092915050565b6000602082019050818103600083015261018a8184610137565b905092915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b600060028204905060018216806101d957607f821691505b6020821081036101ec576101eb610192565b5b5091905056fea26469706673582212203d7f62ad5ef1f9670aa630c438f1a75844e1d2cfaf92e6985c698b7009e3dfa864736f6c63430008140033".to_owned(),
//     };

//     let estimated_fee = provider.estimate_fee(transaction).await.unwrap();

//     assert_eq!(estimated_fee.gas_limit, U256::from(162_436_u32));
//     assert_eq!(estimated_fee.gas_per_pubdata_limit, U256::from(66_u32));
//     assert_eq!(estimated_fee.max_fee_per_gas, U256::from(250_000_000_u32));
//     assert_eq!(estimated_fee.max_priority_fee_per_gas, U256::from(0_u32));
// }

// #[tokio::test]
// async fn test_signer_get_testnet_paymaster() {
//     let provider = era_signer();

//     assert!(provider.get_testnet_paymaster().await.is_ok());
// }

// #[tokio::test]
// async fn test_signer_estimate_gas_l1_to_l2() {
//     let provider = era_signer();
//     #[derive(Serialize, Deserialize, Debug)]
//     struct TestTransaction {
//         from: String,
//         to: String,
//         data: String,
//     }

//     let transaction = TestTransaction {
//         from: "0x1111111111111111111111111111111111111111".to_owned(),
//         to: "0x2222222222222222222222222222222222222222".to_owned(),
//         data: "0x608060405234801561001057600080fd5b50610228806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c80639146769014610030575b600080fd5b61003861004e565b6040516100459190610170565b60405180910390f35b60606000805461005d906101c1565b80601f0160208091040260200160405190810160405280929190818152602001828054610089906101c1565b80156100d65780601f106100ab576101008083540402835291602001916100d6565b820191906000526020600020905b8154815290600101906020018083116100b957829003601f168201915b5050505050905090565b600081519050919050565b600082825260208201905092915050565b60005b8381101561011a5780820151818401526020810190506100ff565b60008484015250505050565b6000601f19601f8301169050919050565b6000610142826100e0565b61014c81856100eb565b935061015c8185602086016100fc565b61016581610126565b840191505092915050565b6000602082019050818103600083015261018a8184610137565b905092915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b600060028204905060018216806101d957607f821691505b6020821081036101ec576101eb610192565b5b5091905056fea26469706673582212203d7f62ad5ef1f9670aa630c438f1a75844e1d2cfaf92e6985c698b7009e3dfa864736f6c63430008140033".to_owned(),
//     };

//     let estimated_fee = provider.estimate_gas_l1_to_l2(transaction).await.unwrap();

//     assert_eq!(estimated_fee, U256::from(36_768_868_u32));
// }

// #[tokio::test]
// // TODO: This test is flacky. It could fail in the future.
// async fn test_signer_get_all_account_balances() {
//     let provider = era_signer();
//     let address: Address = "0xbd29a1b981925b94eec5c4f1125af02a2ec4d1ca"
//         .parse()
//         .unwrap();
//     let balance = provider.get_balance(address, None).await.unwrap();

//     let balances = provider.get_all_account_balances(address).await.unwrap();

//     assert_eq!(
//         balances
//             .get(
//                 &"0x0000000000000000000000000000000000000000"
//                     .parse::<Address>()
//                     .unwrap()
//             )
//             .unwrap()
//             .clone(),
//         balance
//     );
// }

// #[tokio::test]
// async fn test_signer_get_block_details() {
//     let provider = era_signer();
//     let existing_block = 1_u64;
//     let non_existing_block = provider.get_block_number().await.unwrap() + 100_u64;

//     let existing_block_details = provider.get_block_details(existing_block).await.unwrap();
//     let non_existing_block_details = provider
//         .get_block_details(non_existing_block.as_u32())
//         .await
//         .unwrap();

//     assert!(existing_block_details.is_some());
//     assert!(non_existing_block_details.is_none())
// }

// #[tokio::test]
// async fn test_signer_get_bridge_contracts() {
//     let provider = era_signer();

//     assert!(provider.get_bridge_contracts().await.is_ok());
// }

// #[tokio::test]
// async fn test_signer_get_bytecode_by_hash() {
//     let provider = era_signer();
//     let invalid_hash = "0xac9cf301af3b11760feb9d84283513f993dcd29de6e5fd28a8f41b1c7c0469ed"
//         .parse()
//         .unwrap();
//     let valid_hash: H256 = "0x7641711d8997f701a4d5929b6661185aeb5ae1fdff33288b6b5df1c05135cfc9"
//         .parse()
//         .unwrap();

//     assert!(provider.get_bytecode_by_hash(invalid_hash).await.is_ok());
//     assert!(provider.get_bytecode_by_hash(valid_hash).await.is_ok());
// }

// #[ignore]
// #[tokio::test]
// async fn test_signer_get_confirmed_tokens() {
//     let provider = era_signer();
//     let from = 0;
//     let limit = 10;

//     assert!(provider.get_confirmed_tokens(from, limit).await.is_ok());
// }

// // TODO: This test is flacky. It could fail in the future.
// #[tokio::test]
// async fn test_signer_get_l1_batch_block_range() {
//     let provider = era_signer();
//     let batch = 1_u64;

//     assert!(provider.get_l1_batch_block_range(batch).await.is_ok());
// }

// #[tokio::test]
// async fn test_signer_get_l1_batch_details() {
//     let provider = era_signer();
//     let batch = 1_u64;

//     assert!(provider.get_l1_batch_details(batch).await.is_ok());
// }

// #[tokio::test]
// async fn test_signer_get_l2_to_l1_log_proof() {
//     let provider = era_signer();
//     let tx_hash: H256 = "0xac9cf301af3b11760feb9d84283513f993dcd29de6e5fd28a8f41b1c7c0469ed"
//         .parse()
//         .unwrap();

//     assert!(provider.get_l2_to_l1_log_proof(tx_hash, None).await.is_ok());
// }

// // #[tokio::test]
// // async fn test_signer_get_l2_to_l1_msg_proof() {
// //     let provider = local_signer();
// //     let block = 2;
// //     let sender = /* create an address object */;
// //     let msg = /* create a hash object */;

// //     assert!(provider.get_l2_to_l1_msg_proof(block, sender, msg, None).await.is_ok());
// // }

// #[tokio::test]
// async fn test_signer_get_main_contract() {
//     let provider = era_signer();

//     assert!(provider.get_main_contract().await.is_ok());
// }

// // TODO: This test is flacky. It could fail in the future. We should create a
// // transaction, send it, and the assert that the details match.
// #[tokio::test]
// async fn test_signer_get_raw_block_transactions() {
//     let provider = era_signer();
//     let block = 1_u64;

//     assert!(provider.get_raw_block_transactions(block).await.is_ok());
// }

// #[tokio::test]
// async fn test_signer_get_token_price() {
//     let provider = era_signer();
//     let address: Address = "0x0000000000000000000000000000000000000000"
//         .parse()
//         .unwrap();

//     assert!(provider.get_token_price(address).await.is_ok());
// }

// // TODO: This test is flacky. It could fail in the future. We should create a
// // transaction, send it, and the assert that the details match.
// #[tokio::test]
// async fn test_signer_get_transaction_details() {
//     let provider = era_signer();
//     let hash: H256 = "0xac9cf301af3b11760feb9d84283513f993dcd29de6e5fd28a8f41b1c7c0469ed"
//         .parse()
//         .unwrap();

//     assert!(provider.get_transaction_details(hash).await.is_ok());
// }

// #[tokio::test]
// async fn test_signer_get_l1_batch_number() {
//     let provider = era_signer();

//     assert!(provider.get_l1_batch_number().await.is_ok());
// }

// #[tokio::test]
// async fn test_signer_get_l1_chain_id() {
//     let provider = era_signer();

//     assert!(provider.get_l1_chain_id().await.is_ok());
// }

// #[tokio::test]
// async fn test_signer_debug_trace_block_by_hash() {
//     let provider = era_signer();
//     let block_number = provider.get_block_number().await.unwrap() - 1_u64;
//     let test_block = provider
//         .get_block_details(block_number.as_u32())
//         .await
//         .unwrap()
//         .unwrap();
//     let hash = test_block.base.root_hash.unwrap();

//     let options = Some(TracerConfig {
//         tracer: SupportedTracers::CallTracer,
//         tracer_config: CallTracerConfig {
//             only_top_call: true,
//         },
//     });

//     assert!(
//         ZKMiddleware::debug_trace_block_by_hash(&provider, hash, None)
//             .await
//             .is_ok()
//     );
//     assert!(
//         ZKMiddleware::debug_trace_block_by_hash(&provider, hash, options)
//             .await
//             .is_ok()
//     );
// }

// #[tokio::test]
// async fn test_signer_debug_trace_block_by_number() {
//     let provider = era_signer();
//     let existing_block_number = provider.get_block_number().await.unwrap() - 1_u64;
//     let non_existing_block_number = existing_block_number + 100_u64;
//     let options = Some(TracerConfig {
//         tracer: SupportedTracers::CallTracer,
//         tracer_config: CallTracerConfig {
//             only_top_call: true,
//         },
//     });

//     assert!(
//         ZKMiddleware::debug_trace_block_by_number(&provider, existing_block_number, None)
//             .await
//             .is_ok()
//     );
//     assert!(ZKMiddleware::debug_trace_block_by_number(
//         &provider,
//         existing_block_number,
//         options.clone()
//     )
//     .await
//     .is_ok());
//     assert!(
//         ZKMiddleware::debug_trace_block_by_number(&provider, non_existing_block_number, None)
//             .await
//             .is_err()
//     );
//     assert!(ZKMiddleware::debug_trace_block_by_number(
//         &provider,
//         non_existing_block_number,
//         options
//     )
//     .await
//     .is_err());
// }

// #[tokio::test]
// async fn test_signer_debug_trace_call() {
//     let provider = era_signer();
//     #[derive(Serialize, Deserialize, Debug)]
//     struct TestTransaction {
//         from: String,
//         to: String,
//         data: String,
//     }

//     let request = TestTransaction {
//         from: "0x1111111111111111111111111111111111111111".to_owned(),
//         to: "0x2222222222222222222222222222222222222222".to_owned(),
//         data: "0x608060405234801561001057600080fd5b50610228806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c80639146769014610030575b600080fd5b61003861004e565b6040516100459190610170565b60405180910390f35b60606000805461005d906101c1565b80601f0160208091040260200160405190810160405280929190818152602001828054610089906101c1565b80156100d65780601f106100ab576101008083540402835291602001916100d6565b820191906000526020600020905b8154815290600101906020018083116100b957829003601f168201915b5050505050905090565b600081519050919050565b600082825260208201905092915050565b60005b8381101561011a5780820151818401526020810190506100ff565b60008484015250505050565b6000601f19601f8301169050919050565b6000610142826100e0565b61014c81856100eb565b935061015c8185602086016100fc565b61016581610126565b840191505092915050565b6000602082019050818103600083015261018a8184610137565b905092915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b600060028204905060018216806101d957607f821691505b6020821081036101ec576101eb610192565b5b5091905056fea26469706673582212203d7f62ad5ef1f9670aa630c438f1a75844e1d2cfaf92e6985c698b7009e3dfa864736f6c63430008140033".to_owned(),
//     };

//     let block = provider.get_block_number().await.ok();
//     let options = Some(TracerConfig {
//         tracer: SupportedTracers::CallTracer,
//         tracer_config: CallTracerConfig {
//             only_top_call: true,
//         },
//     });

//     assert!(
//         ZKMiddleware::debug_trace_call::<_, u64>(&provider, &request, None, None)
//             .await
//             .is_ok()
//     );
//     assert!(
//         ZKMiddleware::debug_trace_call(&provider, &request, block, None)
//             .await
//             .is_ok()
//     );
//     assert!(
//         ZKMiddleware::debug_trace_call(&provider, &request, block, options.clone())
//             .await
//             .is_ok()
//     );
//     assert!(
//         ZKMiddleware::debug_trace_call::<_, u64>(&provider, request, None, options)
//             .await
//             .is_ok()
//     );
// }

// #[tokio::test]
// async fn test_signer_debug_trace_transaction() {
//     let era_signer = era_signer();
//     let zk_wallet = ZKSWallet::new(local_wallet(), None, Some(era_signer.clone()), None).unwrap();

//     let transfer_request = TransferRequest::new(1_u64.into())
//         .to(Address::from_str("0x36615Cf349d7F6344891B1e7CA7C72883F5dc049").unwrap())
//         .from(zk_wallet.l2_address());
//     let transaction_hash = zk_wallet.transfer(&transfer_request, None).await.unwrap();
//     let invalid_transaction_hash: H256 =
//         "0x84472204e445cb3cd5f3ce5e23abcc2892cda5e61b35855a7f0bb1562a6e30e7"
//             .parse()
//             .unwrap();

//     let options = Some(TracerConfig {
//         tracer: SupportedTracers::CallTracer,
//         tracer_config: CallTracerConfig {
//             only_top_call: true,
//         },
//     });

//     assert!(
//         ZKMiddleware::debug_trace_transaction(&era_signer, transaction_hash, None)
//             .await
//             .is_ok()
//     );
//     assert!(
//         ZKMiddleware::debug_trace_transaction(&era_signer, transaction_hash, options)
//             .await
//             .is_ok()
//     );
//     assert!(
//         ZKMiddleware::debug_trace_transaction(&era_signer, invalid_transaction_hash, None)
//             .await
//             .is_err()
//     );
// }

// #[ignore = "Deprecated"]
// #[tokio::test]
// async fn test_send_function_with_arguments() {
//     // Deploying a test contract
//     let era_provider = era_provider();
//     let wallet = local_wallet();
//     let zk_wallet = ZKSWallet::new(wallet, None, Some(era_provider.clone()), None).unwrap();
//     let mut contract_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
//     contract_path.push("src/abi/test_contracts/storage_combined.json");
//     let contract: CompiledContract =
//         serde_json::from_reader(File::open(contract_path).unwrap()).unwrap();

//     let deploy_request =
//         DeployRequest::with(contract.abi, contract.bin.to_vec(), vec!["0".to_owned()])
//             .from(zk_wallet.l2_address());
//     let contract_address = zk_wallet.deploy(&deploy_request).await.unwrap();
//     let call_request = CallRequest::new(contract_address, "getValue()(uint256)".to_owned());
//     let initial_value = ZKMiddleware::call(&era_provider, &call_request)
//         .await
//         .unwrap();

//     assert_eq!(initial_value, U256::from(0_i32).into_tokens());

//     let value_to_set = String::from("10");
//     era_provider
//         .send_eip712(
//             &zk_wallet.l2_wallet,
//             contract_address,
//             "setValue(uint256)",
//             Some([value_to_set.clone()].into()),
//             None,
//         )
//         .await
//         .unwrap()
//         .await
//         .unwrap()
//         .unwrap();
//     let set_value = ZKMiddleware::call(&era_provider, &call_request)
//         .await
//         .unwrap();

//     assert_eq!(
//         set_value,
//         U256::from(value_to_set.parse::<u64>().unwrap()).into_tokens()
//     );

//     era_provider
//         .send_eip712(
//             &zk_wallet.l2_wallet,
//             contract_address,
//             "incrementValue()",
//             None,
//             None,
//         )
//         .await
//         .unwrap()
//         .await
//         .unwrap()
//         .unwrap();
//     let incremented_value = ZKMiddleware::call(&era_provider, &call_request)
//         .await
//         .unwrap();

//     assert_eq!(
//         incremented_value,
//         (value_to_set.parse::<u64>().unwrap() + 1_u64).into_tokens()
//     );
// }

// #[ignore = "Deprecated"]
// #[tokio::test]
// async fn test_call_view_function_with_no_parameters() {
//     // Deploying a test contract
//     let era_provider = era_provider();
//     let wallet = local_wallet();
//     let zk_wallet = ZKSWallet::new(wallet, None, Some(era_provider.clone()), None).unwrap();
//     let mut contract_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
//     contract_path.push("src/abi/test_contracts/basic_combined.json");
//     let contract: CompiledContract =
//         serde_json::from_reader(File::open(contract_path).unwrap()).unwrap();

//     let deploy_request = DeployRequest::with(contract.abi, contract.bin.to_vec(), vec![]);
//     let contract_address = zk_wallet.deploy(&deploy_request).await.unwrap();
//     let call_request = CallRequest::new(contract_address, "str_out()(string)".to_owned());
//     let output = ZKMiddleware::call(&era_provider, &call_request)
//         .await
//         .unwrap();

//     assert_eq!(output, String::from("Hello World!").into_tokens());
// }

// #[ignore = "Deprecated"]
// #[tokio::test]
// async fn test_call_view_function_with_arguments() {
//     // Deploying a test contract
//     let era_provider = era_provider();
//     let wallet = local_wallet();
//     let zk_wallet = ZKSWallet::new(wallet, None, Some(era_provider.clone()), None).unwrap();

//     let mut contract_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
//     contract_path.push("src/abi/test_contracts/basic_combined.json");
//     let contract: CompiledContract =
//         serde_json::from_reader(File::open(contract_path).unwrap()).unwrap();

//     let deploy_request = DeployRequest::with(contract.abi, contract.bin.to_vec(), vec![])
//         .from(zk_wallet.l2_address());
//     let contract_address = zk_wallet.deploy(&deploy_request).await.unwrap();
//     let call_request = CallRequest::new(contract_address, "plus_one(uint256)".to_owned())
//         .function_parameters(vec!["1".to_owned()]);
//     let no_return_type_output = ZKMiddleware::call(&era_provider, &call_request)
//         .await
//         .unwrap();

//     let call_request = call_request.function_signature("plus_one(uint256)(uint256)".to_owned());
//     let known_return_type_output = ZKMiddleware::call(&era_provider, &call_request)
//         .await
//         .unwrap();

//     assert_eq!(
//         no_return_type_output,
//         Bytes::from([
//             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//             0, 0, 2
//         ])
//         .into_tokens()
//     );
//     assert_eq!(known_return_type_output, U256::from(2_u64).into_tokens());
// }
