mod eip712_transaction_request;
pub use eip712_transaction_request::Eip712TransactionRequest;

mod eip712_sign_input;
pub use eip712_sign_input::Eip712SignInput;

mod utils;

// TODO: Move these tests.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{eip712::eip712_transaction_request::Eip712Meta, zks_provider::ZKSProvider};
    use ethers::{
        prelude::{k256::ecdsa::SigningKey, MiddlewareBuilder, SignerMiddleware},
        providers::{Middleware, Provider},
        signers::{Signer, Wallet},
        types::{transaction::eip712::Eip712, Address, Bytes, U256},
        utils::keccak256,
    };

    #[tokio::test]
    #[ignore = "not yet implemented"]
    async fn test_pay_transaction() {}

    #[tokio::test]
    #[ignore = "not yet implemented"]
    async fn test_call_transaction() {}

    #[tokio::test]
    async fn test_dummy() {
        /* Connect to node */

        let provider = Provider::try_from(format!(
            "http://{host}:{port}",
            host = "65.108.204.116",
            port = 3050
        ))
        .unwrap();

        /* Transaction request building */

        let mut tx = Eip712TransactionRequest::default();

        let mut custom_data = Eip712Meta::default();
        custom_data.gas_per_pubdata = utils::DEFAULT_GAS_PER_PUBDATA_LIMIT.into();
        custom_data.factory_deps = Some(vec![Bytes::from(hex::decode("0002000000000002000500000000000200010000000103550000006001100270000000830010019d0000008001000039000000400010043f0000000101200190000000a80000c13d0000000001000031000000040110008c000001880000413d0000000101000367000000000101043b000000e001100270000000880210009c000001770000613d000000890110009c000001880000c13d0000000001000416000000000110004c000001880000c13d0000000001000031000000040210008a0000008503000041000000200420008c000000000400001900000000040340190000008502200197000000000520004c000000000300a019000000850220009c00000000020400190000000002036019000000000220004c000001880000c13d00000001020003670000000403200370000000000303043b000000840430009c000001880000213d00000023043000390000008505000041000000000614004b0000000006000019000000000605801900000085011001970000008504400197000000000714004b0000000005008019000000000114013f000000850110009c00000000010600190000000001056019000000000110004c000001880000c13d0000000401300039000000000112034f000000000101043b000000840210009c000001c80000213d000000bf04100039000000200200008a000000000424016f000000840540009c000001c80000213d000000400040043f000000800010043f000000240430003900000000034100190000000005000031000000000353004b000001880000213d0000001f0310018f00000001044003670000000505100272000000560000613d00000000060000190000000507600210000000000874034f000000000808043b000000a00770003900000000008704350000000106600039000000000756004b0000004e0000413d000000000630004c000000650000613d0000000505500210000000000454034f0000000303300210000000a005500039000000000605043300000000063601cf000000000636022f000000000404043b0000010003300089000000000434022f00000000033401cf000000000363019f0000000000350435000000a0011000390000000000010435000000800100043d000000840310009c000001c80000213d000000000400041a000000010340019000000001034002700000007f0530018f00000000030560190000001f0530008c00000000050000190000000105002039000000000454013f0000000104400190000001960000c13d000000200430008c000000870000413d0000001f0410003900000005044002700000008a044000410000008a05000041000000200610008c000000000405401900000000000004350000001f0330003900000005033002700000008a03300041000000000534004b000000870000813d000000000004041b0000000104400039000000000534004b000000830000413d0000001f0310008c000001f50000a13d0000000003210170000000a0040000390000008a0200004100000000000004350000009b0000613d0000008a0200004100000020050000390000000004000019000000000605001900000080056000390000000005050433000000000052041b000000200560003900000001022000390000002004400039000000000734004b000000910000413d000000a004600039000000000313004b000000a50000813d0000000303100210000000f80330018f000000010500008a000000000335022f000000000353013f0000000004040433000000000334016f000000000032041b00000001020000390000000103100210000001ff0000013d0000000001000416000000000110004c000001880000c13d00000000010000310000001f02100039000000200900008a000000000492016f000000400200043d0000000003240019000000000443004b00000000040000190000000104004039000000840530009c000001c80000213d0000000104400190000001c80000c13d000000400030043f0000001f0310018f00000001040003670000000505100272000000c60000613d000000000600001900000005076002100000000008720019000000000774034f000000000707043b00000000007804350000000106600039000000000756004b000000be0000413d000000000630004c000000d50000613d0000000505500210000000000454034f00000000055200190000000303300210000000000605043300000000063601cf000000000636022f000000000404043b0000010003300089000000000434022f00000000033401cf000000000363019f00000000003504350000008503000041000000200410008c000000000400001900000000040340190000008505100197000000000650004c000000000300a019000000850550009c000000000304c019000000000330004c000001880000c13d0000000004020433000000840340009c000001880000213d000000000312001900000000012400190000001f021000390000008504000041000000000532004b0000000005000019000000000504801900000085022001970000008506300197000000000762004b0000000004008019000000000262013f000000850220009c00000000020500190000000002046019000000000220004c000001880000c13d0000000002010433000000840420009c000001c80000213d0000003f04200039000000000494016f000000400700043d0000000004470019000000000574004b00000000050000190000000105004039000000840640009c000001c80000213d0000000105500190000001c80000c13d000000400040043f000000000627043600000000042100190000002004400039000000000334004b000001880000213d000000000320004c000001120000613d000000000300001900000000046300190000002003300039000000000513001900000000050504330000000000540435000000000423004b0000010b0000413d000000000126001900000000000104350000000004070433000000840140009c000001c80000213d000000000100041a000000010210019000000001011002700000007f0310018f000000000301c0190000001f0130008c00000000010000190000000101002039000000010110018f000000000112004b000001960000c13d000000200130008c000001480000413d000100000003001d000300000004001d000000000000043500000083010000410000000002000414000000830320009c0000000001024019000000c00110021000000086011001c70000801002000039000500000009001d000400000007001d000200000006001d020802030000040f0000000206000029000000040700002900000005090000290000000102200190000001880000613d00000003040000290000001f024000390000000502200270000000200340008c0000000002004019000000000301043b00000001010000290000001f01100039000000050110027000000000011300190000000002230019000000000312004b000001480000813d000000000002041b0000000102200039000000000312004b000001440000413d0000001f0140008c000001e40000a13d000300000004001d000000000000043500000083010000410000000002000414000000830320009c0000000001024019000000c00110021000000086011001c70000801002000039000500000009001d000400000007001d020802030000040f000000040600002900000005030000290000000102200190000001880000613d000000030700002900000000033701700000002002000039000000000101043b000001690000613d0000002002000039000000000400001900000000056200190000000005050433000000000051041b000000200220003900000001011000390000002004400039000000000534004b000001610000413d000000000373004b000001740000813d0000000303700210000000f80330018f000000010400008a000000000334022f000000000343013f00000000026200190000000002020433000000000232016f000000000021041b00000001010000390000000102700210000001ee0000013d0000000001000416000000000110004c000001880000c13d000000040100008a00000000011000310000008502000041000000000310004c000000000300001900000000030240190000008501100197000000000410004c000000000200a019000000850110009c00000000010300190000000001026019000000000110004c0000018a0000613d00000000010000190000020a00010430000000000400041a000000010540019000000001014002700000007f0210018f000000000301001900000000030260190000001f0130008c00000000010000190000000101002039000000000114013f00000001011001900000019c0000613d0000008b0100004100000000001004350000002201000039000000040010043f0000008c010000410000020a00010430000000400200043d0000000001320436000000000550004c000001ae0000613d0000000000000435000000000430004c0000000004000019000001b40000613d0000008a0500004100000000040000190000000006410019000000000705041a000000000076043500000001055000390000002004400039000000000634004b000001a60000413d000001b40000013d000001000500008a000000000454016f0000000000410435000000000330004c000000200400003900000000040060190000003f03400039000000200400008a000000000543016f0000000003250019000000000553004b00000000050000190000000105004039000000840630009c000001c80000213d0000000105500190000001c80000c13d000000400030043f0000002005000039000000000553043600000000020204330000000000250435000000000520004c000001ce0000c13d0000004005300039000001d70000013d0000008b0100004100000000001004350000004101000039000000040010043f0000008c010000410000020a000104300000004005300039000000000600001900000000075600190000000008610019000000000808043300000000008704350000002006600039000000000726004b000001d00000413d000000000125001900000000000104350000005f01200039000000000141016f0000008302000041000000830410009c0000000001028019000000830430009c000000000203401900000040022002100000006001100210000000000121019f000002090001042e000000000140004c0000000001000019000001e80000613d00000000010604330000000302400210000000010300008a000000000223022f000000000232013f000000000221016f0000000101400210000000000112019f000000000010041b0000002001000039000001000010044300000120000004430000008701000041000002090001042e000000000210004c0000000002000019000001f90000613d000000a00200043d0000000303100210000000010400008a000000000334022f000000000343013f000000000332016f0000000102100210000000000123019f000000000010041b0000000001000019000002090001042e00000206002104230000000102000039000000000001042d0000000002000019000000000001042d0000020800000432000002090001042e0000020a00010430000000000000000000000000000000000000000000000000000000000000000000000000ffffffff000000000000000000000000000000000000000000000000ffffffffffffffff80000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000020000000000000000000000000000000020000000000000000000000000000004000000100000000000000000000000000000000000000000000000000000000000000000000000000cfae321700000000000000000000000000000000000000000000000000000000a4136862290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e5634e487b710000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000240000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e36c64be93d5ed43bb9f3caf103f20032ebd5e8a2a819eba2429d4e7f7f27738").unwrap())]);

        tx.r#type = utils::EIP712_TX_TYPE.into();
        tx.from = "0x36615Cf349d7F6344891B1e7CA7C72883F5dc049"
            .parse::<Address>()
            .ok();
        tx.to = "0x0000000000000000000000000000000000008006"
            .parse::<Address>()
            .ok();
        tx.data = Some(Bytes::from(hex::decode("9c4d535b00000000000000000000000000000000000000000000000000000000000000000100008f4ba7acf2a15d4d159ee5f98b53b01ddccc75588290280820b725987100000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000094869207468657265210000000000000000000000000000000000000000000000").unwrap()));
        tx.custom_data = Some(custom_data);
        tx.chain_id = 270.into();

        // let fee = provider.estimate_fee(tx.clone()).await.unwrap();

        // tx.max_priority_fee_per_gas = Some(fee.max_priority_fee_per_gas);
        // tx.max_fee_per_gas = Some(fee.max_fee_per_gas);
        // tx.gas_limit = Some(fee.gas_limit);

        let tx_sign_input: Eip712SignInput = tx.into();

        // tx_sign_input.gas_per_pubdata_byte_limit = Some(fee.gas_per_pubdata_limit);

        /* Create Wallet */

        let mut wallet = "0x7726827caac94a7f9e1b160f7ea819f172f7b6f9d2a97f992c38edeab82d4110"
            .parse::<Wallet<SigningKey>>()
            .unwrap();
        wallet = Wallet::with_chain_id(
            wallet,
            tx_sign_input.domain().unwrap().chain_id.unwrap().as_u64(),
        );

        let signer = provider.with_signer(wallet.clone());

        /* Sign Transaction */

        let signature = Wallet::sign_typed_data(&wallet, &tx_sign_input)
            .await
            .unwrap();
        let pre_encoded_signature = <[u8; 65]>::from(signature);

        let mut encoded_signature = vec![];
        encoded_signature.extend_from_slice(&[0x71]);
        encoded_signature.extend_from_slice(&pre_encoded_signature);
        // encoded_signature.extend_from_slice(provider.rlp_signed(signature).as_ref());
        // let encoded_signature = Bytes::from(&);

        /* Send Transaction */

        let receipt =
            SignerMiddleware::send_raw_transaction(&signer, Bytes::from(encoded_signature))
                .await
                .unwrap()
                .await
                .unwrap()
                .unwrap();

        println!("{:#?}", receipt);
    }

    #[tokio::test]
    async fn test_deploy_transaction() {
        /* Connect to node */

        let provider = Provider::try_from(format!(
            "http://{host}:{port}",
            host = "65.108.204.116",
            port = 3050
        ))
        .unwrap();

        /* Create Transaction */

        let mut tx = Eip712TransactionRequest {
            r#type: utils::EIP712_TX_TYPE.into(),
            from: "0xbd29A1B981925B94eEc5c4F1125AF02a2Ec4d1cA".parse().ok(),
            // The ContractFactory contract address.
            to: "0xa61464658AfeAf65CccaaFD3a512b69A83B77618".parse().ok(),
            nonce: U256::default(),
            gas_limit: None,
            gas_price: None,
            value: None,
            data: None,
            // TODO: Use the constant.
            chain_id: 270.into(),
            access_list: None,
            max_priority_fee_per_gas: None,
            max_fee_per_gas: None,
            custom_data: None,
            ccip_read_enabled: None,
        };

        let fee = provider.estimate_fee(tx.clone()).await.unwrap();
        tx.max_priority_fee_per_gas = Some(fee.max_priority_fee_per_gas);
        tx.max_fee_per_gas = Some(fee.max_fee_per_gas);
        tx.gas_limit = Some(fee.gas_limit);

        // Build data
        let build_data = |function_signature: &str| -> eyre::Result<Vec<u8>> {
            // See https://docs.soliditylang.org/en/latest/abi-spec.html#examples
            // TODO: Support all kind of function calls and return cast
            // (nowadays we only support empty function calls).
            Ok(keccak256(function_signature.as_bytes())
                .get(0..4)
                .unwrap()
                .to_vec())
        };

        tx.data = Some(build_data("create()").unwrap().into());

        // Build custom data
        let paymaster_contract = provider.get_testnet_paymaster().await.unwrap();
        let paymaster_contract_bytecode =
            provider.get_code(paymaster_contract, None).await.unwrap();

        let custom_data = Eip712Meta {
            gas_per_pubdata: 0.into(),
            factory_deps: Some(vec![paymaster_contract_bytecode]),
            custom_signature: None,
            paymaster_params: None,
        };

        tx.custom_data = Some(custom_data);

        /* Create Sign Input */

        let mut tx_sign_input: Eip712SignInput = tx.clone().into();
        tx_sign_input.gas_per_pubdata_byte_limit = Some(fee.gas_per_pubdata_limit);

        println!("TX: {:#?}", tx);
        println!("TX_INPUT: {:#?}", tx_sign_input);

        /* Create Wallet */

        let mut wallet = "0x28a574ab2de8a00364d5dd4b07c4f2f574ef7fcc2a86a197f65abaec836d1959"
            .parse::<Wallet<SigningKey>>()
            .unwrap();
        wallet = Wallet::with_chain_id(
            wallet,
            tx_sign_input.domain().unwrap().chain_id.unwrap().as_u64(),
        );

        let signature = wallet.sign_typed_data(&tx_sign_input).await.unwrap();

        println!("{:#?}", signature.to_vec());

        println!(
            "{:?}",
            provider
                .send_raw_transaction(signature.to_vec().into())
                .await
                .unwrap()
        );
    }
}
