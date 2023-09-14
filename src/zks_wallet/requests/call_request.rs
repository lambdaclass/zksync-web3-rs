/// Parameters to call a contract's view function i.e.
/// functions which do not alter the net's state.
/// # Example
/// ```compile_fail
/// # let contract_address: zksync_web3_rs::types::Address = Default::default();
/// /// Call request for the greet contract from the [getting started](https://docs.zksync.io/api/sdk/rust/tutorial/) tutorial
/// /// that returns a String.
/// let call_request = CallRequest::new(contract_address, "greet()(string)".to_owned());
/// let greet = ZKSProvider::call(era_provider.as_ref(), &call_request)
///            .await
///            .unwrap();
/// println!("greet: {}", greet[0]);
/// ```
use ethers::{
    abi::{encode, Function, HumanReadableParser, ParseError},
    types::{Address, Eip1559TransactionRequest},
};
use std::fmt::Debug;

use crate::{
    zks_utils::{self, is_precompile},
    zks_wallet::errors::ZKRequestError,
};

/// Parameters to call a contract's view function i.e.
/// functions which do not alter the net's state.
#[derive(Clone, Debug)]
pub struct CallRequest {
    /// The contract's address.
    pub to: Address,
    /// The function to call, with its signature.
    pub function_signature: String,
    /// The parameters for the function.
    pub function_parameters: Option<Vec<String>>,
}

impl CallRequest {
    pub fn new(to: Address, function_signature: String) -> Self {
        Self {
            to,
            function_signature,
            function_parameters: None,
        }
    }

    pub fn function_parameters(mut self, function_parameters: Vec<String>) -> Self {
        self.function_parameters = Some(function_parameters);
        self
    }

    pub fn to(mut self, to: Address) -> Self {
        self.to = to;
        self
    }

    pub fn function_signature(mut self, function_signature: String) -> Self {
        self.function_signature = function_signature;
        self
    }

    pub fn get_parsed_function(&self) -> Result<Function, ParseError> {
        if self.to == zks_utils::ECADD_PRECOMPILE_ADDRESS {
            Ok(zks_utils::ec_add_function())
        } else if self.to == zks_utils::ECMUL_PRECOMPILE_ADDRESS {
            Ok(zks_utils::ec_mul_function())
        } else if self.to == zks_utils::MODEXP_PRECOMPILE_ADDRESS {
            Ok(zks_utils::mod_exp_function())
        } else {
            HumanReadableParser::parse_function(&self.function_signature)
                .map_err(ParseError::LexerError)
        }
    }
}

impl TryFrom<CallRequest> for Eip1559TransactionRequest {
    type Error = ZKRequestError;

    fn try_from(request: CallRequest) -> Result<Eip1559TransactionRequest, Self::Error> {
        let function = request.get_parsed_function()?;
        let function_args = if let Some(function_args) = request.function_parameters {
            function.decode_input(&zks_utils::encode_args(&function, &function_args)?)?
        } else {
            vec![]
        };

        let data = match (!function_args.is_empty(), is_precompile(request.to)) {
            // The contract to call is a precompile with arguments.
            (true, true) => encode(&function_args),
            // The contract to call is a regular contract with arguments.
            (true, false) => function.encode_input(&function_args)?,
            // The contract to call is a precompile without arguments.
            (false, true) => Default::default(),
            // The contract to call is a regular contract without arguments.
            (false, false) => function.short_signature().into(),
        };

        Ok(Eip1559TransactionRequest::new().to(request.to).data(data))
    }
}
