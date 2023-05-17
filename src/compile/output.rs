use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum ContractOutput {
    AbiCompiledOutput(AbiCompiledOutput),
    BinCompiledOutput(BinCompiledOutput)
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FunctionArgsTypesOutput {
    pub internal_type: String,
    pub name: String,
    #[serde(rename = "type")]
    pub sol_type: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ContractFunctionOutput {
    pub inputs: Vec<FunctionArgsTypesOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outputs: Option<Vec<FunctionArgsTypesOutput>>,
    pub state_mutability: String,
    #[serde(rename = "type")]
    pub sol_struct_type: String,
}

// TODO check correct fields of Factory Deps
#[derive(Serialize, Deserialize, Debug)]
pub struct FactoryDepsOutput {}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct AbiCompiledOutput {
    pub abi: Vec<ContractFunctionOutput>,
    pub factory_deps: FactoryDepsOutput,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct BinCompiledOutput {
    pub bin: String,
    pub factory_deps: FactoryDepsOutput,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ZKCompilationOutput {
    pub contracts: HashMap<String, ContractOutput>,
    pub version: String,
    pub zk_version: String,
}
