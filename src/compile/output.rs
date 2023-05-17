use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct ContractOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    abi: Option<ContractFunctionOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    devdoc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    userdoc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "kebab-case")]
    storage_layout: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ast: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    asm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "kebab-case")]
    bin_runtime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hashes: Option<HashMap<String, String>>,
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
