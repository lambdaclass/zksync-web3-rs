use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct ContractOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    abi: Option<Vec<ContractFunctionOutput>>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    factory_deps: Option<HashMap<String, String>>,
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

#[derive(Serialize, Deserialize, Debug)]
pub struct ZKCompilationOutput {
    pub contracts: HashMap<String, ContractOutput>,
    pub version: String,
    pub zk_version: String,
}
