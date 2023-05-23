#![warn(warnings, rust_2018_idioms)]
#![forbid(unsafe_code)]
#![recursion_limit = "256"]
#![warn(
    clippy::allow_attributes_without_reason,
    clippy::as_conversions,
    clippy::as_ptr_cast_mut,
    clippy::unnecessary_cast,
    clippy::clone_on_ref_ptr,
    clippy::create_dir,
    clippy::dbg_macro,
    clippy::decimal_literal_representation,
    clippy::default_numeric_fallback,
    clippy::deref_by_slicing,
    clippy::empty_structs_with_brackets,
    clippy::float_cmp_const,
    clippy::fn_to_numeric_cast_any,
    clippy::indexing_slicing,
    clippy::iter_kv_map,
    clippy::manual_clamp,
    clippy::manual_filter,
    clippy::map_err_ignore,
    clippy::uninlined_format_args,
    clippy::unseparated_literal_suffix,
    clippy::unused_format_specs,
    clippy::single_char_lifetime_names,
    clippy::str_to_string,
    clippy::string_add,
    clippy::string_slice,
    clippy::string_to_string,
    clippy::todo,
    clippy::try_err
)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![allow(
    clippy::module_inception,
    clippy::module_name_repetitions,
    clippy::let_underscore_must_use
)]

pub use ethers::addressbook;
pub use ethers::contract;
pub use ethers::etherscan;
pub use ethers::middleware;
pub use ethers::providers;
pub use ethers::signers;
pub use ethers::solc;
pub use ethers::{
    core,
    core::{abi, types, utils},
};

/// Easy imports of frequently used type definitions and traits.
pub mod prelude {
    pub use super::addressbook::contract;

    pub use super::contract::*;

    pub use super::core::{types::*, *};

    pub use super::etherscan::*;

    pub use super::middleware::*;

    pub use super::providers::*;

    pub use super::signers::*;

    pub use super::solc::*;
}

// TODO: This should be visible only for this crate and not for the library users.
pub mod cli;
pub mod compile;
pub mod eip712;
pub mod zks_provider;
pub mod zks_utils;

// For macro expansions only, not public API.
#[allow(unused_extern_crates)]
extern crate self as zkethers;
