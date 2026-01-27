//! # Kobe - Lightweight Multi-Chain Wallet Core Library
//!
//! A modern, `no_std` compatible wallet library providing core cryptographic
//! primitives and traits for building cryptocurrency wallets.
//!
//! ## Features
//!
//! - **no_std compatible**: Works in embedded and WASM environments
//! - **Modern cryptography**: Uses k256, sha3, and other audited libraries
//! - **Secure by design**: Zeroize secrets, constant-time operations
//! - **Minimal dependencies**: Lightweight and fast compilation

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    clippy::all,
    clippy::pedantic,
    clippy::nursery
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::missing_const_for_fn,
    clippy::use_self,
    clippy::uninlined_format_args,
    clippy::return_self_not_must_use,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::cast_lossless,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::cognitive_complexity,
    clippy::many_single_char_names,
    clippy::redundant_closure_for_method_calls,
    clippy::option_if_let_else,
    clippy::needless_pass_by_value,
    clippy::format_push_string,
    clippy::unnecessary_wraps,
    clippy::implicit_clone,
    clippy::items_after_statements,
    clippy::struct_field_names,
    clippy::unreadable_literal,
    clippy::missing_fields_in_debug
)]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod encoding;
pub mod error;
pub mod hash;
pub mod traits;
pub mod transaction;
pub mod types;

pub use error::{Error, Result};
pub use traits::*;
pub use transaction::{Eip1559TxParams, EthTxParams, SigHashType, TxInput, TxOutput};
pub use types::*;

// Re-export rand_core from k256 for consistent RNG trait versions
pub use k256::elliptic_curve::rand_core;
