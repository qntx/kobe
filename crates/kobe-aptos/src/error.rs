//! Error types for Aptos wallet operations.
//!
//! Aptos derivation never produces chain-specific failures beyond what
//! [`kobe_primitives::DeriveError`] already covers, so the core error type
//! is re-exported directly to avoid a redundant wrapper enum.

pub use kobe_primitives::DeriveError;
