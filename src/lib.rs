//! # local-sss
//!
//! A fully local, dependency-free implementation of Shamir's Secret Sharing
//! over GF(2^8) for small binary secrets. See the repository README for the
//! mathematical model, file format and security boundaries.

pub mod error;
pub mod gf256;
pub mod rng;
pub mod sha256;
pub mod share;
pub mod sss;

pub use error::{Result, SssError};
pub use rng::OsRng;
pub use share::Share;
pub use sss::{combine_shares, split_secret, validate_params, SecretBytes, MAX_SECRET_LEN, MAX_SHARES};
