//! # local-shamir
//!
//! A fully **local** Shamir Secret Sharing tool. Splits small binary secrets
//! into `n` shares, any `k` of which reconstruct the original byte-for-byte,
//! using exact arithmetic over GF(2^8) — never floating point. Everything
//! (secret, shares, metadata, randomness, hashing) stays on the local machine;
//! there is no KMS, Vault, network key service or any other external
//! dependency (the crate itself depends only on the Rust standard library).
//!
//! See `README.md` for the mathematical model, file format and security
//! boundaries.
//!
//! ## Example
//!
//! ```
//! use local_shamir::{split, combine};
//!
//! let secret = b"hunter2-but-binary-\x00\xff\xfe";
//! let shares = split(secret, 3, 5).unwrap();
//! assert_eq!(shares.len(), 5);
//!
//! // Any 3 of the 5 shares recover the identical secret.
//! let subset = vec![shares[0].clone_share(), shares[2].clone_share(), shares[4].clone_share()];
//! let recovered = combine(&subset).unwrap();
//! assert_eq!(&recovered[..], secret);
//! ```

pub mod gf256;
pub mod rng;
pub mod sha256;
pub mod share;
pub mod shamir;

pub use share::{
    validate_params, Share, ShareHeader, SssError, ZeroizingBytes, FORMAT_VERSION, MAX_SECRET_LEN,
};
pub use shamir::{combine, split};

impl Share {
    /// Clone a share. Kept as an explicit method rather than a `Clone` derive:
    /// share payloads are sensitive and call sites should opt in.
    pub fn clone_share(&self) -> Share {
        Share { header: self.header.clone(), payload: self.payload.clone() }
    }
}

#[cfg(test)]
mod tests;
