//! Crate-wide error type. Every failure mode of split/combine has its own
//! variant so callers (and tests) can distinguish "not enough shares" from
//! "corrupt share" etc.

use std::fmt;

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, SssError>;

/// All errors the library can produce.
#[derive(Debug)]
pub enum SssError {
    /// Requested parameters are invalid (e.g. k > n, n > 255).
    BadParams(String),
    /// Secret exceeds [`crate::sss::MAX_SECRET_LEN`] or is otherwise invalid.
    SecretTooLarge(usize),
    /// Secure randomness could not be obtained.
    Rng(String),
    /// Fewer than k valid shares were supplied for reconstruction.
    NotEnoughShares { have: usize, need: usize },
    /// Two supplied shares carry the same share index.
    DuplicateIndex(u8),
    /// Shares were generated in different split operations / for different
    /// secrets (their random session identifiers differ).
    SessionMismatch { first: u8, other: u8 },
    /// Shares agree on session but disagree on fixed parameters
    /// (version/threshold/secret length).
    ParameterMismatch(String),
    /// Share declares a format version this build cannot parse.
    UnsupportedVersion(u8),
    /// A share file is truncated or structurally malformed.
    MalformedShare(String),
    /// The embedded SHA-256 checksum does not match the share contents.
    ChecksumFailed { index: u8 },
    /// A share index is outside the valid range 1..=n.
    BadIndex(u8),
    /// Local file I/O failure.
    Io(std::io::Error),
}

impl fmt::Display for SssError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SssError::BadParams(s) => write!(f, "invalid parameters: {s}"),
            SssError::SecretTooLarge(len) => write!(
                f,
                "secret is {len} bytes, maximum allowed is {} bytes",
                crate::sss::MAX_SECRET_LEN
            ),
            SssError::Rng(s) => write!(f, "secure randomness unavailable: {s}"),
            SssError::NotEnoughShares { have, need } => write!(
                f,
                "not enough shares: have {have}, need at least {need} — \
                 reconstruction refused (no partial secret is returned)"
            ),
            SssError::DuplicateIndex(i) => {
                write!(f, "duplicate share index {i}; each share may be used at most once")
            }
            SssError::SessionMismatch { first, other } => write!(
                f,
                "share set mixes shares from different split operations \
                 (session ids differ: share {first} vs share {other})"
            ),
            SssError::ParameterMismatch(s) => write!(f, "inconsistent share parameters: {s}"),
            SssError::UnsupportedVersion(v) => {
                write!(f, "unsupported share format version {v} (supported: 1)")
            }
            SssError::MalformedShare(s) => write!(f, "malformed share: {s}"),
            SssError::ChecksumFailed { index } => {
                write!(f, "share {index} failed integrity check: contents are corrupt or tampered")
            }
            SssError::BadIndex(i) => write!(f, "share index {i} is outside the valid range 1..=n"),
            SssError::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for SssError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SssError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for SssError {
    fn from(e: std::io::Error) -> Self {
        SssError::Io(e)
    }
}

impl From<crate::rng::RngError> for SssError {
    fn from(e: crate::rng::RngError) -> Self {
        SssError::Rng(e.0)
    }
}
