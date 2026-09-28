//! Share file format, (de)serialization, integrity checks and error types.
//!
//! # Wire format (all integers big-endian, fixed layout except the payload)
//!
//! ```text
//! offset   size        field
//! 0        4           magic            ASCII "LSSS"
//! 4        1           format_version   currently 1
//! 5        1           k                reconstruction threshold (2..=n)
//! 6        1           n                total number of shares (k..=255)
//! 7        2           secret_len S     original secret length, u16 BE
//! 9        1           index x          share x-coordinate, 1..=n
//! 10       32          session_id R     random 32-byte session identifier,
//!                                       ALSO the bytes that bind the
//!                                       commitment (it is split as part of
//!                                       the polynomial input)
//! 42       32          commitment       SHA-256(R)
//! 74       S + 32      payload y        share bytes for R || secret
//! 74+S+32  32          checksum         SHA-256 over everything above it
//! ```
//!
//! Total share size: `S + 138` bytes.
//!
//! # What the fields defend against
//!
//! * **checksum** — accidental corruption (and any tampering with a single
//!   share file), detected *before* interpolation.
//! * **session_id / commitment** — mixing shares from different splits and
//!   share-forging by an active holder: reconstruction only succeeds if the
//!   recovered `R` hashes to `commitment`, which an attacker cannot satisfy
//!   without knowing the random 32-byte `R`. See `README.md` for the exact
//!   security boundary.
//! * **index** — duplicate indices are rejected explicitly.
//! * **format_version** — files from an incompatible future/past version are
//!   rejected with a dedicated error.

use crate::rng;
use crate::sha256::{hash, Sha256};
use std::fmt;

pub const MAGIC: &[u8; 4] = b"LSSS";
pub const FORMAT_VERSION: u8 = 1;

/// Maximum supported secret size in bytes. The on-disk format stores the
/// length in a u16 and the tool targets small sensitive data, so the bound is
/// 65 535 bytes (the largest u16 value). This also keeps per-byte polynomial
/// work and share sizes predictable.
pub const MAX_SECRET_LEN: usize = 65_535;

/// Length of the random session value `R`.
pub const NONCE_LEN: usize = 32;
/// Length of the SHA-256 commitment / per-file checksum.
pub const TAG_LEN: usize = 32;

const HEADER_LEN: usize = MAGIC.len() + 1 + 1 + 1 + 2 + 1 + NONCE_LEN + TAG_LEN; // 74
/// Total non-secret bytes in a serialized share: header (74) + the 32-byte
/// nonce carried inside the payload + trailing checksum (32) = 138.
/// Share size = secret_len + FIXED_OVERHEAD.
const FIXED_OVERHEAD: usize = HEADER_LEN + NONCE_LEN + TAG_LEN; // 138

/// Errors produced by splitting, parsing and combining. Messages never contain
/// secret material (only metadata such as indices and lengths).
#[derive(Debug, PartialEq, Eq)]
pub enum SssError {
    /// Secret exceeds [`MAX_SECRET_LEN`].
    SecretTooLong(usize),
    /// k/n parameters were invalid (carries a human-readable reason).
    InvalidParameters(String),
    /// Operating-system entropy was unavailable.
    RngUnavailable(String),
    /// A share file's bytes do not parse or fail their checksum.
    CorruptedShare { index: Option<u16>, reason: String },
    /// The magic bytes do not match this tool's format.
    BadMagic,
    /// The file declares an unsupported format version.
    VersionMismatch(u8),
    /// Fewer than k structurally-valid shares were supplied.
    TooFewShares { have: usize, need: usize },
    /// Two shares carry the same x-coordinate.
    DuplicateIndex(u8),
    /// Shares do not belong together (differing headers/session ids).
    MixedShares(String),
    /// Reconstructed data failed the commitment check: at least one share was
    /// forged or the shares come from incompatible sessions.
    CommitmentCheckFailed,
    /// Local file I/O failure.
    Io(String),
}

impl fmt::Display for SssError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SssError::SecretTooLong(len) => write!(
                f,
                "secret is {len} bytes, maximum allowed is {MAX_SECRET_LEN}"
            ),
            SssError::InvalidParameters(reason) => write!(f, "invalid parameters: {reason}"),
            SssError::RngUnavailable(reason) => {
                write!(f, "secure randomness unavailable: {reason}")
            }
            SssError::CorruptedShare { index: Some(i), reason } => {
                write!(f, "share index {i} is corrupted: {reason}")
            }
            SssError::CorruptedShare { index: None, reason } => {
                write!(f, "share is corrupted: {reason}")
            }
            SssError::BadMagic => write!(f, "not a local-shamir share file (bad magic)"),
            SssError::VersionMismatch(v) => write!(
                f,
                "unsupported share format version {v} (supported: {FORMAT_VERSION})"
            ),
            SssError::TooFewShares { have, need } => {
                write!(f, "not enough shares: have {have}, need at least {need}")
            }
            SssError::DuplicateIndex(i) => write!(f, "duplicate share index {i}"),
            SssError::MixedShares(reason) => write!(f, "shares from different splits: {reason}"),
            SssError::CommitmentCheckFailed => write!(
                f,
                "reconstruction failed the commitment check: a share is forged or mismatched"
            ),
            SssError::Io(reason) => write!(f, "I/O error: {reason}"),
        }
    }
}

impl std::error::Error for SssError {}

/// A byte buffer that is overwritten with zeros when dropped, limiting the
/// lifetime of secret material in memory. Best-effort: it cannot erase copies
/// the allocator or compiler placed elsewhere (e.g. stack temporaries); the
/// crate is written to avoid extra heap copies of the secret.
pub struct ZeroizingBytes(pub Vec<u8>);

impl fmt::Debug for ZeroizingBytes {
    /// Redacting: never prints the contained bytes, only their count.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ZeroizingBytes(<{} redacted bytes>)", self.0.len())
    }
}

impl Drop for ZeroizingBytes {
    fn drop(&mut self) {
        // SAFETY: the slice is fully initialized (it is the Vec's own
        // allocation); we only overwrite bytes, never observe them
        // uninitialized, and Vec's own drop then frees the memory normally.
        unsafe {
            std::ptr::write_bytes(self.0.as_mut_ptr(), 0, self.0.len());
        }
    }
}

impl std::ops::Deref for ZeroizingBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for ZeroizingBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Parameters and identifying header shared by every share of one split.
#[derive(Clone, PartialEq, Eq)]
pub struct ShareHeader {
    pub version: u8,
    pub k: u8,
    pub n: u8,
    pub secret_len: u16,
    pub index: u8,
    pub session_id: [u8; NONCE_LEN],
    pub commitment: [u8; TAG_LEN],
}

impl fmt::Debug for ShareHeader {
    /// Redacts the session id and commitment; metadata-only fields are shown.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShareHeader")
            .field("version", &self.version)
            .field("k", &self.k)
            .field("n", &self.n)
            .field("secret_len", &self.secret_len)
            .field("index", &self.index)
            .field("session_id", &"<redacted>")
            .field("commitment", &"<redacted>")
            .finish()
    }
}

/// One share. The `payload` is sensitive (it is a point on the secret-bearing
/// polynomial), so [`Share`]'s `Debug` implementation deliberately omits it.
pub struct Share {
    pub header: ShareHeader,
    pub payload: Vec<u8>,
}

impl fmt::Debug for Share {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Share")
            .field("version", &self.header.version)
            .field("k", &self.header.k)
            .field("n", &self.header.n)
            .field("secret_len", &self.header.secret_len)
            .field("index", &self.header.index)
            .field("session_id", &"<redacted>")
            .field("commitment", &"<redacted>")
            .field("payload", &"<redacted>")
            .finish()
    }
}

impl Share {
    /// Serialize the share to its on-disk byte representation.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len() + TAG_LEN);
        out.extend_from_slice(MAGIC);
        out.push(self.header.version);
        out.push(self.header.k);
        out.push(self.header.n);
        out.extend_from_slice(&self.header.secret_len.to_be_bytes());
        out.push(self.header.index);
        out.extend_from_slice(&self.header.session_id);
        out.extend_from_slice(&self.header.commitment);
        out.extend_from_slice(&self.payload);
        let checksum = hash(&out);
        out.extend_from_slice(&checksum);
        out
    }

    /// Parse a share, fully validating structure and checksum. On a parse
    /// failure before the index is known, `index` is `None`.
    pub fn from_bytes(data: &[u8]) -> Result<Share, SssError> {
        if data.len() < FIXED_OVERHEAD {
            return Err(SssError::CorruptedShare {
                index: None,
                reason: format!("file too short ({} bytes)", data.len()),
            });
        }
        if &data[0..4] != MAGIC {
            return Err(SssError::BadMagic);
        }
        let version = data[4];
        if version != FORMAT_VERSION {
            return Err(SssError::VersionMismatch(version));
        }
        let k = data[5];
        let n = data[6];
        let secret_len = u16::from_be_bytes([data[7], data[8]]);
        let index = data[9];

        let structural = |reason: String| SssError::CorruptedShare {
            index: Some(index as u16),
            reason,
        };

        if !(2..=255).contains(&k) || n < k || !(1..=255).contains(&n) {
            return Err(structural(format!("bad k/n header: k={k} n={n}")));
        }
        if index == 0 || index > n {
            return Err(structural(format!("index {index} outside 1..=n ({n})")));
        }
        if secret_len as usize > MAX_SECRET_LEN {
            return Err(structural(format!("declared secret length {secret_len} exceeds limit")));
        }
        let payload_len = secret_len as usize + NONCE_LEN;
        let expected_len = HEADER_LEN + payload_len + TAG_LEN;
        if data.len() != expected_len {
            return Err(structural(format!(
                "length {} inconsistent with declared payload length {}",
                data.len(),
                expected_len
            )));
        }

        // Checksum before any field is trusted further.
        let (body, tag) = data.split_at(data.len() - TAG_LEN);
        let actual = hash(body);
        if !ct_eq(&actual, tag) {
            return Err(structural("integrity checksum mismatch".into()));
        }

        let mut session_id = [0u8; NONCE_LEN];
        session_id.copy_from_slice(&data[10..10 + NONCE_LEN]);
        let mut commitment = [0u8; TAG_LEN];
        commitment.copy_from_slice(&data[10 + NONCE_LEN..HEADER_LEN]);

        Ok(Share {
            header: ShareHeader {
                version,
                k,
                n,
                secret_len,
                index,
                session_id,
                commitment,
            },
            payload: data[HEADER_LEN..HEADER_LEN + payload_len].to_vec(),
        })
    }

    /// Hash everything except the trailing checksum — used internally by
    /// [`Share::to_bytes`] and exposed for tests/tooling.
    pub fn body_hash(&self) -> [u8; TAG_LEN] {
        let mut h = Sha256::new();
        h.update(MAGIC);
        h.update(&[self.header.version, self.header.k, self.header.n]);
        h.update(&self.header.secret_len.to_be_bytes());
        h.update(&[self.header.index]);
        h.update(&self.header.session_id);
        h.update(&self.header.commitment);
        h.update(&self.payload);
        h.finish()
    }
}

/// Validate caller-supplied `(k, n)`.
pub fn validate_params(k: u8, n: u8) -> Result<(), SssError> {
    if !(1..=255).contains(&n) {
        return Err(SssError::InvalidParameters(format!("n must be in 1..=255, got {n}")));
    }
    if k < 2 {
        return Err(SssError::InvalidParameters(format!(
            "threshold k must be at least 2, got {k}"
        )));
    }
    if k > n {
        return Err(SssError::InvalidParameters(format!(
            "threshold k ({k}) cannot exceed number of shares n ({n})"
        )));
    }
    Ok(())
}

/// Generate a fresh random nonce `R`.
pub fn random_nonce() -> Result<[u8; NONCE_LEN], SssError> {
    let mut r = [0u8; NONCE_LEN];
    rng::fill(&mut r).map_err(SssError::RngUnavailable)?;
    Ok(r)
}

/// Constant-time equality for fixed-length tags.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
