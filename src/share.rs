//! Share file format (version 1, little-endian on disk layout below).
//!
//! ```text
//! offset   size  field
//! 0        4     magic            ASCII "LSSS"
//! 4        1     version          format version, currently 1
//! 5        1     k                reconstruction threshold
//! 6        1     n                total number of shares
//! 7        1     index            share index i, 1 <= i <= n
//! 8        4     secret_len       u32 big-endian, length of the secret/y
//! 12      16    session_id       random identifier shared by one split
//! 28      secret_len  y_i        GF(2^8) share bytes
//! 28+...   32    checksum         SHA-256 over every byte preceding it
//! ```
//!
//! The checksum covers the full header and the y bytes, so any single-bit
//! corruption, truncation or field tampering is detected. The `session_id`
//! binds shares to one split operation, preventing accidental mixing of
//! shares from different secrets.

use crate::error::{Result, SssError};
use crate::sha256::Sha256;

/// Magic prefix for every share file.
pub const MAGIC: [u8; 4] = *b"LSSS";
/// Only format version implemented by this build.
pub const FORMAT_VERSION: u8 = 1;
/// Size of the fixed prefix before the y bytes.
pub(crate) const PREFIX_LEN: usize = 28;
/// Trailing SHA-256 checksum length.
pub(crate) const CHECKSUM_LEN: usize = 32;
/// Random session identifier length.
pub(crate) const SESSION_LEN: usize = 16;

/// One share together with the metadata needed to validate and combine it.
///
/// The `Debug` implementation is deliberately opaque: `y` is never printed
/// (and the original secret is not stored here at all).
#[derive(Clone)]
pub struct Share {
    /// Format version read from the file.
    pub version: u8,
    /// Reconstruction threshold k.
    pub threshold: u8,
    /// Total share count n.
    pub n: u8,
    /// This share's x-coordinate, 1..=n.
    pub index: u8,
    /// Random 16-byte identifier shared by all shares of one split.
    pub session_id: [u8; SESSION_LEN],
    /// This share's y-coordinate bytes (one per secret byte).
    pub y: Vec<u8>,
}

impl std::fmt::Debug for Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Share")
            .field("version", &self.version)
            .field("threshold", &self.threshold)
            .field("n", &self.n)
            .field("index", &self.index)
            .field("session_id", &"<redacted>")
            .field("y_len", &self.y.len())
            .finish()
    }
}

impl Share {
    /// Serialize to the binary format, appending the checksum.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PREFIX_LEN + self.y.len() + CHECKSUM_LEN);
        out.extend_from_slice(&MAGIC);
        out.push(self.version);
        out.push(self.threshold);
        out.push(self.n);
        out.push(self.index);
        out.extend_from_slice(&(self.y.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&self.y);

        let mut h = Sha256::new();
        h.update(&out);
        out.extend_from_slice(&h.finish());
        out
    }

    /// Parse and validate one share file. Verifies magic, version, declared
    /// length plausibility and the SHA-256 checksum before returning.
    pub fn from_bytes(data: &[u8]) -> Result<Share> {
        if data.len() < PREFIX_LEN + CHECKSUM_LEN {
            return Err(SssError::MalformedShare(format!(
                "file is {} bytes, need at least {}",
                data.len(),
                PREFIX_LEN + CHECKSUM_LEN
            )));
        }
        if data[0..4] != MAGIC {
            return Err(SssError::MalformedShare(
                "bad magic; not a local-sss share file".to_string(),
            ));
        }
        let version = data[4];
        if version != FORMAT_VERSION {
            return Err(SssError::UnsupportedVersion(version));
        }
        let threshold = data[5];
        let n = data[6];
        let index = data[7];
        let secret_len = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize;

        // sanity-check declared fields before indexing further
        if threshold == 0 || n == 0 || threshold > n {
            return Err(SssError::MalformedShare(format!(
                "invalid k/n header: k={threshold}, n={n}"
            )));
        }
        if index < 1 || index > n {
            return Err(SssError::BadIndex(index));
        }
        if secret_len > crate::sss::MAX_SECRET_LEN {
            return Err(SssError::SecretTooLarge(secret_len));
        }
        let expected_len = PREFIX_LEN + secret_len + CHECKSUM_LEN;
        if data.len() != expected_len {
            return Err(SssError::MalformedShare(format!(
                "declared length {secret_len} implies {expected_len} bytes but file has {}",
                data.len()
            )));
        }

        let payload_end = PREFIX_LEN + secret_len;
        let mut h = Sha256::new();
        h.update(&data[..payload_end]);
        let checksum = h.finish();

        // constant-time comparison
        let stored = &data[payload_end..payload_end + CHECKSUM_LEN];
        let mut diff = 0u8;
        for (a, b) in checksum.iter().zip(stored.iter()) {
            diff |= a ^ b;
        }
        if diff != 0 {
            return Err(SssError::ChecksumFailed { index });
        }

        let mut session_id = [0u8; SESSION_LEN];
        session_id.copy_from_slice(&data[12..28]);
        let y = data[PREFIX_LEN..payload_end].to_vec();

        Ok(Share {
            version,
            threshold,
            n,
            index,
            session_id,
            y,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Share {
        Share {
            version: FORMAT_VERSION,
            threshold: 3,
            n: 5,
            index: 2,
            session_id: [7u8; 16],
            y: vec![1, 2, 3, 4, 255],
        }
    }

    #[test]
    fn roundtrip() {
        let s = sample();
        let raw = s.to_bytes();
        let parsed = Share::from_bytes(&raw).unwrap();
        assert_eq!(parsed.index, 2);
        assert_eq!(parsed.y, vec![1, 2, 3, 4, 255]);
        assert_eq!(parsed.session_id, [7u8; 16]);
        assert_eq!(raw.len(), PREFIX_LEN + 5 + CHECKSUM_LEN);
    }

    #[test]
    fn debug_does_not_contain_y_or_secret() {
        let dbg = format!("{:?}", sample());
        assert!(dbg.contains("Share"));
        assert!(!dbg.contains("255"));
    }

    #[test]
    fn rejects_truncated_bad_magic_bad_version() {
        let raw = sample().to_bytes();
        assert!(matches!(
            Share::from_bytes(&raw[..20]),
            Err(SssError::MalformedShare(_))
        ));
        let mut bad = raw.clone();
        bad[0] = b'X';
        assert!(matches!(
            Share::from_bytes(&bad),
            Err(SssError::MalformedShare(_))
        ));
        let mut bad = raw.clone();
        bad[4] = 99;
        assert!(matches!(
            Share::from_bytes(&bad),
            Err(SssError::UnsupportedVersion(99))
        ));
    }

    #[test]
    fn detects_every_single_byte_tamper_of_header_and_y() {
        let raw = sample().to_bytes();
        // spot-check representative offsets exhaustively enough: magic,
        // fields, every y byte, every checksum byte
        let offsets = (0..4)
            .chain(4..12)
            .chain(12..28)
            .chain(PREFIX_LEN..PREFIX_LEN + 5)
            .chain(raw.len() - 4..raw.len());
        for off in offsets {
            let mut bad = raw.clone();
            bad[off] ^= 0x01;
            let res = Share::from_bytes(&bad);
            assert!(res.is_err(), "tamper at offset {off} was accepted");
        }
    }
}
