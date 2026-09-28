//! Core Shamir Secret Sharing logic over GF(2^8).
//!
//! Each *byte* of the secret is treated independently as the constant term of
//! a random degree-(k-1) polynomial over GF(2^8); the share byte at index i is
//! that polynomial evaluated at i. Reconstruction is byte-wise Lagrange
//! interpolation at x = 0. No floating-point arithmetic is used anywhere.

use crate::error::{Result, SssError};
use crate::gf256;
use crate::rng::Rng;
use crate::share::Share;

/// Maximum supported secret size: 64 KiB.
///
/// The tool targets *small* sensitive values (keys, seeds, passwords, short
/// documents). The bound caps memory use and share size (every share is the
/// same size as the secret); it is enforced on both split and combine.
pub const MAX_SECRET_LEN: usize = 64 * 1024;

/// Maximum number of shares. GF(2^8) provides x-coordinates 1..=255.
pub const MAX_SHARES: u8 = 255;

/// A byte buffer holding secret material that zeroizes its contents on drop
/// and never exposes them through Debug/Display.
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(v: Vec<u8>) -> Self {
        SecretBytes(v)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consume the wrapper, returning the inner vector (caller is then
    /// responsible for its lifetime).
    pub fn into_vec(self) -> Vec<u8> {
        // Move out without running Drop's zeroization: ManuallyDrop would be
        // equivalent; here we use a short-lived owned transfer.
        let inner = std::mem::ManuallyDrop::new(self);
        // SAFETY: inner is a valid SecretBytes and is never dropped, so its
        // unique Vec is read exactly once.
        unsafe { std::ptr::read(&inner.0) }
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        // Best-effort zeroization via a volatile write so the compiler cannot
        // elide it as a dead store. The references are valid and aligned.
        for b in self.0.iter_mut() {
            // SAFETY: `b` is a valid, aligned, exclusive &mut u8.
            unsafe { std::ptr::write_volatile(b as *mut u8, 0) };
        }
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes([{} bytes redacted])", self.0.len())
    }
}

/// Validate the (k, n) parameter pair.
pub fn validate_params(k: u8, n: u8) -> Result<()> {
    if k == 0 || n == 0 {
        return Err(SssError::BadParams("k and n must be >= 1".into()));
    }
    if k > n {
        return Err(SssError::BadParams(format!(
            "threshold k={k} cannot exceed total shares n={n}"
        )));
    }
    if n > MAX_SHARES {
        return Err(SssError::BadParams(format!(
            "n={n} exceeds maximum {MAX_SHARES} (GF(2^8) has 255 non-zero coordinates)"
        )));
    }
    Ok(())
}

/// Split `secret` into `n` shares, any `k` of which reconstruct it.
///
/// Randomness is taken from `rng`; production callers pass
/// [`crate::rng::OsRng`]. Returns one [`Share`] per index 1..=n in order.
pub fn split_secret<R: Rng>(secret: &[u8], k: u8, n: u8, rng: &mut R) -> Result<Vec<Share>> {
    validate_params(k, n)?;
    if secret.len() > MAX_SECRET_LEN {
        return Err(SssError::SecretTooLarge(secret.len()));
    }

    let mut session_id = [0u8; crate::share::SESSION_LEN];
    rng.fill(&mut session_id)?;

    // k=1 has no random coefficients: each byte polynomial is constant,
    // every share equals the secret.
    let coeff_count = k as usize;
    // coeffs[b] = [secret_byte, a_1, ..., a_{k-1}] for the current secret
    // byte; rewritten for each byte.
    let mut coeffs = vec![0u8; coeff_count];
    // rows[i] holds the y bytes of the share with index i+1.
    let mut rows = vec![vec![0u8; secret.len()]; n as usize];

    for (b, &secret_byte) in secret.iter().enumerate() {
        coeffs[0] = secret_byte;
        if coeff_count > 1 {
            rng.fill(&mut coeffs[1..])?;
        }
        for idx in 1..=n {
            rows[(idx - 1) as usize][b] = gf256::eval_poly(&coeffs, idx);
        }
    }

    let shares = (1..=n)
        .map(|idx| Share {
            version: crate::share::FORMAT_VERSION,
            threshold: k,
            n,
            index: idx,
            session_id,
            y: std::mem::take(&mut rows[(idx - 1) as usize]),
        })
        .collect();

    // zeroize transient coefficient/row scratch.
    for c in coeffs.iter_mut() {
        // SAFETY: valid aligned &mut u8 in a local Vec.
        unsafe { std::ptr::write_volatile(c as *mut u8, 0) };
    }
    for row in rows.iter_mut() {
        for b in row.iter_mut() {
            // SAFETY: valid aligned &mut u8 in a local Vec.
            unsafe { std::ptr::write_volatile(b as *mut u8, 0) };
        }
    }

    Ok(shares)
}

/// Reconstruct the secret from `shares`.
///
/// Every share is checksum-verified on parsing; this function additionally
/// enforces:
/// * no duplicate indices,
/// * all shares belong to the same split (session id),
/// * all shares agree on k/n and secret length,
/// * at least k shares are present.
///
/// More than k shares are accepted and any subset works (Lagrange
/// interpolation is run over the supplied set).
pub fn combine_shares(shares: &[Share]) -> Result<SecretBytes> {
    if shares.is_empty() {
        return Err(SssError::NotEnoughShares { have: 0, need: 1 });
    }

    let first = &shares[0];
    let k = first.threshold;
    let n = first.n;
    let secret_len = first.y.len();

    if shares.len() < k as usize {
        return Err(SssError::NotEnoughShares {
            have: shares.len(),
            need: k as usize,
        });
    }

    let mut seen = [false; 256];
    for s in shares {
        if s.version != crate::share::FORMAT_VERSION {
            return Err(SssError::UnsupportedVersion(s.version));
        }
        if s.index < 1 || s.index > n {
            return Err(SssError::BadIndex(s.index));
        }
        if seen[s.index as usize] {
            return Err(SssError::DuplicateIndex(s.index));
        }
        seen[s.index as usize] = true;

        if s.session_id != first.session_id {
            return Err(SssError::SessionMismatch {
                first: first.index,
                other: s.index,
            });
        }
        if s.threshold != k || s.n != n {
            return Err(SssError::ParameterMismatch(format!(
                "share {} declares k={},n={} but share {} declares k={k},n={n}",
                s.index, s.threshold, s.n, first.index
            )));
        }
        if s.y.len() != secret_len {
            return Err(SssError::ParameterMismatch(format!(
                "share {} has {} data bytes, expected {secret_len}",
                s.index,
                s.y.len()
            )));
        }
    }

    let m = shares.len();
    let coords: Vec<u8> = shares.iter().map(|s| s.index).collect();
    let mut points = vec![(0u8, 0u8); m];
    let mut out = vec![0u8; secret_len];
    for b in 0..secret_len {
        for (i, s) in shares.iter().enumerate() {
            points[i] = (coords[i], s.y[b]);
        }
        // guaranteed Some: indices were checked pairwise distinct.
        out[b] = gf256::interpolate_zero(&points)
            .expect("distinct indices verified above make interpolation always defined");
    }

    // coords/points hold no secret-byte material beyond one column at a
    // time; zeroize them defensively before returning.
    for p in points.iter_mut() {
        // SAFETY: valid aligned &mut in a local Vec.
        unsafe { std::ptr::write_volatile(p as *mut (u8, u8), (0, 0)) };
    }

    Ok(SecretBytes::new(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::DeterministicRng;

    fn drng(seed: u8) -> DeterministicRng {
        DeterministicRng::new(&[seed])
    }

    #[test]
    fn param_validation() {
        assert!(validate_params(0, 0).is_err());
        assert!(validate_params(3, 2).is_err());
        assert!(validate_params(1, 1).is_ok());
        assert!(validate_params(255, 255).is_ok());
    }

    #[test]
    fn size_limit_enforced() {
        let big = vec![0u8; MAX_SECRET_LEN + 1];
        assert!(matches!(
            split_secret(&big, 2, 3, &mut drng(1)),
            Err(SssError::SecretTooLarge(_))
        ));
        // exactly at the boundary is allowed
        let max = vec![0u8; MAX_SECRET_LEN];
        assert!(split_secret(&max, 2, 3, &mut drng(1)).is_ok());
    }

    #[test]
    fn empty_secret_roundtrips() {
        let shares = split_secret(&[], 3, 5, &mut drng(9)).unwrap();
        assert_eq!(shares.len(), 5);
        let rec = combine_shares(&shares[..3]).unwrap();
        assert!(rec.is_empty());
    }

    #[test]
    fn threshold_one_shares_equal_secret() {
        let secret = b"k=1 means no randomness at all";
        let shares = split_secret(secret, 1, 4, &mut drng(2)).unwrap();
        for s in &shares {
            assert_eq!(s.y, secret);
        }
        let rec = combine_shares(&shares[..1]).unwrap();
        assert_eq!(rec.as_slice(), secret);
    }

    #[test]
    fn k_equals_n_needs_all() {
        let secret: Vec<u8> = (0..=255u16).map(|i| i as u8).collect();
        let shares = split_secret(&secret, 4, 4, &mut drng(3)).unwrap();
        // any 3 fail with NotEnoughShares
        let err = combine_shares(&shares[..3]).unwrap_err();
        assert!(matches!(
            err,
            SssError::NotEnoughShares { have: 3, need: 4 }
        ));
        // all 4 recover
        let rec = combine_shares(&shares).unwrap();
        assert_eq!(rec.as_slice(), secret);
    }

    /// Exhaustively check every subset of size >= k for a small scheme.
    #[test]
    fn every_quorum_subset_reconstructs() {
        let secret: Vec<u8> = vec![0x00, 0x01, 0x7F, 0x80, 0xFF, 0xAB, 0xCD];
        let (k, n) = (3u8, 5u8);
        let shares = split_secret(&secret, k, n, &mut drng(4)).unwrap();

        let mut mask: u32 = 0;
        while mask < 1u32 << n {
            let chosen: Vec<&Share> = shares
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, s)| s)
                .collect();
            if chosen.len() >= k as usize {
                let owned: Vec<Share> = chosen.into_iter().cloned().collect();
                let rec = combine_shares(&owned).unwrap();
                assert_eq!(rec.as_slice(), secret, "mask {mask:05b} failed");
            }
            mask += 1;
        }
    }

    /// Deterministic split must place different random polynomials for
    /// different secrets, and repeated splits of the same secret differ.
    #[test]
    fn randomized_polynomials_differ_per_split() {
        let secret = b"same input";
        let a = split_secret(secret, 3, 5, &mut drng(10)).unwrap();
        let b = split_secret(secret, 3, 5, &mut drng(11)).unwrap();
        assert_ne!(a[0].y, b[0].y);
        // session ids random too
        assert_ne!(a[0].session_id, b[0].session_id);
        // but both still reconstruct
        assert_eq!(combine_shares(&a[..3]).unwrap().as_slice(), secret);
        assert_eq!(combine_shares(&b[..3]).unwrap().as_slice(), secret);
    }

    #[test]
    fn combine_rejects_duplicate_index() {
        let secret = b"dup test";
        let mut shares = split_secret(secret, 2, 3, &mut drng(5)).unwrap();
        shares[1] = shares[0].clone();
        assert!(matches!(
            combine_shares(&shares),
            Err(SssError::DuplicateIndex(1))
        ));
    }

    #[test]
    fn combine_rejects_mixed_sessions() {
        let s1 = split_secret(b"secret one", 2, 3, &mut drng(6)).unwrap();
        let s2 = split_secret(b"secret two", 2, 3, &mut drng(7)).unwrap();
        let mixed = vec![s1[0].clone(), s2[1].clone()];
        assert!(matches!(
            combine_shares(&mixed),
            Err(SssError::SessionMismatch { .. })
        ));
    }

    #[test]
    fn combine_rejects_tampered_y() {
        let secret: Vec<u8> = (0..100u8).collect();
        let shares = split_secret(&secret, 3, 5, &mut drng(8)).unwrap();
        // tamper at the wire level so the checksum catches it
        let mut raw = shares[2].to_bytes();
        raw[crate::share::PREFIX_LEN + 10] ^= 0xFF;
        let parsed = Share::from_bytes(&raw);
        assert!(matches!(
            parsed,
            Err(SssError::ChecksumFailed { index: 3 })
        ));
    }

    #[test]
    fn combine_rejects_parameter_mismatch() {
        let s1 = split_secret(b"abc", 2, 3, &mut drng(12)).unwrap();
        let s2 = split_secret(b"abcd", 2, 3, &mut drng(13)).unwrap();
        // Forge a different-length share so it: distinct index (avoids
        // DuplicateIndex), matching session id, different data length.
        let mut forged = s2[1].clone();
        forged.session_id = s1[0].session_id;
        let mixed = vec![s1[0].clone(), forged];
        assert!(matches!(
            combine_shares(&mixed),
            Err(SssError::ParameterMismatch(_))
        ));
    }

    #[test]
    fn maximal_params_255_of_255_roundtrip() {
        // Exercises every non-zero GF(2^8) x-coordinate 1..=255, including
        // interpolation across 255 points (degree-254 polynomials).
        let secret: Vec<u8> = vec![0x00, 0x80, 0xFF, 0xA5];
        let shares = split_secret(&secret, 255, 255, &mut drng(14)).unwrap();
        assert_eq!(shares.len(), 255);
        assert!(shares.iter().all(|s| s.index >= 1));
        let rec = combine_shares(&shares).unwrap();
        assert_eq!(rec.as_slice(), secret);
        // exactly 254 shares must be refused
        let err = combine_shares(&shares[..254]).unwrap_err();
        assert!(matches!(
            err,
            SssError::NotEnoughShares { have: 254, need: 255 }
        ));
    }
}
