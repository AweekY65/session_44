//! Shamir Secret Sharing over GF(2^8): share generation and threshold
//! reconstruction by exact Lagrange interpolation.
//!
//! ## Model
//!
//! For a byte string `M = R || secret` (a random 32-byte nonce followed by the
//! secret) and parameters `(k, n)`, each *byte position* `p` of `M` gets its
//! own random polynomial over GF(2^8):
//!
//! ```text
//! f_p(x) = M[p] + a_{p,1} x + ... + a_{p,k-1} x^{k-1},   a_{p,i} <-- CSPRNG
//! ```
//!
//! Share `j` (x-coordinate `j` in `1..=n`) is the byte string
//! `y_p = f_p(j)` for all positions `p`. Any `k` distinct shares determine
//! every polynomial and hence `M`; any `k-1` shares leave `M[0..32]`
//! (the random nonce) information-theoretically undetermined, and the
//! commitment check then cannot be satisfied. Every operation is an exact
//! GF(2^8) operation — no floats are used anywhere in this module.

use crate::gf256;
use crate::rng;
use crate::share::{
    ct_eq, random_nonce, validate_params, Share, ShareHeader, SssError, NONCE_LEN,
};

/// Split `secret` into `n` shares, any `k` of which reconstruct it.
///
/// The secret is accepted as arbitrary bytes (binary or text); size is bounded
/// by [`crate::share::MAX_SECRET_LEN`]. The secret bytes are referenced, not
/// copied into a second long-lived buffer: the assembled message
/// `R || secret` is the only extra copy of the secret material, and share
/// payloads are built from freshly sampled randomness.
pub fn split(secret: &[u8], k: u8, n: u8) -> Result<Vec<Share>, SssError> {
    validate_params(k, n)?;
    if secret.len() > crate::share::MAX_SECRET_LEN {
        return Err(SssError::SecretTooLong(secret.len()));
    }

    // Fresh random session value R and its commitment.
    let nonce = random_nonce()?;
    let commitment = crate::sha256::hash(&nonce);

    let msg_len = NONCE_LEN + secret.len();

    // Allocate payloads once.
    let mut payloads: Vec<Vec<u8>> = (0..n as usize).map(|_| vec![0u8; msg_len]).collect();

    // Coefficient buffer, reused per byte position; zeroed between positions
    // by full overwrite. coeffs[0] is the message byte (the secret).
    let mut coeffs = vec![0u8; k as usize];

    for pos in 0..msg_len {
        let message_byte = if pos < NONCE_LEN {
            nonce[pos]
        } else {
            secret[pos - NONCE_LEN]
        };
        coeffs[0] = message_byte;
        if k > 1 {
            rng::fill(&mut coeffs[1..]).map_err(SssError::RngUnavailable)?;
        }
        // Evaluate at x = 1..=n.
        for x in 1..=n {
            payloads[(x - 1) as usize][pos] = gf256::eval(&coeffs, x);
        }
    }

    let header_common = |index: u8| ShareHeader {
        version: crate::share::FORMAT_VERSION,
        k,
        n,
        secret_len: secret.len() as u16,
        index,
        session_id: nonce,
        commitment,
    };

    Ok(payloads
        .into_iter()
        .enumerate()
        .map(|(i, payload)| Share {
            header: header_common((i + 1) as u8),
            payload,
        })
        .collect())
}

/// Reconstruct the secret from any `k` (or more) valid, distinct shares.
///
/// Shares are first fully validated (checksum, structure, mutual consistency),
/// interpolation is exact over GF(2^8), and the recovered nonce is checked
/// against the commitment before the secret is returned. Fewer than `k`
/// shares, duplicate indices, mixed/corrupted/forged shares each produce a
/// distinct error.
pub fn combine(shares: &[Share]) -> Result<crate::share::ZeroizingBytes, SssError> {
    if shares.is_empty() {
        return Err(SssError::TooFewShares { have: 0, need: 0 });
    }

    // All shares must agree on the session header. The first share defines the
    // expected parameters.
    let first = &shares[0].header;
    let k = first.k;
    let n = first.n;
    let secret_len = first.secret_len as usize;
    let payload_len = secret_len + NONCE_LEN;

    let mut seen_indices = [false; 256];
    for s in shares {
        let h = &s.header;
        if h.version != first.version
            || h.k != k
            || h.n != n
            || h.secret_len != first.secret_len
        {
            return Err(SssError::MixedShares(format!(
                "share {} has k/n/length {}/{}/{}, expected {}/{}/{}",
                h.index, h.k, h.n, h.secret_len, k, n, first.secret_len
            )));
        }
        if !ct_eq(&h.session_id, &first.session_id) {
            return Err(SssError::MixedShares(format!(
                "share {} carries a different session id",
                h.index
            )));
        }
        if !ct_eq(&h.commitment, &first.commitment) {
            return Err(SssError::MixedShares(format!(
                "share {} carries a different commitment",
                h.index
            )));
        }
        if s.payload.len() != payload_len {
            return Err(SssError::CorruptedShare {
                index: Some(h.index as u16),
                reason: format!("payload length {}, expected {}", s.payload.len(), payload_len),
            });
        }
        if seen_indices[h.index as usize] {
            return Err(SssError::DuplicateIndex(h.index));
        }
        seen_indices[h.index as usize] = true;
    }

    if shares.len() < k as usize {
        return Err(SssError::TooFewShares {
            have: shares.len(),
            need: k as usize,
        });
    }

    // Use exactly the first k shares when more were supplied. All supplied
    // shares are structurally valid and consistent, so any k of them recover
    // the same polynomial; using the first k is deterministic.
    let chosen = &shares[..k as usize];
    let xs: Vec<u8> = chosen.iter().map(|s| s.header.index).collect();

    // Reconstructed R || secret, in a buffer that is zeroed on drop.
    let mut recovered = crate::share::ZeroizingBytes(vec![0u8; payload_len]);

    // Interpolate each byte independently.
    let mut ys = vec![0u8; k as usize];
    for pos in 0..payload_len {
        for (i, s) in chosen.iter().enumerate() {
            ys[i] = s.payload[pos];
        }
        // lagrange_at_zero only fails on duplicate/zero indices, both of which
        // were ruled out above; map defensively.
        recovered.0[pos] = gf256::lagrange_at_zero(&xs, &ys).map_err(|e| {
            SssError::CorruptedShare { index: None, reason: e.to_string() }
        })?;
    }

    // Commitment gate: the recovered nonce must hash to the stored commitment.
    let recovered_nonce = &recovered.0[..NONCE_LEN];
    let check = crate::sha256::hash(recovered_nonce);
    if !ct_eq(&check, &first.commitment) {
        return Err(SssError::CommitmentCheckFailed);
    }

    // Strip the nonce and return just the secret. Splitting off the nonce
    // copies the secret once into the returned buffer; the working buffer
    // (including R) is zeroized when dropped.
    let secret_bytes = recovered.0[NONCE_LEN..].to_vec();
    Ok(crate::share::ZeroizingBytes(secret_bytes))
}
