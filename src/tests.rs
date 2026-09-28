//! Automated tests for split/combine correctness, format parsing and every
//! failure mode required by the specification.

use crate::rng;
use crate::share::{
    ct_eq, Share, SssError, FORMAT_VERSION, MAGIC, MAX_SECRET_LEN, NONCE_LEN,
};
use crate::{combine, split};
use std::collections::HashSet;

/// Parse a share from its serialized bytes.
fn parse(bytes: &[u8]) -> Share {
    Share::from_bytes(bytes).expect("share should parse")
}

/// Serialize all shares.
fn serialize(shares: &[Share]) -> Vec<Vec<u8>> {
    shares.iter().map(|s| s.to_bytes()).collect()
}

/// Recompute the trailing checksum after mutating a share file's body,
/// simulating an attacker who can rewrite the whole file (not just flip a bit).
fn reseal(mut bytes: Vec<u8>) -> Vec<u8> {
    let body_len = bytes.len() - 32;
    let tag = crate::sha256::hash(&bytes[..body_len]);
    bytes[body_len..].copy_from_slice(&tag);
    bytes
}

fn combine_raw(raw_shares: &[Vec<u8>]) -> Result<crate::ZeroizingBytes, SssError> {
    let parsed: Vec<Share> = raw_shares.iter().map(|b| Share::from_bytes(b).unwrap()).collect();
    combine(&parsed)
}

// ---------------------------------------------------------------------------
// Correctness across different k/n
// ---------------------------------------------------------------------------

#[test]
fn various_k_n_all_recover() {
    let cases: &[(u8, u8)] = &[
        (2, 2),
        (2, 3),
        (3, 5),
        (5, 5),
        (2, 10),
        (4, 7),
        (2, 255), // boundary: maximum number of shares
    ];
    for &(k, n) in cases {
        let secret = b"local-only secret \x00\x01\xfe\xff";
        let shares = split(secret, k, n).unwrap();
        assert_eq!(shares.len(), n as usize, "case ({k},{n})");

        let raw = serialize(&shares);
        // Recover using shares at the extremes: index 1 and index n (plus
        // interior shares as needed), always from serialized bytes.
        let mut pick_idx: Vec<usize> = vec![0, n as usize - 1];
        for i in 1..(k as usize - 1) {
            pick_idx.push(i * (n as usize) / (k as usize));
        }
        let subset: Vec<Vec<u8>> = pick_idx.iter().map(|&i| raw[i].clone()).collect();
        let recovered = combine_raw(&subset).unwrap_or_else(|e| {
            panic!("case ({k},{n}) recovery failed: {e}")
        });
        assert_eq!(&recovered[..], secret, "case ({k},{n}) mismatch");
    }
}

#[test]
fn every_3_of_5_combination_works() {
    // All C(5,3) = 10 threshold subsets must recover the identical secret.
    let secret = b"any three holders can open this";
    let shares = split(secret, 3, 5).unwrap();
    let raw = serialize(&shares);

    for i in 0..5 {
        for j in (i + 1)..5 {
            for m in (j + 1)..5 {
                let subset = vec![raw[i].clone(), raw[j].clone(), raw[m].clone()];
                let recovered = combine_raw(&subset).unwrap();
                assert_eq!(&recovered[..], secret, "subset {i},{j},{m}");
            }
        }
    }
}

#[test]
fn more_than_k_shares_also_works() {
    let secret = b"extra shares are fine";
    let shares = split(secret, 2, 4).unwrap();
    let raw = serialize(&shares);
    // 3 and then all 4 shares.
    assert_eq!(&combine_raw(&raw[..3]).unwrap()[..], secret);
    assert_eq!(&combine_raw(&raw[..4]).unwrap()[..], secret);
}

#[test]
fn recovered_bytes_are_exactly_identical() {
    // Include every possible byte value, repeated, so a wrong field element
    // could not hide.
    let mut secret = Vec::with_capacity(512);
    for v in 0u16..=255 {
        secret.push(v as u8);
    }
    secret.extend_from_slice(&secret.clone());
    let shares = split(&secret, 3, 5).unwrap();
    let raw = serialize(&shares);
    let recovered = combine_raw(&[raw[4].clone(), raw[0].clone(), raw[2].clone()]).unwrap();
    assert_eq!(&recovered[..], &secret[..]);
}

// ---------------------------------------------------------------------------
// Binary data, empty data and size limits
// ---------------------------------------------------------------------------

#[test]
fn arbitrary_binary_data() {
    let mut secret = vec![0u8, 0xFF, 0x00, 0x80, 0x7F];
    secret.extend_from_slice(&rng::bytes(1000).unwrap());
    for &(k, n) in &[(2u8, 3u8), (3, 5)] {
        let shares = split(&secret, k, n).unwrap();
        let raw = serialize(&shares);
        let recovered = combine_raw(&raw[..k as usize]).unwrap();
        assert_eq!(&recovered[..], &secret[..]);
    }
}

#[test]
fn empty_secret_supported() {
    let shares = split(&[], 3, 5).unwrap();
    let raw = serialize(&shares);
    assert_eq!(raw[0].len(), 138); // header 74 + nonce payload 32 + checksum 32
    let recovered = combine_raw(&raw[..3]).unwrap();
    assert!(recovered.is_empty());
}

#[test]
fn max_size_accepted_and_oversize_rejected() {
    let max_secret = vec![0xA5u8; MAX_SECRET_LEN];
    let shares = split(&max_secret, 2, 2).unwrap();
    let raw = serialize(&shares);
    let recovered = combine_raw(&raw).unwrap();
    assert_eq!(&recovered[..], &max_secret[..]);

    let too_big = vec![0u8; MAX_SECRET_LEN + 1];
    assert_eq!(
        split(&too_big, 2, 2).unwrap_err(),
        SssError::SecretTooLong(MAX_SECRET_LEN + 1)
    );
}
// ---------------------------------------------------------------------------
// Below-threshold / missing shares
// ---------------------------------------------------------------------------

#[test]
fn fewer_than_k_shares_rejected() {
    let secret = b"threshold is three";
    let shares = split(secret, 3, 5).unwrap();
    let raw = serialize(&shares);

    assert_eq!(
        combine_raw(&raw[..2]).unwrap_err(),
        SssError::TooFewShares { have: 2, need: 3 }
    );
    assert_eq!(
        combine_raw(&raw[..1]).unwrap_err(),
        SssError::TooFewShares { have: 1, need: 3 }
    );
    let err = combine_raw(&[]).unwrap_err();
    assert!(matches!(err, SssError::TooFewShares { .. }));

    // The two shares must not contain a reconstruction path: combine must not
    // return secret-shaped output under any circumstances.
    let parsed: Vec<Share> = raw[..2].iter().map(|b| parse(b)).collect();
    assert!(combine(&parsed).is_err());
}

// ---------------------------------------------------------------------------
// Duplicate indices
// ---------------------------------------------------------------------------

#[test]
fn duplicate_index_detected() {
    let shares = split(b"dup test", 3, 5).unwrap();
    let mut raw = serialize(&shares);

    // Rewrite share 2 so that it claims index 1 (same as share 1), keeping a
    // valid checksum.
    raw[1][9] = raw[0][9]; // index byte -> 1
    raw[1] = reseal(raw[1].clone());

    let parsed: Vec<Share> = raw[..3].iter().map(|b| parse(b)).collect();
    assert_eq!(combine(&parsed).unwrap_err(), SssError::DuplicateIndex(1));
}

// ---------------------------------------------------------------------------
// Content corruption and forged shares
// ---------------------------------------------------------------------------

#[test]
fn bit_flip_in_payload_fails_checksum_at_parse() {
    let shares = split(b"integrity", 3, 5).unwrap();
    let mut raw = serialize(&shares);
    raw[0][74] ^= 0x01; // flip a payload byte, do NOT fix the checksum

    let err = Share::from_bytes(&raw[0]).unwrap_err();
    match err {
        SssError::CorruptedShare { index, reason } => {
            assert_eq!(index, Some(1));
            assert!(reason.contains("checksum"), "reason was: {reason}");
        }
        other => panic!("expected CorruptedShare, got {other:?}"),
    }
}

#[test]
fn bit_flip_in_header_fails_checksum_at_parse() {
    let shares = split(b"hdr integrity", 2, 3).unwrap();
    let mut raw = serialize(&shares);
    raw[2][5] ^= 0x01; // corrupt k
    let err = Share::from_bytes(&raw[2]).unwrap_err();
    assert!(matches!(err, SssError::CorruptedShare { .. }));
}

#[test]
fn truncated_file_rejected() {
    let shares = split(b"trunc", 2, 3).unwrap();
    let raw = serialize(&shares);
    assert!(matches!(
        Share::from_bytes(&raw[0][..raw[0].len() - 5]).unwrap_err(),
        SssError::CorruptedShare { .. }
    ));
    assert!(matches!(
        Share::from_bytes(&[]).unwrap_err(),
        SssError::CorruptedShare { .. }
    ));
}

#[test]
fn forged_share_with_valid_checksum_fails_commitment() {
    // An active attacker rewrites a whole share file (payload + checksum).
    // Parsing succeeds, but the bogus point cannot satisfy the commitment.
    let shares = split(b"forgery attempt", 3, 5).unwrap();
    let mut raw = serialize(&shares);
    raw[0][80] ^= 0x01;
    raw[0] = reseal(raw[0].clone());

    let parsed: Vec<Share> = raw[..3].iter().map(|b| parse(b)).collect();
    assert_eq!(combine(&parsed).unwrap_err(), SssError::CommitmentCheckFailed);
}

// ---------------------------------------------------------------------------
// Mixing shares from different secrets / parameters
// ---------------------------------------------------------------------------

#[test]
fn shares_from_different_splits_rejected() {
    let a = split(b"secret alpha", 3, 5).unwrap();
    let b = split(b"secret beta!!", 3, 5).unwrap();
    let ra = serialize(&a);
    let rb = serialize(&b);

    // Same k/n, different session ids.
    let mixed_raw = [ra[0].clone(), ra[1].clone(), rb[2].clone()];
    let mixed: Vec<Share> = mixed_raw.iter().map(|x| parse(x.as_slice())).collect();
    assert!(matches!(combine(&mixed).unwrap_err(), SssError::MixedShares(_)));
}

#[test]
fn shares_with_different_parameters_rejected() {
    let a = split(b"params a", 3, 5).unwrap();
    let b = split(b"params bbbbbb", 2, 4).unwrap();
    let ra = serialize(&a);
    let rb = serialize(&b);

    // Different k/n headers even before session check.
    let mixed_raw = [ra[0].clone(), rb[0].clone(), ra[2].clone()];
    let mixed: Vec<Share> = mixed_raw.iter().map(|x| parse(x.as_slice())).collect();
    assert!(matches!(combine(&mixed).unwrap_err(), SssError::MixedShares(_)));
}

// ---------------------------------------------------------------------------
// Version and magic
// ---------------------------------------------------------------------------

#[test]
fn wrong_version_rejected() {
    let shares = split(b"versioned", 2, 3).unwrap();
    let mut raw = serialize(&shares);
    raw[0][4] = FORMAT_VERSION.wrapping_add(99);
    // Version is checked before checksum, so the stale checksum does not
    // obscure the version error.
    assert_eq!(
        Share::from_bytes(&raw[0]).unwrap_err(),
        SssError::VersionMismatch(FORMAT_VERSION.wrapping_add(99))
    );
}

#[test]
fn bad_magic_rejected() {
    let shares = split(b"magic", 2, 3).unwrap();
    let mut raw = serialize(&shares);
    raw[0][0] ^= 0xFF;
    assert!(matches!(Share::from_bytes(&raw[0]).unwrap_err(), SssError::BadMagic));

    // Random unrelated bytes must never parse.
    let junk = rng::bytes(300).unwrap();
    assert!(matches!(Share::from_bytes(&junk).unwrap_err(), SssError::BadMagic | SssError::CorruptedShare { .. }));
}

// ---------------------------------------------------------------------------
// Parameter validation
// ---------------------------------------------------------------------------

#[test]
fn invalid_parameters_rejected() {
    assert!(matches!(split(b"x", 1, 3), Err(SssError::InvalidParameters(_))));
    assert!(matches!(split(b"x", 0, 3), Err(SssError::InvalidParameters(_))));
    assert!(matches!(split(b"x", 4, 3), Err(SssError::InvalidParameters(_))));
    assert!(matches!(split(b"x", 2, 0), Err(SssError::InvalidParameters(_))));
    assert!(crate::validate_params(255, 255).is_ok());
}

#[test]
fn indices_are_unique_one_through_n() {
    let shares = split(b"idx", 3, 7).unwrap();
    let indices: Vec<u8> = shares.iter().map(|s| s.header.index).collect();
    let unique: HashSet<u8> = indices.iter().copied().collect();
    assert_eq!(unique.len(), 7);
    assert_eq!(indices, vec![1, 2, 3, 4, 5, 6, 7]);
    for s in &shares {
        assert_eq!(s.header.version, FORMAT_VERSION);
        assert_eq!(s.header.k, 3);
        assert_eq!(s.header.n, 7);
        assert_eq!(s.header.secret_len, 3);
        assert_eq!(s.payload.len(), 3 + NONCE_LEN);
    }
}

#[test]
fn session_id_and_commitment_match_across_shares() {
    let shares = split(b"bind", 2, 3).unwrap();
    let ids: Vec<[u8; 32]> = shares.iter().map(|s| s.header.session_id).collect();
    let commitments: Vec<[u8; 32]> = shares.iter().map(|s| s.header.commitment).collect();
    for i in 1..3 {
        assert!(ct_eq(&ids[0], &ids[i]));
        assert!(ct_eq(&commitments[0], &commitments[i]));
    }
    // Commitment must actually commit to the nonce recovered at combine time.
    assert!(ct_eq(&crate::sha256::hash(&ids[0]), &commitments[0]));
    // Magic constant sanity.
    assert_eq!(MAGIC, b"LSSS");
}

// ---------------------------------------------------------------------------
// Confidentiality: secrets must not appear in logs / debug output
// ---------------------------------------------------------------------------

#[test]
fn debug_and_error_output_do_not_leak_secret() {
    let secret = b"UNIQUE-SECRET-MARKER-DoNotLeak-1234567890";
    let shares = split(secret, 3, 5).unwrap();

    // Share Debug must redact payload and identifiers.
    let dbg = format!("{:?}", shares[0]);
    assert!(!dbg.contains("UNIQUE-SECRET-MARKER"));
    assert!(dbg.contains("redacted"));

    // Serialized share bytes necessarily encode points of the secret-bearing
    // polynomial (that is the point of SSS), but the plaintext secret must not
    // appear as a substring of any share file.
    for raw in serialize(&shares) {
        assert!(!raw.windows(secret.len()).any(|w| w == secret));
    }

    // Error messages carry metadata only.
    let errors = [
        format!("{}", SssError::TooFewShares { have: 1, need: 3 }),
        format!("{}", SssError::DuplicateIndex(2)),
        format!("{}", SssError::CommitmentCheckFailed),
        format!("{}", SssError::VersionMismatch(9)),
        format!("{}", SssError::BadMagic),
        format!("{}", SssError::MixedShares("session id".into())),
    ];
    for msg in errors {
        assert!(!msg.contains("UNIQUE-SECRET-MARKER"));
    }
}

// ---------------------------------------------------------------------------
// Determinism of parsing and stability of serialization
// ---------------------------------------------------------------------------

#[test]
fn serialization_roundtrip_is_stable() {
    let shares = split(b"stable format \xff\x00", 2, 3).unwrap();
    for s in &shares {
        let bytes = s.to_bytes();
        let reparsed = Share::from_bytes(&bytes).unwrap();
        assert_eq!(reparsed.header, s.header);
        assert_eq!(reparsed.payload, s.payload);
        // Re-serializing reproduces identical bytes.
        assert_eq!(reparsed.to_bytes(), bytes);
    }
}
