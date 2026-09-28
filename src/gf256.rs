//! Arithmetic in GF(2^8) with the standard Rijndael/AES irreducible
//! polynomial `x^8 + x^4 + x^3 + x + 1` (0x11B, without the x^8 bit: 0x1B).
//!
//! All operations are exact integer/table operations. Floating point is never
//! used anywhere in this crate.

/// Irreducible reduction polynomial (low 8 bits of x^8+x^4+x^3+x+1).
const POLY: u16 = 0x11B;

/// Generates the anti-log table at compile time: EXP[i] = g^i, g = 3.
const fn build_exp() -> [u8; 512] {
    let mut table = [0u8; 512];
    let mut x: u16 = 1;
    let mut i = 0;
    while i < 256 {
        table[i] = x as u8;
        // x * 3 in the field: xtime(x) ^ x
        x = (x << 1) ^ ((x >> 7) * POLY) ^ x;
        x &= 0xFF;
        i += 1;
    }
    // Duplicate the first 255 entries starting at index 255, so multiplication
    // can index log(a)+log(b) (at most 254+254 = 508) without a modulo on
    // every call: EXP[i+255] == EXP[i] because g^255 == 1.
    i = 0;
    while i < 255 {
        table[i + 255] = table[i];
        i += 1;
    }
    table
}

/// Generates the log table at compile time: LOG[g^i] = i. LOG[0] is 0 and is
/// never consulted by callers (mul/div reject zero through explicit checks).
const fn build_log() -> [u8; 256] {
    let exp = build_exp();
    let mut table = [0u8; 256];
    let mut i = 0;
    while i < 255 {
        table[exp[i] as usize] = i as u8;
        i += 1;
    }
    table
}

/// Anti-log table: generator 3 powers, doubled for wrap-free indexing.
pub const EXP: [u8; 512] = build_exp();
/// Log table base generator 3.
pub const LOG: [u8; 256] = build_log();

/// Multiplication in GF(2^8).
#[inline]
pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        0
    } else {
        EXP[(LOG[a as usize] as u16 + LOG[b as usize] as u16) as usize]
    }
}

/// Division in GF(2^8). Returns None when the divisor is zero.
#[inline]
pub fn div(a: u8, b: u8) -> Option<u8> {
    if b == 0 {
        None
    } else if a == 0 {
        Some(0)
    } else {
        let la = LOG[a as usize] as i16;
        let lb = LOG[b as usize] as i16;
        let mut d = la - lb;
        if d < 0 {
            d += 255;
        }
        Some(EXP[d as usize])
    }
}

/// Multiplicative inverse in GF(2^8); inverse of 0 is 0 (used only in tests).
#[inline]
pub fn inv(a: u8) -> u8 {
    if a == 0 {
        0
    } else {
        EXP[255 - LOG[a as usize] as usize]
    }
}

/// Evaluate the polynomial whose constant term is `coeffs[0]` at point `x`.
/// Horner's method, all in GF(2^8). For x == 0 the result is coeffs[0].
pub fn eval_poly(coeffs: &[u8], x: u8) -> u8 {
    if x == 0 {
        return coeffs[0];
    }
    let mut acc = 0u8;
    for &c in coeffs.iter().rev() {
        acc = mul(acc, x) ^ c;
    }
    acc
}

/// Lagrange interpolation at x = 0 over GF(2^8).
///
/// `points` contains `(x_i, y_i)` pairs with pairwise distinct x_i; it must
/// contain at least one pair. Returns the unique constant term of the
/// degree < m polynomial through the points:
///
///   f(0) = Σ_i y_i * Π_{j≠i} x_j / (x_j ⊕ x_i)
///
/// Returns None if two x coordinates coincide (denominator zero), which can
/// only happen if the caller fails to de-duplicate indices.
pub fn interpolate_zero(points: &[(u8, u8)]) -> Option<u8> {
    let mut secret = 0u8;
    for (i, &(xi, yi)) in points.iter().enumerate() {
        let mut num = 1u8;
        let mut den = 1u8;
        for (j, &(xj, _)) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            if xi == xj {
                return None;
            }
            // In characteristic 2 subtraction equals addition (XOR).
            num = mul(num, xj);
            den = mul(den, xj ^ xi);
        }
        let term = mul(yi, div(num, den)?);
        secret ^= term;
    }
    Some(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS-197 / known AES field test vectors.
    #[test]
    fn known_aes_field_vectors() {
        // {57} · {13} = {fe}
        assert_eq!(mul(0x57, 0x13), 0xfe);
        assert_eq!(mul(0x53, 0xCA), 0x01); // multiplicative pair
        // generator powers
        assert_eq!(EXP[0], 1);
        assert_eq!(EXP[255], 1);
        assert_eq!(LOG[3], 1);
        assert_eq!(LOG[1], 0);
    }

    #[test]
    fn mul_identity_zero_and_commutative() {
        for a in 0u16..=255 {
            let a = a as u8;
            assert_eq!(mul(a, 1), a);
            assert_eq!(mul(a, 0), 0);
            assert_eq!(mul(0, a), 0);
            for b in [1u8, 2, 3, 7, 53, 200, 255] {
                assert_eq!(mul(a, b), mul(b, a));
            }
        }
    }

    #[test]
    fn division_roundtrip_and_div_zero() {
        assert_eq!(div(1, 0), None);
        for a in 0u16..=255 {
            let a = a as u8;
            for b in 1u16..=255 {
                let b = b as u8;
                let q = div(a, b).unwrap();
                assert_eq!(mul(q, b), a, "{a}/{b} inconsistent");
            }
        }
    }

    #[test]
    fn inverse_vectors() {
        assert_eq!(inv(0), 0);
        for a in 1u16..=255 {
            let a = a as u8;
            assert_eq!(mul(a, inv(a)), 1);
        }
    }

    #[test]
    fn poly_eval_matches_naive() {
        let coeffs = [0x53u8, 0xCA, 0x11, 0x22, 0xDE];
        for x in 0u16..=255 {
            let x = x as u8;
            // naive: c0 + c1*x + c2*x^2 + ...
            let mut want = coeffs[0];
            let mut xp = 1u8;
            for c in &coeffs[1..] {
                xp = mul(xp, x);
                want ^= mul(*c, xp);
            }
            assert_eq!(eval_poly(&coeffs, x), want);
        }
    }

    #[test]
    fn interpolation_recovers_constant_term() {
        // For each degree k-1 (k = 1..=5), enumerate every k-subset of 7
        // evaluated points and confirm they recover the constant term.
        let high = [0xABu8, 0xCD, 0xEF, 0x42];
        let xs = [10u8, 20, 30, 40, 50, 60, 70];

        for k in 1..=5usize {
            let coeffs: Vec<u8> = std::iter::once(0x01u8)
                .chain(high[..k - 1].iter().copied())
                .collect();
            let pts: Vec<(u8, u8)> = xs.iter().map(|&x| (x, eval_poly(&coeffs, x))).collect();

            let mut combo: Vec<usize> = (0..k).collect();
            loop {
                let sub: Vec<(u8, u8)> = combo.iter().map(|&i| pts[i]).collect();
                assert_eq!(interpolate_zero(&sub), Some(0x01), "k={k} combo={combo:?}");

                // Generate the next k-combination of 0..7; break when exhausted.
                let mut pos = k;
                loop {
                    if pos == 0 {
                        break;
                    }
                    pos -= 1;
                    combo[pos] += 1;
                    if combo[pos] <= 7 - (k - pos) {
                        for j in (pos + 1)..k {
                            combo[j] = combo[j - 1] + 1;
                        }
                        break;
                    }
                }
                if combo[0] > 7 - k {
                    break;
                }
            }
        }
        // all points together always interpolate to the constant term
        let coeffs = [0x01u8, 0xAB, 0xCD, 0xEF, 0x42];
        let pts: Vec<(u8, u8)> = xs.iter().map(|&x| (x, eval_poly(&coeffs, x))).collect();
        assert_eq!(interpolate_zero(&pts), Some(0x01));
    }

    #[test]
    fn interpolation_rejects_duplicate_coordinates() {
        assert_eq!(interpolate_zero(&[(1, 2), (1, 3)]), None);
    }
}
