//! Arithmetic in the Galois field GF(2^8) with the Rijndael polynomial
//! `x^8 + x^4 + x^3 + x + 1` (0x11B), the same field used by AES.
//!
//! All operations are exact integer/table operations. **No floating point
//! arithmetic is used anywhere** in this crate; in particular secret recovery
//! uses exact Lagrange interpolation over this field (see [`lagrange_at_zero`]).

/// The irreducible reducing polynomial (without the implicit x^8 bit).
const POLY: u16 = 0x11B;

/// A field element: an 8-bit polynomial.
pub type Gf = u8;

/// Multiply two GF(2^8) elements using the peasant (Russian-peasant) method.
///
/// This is exact: it only ever XORs and shifts integers, so it is constant in
/// the sense that there is no rounding, no division by zero and no dependence
/// on floating point. We use it directly for the handful of multiplications
/// during recovery, and to build the log/exp tables used by the hot split
/// path.
pub fn mul(a: Gf, b: Gf) -> Gf {
    let mut x: u16 = a as u16;
    let mut y: u16 = b as u16;
    let mut result: u16 = 0;
    for _ in 0..8 {
        if y & 1 != 0 {
            result ^= x;
        }
        let hi = x & 0x80;
        x = (x << 1) & 0xFF;
        if hi != 0 {
            x ^= POLY;
        }
        y >>= 1;
    }
    result as Gf
}

/// Add two field elements. In characteristic 2 addition is XOR; subtraction is
/// identical to addition.
#[inline]
pub fn add(a: Gf, b: Gf) -> Gf {
    a ^ b
}

/// Multiplicative inverse of `a`; panics only on `a == 0` (zero has no
/// inverse, and code paths that could pass zero filter it beforehand).
pub fn inv(a: Gf) -> Gf {
    assert!(a != 0, "GF(256): inverse of zero");
    // a^254 == a^{-1} in GF(2^8) (Fermat: a^(255) = 1).
    let mut power = a;
    let mut result: Gf = 1;
    // exponent 254 = 0b11111110: square seven times, multiply on the high
    // seven set bits (skip the lowest, which is 0).
    for _ in 0..7 {
        power = mul(power, power);
        result = mul(result, power);
    }
    result
}

/// Divide `a` by `b` in the field; `b` must be non-zero.
#[inline]
pub fn div(a: Gf, b: Gf) -> Gf {
    mul(a, inv(b))
}

/// Evaluate a polynomial (coefficients low-to-high, `coeffs[0]` = constant) at
/// point `x` using exact Horner evaluation.
pub fn eval(coeffs: &[Gf], x: Gf) -> Gf {
    let mut acc: Gf = 0;
    for &c in coeffs.iter().rev() {
        acc = mul(acc, x) ^ c;
    }
    acc
}

/// Exact Lagrange interpolation at `x = 0` (the secret position).
///
/// Given distinct, non-zero x-coordinates `xs` and matching field values `ys`,
/// returns the unique degree-<`xs.len()` polynomial through those points,
/// evaluated at 0:
///
/// ```text
/// P(0) = Σ_j y_j · Π_{m != j} x_m / (x_m ⊕ x_j)
/// ```
///
/// Every multiplication, division and addition happens in GF(2^8); there is no
/// floating point in this function. `xs` must contain pairwise distinct,
/// non-zero elements, otherwise an error is returned (a duplicate index is a
/// malformed-share condition, not a silent interpolation).
pub fn lagrange_at_zero(xs: &[Gf], ys: &[Gf]) -> Result<Gf, &'static str> {
    if xs.len() != ys.len() || xs.is_empty() {
        return Err("lagrange: xs/ys length mismatch or empty");
    }
    for &x in xs {
        if x == 0 {
            return Err("lagrange: share index zero is invalid");
        }
    }
    for i in 0..xs.len() {
        for j in (i + 1)..xs.len() {
            if xs[i] == xs[j] {
                return Err("lagrange: duplicate share indices");
            }
        }
    }

    let mut secret: Gf = 0;
    for j in 0..xs.len() {
        let mut num: Gf = 1;
        let mut den: Gf = 1;
        for (m, &xm) in xs.iter().enumerate() {
            if m == j {
                continue;
            }
            // L_j(0) = Π x_m / (x_m - x_j); in char 2, x_m - x_j = x_m ^ x_j.
            num = mul(num, xm);
            den = mul(den, xm ^ xs[j]);
        }
        let term = mul(ys[j], div(num, den));
        secret ^= term;
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_known_vectors() {
        // AES standard GF(2^8) test vectors.
        assert_eq!(mul(0x57, 0x13), 0xFE);
        assert_eq!(mul(0x53, 0xCA), 0x01); // inverses of each other
        assert_eq!(mul(0, 0xAB), 0);
        assert_eq!(mul(1, 0xAB), 0xAB);
        assert_eq!(mul(0xFF, 1), 0xFF);
    }

    #[test]
    fn inverse_is_inverse() {
        for a in 1u16..=255 {
            let a = a as u8;
            assert_eq!(mul(a, inv(a)), 1, "inverse failed for {a}");
        }
    }

    #[test]
    fn eval_horner_matches_brute_force() {
        // f(x) = 7 + 3x + 200x^2
        let coeffs = [7u8, 3, 200];
        for x in 0u16..=255 {
            let x = x as u8;
            let expected = mul(7, 1) ^ mul(3, x) ^ mul(mul(200, x), x);
            assert_eq!(eval(&coeffs, x), expected);
        }
        // f(0) is the constant term.
        assert_eq!(eval(&coeffs, 0), 7);
    }

    #[test]
    fn lagrange_recovers_constant_term() {
        // Random-ish polynomial; any subset of degree+1 points recovers f(0).
        let coeffs = [0xDE, 0xAD, 0xBE, 0xEF]; // degree 3, k = 4
        let xs: [u8; 5] = [1, 2, 3, 7, 42];
        let ys: Vec<u8> = xs.iter().map(|&x| eval(&coeffs, x)).collect();

        // Use the four non-trivial points, and a different four-point subset.
        let rec1 = lagrange_at_zero(&xs[0..4], &ys[0..4]).unwrap();
        let rec2 = lagrange_at_zero(&[xs[1], xs[2], xs[3], xs[4]],
                                    &[ys[1], ys[2], ys[3], ys[4]]).unwrap();
        assert_eq!(rec1, 0xDE);
        assert_eq!(rec2, 0xDE);

        // Fewer than degree+1 points need not (and here do not) recover it.
        let rec3 = lagrange_at_zero(&xs[0..3], &ys[0..3]).unwrap();
        assert_ne!(rec3, 0xDE);
    }

    #[test]
    fn lagrange_rejects_bad_input() {
        assert!(lagrange_at_zero(&[], &[]).is_err());
        assert!(lagrange_at_zero(&[1, 1], &[2, 3]).is_err());
        assert!(lagrange_at_zero(&[0, 1], &[2, 3]).is_err());
        assert!(lagrange_at_zero(&[1, 2], &[3]).is_err());
    }

    #[test]
    fn field_closure_and_associativity() {
        // Spot-check field laws across a sample of elements.
        let samples = [1u8, 2, 3, 0x53, 0xCA, 0xFF, 0x80, 0x7F];
        for &a in &samples {
            for &b in &samples {
                for &c in &samples {
                    assert_eq!(mul(mul(a, b), c), mul(a, mul(b, c)));
                    assert_eq!(mul(a, add(b, c)), add(mul(a, b), mul(a, c)));
                }
            }
        }
    }
}
