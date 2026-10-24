//! The knowledge-soundness error of the payment proof, round by round.
//!
//! The interactive protocol is the zero-knowledge DEEP-ALI of Haboeck and
//! Kindi, whose round-by-round knowledge soundness Atapoor, Delpech de Saint
//! Guilhem and Kindi prove (ePrint 2024/1553, Theorems 2 and 3). Plonky3
//! combines the constraints and the opened columns by the powers of one
//! challenge, folds by arities 4, 4 and 4, and grinds before the queries; each
//! changes one term, as `SourceCode/Analysis/se_bound.py` sets out. This file
//! computes the same terms so that the harness prints what the paper states.
//!
//! The challenge field is the degree-5 extension of Goldilocks. Over the
//! cubic one the batching term caps the Johnson-regime figure near 107 bits
//! round by round, which leaves about 43 bits against 2^64 oracle queries;
//! over degree 5 the query term decides, and the deployed queries give
//! more than 100 bits against 2^64.
//! The provable figure is the better of the Johnson and unique-decoding
//! regimes. The conjectured figure charges the queries the full rate and every
//! other term its unique-decoding value. Both are round-by-round figures; an
//! adversary making q oracle queries gains a factor q + 7 on top.

const P: f64 = 18446744069414584321.0;
const FOLDS: [f64; 3] = [4.0, 4.0, 4.0];

/// What the error depends on besides the FRI parameters.
#[derive(Clone, Copy)]
pub struct Shape {
    pub rows: usize,
    /// AIR columns.
    pub width: usize,
    pub constraints: usize,
    pub degree: usize,
    pub chunks: usize,
    pub ext: i32,
}

/// The composed circuit as built.
pub const COMPOSED: Shape = Shape { rows: crate::prover::ROWS, width: 14_292, constraints: 14_302, degree: 7, chunks: 16, ext: crate::prover::EXT_DEGREE as i32 };

/// Openings the batching challenge combines: the trace with its two random
/// codewords at two points, and at one point each quotient chunk's base
/// coordinates and the mask's polynomials, one per degree of the extension,
/// each with the two random codewords.
fn batched(s: &Shape) -> f64 {
    let e = s.ext as usize;
    (2 * (s.width + 2) + s.chunks * (e + 2) + (e + 2)) as f64
}

enum Regime {
    Johnson(f64),
    Unique,
    Conjectured,
}

fn worst(s: &Shape, r: Regime, queries: usize, log_blowup: usize, pow: usize) -> f64 {
    let g = P.powi(s.ext);
    let k = (2 * s.rows) as f64;
    let d = k * (1u64 << log_blowup) as f64;
    let rho = k / d;
    let kp = k + 2.0;
    let n = batched(s);
    let deg = ((s.degree as f64) * (kp - 1.0) + (k - 1.0)).max(kp + (s.chunks as f64 - 1.0) * k + (kp - 1.0));
    let grind = 2f64.powi(-(pow as i32));
    let c = (s.constraints - 1) as f64;
    let q = queries as i32;
    let terms: [f64; 5] = match r {
        Regime::Johnson(m) => {
            let l = m / (rho - 2.0 * m / d);
            let gap = (m + 0.5).powi(7) * d * d / (3.0 * rho.powf(1.5) * g);
            let fold = FOLDS
                .iter()
                .map(|a| (a - 1.0) * (gap + (2.0 * m + 1.0) / rho.sqrt() * (d + 1.0) / g))
                .fold(0.0, f64::max);
            [
                l * c / g,
                l * l * deg / (g - 2.0 * d) + 2.0 * d / g,
                (n - 1.0) * gap,
                fold,
                (rho.sqrt() * (1.0 + 1.0 / (2.0 * m))).powi(q) * grind,
            ]
        }
        Regime::Unique | Regime::Conjectured => {
            let query = match r {
                Regime::Unique => ((1.0 + kp / d) / 2.0).powi(q),
                _ => rho.powi(q),
            };
            [
                c / g,
                deg / (g - 2.0 * d) + 2.0 * d / g,
                (n - 1.0) * d / g,
                FOLDS.iter().map(|a| (a - 1.0) * (d + 1.0) / g).fold(0.0, f64::max),
                query * grind,
            ]
        }
    };
    terms.iter().cloned().fold(0.0, f64::max)
}

/// Provable bits: the better of the Johnson regime, minimised over the
/// multiplicity, and the unique-decoding regime.
pub fn provable(s: &Shape, queries: usize, log_blowup: usize, pow: usize) -> f64 {
    let k = (2 * s.rows) as f64;
    let d = k * (1u64 << log_blowup) as f64;
    let rho = k / d;
    let mut best = worst(s, Regime::Unique, queries, log_blowup, pow);
    for m in 3..4096 {
        let m = m as f64;
        // The Johnson-regime theorem asks 3 <= m < k/2 and
        // eta = sqrt(rho)(1 + 1/(2m)) - sqrt((k + 2)/|D|) > 0.
        let eta = rho.sqrt() * (1.0 + 1.0 / (2.0 * m)) - ((k + 2.0) / d).sqrt();
        if m >= k / 2.0 || rho - 2.0 * m / d <= 0.0 || eta <= 0.0 || rho.sqrt() * (1.0 + 1.0 / (2.0 * m)) >= 1.0 {
            continue;
        }
        best = best.min(worst(s, Regime::Johnson(m), queries, log_blowup, pow));
    }
    -best.log2()
}

/// Provable bits against an adversary making 2^h oracle queries: the
/// round-by-round error times 2^h + 7, the rounds of the protocol.
pub fn provable_against(s: &Shape, queries: usize, log_blowup: usize, pow: usize, h: i32) -> f64 {
    provable(s, queries, log_blowup, pow) - (2f64.powi(h) + 7.0).log2()
}

/// Conjectured bits: queries at the full rate, every other term at its unique-decoding value.
pub fn conjectured(s: &Shape, queries: usize, log_blowup: usize, pow: usize) -> f64 {
    -worst(s, Regime::Conjectured, queries, log_blowup, pow).log2()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deployed_matches_the_analysis_script() {
        use crate::prover::{LOG_BLOWUP, NUM_QUERIES, POW_BITS};
        let d = provable(&COMPOSED, NUM_QUERIES, LOG_BLOWUP, POW_BITS);
        let (q, b, g) = (NUM_QUERIES, LOG_BLOWUP, POW_BITS);
        let script = match (q, b, g) {
            (74, 4, 20) => (167, 103, 292),
            (68, 4, 30) => (165, 101, 292),
            (58, 5, 20) => (164, 100, 291),
            _ => panic!("no figures from se_bound.py for this setting"),
        };
        assert_eq!(d.floor() as usize, script.0);
        assert_eq!(provable_against(&COMPOSED, q, b, g, 64).floor() as usize, script.1);
        assert_eq!(conjectured(&COMPOSED, q, b, g).floor() as usize, script.2);
        let cubic = Shape { ext: 3, ..COMPOSED };
        assert_eq!(provable(&cubic, 44, 4, 20).floor() as usize, 107);
        assert_eq!(provable_against(&cubic, 44, 4, 20, 64).floor() as usize, 43);
    }
}
