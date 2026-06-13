//! Anti-spam proof-of-work lane (WP16a).
//!
//! v0 is a BLAKE3 hashcash puzzle bound to the transaction binding digest,
//! with UNIFORM difficulty (no per-sender variance — variable difficulty
//! would fingerprint senders, feasibility §7.2). The production lane swaps
//! this for arti's `equix` (asymmetric, ASIC-resistant) behind the same
//! `solve`/`verify` interface; the challenge binding stays identical.

use unknown_primitives::{ds, hash_parts};

/// Network-wide uniform difficulty: required leading zero bits of the PoW
/// hash. A genesis/consensus parameter; small for the dev prototype.
pub const DEFAULT_DIFFICULTY_BITS: u32 = 8;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PowSolution {
    pub nonce: u64,
}

impl PowSolution {
    pub fn to_bytes(self) -> [u8; 8] {
        self.nonce.to_le_bytes()
    }
    pub fn from_bytes(b: [u8; 8]) -> Self {
        Self {
            nonce: u64::from_le_bytes(b),
        }
    }
}

fn pow_hash(challenge: &[u8; 32], nonce: u64) -> [u8; 32] {
    hash_parts(ds::POW, &[challenge, &nonce.to_le_bytes()])
}

fn leading_zero_bits(h: &[u8; 32]) -> u32 {
    let mut bits = 0;
    for &byte in h {
        if byte == 0 {
            bits += 8;
        } else {
            bits += byte.leading_zeros();
            break;
        }
    }
    bits
}

/// Solve the puzzle for `challenge` (the tx binding digest) at `difficulty`.
pub fn solve(challenge: &[u8; 32], difficulty_bits: u32) -> PowSolution {
    let mut nonce = 0u64;
    loop {
        if leading_zero_bits(&pow_hash(challenge, nonce)) >= difficulty_bits {
            return PowSolution { nonce };
        }
        nonce = nonce.wrapping_add(1);
    }
}

/// Verify a solution. Fast path used in stateless tx validation.
pub fn verify(challenge: &[u8; 32], solution: &PowSolution, difficulty_bits: u32) -> bool {
    leading_zero_bits(&pow_hash(challenge, solution.nonce)) >= difficulty_bits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solve_then_verify() {
        let challenge = [42u8; 32];
        let sol = solve(&challenge, 8);
        assert!(verify(&challenge, &sol, 8));
    }

    #[test]
    fn solution_does_not_transfer_between_challenges() {
        let sol = solve(&[1u8; 32], 8);
        // Overwhelmingly likely to fail against a different challenge.
        assert!(!verify(&[2u8; 32], &sol, 8));
    }

    #[test]
    fn higher_difficulty_rejects_easy_solution() {
        let challenge = [7u8; 32];
        let sol = solve(&challenge, 4);
        // A 4-bit solution only meets 16-bit by luck; assert the common case.
        if leading_zero_bits(&pow_hash(&challenge, sol.nonce)) < 16 {
            assert!(!verify(&challenge, &sol, 16));
        }
    }
}
