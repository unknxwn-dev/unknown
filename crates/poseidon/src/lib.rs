//! Shared Poseidon2-over-BabyBear protocol hash (decision D3).
//!
//! This is the single source of truth for the in-circuit hash: the same round
//! constants and host permutation are used by the STARK spend circuit
//! (`circuit-spend`) and by the pipeline (`notes`, `tree`). Because both sides
//! call into here, out-of-circuit commitments/nullifiers/Merkle roots are
//! byte-for-byte what the circuit proves.
//!
//! Digests are 8 BabyBear elements; [`pack`]/[`unpack`] map them to the 32-byte
//! representation the wire/interface types use (4 little-endian bytes per
//! element — lossless because every BabyBear value is < 2³¹). Arbitrary
//! 32-byte material (e.g. a key-derived `addr_tag`) maps to field elements via
//! the same chunk decoding (reducing mod p as needed); see [`bytes_to_field`].
//!
//! Round constants are derived deterministically from a fixed seed. Production
//! must freeze them into `specs/vectors/poseidon2.json` (plan WP1); centralising
//! generation here keeps the circuit and pipeline in lock-step until then.

use std::sync::OnceLock;

use p3_baby_bear::{
    BabyBear, GenericPoseidon2LinearLayersBabyBear as LL, BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS,
    BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16,
};
use p3_field::integers::QuotientMap;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_poseidon2::GenericPoseidon2LinearLayers;
use rand::distr::StandardUniform;
use rand::rngs::SmallRng;
use rand::{RngExt, SeedableRng};

/// Protocol field.
pub type F = BabyBear;
/// Poseidon2 state width.
pub const WIDTH: usize = 16;
/// Sponge rate / digest size in field elements.
pub const RATE: usize = 8;
/// Digest size in field elements.
pub const DIGEST: usize = 8;
/// Half the number of full rounds.
pub const HALF_FULL: usize = BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS;
/// Number of partial rounds.
pub const PARTIAL: usize = BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16;
const SBOX: u64 = 7;
const SEED: u64 = 42;

/// Poseidon2 round constants (the begin/partial/end split the AIR consumes).
#[derive(Clone)]
pub struct Constants {
    pub begin: [[F; WIDTH]; HALF_FULL],
    pub partial: [F; PARTIAL],
    pub end: [[F; WIDTH]; HALF_FULL],
}

/// Freshly derive the frozen round constants from the fixed seed.
pub fn constants() -> Constants {
    let mut rng = SmallRng::seed_from_u64(SEED);
    Constants {
        begin: core::array::from_fn(|_| core::array::from_fn(|_| rng.sample(StandardUniform))),
        partial: core::array::from_fn(|_| rng.sample(StandardUniform)),
        end: core::array::from_fn(|_| core::array::from_fn(|_| rng.sample(StandardUniform))),
    }
}

fn cached() -> &'static Constants {
    static C: OnceLock<Constants> = OnceLock::new();
    C.get_or_init(constants)
}

/// The Poseidon2 permutation (S-box `x^7`), matching the circuit AIR exactly.
pub fn permute(mut state: [F; WIDTH]) -> [F; WIDTH] {
    let c = cached();
    LL::external_linear_layer(&mut state);
    for rc in &c.begin {
        for (s, r) in state.iter_mut().zip(rc) {
            *s = (*s + *r).exp_const_u64::<SBOX>();
        }
        LL::external_linear_layer(&mut state);
    }
    for &rc in &c.partial {
        state[0] = (state[0] + rc).exp_const_u64::<SBOX>();
        LL::internal_linear_layer(&mut state);
    }
    for rc in &c.end {
        for (s, r) in state.iter_mut().zip(rc) {
            *s = (*s + *r).exp_const_u64::<SBOX>();
        }
        LL::external_linear_layer(&mut state);
    }
    state
}

/// Rate-8 overwrite sponge (IV 0): absorb each block into the rate, permute,
/// squeeze the first 8 elements.
pub fn sponge(blocks: &[[F; RATE]]) -> [F; DIGEST] {
    let mut state = [F::ZERO; WIDTH];
    for block in blocks {
        state[0..RATE].copy_from_slice(block);
        state = permute(state);
    }
    state[0..DIGEST].try_into().unwrap()
}

/// 2-to-1 Merkle compression: `permute(left ‖ right)[0..8]`.
pub fn compress(left: [F; DIGEST], right: [F; DIGEST]) -> [F; DIGEST] {
    let mut s = [F::ZERO; WIDTH];
    s[..DIGEST].copy_from_slice(&left);
    s[DIGEST..].copy_from_slice(&right);
    let o = permute(s);
    o[..DIGEST].try_into().unwrap()
}

/// Pack a digest into 32 bytes (4 LE bytes per element).
pub fn pack(digest: [F; DIGEST]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, v) in digest.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.as_canonical_u32().to_le_bytes());
    }
    out
}

/// Inverse of [`pack`] (exact for packed digests; reduces mod p for arbitrary
/// 32-byte material, so it doubles as [`bytes_to_field`]).
pub fn unpack(bytes: [u8; 32]) -> [F; DIGEST] {
    core::array::from_fn(|i| {
        let x = u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap());
        F::from_int(x)
    })
}

/// Map arbitrary 32-byte material to 8 field elements (alias of [`unpack`]).
pub fn bytes_to_field(bytes: [u8; 32]) -> [F; DIGEST] {
    unpack(bytes)
}

/// Decompose a `u64` value into 8 byte-limbs as field elements (the in-circuit
/// value representation used by the balance/range constraints).
pub fn value_limbs(v: u64) -> [F; RATE] {
    core::array::from_fn(|j| F::from_int(((v >> (8 * j)) & 0xff) as u8))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::borrow::Borrow;
    use p3_poseidon2_air::{generate_trace_rows, num_cols, Poseidon2Cols, RoundConstants};

    fn rand_state(seed: u64) -> [F; WIDTH] {
        let mut rng = SmallRng::seed_from_u64(seed);
        core::array::from_fn(|_| rng.sample(StandardUniform))
    }

    /// The host permutation must match Plonky3's reference Poseidon2 AIR for the
    /// same constants — anchoring correctness to the audited implementation.
    #[test]
    fn permute_matches_plonky3_reference() {
        let c = constants();
        let input = rand_state(7);
        let mine = permute(input);

        let rc = RoundConstants::<F, WIDTH, HALF_FULL, PARTIAL>::new(c.begin, c.partial, c.end);
        let trace =
            generate_trace_rows::<F, LL, WIDTH, SBOX, 0, HALF_FULL, PARTIAL>(vec![input], &rc, 0);
        let ncols = num_cols::<WIDTH, SBOX, 0, HALF_FULL, PARTIAL>();
        let cols: &Poseidon2Cols<F, WIDTH, SBOX, 0, HALF_FULL, PARTIAL> =
            trace.values[..ncols].borrow();
        assert_eq!(mine, cols.ending_full_rounds[HALF_FULL - 1].post);
    }

    #[test]
    fn pack_round_trips() {
        let d = sponge(&[value_limbs(123), [F::ONE; RATE]]);
        assert_eq!(unpack(pack(d)), d);
    }

    #[test]
    fn sponge_and_compress_are_deterministic() {
        let a = sponge(&[value_limbs(1), value_limbs(2)]);
        let b = sponge(&[value_limbs(1), value_limbs(2)]);
        assert_eq!(a, b);
        assert_eq!(compress(a, b), compress(a, b));
        assert_ne!(sponge(&[value_limbs(1)]), sponge(&[value_limbs(2)]));
    }
}
