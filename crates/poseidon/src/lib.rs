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
//! Round constants are **frozen** in [`specs/vectors/poseidon2.json`] and loaded
//! from there (plan WP1), so they are an auditable spec artifact rather than a
//! runtime accident. They were generated once from a fixed seed
//! ([`derive_from_seed`]); a test asserts the frozen file still equals the
//! generator, so the JSON and the generator can never silently diverge.
//!
//! [`specs/vectors/poseidon2.json`]: ../../../specs/vectors/poseidon2.json

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
use serde::{Deserialize, Serialize};

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

/// The frozen round-constant spec, embedded at build time.
const FROZEN_JSON: &str = include_str!("../../../specs/vectors/poseidon2.json");

/// Poseidon2 round constants (the begin/partial/end split the AIR consumes).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Constants {
    pub begin: [[F; WIDTH]; HALF_FULL],
    pub partial: [F; PARTIAL],
    pub end: [[F; WIDTH]; HALF_FULL],
}

/// On-disk shape of `specs/vectors/poseidon2.json`: metadata (for human/auditor
/// review) plus the three round-constant groups as canonical `u32` field values.
#[derive(Serialize, Deserialize)]
pub struct ConstantsSpec {
    pub hash: String,
    pub field: String,
    pub width: usize,
    pub sbox: u64,
    pub half_full_rounds: usize,
    pub partial_rounds: usize,
    /// How the values were produced, so the spec is reproducible.
    pub generator: String,
    pub begin: Vec<Vec<u32>>,
    pub partial: Vec<u32>,
    pub end: Vec<Vec<u32>>,
}

fn rows_to_array(rows: &[Vec<u32>]) -> [[F; WIDTH]; HALF_FULL] {
    assert_eq!(
        rows.len(),
        HALF_FULL,
        "frozen constants: wrong full-round count"
    );
    core::array::from_fn(|i| {
        assert_eq!(rows[i].len(), WIDTH, "frozen constants: wrong width");
        core::array::from_fn(|j| F::from_int(rows[i][j]))
    })
}

impl ConstantsSpec {
    /// Reconstruct the typed [`Constants`] from the spec.
    pub fn to_constants(&self) -> Constants {
        assert_eq!(
            self.partial.len(),
            PARTIAL,
            "frozen constants: wrong partial-round count"
        );
        Constants {
            begin: rows_to_array(&self.begin),
            partial: core::array::from_fn(|i| F::from_int(self.partial[i])),
            end: rows_to_array(&self.end),
        }
    }

    /// Build a spec from typed [`Constants`] (used by the generator example).
    pub fn from_constants(c: &Constants) -> Self {
        let rows = |g: &[[F; WIDTH]; HALF_FULL]| {
            g.iter()
                .map(|r| r.iter().map(|v| v.as_canonical_u32()).collect())
                .collect()
        };
        Self {
            hash: "Poseidon2".to_string(),
            field: "BabyBear".to_string(),
            width: WIDTH,
            sbox: SBOX,
            half_full_rounds: HALF_FULL,
            partial_rounds: PARTIAL,
            generator: format!("SmallRng(seed={SEED}) StandardUniform, in begin/partial/end order"),
            begin: rows(&c.begin),
            partial: c.partial.iter().map(|v| v.as_canonical_u32()).collect(),
            end: rows(&c.end),
        }
    }
}

/// Derive the round constants from the fixed seed. This is the *generator* of
/// record; the frozen JSON is its pinned output (see [`constants`]).
pub fn derive_from_seed() -> Constants {
    let mut rng = SmallRng::seed_from_u64(SEED);
    Constants {
        begin: core::array::from_fn(|_| core::array::from_fn(|_| rng.sample(StandardUniform))),
        partial: core::array::from_fn(|_| rng.sample(StandardUniform)),
        end: core::array::from_fn(|_| core::array::from_fn(|_| rng.sample(StandardUniform))),
    }
}

/// The frozen protocol round constants, loaded from `specs/vectors/poseidon2.json`.
pub fn constants() -> Constants {
    let spec: ConstantsSpec =
        serde_json::from_str(FROZEN_JSON).expect("specs/vectors/poseidon2.json is valid");
    spec.to_constants()
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

    /// The committed `specs/vectors/poseidon2.json` must equal the seed
    /// generator of record. If this fails, regenerate the spec with
    /// `cargo run -p unknown-poseidon --example freeze_constants`.
    #[test]
    fn frozen_constants_match_generator() {
        assert_eq!(
            constants(),
            derive_from_seed(),
            "specs/vectors/poseidon2.json has drifted from the seed generator"
        );
    }

    /// The spec round-trips through its on-disk form (parse → typed → spec).
    #[test]
    fn spec_round_trips() {
        let spec = ConstantsSpec::from_constants(&derive_from_seed());
        let json = serde_json::to_string(&spec).unwrap();
        let back: ConstantsSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(back.to_constants(), derive_from_seed());
    }

    /// Golden digests pin the protocol hash. If Poseidon2 constants or the
    /// permutation ever change, these break — a deliberate consensus tripwire.
    #[test]
    fn golden_vectors() {
        // A two-block sponge over fixed value-limbs.
        let d = sponge(&[value_limbs(1), value_limbs(2)]);
        let canon: [u32; DIGEST] = core::array::from_fn(|i| d[i].as_canonical_u32());
        assert_eq!(
            canon,
            [
                1972431003, 1230026623, 3969181, 165564308, 1122360059, 1275594131, 912807871,
                1396653160
            ],
            "sponge golden vector changed (constants or permutation drifted)"
        );

        // 2-to-1 compression of two distinct digests.
        let c = compress(sponge(&[value_limbs(3)]), sponge(&[value_limbs(4)]));
        let canon_c: [u32; DIGEST] = core::array::from_fn(|i| c[i].as_canonical_u32());
        assert_eq!(
            canon_c,
            [
                342235067, 96420216, 1041534851, 1739587423, 443073354, 1984062978, 720866480,
                984897615
            ],
            "compress golden vector changed (constants or permutation drifted)"
        );
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
