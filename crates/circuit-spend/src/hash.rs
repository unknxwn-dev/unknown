//! WP6a gadget — in-circuit Poseidon2 sponge hash (constraints C2/C5 primitive).
//!
//! A rate-8 overwrite sponge over BabyBear: absorb the preimage in 8-element
//! blocks (overwriting the rate, keeping the 8-element capacity), permute after
//! each block, then squeeze the first 8 elements as the digest. This is how the
//! spend statement derives note commitments and nullifiers — `cm = H(note
//! fields)`, `nf = H(nk ‖ rho)` — so it is the hashing primitive C2/C5 rest on.
//!
//! The whole sponge lives in **one trace row**: block `b`'s permutation
//! occupies columns `b*WIDTH_COLS .. (b+1)*WIDTH_COLS` (reusing [`crate::perm`]
//! via the base-offset `eval_perm_body`), and the capacity chains intra-row from
//! one block's output to the next block's input. With no cross-row constraints
//! the single row is replicated to satisfy the FRI minimum height — the same
//! pattern as the permutation gadget. The preimage is witness; only the digest
//! is bound to a public value (so this proves knowledge of a preimage for a
//! given digest, which is exactly what commitment/nullifier derivation needs).
//!
//! Degree 7 (Poseidon2 S-box) ⇒ proves under the COMPACT profile (blowup 8).

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{prove, verify, Proof};

use crate::field::{make_config, Config, FriProfile, Val};
use crate::perm::{eval_perm_body, input_off, output_off, Poseidon2PermAir, WIDTH, WIDTH_COLS};

/// Sponge rate (elements absorbed per permutation).
pub const RATE: usize = 8;
/// Capacity (state elements preserved across absorptions).
pub const CAP: usize = WIDTH - RATE;
/// Digest size in field elements.
pub const DIGEST: usize = 8;
/// Replicated rows (single-row computation; height for the COMPACT profile).
pub const ROWS: usize = 32;

/// Poseidon2 sponge AIR over a fixed number of rate-8 blocks.
#[derive(Clone)]
pub struct SpongeHashAir<F> {
    perm: Poseidon2PermAir<F>,
    blocks: usize,
}

impl SpongeHashAir<Val> {
    /// A sponge absorbing exactly `blocks` blocks (preimage length
    /// `blocks * RATE`; callers zero-pad to a block boundary).
    pub fn new_seeded(blocks: usize) -> Self {
        assert!(blocks >= 1, "need at least one block");
        Self {
            perm: Poseidon2PermAir::new_seeded(),
            blocks,
        }
    }

    /// Host sponge evaluation. `preimage.len()` must equal `blocks * RATE`.
    pub fn hash(&self, preimage: &[Val]) -> [Val; DIGEST] {
        assert_eq!(preimage.len(), self.blocks * RATE);
        let mut state = [Val::ZERO; WIDTH];
        for b in 0..self.blocks {
            state[0..RATE].copy_from_slice(&preimage[b * RATE..b * RATE + RATE]);
            state = self.perm.permute(state);
        }
        state[0..DIGEST].try_into().unwrap()
    }

    /// Build the (row-replicated) trace and return it with the digest.
    pub fn generate_trace(&self, preimage: &[Val]) -> (RowMajorMatrix<Val>, [Val; DIGEST]) {
        assert_eq!(preimage.len(), self.blocks * RATE);
        let width = self.blocks * WIDTH_COLS;
        let mut row = vec![Val::ZERO; width];

        let mut capacity = [Val::ZERO; CAP];
        let mut digest = [Val::ZERO; DIGEST];
        for b in 0..self.blocks {
            let base = b * WIDTH_COLS;
            let mut input = [Val::ZERO; WIDTH];
            input[0..RATE].copy_from_slice(&preimage[b * RATE..b * RATE + RATE]);
            input[RATE..WIDTH].copy_from_slice(&capacity);
            self.perm
                .fill_perm_row(input, &mut row[base..base + WIDTH_COLS]);
            let out = base + output_off();
            capacity = row[out + RATE..out + WIDTH].try_into().unwrap();
            digest = row[out..out + DIGEST].try_into().unwrap();
        }

        let mut values = Vec::with_capacity(width * ROWS);
        for _ in 0..ROWS {
            values.extend_from_slice(&row);
        }
        (RowMajorMatrix::new(values, width), digest)
    }
}

/// Public values: the digest.
pub fn public_values(digest: [Val; DIGEST]) -> Vec<Val> {
    digest.to_vec()
}

impl<F: PrimeCharacteristicRing + Sync> BaseAir<F> for SpongeHashAir<F> {
    fn width(&self) -> usize {
        self.blocks * WIDTH_COLS
    }
    fn num_public_values(&self) -> usize {
        DIGEST
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new() // single-row computation
    }
}

impl<AB: AirBuilder> Air<AB> for SpongeHashAir<AB::F> {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let pis: Vec<AB::PublicVar> = builder.public_values().to_vec();

        for b in 0..self.blocks {
            let base = b * WIDTH_COLS;
            // Capacity input: the IV (zero) for block 0, else the previous
            // block's output capacity. The rate input is the free preimage.
            for j in 0..CAP {
                let cap_in = base + input_off() + RATE + j;
                if b == 0 {
                    builder.assert_zero(local[cap_in]);
                } else {
                    let prev_out = (base - WIDTH_COLS) + output_off() + RATE + j;
                    builder.assert_eq(local[cap_in], local[prev_out]);
                }
            }
            eval_perm_body(&self.perm, builder, local, base);
        }

        // Squeeze: the last block's output rate is the digest.
        let last = (self.blocks - 1) * WIDTH_COLS + output_off();
        for j in 0..DIGEST {
            builder.assert_eq(local[last + j], pis[j]);
        }
    }
}

/// Prove that some witness preimage hashes to its (public) digest.
pub fn prove_hash(air: &SpongeHashAir<Val>, preimage: &[Val]) -> (Config, Proof<Config>, Vec<Val>) {
    let config = make_config(FriProfile::COMPACT);
    let (trace, digest) = air.generate_trace(preimage);
    let pis = public_values(digest);
    let proof = prove(&config, air, trace, &pis);
    (config, proof, pis)
}

/// Verify a hash proof against the public digest.
pub fn verify_hash(
    config: &Config,
    air: &SpongeHashAir<Val>,
    proof: &Proof<Config>,
    pis: &[Val],
) -> Result<(), String> {
    verify(config, air, proof, pis).map_err(|e| format!("{e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::distr::StandardUniform;
    use rand::rngs::SmallRng;
    use rand::{RngExt, SeedableRng};

    fn rand_preimage(seed: u64, len: usize) -> Vec<Val> {
        let mut rng = SmallRng::seed_from_u64(seed);
        (0..len).map(|_| rng.sample(StandardUniform)).collect()
    }

    #[test]
    fn commitment_hash_proves_and_verifies() {
        // 4 blocks ≈ a note commitment preimage (value ‖ addr_tag ‖ rho ‖ rseed).
        let air = SpongeHashAir::new_seeded(4);
        let preimage = rand_preimage(1, 4 * RATE);
        let (config, proof, pis) = prove_hash(&air, &preimage);
        verify_hash(&config, &air, &proof, &pis).expect("hash verifies");
    }

    #[test]
    fn nullifier_hash_proves_and_verifies() {
        // 2 blocks ≈ a nullifier preimage (nk ‖ rho).
        let air = SpongeHashAir::new_seeded(2);
        let preimage = rand_preimage(2, 2 * RATE);
        let (config, proof, pis) = prove_hash(&air, &preimage);
        verify_hash(&config, &air, &proof, &pis).expect("hash verifies");
    }

    #[test]
    fn wrong_digest_is_rejected() {
        let air = SpongeHashAir::new_seeded(4);
        let preimage = rand_preimage(3, 4 * RATE);
        let (config, proof, mut pis) = prove_hash(&air, &preimage);
        pis[0] += Val::ONE;
        assert!(verify_hash(&config, &air, &proof, &pis).is_err());
    }

    #[test]
    fn tampered_proof_is_rejected() {
        let air = SpongeHashAir::new_seeded(4);
        let preimage = rand_preimage(4, 4 * RATE);
        let (config, mut proof, pis) = prove_hash(&air, &preimage);
        proof.degree_bits = proof.degree_bits.wrapping_add(1);
        assert!(verify_hash(&config, &air, &proof, &pis).is_err());
    }

    #[test]
    fn distinct_preimages_give_distinct_digests() {
        let air = SpongeHashAir::new_seeded(4);
        let a = air.hash(&rand_preimage(5, 4 * RATE));
        let b = air.hash(&rand_preimage(6, 4 * RATE));
        assert_ne!(a, b);
        // Determinism.
        let p = rand_preimage(7, 4 * RATE);
        assert_eq!(air.hash(&p), air.hash(&p));
    }
}
