//! WP6b fusion — the full input-side spend core (C1 + C2 + C3 + C5).
//!
//! For one input note this proves, in a single STARK:
//! - **C5** the commitment `cm = H(value ‖ addr_tag ‖ rho)` (3-block sponge);
//! - **C1** that `cm` is a depth-32 Merkle leaf to the public anchor root;
//! - **C2** the nullifier `nf = H(nk ‖ rho)` (2-block sponge), bound to public;
//! - **C3** ownership: the note's `addr_tag` equals the spender's key `nk`, so
//!   only the holder of `nk` (which also derives the nullifier) can spend it.
//!
//! The cross-wiring is the point: `rho` is shared between the commitment and
//! nullifier sponges (the same witness columns), and `addr_tag` is constrained
//! equal to `nk`. Everything stays witness except the public anchor root and
//! nullifier — so the note and key are never revealed.
//!
//! Layout is single-row (replicated for FRI height): commitment sponge,
//! nullifier sponge, then the 32 Merkle compressions, then per-level siblings
//! and direction bits — all composed via the base-offset `eval_perm_body`.
//! This is the per-input core of the spend statement; the output commitments,
//! balance, and uniform 2-in/2-out arity layer on the same way.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{prove, verify, Proof};
use unknown_interfaces::TREE_DEPTH;

use crate::field::{make_config, Config, FriProfile, Val};
use crate::hash::{CAP, DIGEST, RATE};
use crate::perm::{eval_perm_body, input_off, output_off, Poseidon2PermAir, WIDTH, WIDTH_COLS};

/// Commitment preimage blocks: value ‖ addr_tag ‖ rho.
pub const CM_BLOCKS: usize = 3;
/// Nullifier preimage blocks: nk ‖ rho.
pub const NF_BLOCKS: usize = 2;
/// Merkle depth.
pub const DEPTH: usize = TREE_DEPTH;
/// Replicated rows (single-row computation; height for the COMPACT profile).
pub const ROWS: usize = 32;

// Column layout.
const CM_BASE: usize = 0;
const NF_BASE: usize = CM_BLOCKS * WIDTH_COLS;
const MERKLE_BASE: usize = NF_BASE + NF_BLOCKS * WIDTH_COLS;
const EXTRA_BASE: usize = MERKLE_BASE + DEPTH * WIDTH_COLS;
/// Total trace width.
pub const TOTAL_COLS: usize = EXTRA_BASE + DEPTH * (DIGEST + 1);

const fn cm_block(b: usize) -> usize {
    CM_BASE + b * WIDTH_COLS
}
const fn nf_block(b: usize) -> usize {
    NF_BASE + b * WIDTH_COLS
}
const fn merkle_level(l: usize) -> usize {
    MERKLE_BASE + l * WIDTH_COLS
}
const fn sib_off(l: usize) -> usize {
    EXTRA_BASE + l * (DIGEST + 1)
}
const fn dir_off(l: usize) -> usize {
    EXTRA_BASE + l * (DIGEST + 1) + DIGEST
}
const fn cm_out() -> usize {
    cm_block(CM_BLOCKS - 1) + output_off()
}
const fn nf_out() -> usize {
    nf_block(NF_BLOCKS - 1) + output_off()
}

/// One Merkle path step (sibling digest, direction bit).
pub type PathStep = ([Val; DIGEST], bool);

/// Input-note core AIR.
#[derive(Clone)]
pub struct SpendInputAir<F> {
    perm: Poseidon2PermAir<F>,
}

impl SpendInputAir<Val> {
    pub fn new_seeded() -> Self {
        Self {
            perm: Poseidon2PermAir::new_seeded(),
        }
    }

    fn join(left: [Val; DIGEST], right: [Val; DIGEST]) -> [Val; WIDTH] {
        let mut out = [Val::ZERO; WIDTH];
        out[..DIGEST].copy_from_slice(&left);
        out[DIGEST..].copy_from_slice(&right);
        out
    }

    /// Host sponge over `blocks` rate-8 blocks (IV 0), into `dst[base..]`.
    fn fill_sponge(&self, blocks: &[[Val; RATE]], dst: &mut [Val], base: usize) -> [Val; DIGEST] {
        let mut cap = [Val::ZERO; CAP];
        let mut digest = [Val::ZERO; DIGEST];
        for (b, block) in blocks.iter().enumerate() {
            let off = base + b * WIDTH_COLS;
            let mut input = [Val::ZERO; WIDTH];
            input[0..RATE].copy_from_slice(block);
            input[RATE..WIDTH].copy_from_slice(&cap);
            self.perm
                .fill_perm_row(input, &mut dst[off..off + WIDTH_COLS]);
            let out = off + output_off();
            cap = dst[out + RATE..out + WIDTH].try_into().unwrap();
            digest = dst[out..out + DIGEST].try_into().unwrap();
        }
        digest
    }

    /// Build the trace; returns it with the computed root and nullifier.
    pub fn generate_trace(
        &self,
        value: [Val; RATE],
        nk: [Val; RATE],
        rho: [Val; RATE],
        path: &[PathStep],
    ) -> (RowMajorMatrix<Val>, [Val; DIGEST], [Val; DIGEST]) {
        assert_eq!(path.len(), DEPTH);
        let mut row = vec![Val::ZERO; TOTAL_COLS];

        // C5 commitment: H(value ‖ addr_tag ‖ rho), with addr_tag = nk (C3).
        let cm = self.fill_sponge(&[value, nk, rho], &mut row, CM_BASE);
        // C2 nullifier: H(nk ‖ rho).
        let nf = self.fill_sponge(&[nk, rho], &mut row, NF_BASE);

        // C1 membership: fold cm up the path.
        let mut cur = cm;
        for (l, &(sib, dir)) in path.iter().enumerate() {
            let pbase = merkle_level(l);
            let input = if dir {
                Self::join(sib, cur)
            } else {
                Self::join(cur, sib)
            };
            self.perm
                .fill_perm_row(input, &mut row[pbase..pbase + WIDTH_COLS]);
            row[sib_off(l)..sib_off(l) + DIGEST].copy_from_slice(&sib);
            row[dir_off(l)] = Val::from_bool(dir);
            let out = pbase + output_off();
            cur = row[out..out + DIGEST].try_into().unwrap();
        }
        let root = cur;

        let mut values = Vec::with_capacity(TOTAL_COLS * ROWS);
        for _ in 0..ROWS {
            values.extend_from_slice(&row);
        }
        (RowMajorMatrix::new(values, TOTAL_COLS), root, nf)
    }
}

/// Public values: anchor root followed by nullifier.
pub fn public_values(root: [Val; DIGEST], nf: [Val; DIGEST]) -> Vec<Val> {
    root.into_iter().chain(nf).collect()
}

impl<F: PrimeCharacteristicRing + Sync> BaseAir<F> for SpendInputAir<F> {
    fn width(&self) -> usize {
        TOTAL_COLS
    }
    fn num_public_values(&self) -> usize {
        2 * DIGEST
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }
}

/// Constrain a rate-8 overwrite sponge of `blocks` blocks at `base` (IV 0).
fn eval_sponge<AB: AirBuilder>(
    perm: &Poseidon2PermAir<AB::F>,
    builder: &mut AB,
    local: &[AB::Var],
    base: usize,
    blocks: usize,
) {
    for b in 0..blocks {
        let off = base + b * WIDTH_COLS;
        for j in 0..CAP {
            let cap_in = off + input_off() + RATE + j;
            if b == 0 {
                builder.assert_zero(local[cap_in]);
            } else {
                let prev_out = (off - WIDTH_COLS) + output_off() + RATE + j;
                builder.assert_eq(local[cap_in], local[prev_out]);
            }
        }
        eval_perm_body(perm, builder, local, off);
    }
}

impl<AB: AirBuilder> Air<AB> for SpendInputAir<AB::F> {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let pis: Vec<AB::PublicVar> = builder.public_values().to_vec();

        // Commitment and nullifier sponges.
        eval_sponge(&self.perm, builder, local, CM_BASE, CM_BLOCKS);
        eval_sponge(&self.perm, builder, local, NF_BASE, NF_BLOCKS);

        // C3 ownership: the commitment's addr_tag block equals the nullifier's
        // key block (both are `nk`).
        let addr_tag = cm_block(1) + input_off();
        let nk = nf_block(0) + input_off();
        for j in 0..RATE {
            builder.assert_eq(local[addr_tag + j], local[nk + j]);
        }
        // rho is shared: commitment's rho block equals the nullifier's rho block.
        let cm_rho = cm_block(2) + input_off();
        let nf_rho = nf_block(1) + input_off();
        for j in 0..RATE {
            builder.assert_eq(local[cm_rho + j], local[nf_rho + j]);
        }

        // C2: nullifier output bound to the public nullifier.
        for j in 0..DIGEST {
            builder.assert_eq(local[nf_out() + j], pis[DIGEST + j]);
        }

        // C1: Merkle path; level 0's current digest is the commitment.
        for l in 0..DEPTH {
            let pbase = merkle_level(l);
            builder.assert_bool(local[dir_off(l)]);
            let cur_src = if l == 0 {
                cm_out()
            } else {
                merkle_level(l - 1) + output_off()
            };
            for j in 0..DIGEST {
                let cur = local[cur_src + j];
                let sib = local[sib_off(l) + j];
                let dir: AB::Expr = local[dir_off(l)].into();
                let left = cur * (AB::Expr::ONE - dir.clone()) + sib * dir.clone();
                let right = sib * (AB::Expr::ONE - dir.clone()) + cur * dir;
                builder.assert_eq(local[pbase + input_off() + j], left);
                builder.assert_eq(local[pbase + input_off() + DIGEST + j], right);
            }
            eval_perm_body(&self.perm, builder, local, pbase);
        }

        // C1: root bound to the public anchor.
        let root = merkle_level(DEPTH - 1) + output_off();
        for j in 0..DIGEST {
            builder.assert_eq(local[root + j], pis[j]);
        }
    }
}

/// Prove the input-note core. Returns config, proof, and public values.
pub fn prove_input(
    air: &SpendInputAir<Val>,
    value: [Val; RATE],
    nk: [Val; RATE],
    rho: [Val; RATE],
    path: &[PathStep],
) -> (Config, Proof<Config>, Vec<Val>) {
    let config = make_config(FriProfile::COMPACT);
    let (trace, root, nf) = air.generate_trace(value, nk, rho, path);
    let pis = public_values(root, nf);
    let proof = prove(&config, air, trace, &pis);
    (config, proof, pis)
}

/// Verify an input-note-core proof.
pub fn verify_input(
    config: &Config,
    air: &SpendInputAir<Val>,
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

    fn rand_inputs(seed: u64) -> ([Val; RATE], [Val; RATE], [Val; RATE], Vec<PathStep>) {
        let mut rng = SmallRng::seed_from_u64(seed);
        let value = core::array::from_fn(|_| rng.sample(StandardUniform));
        let nk = core::array::from_fn(|_| rng.sample(StandardUniform));
        let rho = core::array::from_fn(|_| rng.sample(StandardUniform));
        let path = (0..DEPTH)
            .map(|_| {
                let sib: [Val; DIGEST] = core::array::from_fn(|_| rng.sample(StandardUniform));
                (sib, rng.sample::<bool, _>(StandardUniform))
            })
            .collect();
        (value, nk, rho, path)
    }

    #[test]
    fn input_core_proves_and_verifies() {
        let air = SpendInputAir::new_seeded();
        let (value, nk, rho, path) = rand_inputs(1);
        let (config, proof, pis) = prove_input(&air, value, nk, rho, &path);
        verify_input(&config, &air, &proof, &pis).expect("input core verifies");
    }

    #[test]
    fn wrong_nullifier_is_rejected() {
        let air = SpendInputAir::new_seeded();
        let (value, nk, rho, path) = rand_inputs(2);
        let (config, proof, mut pis) = prove_input(&air, value, nk, rho, &path);
        pis[DIGEST] += Val::ONE; // tamper nullifier
        assert!(verify_input(&config, &air, &proof, &pis).is_err());
    }

    #[test]
    fn wrong_root_is_rejected() {
        let air = SpendInputAir::new_seeded();
        let (value, nk, rho, path) = rand_inputs(3);
        let (config, proof, mut pis) = prove_input(&air, value, nk, rho, &path);
        pis[0] += Val::ONE; // tamper root
        assert!(verify_input(&config, &air, &proof, &pis).is_err());
    }

    #[test]
    fn tampered_proof_is_rejected() {
        let air = SpendInputAir::new_seeded();
        let (value, nk, rho, path) = rand_inputs(4);
        let (config, mut proof, pis) = prove_input(&air, value, nk, rho, &path);
        proof.degree_bits = proof.degree_bits.wrapping_add(1);
        assert!(verify_input(&config, &air, &proof, &pis).is_err());
    }
}
