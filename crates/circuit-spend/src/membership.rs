//! WP6b fusion — committed-note membership (C5 + C1 in one circuit).
//!
//! Proves: *there exists a note whose Poseidon2 commitment is a leaf of the
//! commitment tree at the public anchor root.* This is the first fusion of two
//! WP6a gadgets — the output of the sponge commitment ([`crate::hash`]) is wired
//! directly into the leaf of the Merkle path ([`crate::merkle`]) — so the
//! commitment is never revealed, only the membership.
//!
//! Layout (single trace row, replicated for FRI height): the note's commitment
//! sponge occupies the first `NOTE_BLOCKS * WIDTH_COLS` columns; the 32 Merkle
//! compressions follow, one Poseidon2 permutation each; then per-level sibling
//! digests and direction bits. Level 0's current digest is read *directly from
//! the sponge's output columns* — that wire is the fusion. Each level chains to
//! the next intra-row; the last level's output is bound to the public root.
//!
//! Witness: the note preimage and the Merkle path. Public: the anchor root.
//! In the full spend statement this is the per-input-note core of constraints
//! C1/C5; the remaining wiring (nullifiers, balance, output commitments) layers
//! on the same way.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{prove, verify, Proof};
use unknown_interfaces::TREE_DEPTH;

use crate::field::{make_config, Config, FriProfile, Val};
use crate::hash::{CAP, DIGEST, RATE};
use crate::perm::{eval_perm_body, input_off, output_off, Poseidon2PermAir, WIDTH, WIDTH_COLS};

/// Note commitment preimage length in rate-8 blocks (e.g. value-limbs ‖ rand).
pub const NOTE_BLOCKS: usize = 2;
/// Merkle depth.
pub const DEPTH: usize = TREE_DEPTH;
/// Replicated rows (single-row computation; height for the COMPACT profile).
pub const ROWS: usize = 32;

// Column layout.
const SPONGE_COLS: usize = NOTE_BLOCKS * WIDTH_COLS;
const MERKLE_BASE: usize = SPONGE_COLS;
const MERKLE_COLS: usize = DEPTH * WIDTH_COLS;
const EXTRA_BASE: usize = MERKLE_BASE + MERKLE_COLS;
/// Total trace width.
pub const TOTAL_COLS: usize = EXTRA_BASE + DEPTH * (DIGEST + 1);

const fn sponge_block(b: usize) -> usize {
    b * WIDTH_COLS
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
/// Column offset of the commitment (sponge output digest).
const fn cm_off() -> usize {
    sponge_block(NOTE_BLOCKS - 1) + output_off()
}

/// One Merkle path step (sibling digest, direction bit).
pub type PathStep = ([Val; DIGEST], bool);

/// Committed-note membership AIR.
#[derive(Clone)]
pub struct MembershipAir<F> {
    perm: Poseidon2PermAir<F>,
}

impl MembershipAir<Val> {
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

    /// Host: commitment of a note preimage (rate-8 sponge, IV 0).
    pub fn commit(&self, note: &[Val]) -> [Val; DIGEST] {
        assert_eq!(note.len(), NOTE_BLOCKS * RATE);
        let mut state = [Val::ZERO; WIDTH];
        for b in 0..NOTE_BLOCKS {
            state[0..RATE].copy_from_slice(&note[b * RATE..b * RATE + RATE]);
            state = self.perm.permute(state);
        }
        state[0..DIGEST].try_into().unwrap()
    }

    /// Host: fold a commitment up a path to the root.
    pub fn root(&self, cm: [Val; DIGEST], path: &[PathStep]) -> [Val; DIGEST] {
        let mut cur = cm;
        for &(sib, dir) in path {
            let input = if dir {
                Self::join(sib, cur)
            } else {
                Self::join(cur, sib)
            };
            let out = self.perm.permute(input);
            cur = out[..DIGEST].try_into().unwrap();
        }
        cur
    }

    /// Build the execution trace; returns it with the computed root.
    pub fn generate_trace(
        &self,
        note: &[Val],
        path: &[PathStep],
    ) -> (RowMajorMatrix<Val>, [Val; DIGEST]) {
        assert_eq!(note.len(), NOTE_BLOCKS * RATE);
        assert_eq!(path.len(), DEPTH);
        let mut row = vec![Val::ZERO; TOTAL_COLS];

        // Sponge → commitment.
        let mut cap = [Val::ZERO; CAP];
        for b in 0..NOTE_BLOCKS {
            let base = sponge_block(b);
            let mut input = [Val::ZERO; WIDTH];
            input[0..RATE].copy_from_slice(&note[b * RATE..b * RATE + RATE]);
            input[RATE..WIDTH].copy_from_slice(&cap);
            self.perm
                .fill_perm_row(input, &mut row[base..base + WIDTH_COLS]);
            let out = base + output_off();
            cap = row[out + RATE..out + WIDTH].try_into().unwrap();
        }
        let cm: [Val; DIGEST] = row[cm_off()..cm_off() + DIGEST].try_into().unwrap();

        // Merkle path from the commitment.
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
        (RowMajorMatrix::new(values, TOTAL_COLS), root)
    }
}

/// Public values: the anchor root.
pub fn public_values(root: [Val; DIGEST]) -> Vec<Val> {
    root.to_vec()
}

impl<F: PrimeCharacteristicRing + Sync> BaseAir<F> for MembershipAir<F> {
    fn width(&self) -> usize {
        TOTAL_COLS
    }
    fn num_public_values(&self) -> usize {
        DIGEST
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new() // single-row computation
    }
}

impl<AB: AirBuilder> Air<AB> for MembershipAir<AB::F> {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let pis: Vec<AB::PublicVar> = builder.public_values().to_vec();

        // --- commitment sponge (IV 0, overwrite rate) ---
        for b in 0..NOTE_BLOCKS {
            let base = sponge_block(b);
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

        // --- Merkle path; level 0's current digest IS the commitment ---
        for l in 0..DEPTH {
            let pbase = merkle_level(l);
            builder.assert_bool(local[dir_off(l)]);

            // current digest source: the sponge output for level 0, else the
            // previous level's compression output.
            let cur_src = if l == 0 {
                cm_off()
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

        // Root binding.
        let root = merkle_level(DEPTH - 1) + output_off();
        for j in 0..DIGEST {
            builder.assert_eq(local[root + j], pis[j]);
        }
    }
}

/// Prove that the note's commitment is included under the path's root.
pub fn prove_membership(
    air: &MembershipAir<Val>,
    note: &[Val],
    path: &[PathStep],
) -> (Config, Proof<Config>, Vec<Val>) {
    let config = make_config(FriProfile::COMPACT);
    let (trace, root) = air.generate_trace(note, path);
    let pis = public_values(root);
    let proof = prove(&config, air, trace, &pis);
    (config, proof, pis)
}

/// Verify a membership proof against the public root.
pub fn verify_membership(
    config: &Config,
    air: &MembershipAir<Val>,
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

    fn rand_inputs(seed: u64) -> (Vec<Val>, Vec<PathStep>) {
        let mut rng = SmallRng::seed_from_u64(seed);
        let note: Vec<Val> = (0..NOTE_BLOCKS * RATE)
            .map(|_| rng.sample(StandardUniform))
            .collect();
        let path: Vec<PathStep> = (0..DEPTH)
            .map(|_| {
                let sib: [Val; DIGEST] = core::array::from_fn(|_| rng.sample(StandardUniform));
                (sib, rng.sample::<bool, _>(StandardUniform))
            })
            .collect();
        (note, path)
    }

    #[test]
    fn membership_proves_and_verifies() {
        let air = MembershipAir::new_seeded();
        let (note, path) = rand_inputs(1);
        let (config, proof, pis) = prove_membership(&air, &note, &path);
        verify_membership(&config, &air, &proof, &pis).expect("membership verifies");
    }

    #[test]
    fn trace_root_matches_gadget_hosts() {
        // The fused circuit's root must equal commit-then-fold computed with
        // the standalone hosts (same permutation constants).
        let air = MembershipAir::new_seeded();
        let (note, path) = rand_inputs(2);
        let (_trace, root) = air.generate_trace(&note, &path);
        let cm = air.commit(&note);
        let expected = air.root(cm, &path);
        assert_eq!(root, expected);
    }

    #[test]
    fn wrong_root_is_rejected() {
        let air = MembershipAir::new_seeded();
        let (note, path) = rand_inputs(3);
        let (config, proof, mut pis) = prove_membership(&air, &note, &path);
        pis[0] += Val::ONE;
        assert!(verify_membership(&config, &air, &proof, &pis).is_err());
    }

    #[test]
    fn tampered_proof_is_rejected() {
        let air = MembershipAir::new_seeded();
        let (note, path) = rand_inputs(4);
        let (config, mut proof, pis) = prove_membership(&air, &note, &path);
        proof.degree_bits = proof.degree_bits.wrapping_add(1);
        assert!(verify_membership(&config, &air, &proof, &pis).is_err());
    }
}
