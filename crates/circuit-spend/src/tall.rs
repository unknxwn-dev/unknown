//! Tall-layout Poseidon2 gadgets — the foundation of the proof-size fix.
//!
//! The fused spend circuit (`spend.rs`) packs all ~86 Poseidon2 permutations
//! into the *columns* of one replicated row; FRI opens every column, so the
//! proof balloons to ~5.4 MB (see `docs/gate-a-report.md`). The fix is the
//! standard *tall* layout: one permutation per **row**, with transition
//! constraints chaining state from each row to the next. Proof size then
//! scales with the (logarithmic) FRI cost in the row dimension instead of the
//! column width.
//!
//! Two gadgets share the mechanism:
//!
//! [`TallSpongeAir`] proves a rate-8 overwrite sponge `digest = H(b_0‖…‖b_{B-1})`
//! in `B` rows (padded to a FRI-legal power-of-two height):
//!
//! - **Per row** (all rows, unconditional, degree 7): the `WIDTH_COLS` columns
//!   are a valid Poseidon2 permutation of their committed input (reusing the
//!   audited [`eval_perm_body`]).
//! - **First row**: the capacity half of the input is zero (sponge IV).
//! - **Transition** (rows `0..B-1`, selected by a preprocessed `chain` column):
//!   the next row's input capacity equals this row's output capacity — i.e. the
//!   permutation output feeds the next absorb. The rate half of the next input
//!   is the next message block (free witness).
//! - **Digest row** (`B-1`, selected by a preprocessed `digest` column): the
//!   output rate equals the public digest.
//!
//! [`TallMerkleAir`] proves a depth-`D` Merkle membership `root = fold(leaf,
//! path)` in `D` rows — this is the load-bearing conversion: the spend's two
//! depth-32 paths are 64 of its ~86 perms. Each row is one 2-to-1 compression
//! `permute(left ‖ right)`; a boolean `dir` column says which half holds the
//! running digest (the other half is the free sibling witness):
//!
//! - **First row**: the public *leaf* sits in the half `dir` selects.
//! - **Transition** (chained rows): this row's output digest sits in the half
//!   the *next* row's `dir` selects of the next input.
//! - **Root row** (`D-1`): the output digest equals the public *root*.
//!
//! Padding rows beyond the last real row are valid permutations of the zero
//! state, so the degree-7 perm constraints hold everywhere without a selector
//! (which would raise the constraint degree).

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{
    prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed, PreprocessedVerifierKey,
    Proof,
};

use crate::field::{make_config, Config, FriProfile, Val};
use crate::hash::{CAP, DIGEST, RATE};
use crate::perm::{eval_perm_body, input_off, output_off, Poseidon2PermAir, WIDTH, WIDTH_COLS};

/// Minimum trace height for the COMPACT FRI profile (`log_height > lfp+blowup`).
const MIN_ROWS: usize = 32;

/// Preprocessed columns: `[chain, digest]` selectors.
const PRE_COLS: usize = 2;
const PRE_CHAIN: usize = 0;
const PRE_DIGEST: usize = 1;

/// Tall Poseidon2 sponge AIR over `blocks` rate-8 message blocks.
#[derive(Clone)]
pub struct TallSpongeAir<F> {
    perm: Poseidon2PermAir<F>,
    blocks: usize,
    height: usize,
}

impl TallSpongeAir<Val> {
    /// A sponge over `blocks` blocks (≥ 1). Height is padded to a FRI-legal
    /// power of two.
    pub fn new_seeded(blocks: usize) -> Self {
        assert!(blocks >= 1, "sponge needs at least one block");
        let height = blocks.next_power_of_two().max(MIN_ROWS);
        Self {
            perm: Poseidon2PermAir::new_seeded(),
            blocks,
            height,
        }
    }

    /// Host sponge (reference / digest for the public values).
    pub fn sponge(&self, blocks: &[[Val; RATE]]) -> [Val; DIGEST] {
        assert_eq!(blocks.len(), self.blocks);
        let mut state = [Val::ZERO; WIDTH];
        for block in blocks {
            state[0..RATE].copy_from_slice(block);
            state = self.perm.permute(state);
        }
        state[0..DIGEST].try_into().unwrap()
    }

    /// Build the main trace: one permutation per row, capacity chained.
    pub fn generate_trace(&self, blocks: &[[Val; RATE]]) -> RowMajorMatrix<Val> {
        assert_eq!(blocks.len(), self.blocks);
        let mut values = vec![Val::ZERO; self.height * WIDTH_COLS];
        let mut cap = [Val::ZERO; CAP];
        for r in 0..self.height {
            let mut input = [Val::ZERO; WIDTH];
            if r < self.blocks {
                input[0..RATE].copy_from_slice(&blocks[r]);
                input[RATE..WIDTH].copy_from_slice(&cap);
            }
            let row = &mut values[r * WIDTH_COLS..(r + 1) * WIDTH_COLS];
            self.perm.fill_perm_row(input, row);
            // Carry this row's output capacity into the next absorb.
            let out = output_off();
            cap = row[out + RATE..out + WIDTH].try_into().unwrap();
        }
        RowMajorMatrix::new(values, WIDTH_COLS)
    }

    /// Prove `digest = H(blocks)` with `digest` as the public value. Returns the
    /// preprocessed verifier key alongside the proof (the selector columns are a
    /// preprocessed trace, committed once per degree).
    pub fn prove(
        &self,
        blocks: &[[Val; RATE]],
    ) -> (
        Config,
        Proof<Config>,
        PreprocessedVerifierKey<Config>,
        Vec<Val>,
    ) {
        let config = make_config(FriProfile::COMPACT);
        let degree_bits = self.height.trailing_zeros() as usize;
        let (pd, vk) =
            setup_preprocessed(&config, self, degree_bits).expect("AIR has preprocessed columns");
        let digest = self.sponge(blocks);
        let trace = self.generate_trace(blocks);
        let pis = digest.to_vec();
        let proof = prove_with_preprocessed(&config, self, trace, &pis, Some(&pd));
        (config, proof, vk, pis)
    }
}

/// Verify a tall-sponge proof against its public digest.
pub fn verify_sponge(
    config: &Config,
    air: &TallSpongeAir<Val>,
    proof: &Proof<Config>,
    vk: &PreprocessedVerifierKey<Config>,
    pis: &[Val],
) -> Result<(), String> {
    verify_with_preprocessed(config, air, proof, pis, Some(vk)).map_err(|e| format!("{e:?}"))
}

impl<F: PrimeCharacteristicRing + Sync + Send> BaseAir<F> for TallSpongeAir<F> {
    fn width(&self) -> usize {
        WIDTH_COLS
    }
    fn num_public_values(&self) -> usize {
        DIGEST
    }
    /// The capacity chaining constraint reads the next row's input capacity.
    fn main_next_row_columns(&self) -> Vec<usize> {
        (input_off() + RATE..input_off() + WIDTH).collect()
    }
    fn preprocessed_width(&self) -> usize {
        PRE_COLS
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let mut v = vec![F::ZERO; self.height * PRE_COLS];
        for r in 0..self.height {
            // chain feeds the absorb into the next row: rows 0..blocks-1.
            if r + 1 < self.blocks {
                v[r * PRE_COLS + PRE_CHAIN] = F::ONE;
            }
            // the digest is read off the last real block's row.
            if r == self.blocks - 1 {
                v[r * PRE_COLS + PRE_DIGEST] = F::ONE;
            }
        }
        Some(RowMajorMatrix::new(v, PRE_COLS))
    }
}

impl<AB: AirBuilder> Air<AB> for TallSpongeAir<AB::F>
where
    AB::F: Send,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice().to_vec();
        let next = main.next_slice().to_vec();
        let prep = builder.preprocessed().clone();
        let pcur = prep.current_slice().to_vec();
        let pis: Vec<AB::PublicVar> = builder.public_values().to_vec();

        // Every row is a valid Poseidon2 permutation of its committed input.
        eval_perm_body(&self.perm, builder, &local, 0);

        // First row: the capacity half of the input is the zero IV.
        let first = builder.is_first_row();
        for j in 0..CAP {
            builder.assert_zero(first.clone() * local[input_off() + RATE + j]);
        }

        // Capacity chaining: on chained rows, next.input_cap == local.output_cap.
        let chain = pcur[PRE_CHAIN];
        let out = output_off();
        for j in 0..CAP {
            let nxt_cap: AB::Expr = next[input_off() + RATE + j].into();
            let cur_out: AB::Expr = local[out + RATE + j].into();
            builder.assert_zero(chain * (nxt_cap - cur_out));
        }

        // Digest row: the output rate equals the public digest.
        let dsel = pcur[PRE_DIGEST];
        for j in 0..DIGEST {
            let cur: AB::Expr = local[out + j].into();
            let pi: AB::Expr = pis[j].into();
            builder.assert_zero(dsel * (cur - pi));
        }
    }
}

// ----- tall Merkle membership ----------------------------------------------

/// Column layout: the `WIDTH_COLS` permutation columns, then one `dir` bit.
const MK_DIR: usize = WIDTH_COLS;
/// Total trace width of the tall Merkle gadget.
pub const MERKLE_COLS: usize = WIDTH_COLS + 1;

/// Tall Merkle-membership AIR: one 2-to-1 compression per row.
#[derive(Clone)]
pub struct TallMerkleAir<F> {
    perm: Poseidon2PermAir<F>,
    depth: usize,
    height: usize,
}

impl TallMerkleAir<Val> {
    /// A membership proof of `depth` levels (≥ 1). Height is padded to a
    /// FRI-legal power of two.
    pub fn new_seeded(depth: usize) -> Self {
        assert!(depth >= 1, "Merkle path needs at least one level");
        let height = depth.next_power_of_two().max(MIN_ROWS);
        Self {
            perm: Poseidon2PermAir::new_seeded(),
            depth,
            height,
        }
    }

    /// Host root: fold the leaf up the path (`dir` = the current node is the
    /// *right* child, matching `spend.rs`/`unknown_tree`).
    pub fn root(&self, leaf: [Val; DIGEST], path: &[([Val; DIGEST], bool)]) -> [Val; DIGEST] {
        assert_eq!(path.len(), self.depth);
        let mut cur = leaf;
        for &(sib, dir) in path {
            let mut input = [Val::ZERO; WIDTH];
            let (l, r) = if dir { (sib, cur) } else { (cur, sib) };
            input[..DIGEST].copy_from_slice(&l);
            input[DIGEST..].copy_from_slice(&r);
            cur = self.perm.permute(input)[..DIGEST].try_into().unwrap();
        }
        cur
    }

    /// Build the main trace: one compression per row, digest chained via `dir`.
    pub fn generate_trace(
        &self,
        leaf: [Val; DIGEST],
        path: &[([Val; DIGEST], bool)],
    ) -> RowMajorMatrix<Val> {
        assert_eq!(path.len(), self.depth);
        let mut values = vec![Val::ZERO; self.height * MERKLE_COLS];
        let mut cur = leaf;
        for r in 0..self.height {
            let mut input = [Val::ZERO; WIDTH];
            let mut dir = false;
            if r < self.depth {
                let (sib, d) = path[r];
                dir = d;
                let (l, rt) = if d { (sib, cur) } else { (cur, sib) };
                input[..DIGEST].copy_from_slice(&l);
                input[DIGEST..].copy_from_slice(&rt);
            }
            let row = &mut values[r * MERKLE_COLS..(r + 1) * MERKLE_COLS];
            self.perm.fill_perm_row(input, &mut row[..WIDTH_COLS]);
            row[MK_DIR] = Val::from_bool(dir);
            let out = output_off();
            cur = row[out..out + DIGEST].try_into().unwrap();
        }
        RowMajorMatrix::new(values, MERKLE_COLS)
    }

    /// Prove `root = fold(leaf, path)`; public values are `leaf ‖ root`.
    pub fn prove(
        &self,
        leaf: [Val; DIGEST],
        path: &[([Val; DIGEST], bool)],
    ) -> (
        Config,
        Proof<Config>,
        PreprocessedVerifierKey<Config>,
        Vec<Val>,
    ) {
        let config = make_config(FriProfile::COMPACT);
        let degree_bits = self.height.trailing_zeros() as usize;
        let (pd, vk) =
            setup_preprocessed(&config, self, degree_bits).expect("AIR has preprocessed columns");
        let root = self.root(leaf, path);
        let trace = self.generate_trace(leaf, path);
        let pis: Vec<Val> = leaf.into_iter().chain(root).collect();
        let proof = prove_with_preprocessed(&config, self, trace, &pis, Some(&pd));
        (config, proof, vk, pis)
    }
}

/// Verify a tall Merkle proof against its public `leaf ‖ root`.
pub fn verify_merkle(
    config: &Config,
    air: &TallMerkleAir<Val>,
    proof: &Proof<Config>,
    vk: &PreprocessedVerifierKey<Config>,
    pis: &[Val],
) -> Result<(), String> {
    verify_with_preprocessed(config, air, proof, pis, Some(vk)).map_err(|e| format!("{e:?}"))
}

impl<F: PrimeCharacteristicRing + Sync + Send> BaseAir<F> for TallMerkleAir<F> {
    fn width(&self) -> usize {
        MERKLE_COLS
    }
    fn num_public_values(&self) -> usize {
        2 * DIGEST
    }
    /// The chaining constraint reads the next row's input halves and `dir`.
    fn main_next_row_columns(&self) -> Vec<usize> {
        (input_off()..input_off() + WIDTH).chain([MK_DIR]).collect()
    }
    fn preprocessed_width(&self) -> usize {
        PRE_COLS
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let mut v = vec![F::ZERO; self.height * PRE_COLS];
        for r in 0..self.height {
            // chain feeds this row's output into the next level's compression.
            if r + 1 < self.depth {
                v[r * PRE_COLS + PRE_CHAIN] = F::ONE;
            }
            // the root is read off the last real level's row.
            if r == self.depth - 1 {
                v[r * PRE_COLS + PRE_DIGEST] = F::ONE;
            }
        }
        Some(RowMajorMatrix::new(v, PRE_COLS))
    }
}

impl<AB: AirBuilder> Air<AB> for TallMerkleAir<AB::F>
where
    AB::F: Send,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice().to_vec();
        let next = main.next_slice().to_vec();
        let prep = builder.preprocessed().clone();
        let pcur = prep.current_slice().to_vec();
        let pis: Vec<AB::PublicVar> = builder.public_values().to_vec();

        // Every row is a valid Poseidon2 permutation of its committed input.
        eval_perm_body(&self.perm, builder, &local, 0);
        builder.assert_bool(local[MK_DIR]);

        // First row: the public leaf occupies the half `dir` selects
        // (dir = 0 → left/first half, dir = 1 → right/second half).
        let first = builder.is_first_row();
        let dir: AB::Expr = local[MK_DIR].into();
        for j in 0..DIGEST {
            let leaf: AB::Expr = pis[j].into();
            let l: AB::Expr = local[input_off() + j].into();
            let r: AB::Expr = local[input_off() + DIGEST + j].into();
            let want =
                (AB::Expr::ONE - dir.clone()) * (l - leaf.clone()) + dir.clone() * (r - leaf);
            builder.assert_zero(first.clone() * want);
        }

        // Chaining: this row's output digest occupies the half the *next*
        // row's `dir` selects of the next row's input.
        let chain = pcur[PRE_CHAIN];
        let out = output_off();
        let ndir: AB::Expr = next[MK_DIR].into();
        for j in 0..DIGEST {
            let cur: AB::Expr = local[out + j].into();
            let nl: AB::Expr = next[input_off() + j].into();
            let nr: AB::Expr = next[input_off() + DIGEST + j].into();
            let want =
                (AB::Expr::ONE - ndir.clone()) * (nl - cur.clone()) + ndir.clone() * (nr - cur);
            builder.assert_zero(chain * want);
        }

        // Root row: the output digest equals the public root.
        let dsel = pcur[PRE_DIGEST];
        for j in 0..DIGEST {
            let cur: AB::Expr = local[out + j].into();
            let root: AB::Expr = pis[DIGEST + j].into();
            builder.assert_zero(dsel * (cur - root));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::distr::StandardUniform;
    use rand::rngs::SmallRng;
    use rand::{RngExt, SeedableRng};

    fn block(rng: &mut SmallRng) -> [Val; RATE] {
        core::array::from_fn(|_| rng.sample(StandardUniform))
    }

    #[test]
    fn tall_sponge_proves_and_verifies() {
        for blocks in [1usize, 2, 4] {
            let air = TallSpongeAir::new_seeded(blocks);
            let mut rng = SmallRng::seed_from_u64(10 + blocks as u64);
            let msg: Vec<[Val; RATE]> = (0..blocks).map(|_| block(&mut rng)).collect();
            let (config, proof, vk, pis) = air.prove(&msg);
            verify_sponge(&config, &air, &proof, &vk, &pis).expect("tall sponge verifies");
        }
    }

    #[test]
    fn tall_sponge_matches_shared_hash() {
        // The tall AIR's host sponge equals unknown_poseidon's sponge (the
        // pipeline hash), so this layout computes the same digests.
        let air = TallSpongeAir::new_seeded(2);
        let mut rng = SmallRng::seed_from_u64(99);
        let msg = [block(&mut rng), block(&mut rng)];
        let mine = air.sponge(&msg);
        let theirs = unknown_poseidon::sponge(&msg);
        assert_eq!(mine, theirs);
    }

    #[test]
    fn wrong_digest_is_rejected() {
        let air = TallSpongeAir::new_seeded(4);
        let mut rng = SmallRng::seed_from_u64(7);
        let msg: Vec<[Val; RATE]> = (0..4).map(|_| block(&mut rng)).collect();
        let (config, proof, vk, mut pis) = air.prove(&msg);
        pis[0] += Val::ONE;
        assert!(verify_sponge(&config, &air, &proof, &vk, &pis).is_err());
    }

    fn rand_path(rng: &mut SmallRng, depth: usize) -> Vec<([Val; DIGEST], bool)> {
        (0..depth)
            .map(|_| (block(rng), rng.sample::<bool, _>(StandardUniform)))
            .collect()
    }

    #[test]
    fn tall_merkle_proves_and_verifies() {
        // Depth 32 — the real spend path length (64 of the spend's 86 perms
        // are these compressions).
        let air = TallMerkleAir::new_seeded(unknown_interfaces::TREE_DEPTH);
        let mut rng = SmallRng::seed_from_u64(21);
        let leaf = block(&mut rng);
        let path = rand_path(&mut rng, unknown_interfaces::TREE_DEPTH);
        let (config, proof, vk, pis) = air.prove(leaf, &path);
        verify_merkle(&config, &air, &proof, &vk, &pis).expect("tall Merkle verifies");
    }

    #[test]
    fn tall_merkle_matches_shared_hash() {
        // The tall AIR's host fold equals unknown_poseidon's compression chain
        // (the pipeline tree hash), so this layout proves the same roots.
        let air = TallMerkleAir::new_seeded(8);
        let mut rng = SmallRng::seed_from_u64(22);
        let leaf = block(&mut rng);
        let path = rand_path(&mut rng, 8);
        let mine = air.root(leaf, &path);
        let mut cur = leaf;
        for &(sib, dir) in &path {
            cur = if dir {
                unknown_poseidon::compress(sib, cur)
            } else {
                unknown_poseidon::compress(cur, sib)
            };
        }
        assert_eq!(mine, cur);
    }

    #[test]
    fn tall_merkle_wrong_root_is_rejected() {
        let air = TallMerkleAir::new_seeded(unknown_interfaces::TREE_DEPTH);
        let mut rng = SmallRng::seed_from_u64(23);
        let leaf = block(&mut rng);
        let path = rand_path(&mut rng, unknown_interfaces::TREE_DEPTH);
        let (config, proof, vk, mut pis) = air.prove(leaf, &path);
        pis[DIGEST] += Val::ONE; // corrupt the root
        assert!(verify_merkle(&config, &air, &proof, &vk, &pis).is_err());
    }

    #[test]
    fn tall_merkle_wrong_leaf_is_rejected() {
        let air = TallMerkleAir::new_seeded(unknown_interfaces::TREE_DEPTH);
        let mut rng = SmallRng::seed_from_u64(24);
        let leaf = block(&mut rng);
        let path = rand_path(&mut rng, unknown_interfaces::TREE_DEPTH);
        let (config, proof, vk, mut pis) = air.prove(leaf, &path);
        pis[0] += Val::ONE; // corrupt the leaf
        assert!(verify_merkle(&config, &air, &proof, &vk, &pis).is_err());
    }

    /// A full depth-32 path — 32 of the spend's 86 perms — stays a small
    /// fraction of the 250 KB KPI in the tall layout.
    #[test]
    fn tall_merkle_proof_is_small() {
        let air = TallMerkleAir::new_seeded(unknown_interfaces::TREE_DEPTH);
        let mut rng = SmallRng::seed_from_u64(25);
        let leaf = block(&mut rng);
        let path = rand_path(&mut rng, unknown_interfaces::TREE_DEPTH);
        let (_c, proof, _vk, _pis) = air.prove(leaf, &path);
        let size = postcard::to_allocvec(&proof).unwrap().len();
        println!("tall depth-32 Merkle proof: {size} bytes");
        assert!(
            size < 512 * 1024,
            "tall Merkle proof ({size} B) unexpectedly large"
        );
    }

    /// The payoff: a tall 4-block sponge proof (one perm per row) is a small
    /// fraction of the wide fused spend proof (~5.4 MB, see
    /// `docs/gate-a-report.md`), validating the layout fix. A 4-block sponge is
    /// 4 of the spend's ~86 perms, so even scaled up the tall layout stays well
    /// under the 250 KB Gate-A KPI.
    #[test]
    fn tall_layout_shrinks_proof() {
        let air = TallSpongeAir::new_seeded(4);
        let mut rng = SmallRng::seed_from_u64(3);
        let msg: Vec<[Val; RATE]> = (0..4).map(|_| block(&mut rng)).collect();
        let (_c, proof, _vk, _pis) = air.prove(&msg);
        let tall = postcard::to_allocvec(&proof).unwrap().len();

        println!("tall 4-block sponge proof: {tall} bytes");
        // The wide fused spend proof is ~5.4 MB; the tall sponge must be a tiny
        // fraction of that (orders of magnitude smaller per perm).
        assert!(
            tall < 512 * 1024,
            "tall sponge proof ({tall} B) unexpectedly large"
        );
    }
}
