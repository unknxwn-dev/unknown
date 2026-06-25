//! WP6a gadget — in-circuit Merkle authentication-path verification (C1).
//!
//! Proves that a leaf digest sits at some position under a public root, using a
//! depth-[`TREE_DEPTH`] path of sibling digests and direction bits. The 2-to-1
//! compression is Poseidon2 (truncated permutation): `parent = perm([left ‖
//! right])[0..8]`, with `left/right` ordered by the level's direction bit.
//!
//! Layout is one Merkle level per trace row. Each row embeds the Poseidon2
//! permutation gadget (columns `0..WIDTH_COLS`, reusing [`crate::perm`]) plus
//! the level's current digest, sibling, and direction bit. A transition
//! constraint chains each level's compression output into the next level's
//! current digest; boundary constraints bind the first row's current digest to
//! the public leaf and the last row's output to the public root.
//!
//! Constraints are degree 7 (the Poseidon2 S-box), so it proves under the
//! COMPACT FRI profile (blowup 8). This is constraint C1 of the spend
//! statement; in the fused circuit the leaf is wired to a note commitment and
//! the root to the public anchor.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{prove, verify, Proof};
use unknown_interfaces::TREE_DEPTH;

use crate::field::{make_config, Config, FriProfile, Val};
use crate::perm::{eval_perm_body, input_off, output_off, Poseidon2PermAir, WIDTH, WIDTH_COLS};

/// Digest size in field elements (Poseidon2 rate / output width).
pub const DIGEST: usize = 8;
/// Number of compression levels = tree depth.
pub const DEPTH: usize = TREE_DEPTH;

// Per-row layout: [perm gadget columns][cur digest][sibling digest][dir bit].
const CUR_OFF: usize = WIDTH_COLS;
const SIB_OFF: usize = WIDTH_COLS + DIGEST;
const DIR_OFF: usize = WIDTH_COLS + 2 * DIGEST;
/// Total trace width of the Merkle gadget.
pub const MERKLE_COLS: usize = WIDTH_COLS + 2 * DIGEST + 1;

/// One step of a Merkle authentication path: a sibling digest and the direction
/// bit (`false` = current node is the left child).
pub type PathStep = ([Val; DIGEST], bool);

/// Merkle-path verification AIR, parameterised by the constant field (so the
/// embedded Poseidon2 permutation ties to the builder field).
#[derive(Clone)]
pub struct MerklePathAir<F> {
    perm: Poseidon2PermAir<F>,
}

impl MerklePathAir<Val> {
    /// Construct with the deterministic permutation constants.
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

    /// Host: fold a leaf up a path, returning the root.
    pub fn root(&self, leaf: [Val; DIGEST], path: &[PathStep]) -> [Val; DIGEST] {
        let mut cur = leaf;
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

    /// Build the execution trace (one row per level) and return it with the
    /// computed root.
    pub fn generate_trace(
        &self,
        leaf: [Val; DIGEST],
        path: &[PathStep],
    ) -> (RowMajorMatrix<Val>, [Val; DIGEST]) {
        assert_eq!(path.len(), DEPTH, "path must have TREE_DEPTH steps");
        let mut values = vec![Val::ZERO; MERKLE_COLS * DEPTH];
        let mut cur = leaf;
        for (level, &(sib, dir)) in path.iter().enumerate() {
            let row = &mut values[level * MERKLE_COLS..(level + 1) * MERKLE_COLS];
            let input = if dir {
                Self::join(sib, cur)
            } else {
                Self::join(cur, sib)
            };
            self.perm.fill_perm_row(input, row);
            row[CUR_OFF..CUR_OFF + DIGEST].copy_from_slice(&cur);
            row[SIB_OFF..SIB_OFF + DIGEST].copy_from_slice(&sib);
            row[DIR_OFF] = Val::from_bool(dir);
            cur = row[output_off()..output_off() + DIGEST].try_into().unwrap();
        }
        (RowMajorMatrix::new(values, MERKLE_COLS), cur)
    }
}

/// Public values: leaf digest followed by root digest.
pub fn public_values(leaf: [Val; DIGEST], root: [Val; DIGEST]) -> Vec<Val> {
    leaf.into_iter().chain(root).collect()
}

impl<F: PrimeCharacteristicRing + Sync> BaseAir<F> for MerklePathAir<F> {
    fn width(&self) -> usize {
        MERKLE_COLS
    }
    fn num_public_values(&self) -> usize {
        2 * DIGEST
    }
}

impl<AB: AirBuilder> Air<AB> for MerklePathAir<AB::F> {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let pis: Vec<AB::PublicVar> = builder.public_values().to_vec();

        // Direction bit is boolean.
        builder.assert_bool(local[DIR_OFF]);

        // Order the permutation input by the direction bit:
        //   dir = 0 → input = cur ‖ sib   (current is left child)
        //   dir = 1 → input = sib ‖ cur   (current is right child)
        for j in 0..DIGEST {
            let cur = local[CUR_OFF + j];
            let sib = local[SIB_OFF + j];
            let dir: AB::Expr = local[DIR_OFF].into();
            let left = cur * (AB::Expr::ONE - dir.clone()) + sib * dir.clone();
            let right = sib * (AB::Expr::ONE - dir.clone()) + cur * dir;
            builder.assert_eq(local[input_off() + j], left);
            builder.assert_eq(local[input_off() + DIGEST + j], right);
        }

        // The Poseidon2 compression for this level.
        eval_perm_body(&self.perm, builder, local, 0);

        // Chain: this level's output digest is the next level's current digest.
        for j in 0..DIGEST {
            builder
                .when_transition()
                .assert_eq(next[CUR_OFF + j], local[output_off() + j]);
        }

        // Boundaries: leaf at the bottom, root at the top.
        for j in 0..DIGEST {
            builder
                .when_first_row()
                .assert_eq(local[CUR_OFF + j], pis[j]);
            builder
                .when_last_row()
                .assert_eq(local[output_off() + j], pis[DIGEST + j]);
        }
    }
}

/// Prove that `leaf` is included under the root reached by `path`.
pub fn prove_membership(
    air: &MerklePathAir<Val>,
    leaf: [Val; DIGEST],
    path: &[PathStep],
) -> (Config, Proof<Config>, Vec<Val>) {
    let config = make_config(FriProfile::COMPACT);
    let (trace, root) = air.generate_trace(leaf, path);
    let pis = public_values(leaf, root);
    let proof = prove(&config, air, trace, &pis);
    (config, proof, pis)
}

/// Verify a membership proof against the public leaf and root.
pub fn verify_membership(
    config: &Config,
    air: &MerklePathAir<Val>,
    proof: &Proof<Config>,
    pis: &[Val],
) -> Result<(), String> {
    verify(config, air, proof, pis).map_err(|e| format!("{e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::array;
    use rand::distr::StandardUniform;
    use rand::rngs::SmallRng;
    use rand::{RngExt, SeedableRng};

    fn rand_path(seed: u64) -> ([Val; DIGEST], Vec<PathStep>) {
        let mut rng = SmallRng::seed_from_u64(seed);
        let leaf: [Val; DIGEST] = array::from_fn(|_| rng.sample(StandardUniform));
        let path: Vec<PathStep> = (0..DEPTH)
            .map(|_| {
                let sib: [Val; DIGEST] = array::from_fn(|_| rng.sample(StandardUniform));
                let dir = rng.sample::<bool, _>(StandardUniform);
                (sib, dir)
            })
            .collect();
        (leaf, path)
    }

    #[test]
    fn membership_proves_and_verifies() {
        let air = MerklePathAir::new_seeded();
        let (leaf, path) = rand_path(1);
        let (config, proof, pis) = prove_membership(&air, leaf, &path);
        verify_membership(&config, &air, &proof, &pis).expect("membership verifies");
    }

    #[test]
    fn wrong_root_is_rejected() {
        let air = MerklePathAir::new_seeded();
        let (leaf, path) = rand_path(2);
        let (config, proof, mut pis) = prove_membership(&air, leaf, &path);
        // Tamper the claimed root.
        pis[DIGEST] += Val::ONE;
        assert!(verify_membership(&config, &air, &proof, &pis).is_err());
    }

    #[test]
    fn wrong_leaf_is_rejected() {
        let air = MerklePathAir::new_seeded();
        let (leaf, path) = rand_path(3);
        let (config, proof, mut pis) = prove_membership(&air, leaf, &path);
        // Claim a different leaf than the one the path was built for.
        pis[0] += Val::ONE;
        assert!(verify_membership(&config, &air, &proof, &pis).is_err());
    }

    #[test]
    fn tampered_proof_is_rejected() {
        let air = MerklePathAir::new_seeded();
        let (leaf, path) = rand_path(4);
        let (config, mut proof, pis) = prove_membership(&air, leaf, &path);
        proof.degree_bits = proof.degree_bits.wrapping_add(1);
        assert!(verify_membership(&config, &air, &proof, &pis).is_err());
    }

    #[test]
    fn direction_bits_matter() {
        // Flipping a direction bit changes the root (host-level sanity).
        let air = MerklePathAir::new_seeded();
        let (leaf, mut path) = rand_path(5);
        let root_a = air.root(leaf, &path);
        path[0].1 = !path[0].1;
        let root_b = air.root(leaf, &path);
        assert_ne!(root_a, root_b);
    }
}
