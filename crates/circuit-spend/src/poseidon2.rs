//! In-circuit Poseidon2 — the dominant cost of the spend statement.
//!
//! The spend statement (engineering plan §3.3) is, computationally, a batch of
//! Poseidon2 permutations: note commitments, nullifiers, the two depth-32
//! Merkle authentication paths, and the binding-digest sponge. Everything else
//! (range, balance, selectors) is cheap field arithmetic. So the honest Gate-A
//! cost of the circuit is dominated by [`PERM_BUDGET`] Poseidon2 permutations.
//!
//! This module proves exactly that workload with Plonky3's audited
//! [`Poseidon2Air`] over BabyBear (width 16) — a *real* STARK over the
//! production field and hash, not a stand-in. It establishes (a) that the
//! D1/D3 hash choice proves and verifies end to end, and (b) the prove-time /
//! proof-size / verify-throughput numbers Gate A needs.
//!
//! What it does NOT yet do: bind those permutations to the public nullifiers /
//! commitments / anchor (i.e. constrain that the hashed preimages are the
//! witnessed note fields and that the Merkle levels chain to the anchor root).
//! That fusion is the remaining WP6b soundness work; see the crate docs.

use p3_baby_bear::{
    GenericPoseidon2LinearLayersBabyBear, BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS,
    BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16, BABYBEAR_S_BOX_DEGREE,
};
use p3_poseidon2_air::{Poseidon2Air, RoundConstants};
use p3_uni_stark::{prove, verify, Proof};
use rand::rngs::SmallRng;
use rand::SeedableRng;

use crate::field::{make_config, Config, FriProfile, Val};

const WIDTH: usize = 16;
const SBOX_DEGREE: u64 = BABYBEAR_S_BOX_DEGREE;
const SBOX_REGISTERS: usize = 1;
const HALF_FULL_ROUNDS: usize = BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS;
const PARTIAL_ROUNDS: usize = BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16;

/// The Poseidon2 permutation AIR specialized to BabyBear, width 16.
pub type SpendHashAir = Poseidon2Air<
    Val,
    GenericPoseidon2LinearLayersBabyBear,
    WIDTH,
    SBOX_DEGREE,
    SBOX_REGISTERS,
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
>;

/// Poseidon2 permutation budget of the uniform 2-in / 2-out spend statement.
///
/// Counts assume a width-16 / rate-8 sponge for variable-length hashes and one
/// 2-to-1 compression per Merkle level. A note is ~25 field elements
/// (value ‖ addr_tag[8] ‖ rho[8] ‖ rseed[8]) → 4 sponge permutations.
pub mod perm_budget {
    /// 2 inputs × 4 perms — input note commitments (membership preimages).
    pub const INPUT_COMMITMENTS: usize = 2 * 4;
    /// 2 outputs × 4 perms — output note commitments.
    pub const OUTPUT_COMMITMENTS: usize = 2 * 4;
    /// 2 inputs × 2 perms — nullifiers `P2(nk, rho)`.
    pub const NULLIFIERS: usize = 2 * 2;
    /// 2 inputs × 32 levels — depth-32 Merkle paths (uniform worst case: both
    /// inputs real, decision D9).
    pub const MERKLE_PATHS: usize = 2 * 32;
    /// Binding-digest sponge over the public fields (C8).
    pub const BINDING_DIGEST: usize = 5;
    /// Total permutations the spend circuit must prove.
    pub const TOTAL: usize =
        INPUT_COMMITMENTS + OUTPUT_COMMITMENTS + NULLIFIERS + MERKLE_PATHS + BINDING_DIGEST;
}

// Compile-time sanity: the budget sums as documented and is Merkle-dominated.
const _: () = assert!(perm_budget::TOTAL == 89);
const _: () = assert!(perm_budget::MERKLE_PATHS * 2 > perm_budget::TOTAL);

/// Construct the Poseidon2 AIR with deterministic round constants.
///
/// Production must freeze these to `specs/vectors/poseidon2.json` (WP1); the
/// fixed seed keeps Gate-A runs reproducible and self-consistent.
pub fn spend_hash_air() -> SpendHashAir {
    let mut rng = SmallRng::seed_from_u64(1);
    let constants = RoundConstants::from_rng(&mut rng);
    Poseidon2Air::new(constants)
}

/// Prove `num_perms` Poseidon2 permutations under `profile`.
///
/// Returns the config and AIR (needed to verify) alongside the proof.
pub fn prove_hashes(
    profile: FriProfile,
    num_perms: usize,
) -> (Config, SpendHashAir, Proof<Config>) {
    let air = spend_hash_air();
    let config = make_config(profile);
    // The trace height must be a power of two; the prover pays for the padded
    // count regardless, so round the budget up to the next power of two.
    let rows = num_perms.next_power_of_two();
    // extra_capacity_bits must match the FRI blowup so the LDE fits in place.
    let trace = air.generate_trace_rows(rows, profile.log_blowup);
    let proof = prove(&config, &air, trace, &[]);
    (config, air, proof)
}

/// Prove using a pre-built config and AIR (so benchmarks can exclude one-time
/// setup from the timed region).
pub fn prove_with(
    config: &Config,
    air: &SpendHashAir,
    num_perms: usize,
    log_blowup: usize,
) -> Proof<Config> {
    let rows = num_perms.next_power_of_two();
    let trace = air.generate_trace_rows(rows, log_blowup);
    prove(config, air, trace, &[])
}

/// Verify a hash-workload proof. Returns `Err(reason)` on any failure.
pub fn verify_hashes(
    config: &Config,
    air: &SpendHashAir,
    proof: &Proof<Config>,
) -> Result<(), String> {
    verify(config, air, proof, &[]).map_err(|e| format!("{e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spend_hash_workload_proves_and_verifies() {
        // Prove the full spend-statement permutation budget end to end.
        let (config, air, proof) = prove_hashes(FriProfile::FAST, perm_budget::TOTAL);
        verify_hashes(&config, &air, &proof).expect("hash-workload proof verifies");
    }

    #[test]
    fn tampered_proof_is_rejected() {
        let (config, air, mut proof) = prove_hashes(FriProfile::FAST, perm_budget::TOTAL);
        // Corrupt the claimed trace degree; the verifier must reject.
        proof.degree_bits = proof.degree_bits.wrapping_add(1);
        assert!(verify_hashes(&config, &air, &proof).is_err());
    }
}
