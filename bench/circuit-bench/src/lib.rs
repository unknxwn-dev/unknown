//! Gate-A proving benchmark (engineering plan §1 gate A, WP6b/WP8).
//!
//! A REAL Plonky3 STARK on the BabyBear field (decision D1) with a Poseidon2
//! commitment scheme (D3), proving a hash-heavy workload. The workload is
//! `KeccakAir` (N Keccak-f permutations): a deliberate, conservative proxy for
//! the spend circuit's dominant cost, which is the ~32 Poseidon2 compressions of
//! a depth-32 Merkle membership path plus a handful for commitments/nullifiers.
//! Keccak is heavier per hash than Poseidon2, so these prove-time and
//! proof-size numbers are an UPPER BOUND on the eventual spend circuit's hashing
//! cost — if this clears Gate A, the real circuit comfortably does too.
//!
//! This retires the single biggest risk in the design (feasibility §10 risk 1:
//! can post-quantum client-side proving be fast enough on modest hardware?) with
//! real measured data rather than assumption. It is not the spend circuit itself
//! (that is WP6b); it is the toolchain + performance harness Gate A calls for.

use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2Bowers;
use p3_field::extension::BinomialExtensionField;
use p3_field::Field;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_keccak_air::{generate_trace_rows, KeccakAir};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{prove, verify, StarkConfig};
use rand::rngs::SmallRng;
use rand::{RngExt, SeedableRng};
use std::time::Instant;

type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;
type Perm = Poseidon2BabyBear<16>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs =
    MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 2, 8>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Dft = Radix2Bowers;
type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;

/// Keccak permutations per "spend equivalent". A depth-32 Merkle path is ~32
/// hash compressions; commitments/nullifiers/range add a handful — call it ~40.
pub const HASHES_PER_SPEND: usize = 40;

#[derive(Debug, Clone, Copy)]
pub struct BenchResult {
    pub num_hashes: usize,
    pub prove_ms: u128,
    pub verify_ms: u128,
    pub proof_bytes: usize,
}

fn config(rng: &mut SmallRng) -> MyConfig {
    let perm = Perm::new_from_rng_128(rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_params = FriParameters::new_benchmark(challenge_mmcs);
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri_params);
    MyConfig::new(pcs, Challenger::new(perm))
}

/// Prove and verify N Keccak permutations; return timings and serialized proof
/// size. Panics if verification fails (a soundness/setup bug).
pub fn run(num_hashes: usize) -> BenchResult {
    let mut rng = SmallRng::seed_from_u64(1);
    let cfg = config(&mut rng);

    let fri_log_blowup = 1; // matches FriParameters::new_benchmark
    let inputs = (0..num_hashes).map(|_| rng.random()).collect::<Vec<_>>();
    let trace = generate_trace_rows::<Val>(inputs, fri_log_blowup);

    let t0 = Instant::now();
    let proof = prove(&cfg, &KeccakAir {}, trace, &[]);
    let prove_ms = t0.elapsed().as_millis();

    let proof_bytes = postcard::to_allocvec(&proof).expect("proof serializes").len();

    let t1 = Instant::now();
    verify(&cfg, &KeccakAir {}, &proof, &[]).expect("proof must verify");
    let verify_ms = t1.elapsed().as_millis();

    BenchResult { num_hashes, prove_ms, verify_ms, proof_bytes }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_proof_roundtrips() {
        // Correctness: a real STARK proof over a few Keccak perms verifies.
        let r = run(4);
        assert!(r.proof_bytes > 0);
        assert!(r.num_hashes == 4);
    }
}
