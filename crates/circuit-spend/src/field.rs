//! Proof-system foundation: BabyBear field + Poseidon2 (width 16) + FRI.
//!
//! These are the frozen Gate-A choices from the engineering plan:
//! D1 (field = BabyBear), D2 (Plonky3 FRI STARK), D3 (in-circuit hash =
//! Poseidon2 over BabyBear, width 16). The concrete FRI parameters (blowup,
//! query count, PoW bits) are what Gate A sweeps — hence [`FriProfile`].
//!
//! The config wiring mirrors Plonky3's own `uni-stark` two-adic example so the
//! prover/verifier pairing is exactly the upstream-tested one.

use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::Field;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkConfig;
use rand::rngs::SmallRng;
use rand::SeedableRng;

/// Base field (decision D1). 31-bit, two-adic, Poseidon2-friendly.
pub type Val = BabyBear;
/// Poseidon2 permutation over BabyBear, state width 16 (decision D3).
pub type Perm = Poseidon2BabyBear<16>;
/// Sponge hash used for the STARK's own Merkle commitments (rate 8, out 8).
pub type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
/// 2-to-1 compression for the trace commitment tree.
pub type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
/// Mixed-matrix commitment scheme over the base field.
pub type ValMmcs =
    MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 2, 8>;
/// Degree-4 extension used for the FRI challenge field.
pub type Challenge = BinomialExtensionField<Val, 4>;
/// Commitment scheme over the challenge extension.
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
/// Fiat-Shamir challenger (Poseidon2 duplex sponge).
pub type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
/// Parallel radix-2 DIT FFT.
pub type Dft = Radix2DitParallel<Val>;
/// Two-adic FRI polynomial commitment scheme.
pub type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
/// Full uni-stark configuration.
pub type Config = StarkConfig<Pcs, Challenge, Challenger>;

/// A point in the FRI parameter space that Gate A sweeps.
///
/// Conjectured FRI security is roughly `num_queries * log_blowup +
/// proof_of_work_bits` bits, traded against prover work and proof size.
#[derive(Clone, Copy, Debug)]
pub struct FriProfile {
    /// log2 of the LDE blowup factor (rate = 1 / 2^log_blowup).
    pub log_blowup: usize,
    /// Number of FRI query rounds.
    pub num_queries: usize,
    /// Grinding bits applied to both the commit-phase and query-phase PoW.
    pub proof_of_work_bits: usize,
    /// log2 of the final (un-folded) FRI polynomial length.
    pub log_final_poly_len: usize,
    /// Human-readable label for reports.
    pub label: &'static str,
}

impl FriProfile {
    /// Low-security, low-overhead profile for tests (fast prove/verify).
    /// NOT for production — far too few queries.
    pub const FAST: FriProfile = FriProfile {
        log_blowup: 1,
        num_queries: 8,
        proof_of_work_bits: 1,
        log_final_poly_len: 1,
        label: "fast (test only)",
    };

    /// ~100-bit profile, blowup 4. Negligible grind, so prove time reflects
    /// real proving work rather than fixed PoW. Larger proofs than COMPACT.
    pub const BALANCED: FriProfile = FriProfile {
        log_blowup: 2,
        num_queries: 51,
        proof_of_work_bits: 1,
        log_final_poly_len: 1,
        label: "balanced (blowup 4, 51q)",
    };

    /// ~100-bit profile, blowup 8. A single spend is a tiny trace, so the
    /// extra blowup is nearly free and shrinks the proof via fewer queries.
    pub const COMPACT: FriProfile = FriProfile {
        log_blowup: 3,
        num_queries: 34,
        proof_of_work_bits: 1,
        log_final_poly_len: 1,
        label: "compact (blowup 8, 34q)",
    };

    /// Same security as COMPACT but `log_final_poly_len = 0`, which lowers the
    /// FRI minimum trace height to 2^4. Used by the large fused circuits, whose
    /// single-row computation is replicated to only 16 rows.
    pub const COMPACT_SHORT: FriProfile = FriProfile {
        log_blowup: 3,
        num_queries: 34,
        proof_of_work_bits: 1,
        log_final_poly_len: 0,
        label: "compact-short (blowup 8, 34q, lfp0)",
    };

    /// The profiles Gate A reports on (≥ 2 param sets per the plan).
    pub const SWEEP: [FriProfile; 2] = [FriProfile::BALANCED, FriProfile::COMPACT];
}

/// Build a STARK config for the given FRI profile.
///
/// The Poseidon2 permutation used here (for the STARK's *own* Merkle
/// commitments and challenger) is seeded deterministically. Production must
/// freeze these constants into `specs/vectors/poseidon2.json` (plan WP1); the
/// fixed seed keeps Gate-A measurements reproducible.
pub fn make_config(profile: FriProfile) -> Config {
    let mut rng = SmallRng::seed_from_u64(1);
    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_params = FriParameters {
        log_blowup: profile.log_blowup,
        log_final_poly_len: profile.log_final_poly_len,
        max_log_arity: 1,
        num_queries: profile.num_queries,
        commit_proof_of_work_bits: profile.proof_of_work_bits,
        query_proof_of_work_bits: profile.proof_of_work_bits,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm);
    Config::new(pcs, challenger)
}
