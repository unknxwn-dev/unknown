//! WP6b — STARK spend circuit (Gate A).
//!
//! This crate is the real-prover counterpart to `prover-dev`. Where the dev
//! prover's "proof" is a tag over the public inputs (insecure, dev only), this
//! crate proves statements with actual Plonky3 FRI STARKs over BabyBear
//! (decisions D1/D2/D3), and measures the Gate-A KPIs.
//!
//! # What is real here
//!
//! - [`field`] — the production proof-system stack (BabyBear + Poseidon2
//!   width-16 + two-adic FRI), wired exactly like Plonky3's upstream example.
//! - [`poseidon2`] — a real STARK over BabyBear proving the spend statement's
//!   Poseidon2 permutation budget (commitments, nullifiers, the depth-32
//!   Merkle paths, binding digest). This is the dominant cost, so it is the
//!   load-bearing Gate-A measurement.
//! - [`balance`] — a hand-written AIR enforcing the spend statement's
//!   *arithmetic* constraints with real, sound STARK constraints: dummy
//!   selectors (C4), 8-bit-limb range (C6), and the no-inflation balance
//!   `Σ v_in + mint = Σ v_out` (C7) via carry propagation. Tampering with any
//!   value makes the proof fail.
//!
//! # What is NOT yet here (honest coverage, mirroring `prover-dev`'s candor)
//!
//! The two halves above are proven *separately*. The remaining WP6b work is to
//! **fuse** them into one AIR so the proven Poseidon2 outputs are constrained to
//! equal the public nullifiers/commitments, the hashed preimages are the
//! witnessed note fields (C1/C2/C3/C5), and the Merkle levels chain to the
//! public anchor root (C1). Until then this crate is a Gate-A benchmark plus a
//! sound balance circuit — not a drop-in `SpendVerifier`. The executable spec
//! the fused circuit must match remains `prover_dev::check_spend_statement`.

pub mod balance;
pub mod field;
pub mod gate_a;
pub mod hash;
pub mod merkle;
pub mod perm;
pub mod poseidon2;
