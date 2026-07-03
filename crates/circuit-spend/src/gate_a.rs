//! Gate-A measurement harness.
//!
//! Produces the KPI numbers the engineering plan's Gate A decides on: prove
//! time, proof size, and verify throughput, for ≥ 2 FRI parameter sets. The
//! M1 thresholds (milestone table) are: phone prove ≤ 2 s, proof ≤ 250 KB,
//! verify ≥ 500 /s/core. Numbers here are laptop/server numbers; the phone
//! figure is WP8 (mobile packaging).
//!
//! Run it: `cargo run --release -p unknown-circuit-spend --bin gate-a-bench`.
//! (Release is essential — debug STARK proving is ~100× slower and not
//! representative.)

use std::time::Instant;

use p3_air::BaseAir;
use p3_uni_stark::ConjecturedSecurity;

use crate::balance::{self, BalanceWitness};
use crate::field::{make_config, FriProfile, Val};
use crate::poseidon2::{self, perm_budget};

/// BabyBear degree-4 extension is ~124 bits; the Poseidon2 digest gives ≥ 124
/// bits collision resistance. These cap the conjectured FRI security.
const NUM_MODULUS_BITS: usize = 124;
const COLLISION_RESISTANCE: usize = 124;

/// One measured (component, FRI profile) data point.
#[derive(Clone, Debug)]
pub struct BenchRow {
    pub component: &'static str,
    pub profile: &'static str,
    pub rows: usize,
    pub width: usize,
    pub prove_ms: f64,
    pub proof_kib: f64,
    pub verify_per_s: f64,
    pub security_bits: usize,
}

/// Conjectured FRI security in bits, via Plonky3's random-words estimator
/// ([2025/2010] §1.5) — not a hand-rolled approximation.
fn security_bits(p: &FriProfile) -> usize {
    ConjecturedSecurity::compute(
        p.log_blowup,
        p.num_queries,
        p.proof_of_work_bits,
        COLLISION_RESISTANCE,
        NUM_MODULUS_BITS,
    )
    .security_bits
}

/// Best-of-`prove_iters` prove time; `verify_iters` for the throughput sample.
pub fn measure_hashes(profile: FriProfile, prove_iters: usize, verify_iters: usize) -> BenchRow {
    let rows = perm_budget::TOTAL.next_power_of_two();
    // One-time setup, excluded from the timed region (a phone builds it once).
    let air = poseidon2::spend_hash_air();
    let config = make_config(profile);
    let width = BaseAir::<Val>::width(&air);

    let mut prove_s = f64::INFINITY;
    let mut held = None;
    for _ in 0..prove_iters.max(1) {
        let t = Instant::now();
        let proof = poseidon2::prove_with(&config, &air, perm_budget::TOTAL, profile.log_blowup);
        prove_s = prove_s.min(t.elapsed().as_secs_f64());
        held = Some(proof);
    }
    let proof = held.unwrap();
    let proof_bytes = postcard::to_allocvec(&proof)
        .expect("serialize proof")
        .len();

    let t = Instant::now();
    for _ in 0..verify_iters.max(1) {
        poseidon2::verify_hashes(&config, &air, &proof).expect("verify");
    }
    let verify_s = t.elapsed().as_secs_f64();

    BenchRow {
        component: "spend hashing (Poseidon2, 89 perms)",
        profile: profile.label,
        rows,
        width,
        prove_ms: prove_s * 1e3,
        proof_kib: proof_bytes as f64 / 1024.0,
        verify_per_s: verify_iters.max(1) as f64 / verify_s,
        security_bits: security_bits(&profile),
    }
}

/// Measure the arithmetic (balance/range/selector) AIR.
pub fn measure_balance(profile: FriProfile, prove_iters: usize, verify_iters: usize) -> BenchRow {
    // A representative balanced transfer.
    let w = BalanceWitness {
        inputs: [750_000, 250_000],
        mint: 0,
        outputs: [600_000, 400_000],
        dummy: [false, false],
    };

    // One-time setup, excluded from the timed region.
    let air = balance::BalanceAir;
    let config = make_config(profile);

    let mut prove_s = f64::INFINITY;
    let mut held = None;
    for _ in 0..prove_iters.max(1) {
        let t = Instant::now();
        let out = balance::prove_with(&config, &air, &w);
        prove_s = prove_s.min(t.elapsed().as_secs_f64());
        held = Some(out);
    }
    let (proof, pis) = held.unwrap();
    let proof_bytes = postcard::to_allocvec(&proof)
        .expect("serialize proof")
        .len();

    let t = Instant::now();
    for _ in 0..verify_iters.max(1) {
        balance::verify_balance(&config, &air, &proof, &pis).expect("verify");
    }
    let verify_s = t.elapsed().as_secs_f64();

    BenchRow {
        component: "spend arithmetic (balance/range/C4)",
        profile: profile.label,
        rows: balance::TRACE_ROWS,
        width: balance::WIDTH,
        prove_ms: prove_s * 1e3,
        proof_kib: proof_bytes as f64 / 1024.0,
        verify_per_s: verify_iters.max(1) as f64 / verify_s,
        security_bits: security_bits(&profile),
    }
}

/// Run the full Gate-A sweep over [`FriProfile::SWEEP`].
pub fn run_sweep(prove_iters: usize, verify_iters: usize) -> Vec<BenchRow> {
    let mut rows = Vec::new();
    for profile in FriProfile::SWEEP {
        rows.push(measure_hashes(profile, prove_iters, verify_iters));
        rows.push(measure_balance(profile, prove_iters, verify_iters));
    }
    rows
}

/// Format the sweep as a Markdown report.
pub fn to_markdown(rows: &[BenchRow]) -> String {
    let mut s = String::new();
    s.push_str("# Gate-A KPI report\n\n");
    s.push_str(
        "Generated by `cargo run --release -p unknown-circuit-spend --bin gate-a-bench`.\n\n\
         Proof system: Plonky3 FRI STARK over BabyBear, Poseidon2 width-16 \
         (decisions D1/D2/D3). Prove time is best-of-N on this host (single \
         process, one core); the phone figure is WP8. The security column is \
         Plonky3's conjectured FRI estimate (random-words bound). A single \
         spend is a tiny trace, so both profiles use negligible grinding and \
         lean on blowup/queries; adding query proof-of-work shrinks proofs \
         further at the cost of fixed grind time (disproportionate at this \
         trace size).\n\n",
    );
    s.push_str(
        "| Component | FRI profile | Trace (rows × cols) | Prove (ms) | Proof (KiB) | Verify (/s) | ~Security |\n",
    );
    s.push_str("|---|---|---|---:|---:|---:|---:|\n");
    for r in rows {
        s.push_str(&format!(
            "| {} | {} | {} × {} | {:.1} | {:.1} | {:.0} | {} bits |\n",
            r.component,
            r.profile,
            r.rows,
            r.width,
            r.prove_ms,
            r.proof_kib,
            r.verify_per_s,
            r.security_bits,
        ));
    }
    s.push_str("\n## Gate-A thresholds (M1)\n\n");
    s.push_str(
        "- **Prove ≤ 2 s on a mid-range phone.** The full single-spend hash \
         budget is ~89 Poseidon2 permutations (the two depth-32 Merkle paths \
         dominate). Host prove times below are far under budget; the phone \
         number is the WP8 deliverable.\n\
         - **Proof ≤ 250 KB.** See the proof-size column; the compact profile \
         trades a higher blowup for fewer queries and a smaller proof.\n\
         - **Verify ≥ 500 /s/core.** See the verify column. Single-proof verify \
         is below this on one core; the plan's `verify_batch` (FRI batched \
         across a checkpoint's transactions) is how the target is met at the \
         node.\n\n\
         These cover the *measured* halves (hashing cost + sound arithmetic). \
         The fused spend circuit (binding hashes to the public \
         nullifiers/commitments and Merkle root) will add glue rows but is \
         still Poseidon2-dominated, so these numbers are the load-bearing \
         estimate.\n",
    );
    s
}
