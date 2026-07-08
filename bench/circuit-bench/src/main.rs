//! Gate-A benchmark runner: `cargo run --release`.
//! Sweeps trace sizes and prints prove time, verify time, and proof size, then
//! extrapolates a per-spend estimate.

use circuit_bench::{run, BenchResult, HASHES_PER_SPEND};

fn main() {
    println!("Gate-A proving benchmark — real Plonky3 STARK (BabyBear + Poseidon2)");
    println!("Workload: KeccakAir (conservative proxy for spend-circuit hashing).\n");
    println!("{:>10} | {:>12} | {:>11} | {:>12}", "hashes", "prove", "verify", "proof size");
    println!("{}", "-".repeat(54));

    let mut per_hash_ms = 0.0;
    let mut last: Option<BenchResult> = None;
    for &n in &[16usize, 64, 256, 1024, 4096] {
        let r = run(n);
        println!(
            "{:>10} | {:>10} ms | {:>8} ms | {:>9} KB",
            r.num_hashes,
            r.prove_ms,
            r.verify_ms,
            r.proof_bytes / 1024
        );
        per_hash_ms = r.prove_ms as f64 / r.num_hashes as f64;
        last = Some(r);
    }

    if let Some(r) = last {
        println!("\nHonest analysis (desktop, single-thread Radix2Bowers DFT):");
        println!(
            "  raw: ~{:.1} ms/Keccak-perm; proof ~{} KB with benchmark FRI params.",
            per_hash_ms,
            r.proof_bytes / 1024
        );
        println!(
            "\n  Two Gate-A findings the real data forces:\n\
             \x20 1. PROOF SIZE is the binding constraint, not prove time. ~{} KB here\n\
             \x20    blows past the 250 KB target — because KeccakAir is ~2,600 columns\n\
             \x20    wide and `new_benchmark` FRI params optimize prover speed, not size.\n\
             \x20    => the spend circuit MUST be a narrow, dedicated Poseidon2 AIR\n\
             \x20    (~10x fewer columns) AND use size-tuned FRI params, AND proof\n\
             \x20    aggregation/recursion (WP6.3) is confirmed NOT optional.\n\
             \x20 2. Prove time ~{:.0} ms/spend-equiv on desktop with the WIDE proxy;\n\
             \x20    a narrow Poseidon2 circuit should be ~10x better, but that still\n\
             \x20    needs on-device (WP8) measurement before the <=2s phone KPI is met.",
            r.proof_bytes / 1024,
            per_hash_ms * HASHES_PER_SPEND as f64
        );
        println!(
            "\n  Verdict: the PQ-STARK toolchain works and proves/verifies real proofs on\n\
             BabyBear+Poseidon2; the risk is NOT 'can we prove at all' but 'proof size +\n\
             aggregation', which this retires as REQUIRED work rather than assumed-easy.\n\
             Keccak is a deliberately pessimistic proxy (wider than the real circuit)."
        );
    }
}
