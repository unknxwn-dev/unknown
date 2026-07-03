//! Gate-A benchmark: prove time / proof size / verify throughput for the spend
//! statement's STARK components, swept over the FRI profiles. Writes a Markdown
//! report and prints it.
//!
//! `cargo run --release -p unknown-circuit-spend --bin gate-a-bench`

use std::path::PathBuf;

use unknown_circuit_spend::gate_a;

fn main() {
    // A few prove iterations (best-of), more verify iterations for a stable
    // throughput sample.
    let rows = gate_a::run_sweep(3, 20);
    let md = gate_a::to_markdown(&rows);

    print!("{md}");

    // Write next to the crate, into the repo docs dir if reachable.
    let out: PathBuf = std::env::var("GATE_A_OUT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("docs/gate-a-report.md"));
    match std::fs::write(&out, &md) {
        Ok(()) => eprintln!("\nwrote {}", out.display()),
        Err(e) => eprintln!("\n(could not write {}: {e})", out.display()),
    }
}
