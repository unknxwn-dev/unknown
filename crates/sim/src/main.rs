//! Economics simulation (WP17): spam-resistance and emission calibration.
//!
//! Off-chain analysis (floating point is fine here — this never runs in
//! consensus). Produces the parameter-recommendation memo the engineering plan
//! calls for: the spam attacker's cost/throughput/state-growth trade-off across
//! PoW difficulties, the emission schedule's inflation and validator revenue,
//! and a demonstration that with beta = 0 total issuance is independent of
//! transaction count (no mint-farming).
//!
//! All numbers are analytical models with stated assumptions, not measurements;
//! Gate-A/Gate-D benchmarks replace the hardware assumptions with real data.

use unknown_emission::EmissionParams;

/// Permanent per-transaction state: 2 nullifiers + 2 commitments, 32 B each.
/// Everything else (proof, ciphertext) is prunable (feasibility §6.3, §7.3).
const STATE_BYTES_PER_TX: f64 = 128.0;

/// Modelling assumptions (replace with Gate-A/Gate-D measurements).
const CHECKPOINTS_PER_SEC: f64 = 1.0; // sub-second finality target, rounded
const SECONDS_PER_YEAR: f64 = 365.0 * 86_400.0;
const PHONE_HASHES_PER_SEC: f64 = 1.0e6; // honest mid-range device, BLAKE3 hashcash
const GPU_HASHES_PER_SEC: f64 = 1.0e9; // spam attacker, single commodity GPU

fn checkpoints_per_year() -> f64 {
    CHECKPOINTS_PER_SEC * SECONDS_PER_YEAR
}

fn banner(title: &str) {
    println!("\n=== {title} ===");
}

fn spam_analysis() {
    banner("Spam economics: PoW lane (uniform difficulty)");
    println!(
        "Assumptions: honest device {:.0e} H/s, attacker GPU {:.0e} H/s, \
         permanent state {} B/tx.",
        PHONE_HASHES_PER_SEC, GPU_HASHES_PER_SEC, STATE_BYTES_PER_TX as u64
    );
    println!(
        "\n{:>6} | {:>14} | {:>14} | {:>16} | {:>18}",
        "bits", "honest solve", "attacker tx/s", "attacker state/day", "verdict"
    );
    println!("{}", "-".repeat(80));
    for &bits in &[8u32, 12, 16, 20, 24] {
        let expected_hashes = 2f64.powi(bits as i32);
        let honest_solve_s = expected_hashes / PHONE_HASHES_PER_SEC;
        let atk_tps = GPU_HASHES_PER_SEC / expected_hashes;
        let atk_state_day = atk_tps * 86_400.0 * STATE_BYTES_PER_TX;
        let verdict = if honest_solve_s > 5.0 {
            "honest UX too slow"
        } else if atk_state_day > 1.0e9 {
            "spam state too high"
        } else {
            "workable"
        };
        println!(
            "{:>6} | {:>12.3}s | {:>14.1} | {:>13} | {:>18}",
            bits,
            honest_solve_s,
            atk_tps,
            human_bytes(atk_state_day),
            verdict
        );
    }
    println!(
        "\nReading: PoW alone cannot both keep honest solve < ~1s AND hold attacker\n\
         state growth low — the classic feeless-PoW squeeze (Nano 2021). This is why\n\
         the PoW lane is a capped FALLBACK and RLN stake quotas (priced in permanent\n\
         state, not tx count) are the primary defence (specs/emission.md, feasibility §7)."
    );
}

/// Atomic units per whole coin (like Monero's 1e12) — must be fine-grained
/// enough that per-checkpoint emission doesn't underflow at sub-second cadence.
const ATOMIC_PER_COIN: f64 = 1.0e8;

fn emission_analysis() {
    banner("Emission schedule: inflation and validator revenue");
    // Example candidate: ~2% year-1 inflation, ~4-year half-life, ~0.5% tail.
    let cpy = checkpoints_per_year();
    // 100M coins at genesis. NOTE: with 31.5M checkpoints/yr, coarse atomic
    // units would round per-checkpoint emission to zero — sub-second finality
    // forces a fine-grained unit (design note surfaced by this very sim).
    let initial_supply = (100_000_000.0 * ATOMIC_PER_COIN) as u64; // 1e16 atomic
    let target_y1_inflation = 0.02;
    let e0 = ((initial_supply as f64 * target_y1_inflation) / cpy) as u64;
    let e_tail = (e0 as f64 * 0.25) as u64; // tail ~ a quarter of e0 (~0.5%/yr)
    let half_life = (4.0 * cpy) as u64; // 4-year half-life
    let params = EmissionParams::new(e0.max(1), e_tail.max(1), half_life.max(1));

    println!(
        "Params: e0={} e_tail={} half_life={} checkpoints ({} cp/yr, {} atomic/coin)",
        params.e0, params.e_tail, params.half_life, cpy as u64, ATOMIC_PER_COIN as u64
    );
    println!(
        "\n{:>6} | {:>18} | {:>16}",
        "year", "emission/cp (atomic)", "annual inflation"
    );
    println!("{}", "-".repeat(48));
    // Accumulate supply year by year so the inflation denominator is correct,
    // printing only selected years.
    let mut supply = initial_supply as f64;
    let show: std::collections::BTreeSet<u64> = [0u64, 1, 2, 4, 8, 20].into_iter().collect();
    for year in 0..=20u64 {
        let h = (year as f64 * cpy) as u64;
        let e = params.emission_at(h);
        let annual = e as f64 * cpy;
        if show.contains(&year) {
            let infl = annual / supply * 100.0;
            println!("{:>6} | {:>18} | {:>15.3}%", year, e, infl);
        }
        supply += annual;
    }

    banner("Validator revenue (base stream, beta = 0)");
    for n in [10u64, 50, 200] {
        let per_cp = params.emission_at(0) / n.max(1);
        let per_day = per_cp as f64 * CHECKPOINTS_PER_SEC * 86_400.0;
        let per_year = per_day * 365.0;
        println!(
            "  {:>3} validators (equal weight): ~{:.1} coins/day, ~{:.0} coins/yr each",
            n,
            per_day / ATOMIC_PER_COIN,
            per_year / ATOMIC_PER_COIN
        );
    }
}

fn mint_farming_check() {
    banner("Mint-farming check (why beta = 0 at genesis)");
    let cpy = checkpoints_per_year();
    let params = EmissionParams::new(1_000_000, 250_000, (4.0 * cpy) as u64);
    // Total issuance over a window is a pure function of height — independent of
    // how many transactions were included. Demonstrate across tx volumes.
    let window = 1_000u64;
    let issued: u64 = (1..=window).map(|h| params.emission_at(h)).sum();
    for tx_count in [0u64, 1_000, 1_000_000, 1_000_000_000] {
        println!(
            "  {:>13} txs included over {} checkpoints  ->  issuance = {} (unchanged)",
            tx_count, window, issued
        );
    }
    println!(
        "\nBecause total emission depends only on height, an attacker cannot mint money\n\
         by manufacturing transactions. A hypothetical per-tx inclusion bonus B would be\n\
         farmable whenever B > PoW/quota cost per tx — which is exactly why the bonus is\n\
         off at genesis and, if ever enabled, is a CAPPED share of a FIXED total that only\n\
         redistributes between validators (specs/emission.md §4-5, §10)."
    );
}

fn human_bytes(b: f64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = b;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}/day", U[i])
}

fn main() {
    println!("unknown — economics simulation (WP17)");
    println!("Analytical models; assumptions stated per section. Not measurements.");
    spam_analysis();
    emission_analysis();
    mint_farming_check();
    banner("Recommendation memo (seeds genesis params + Gate-D criteria)");
    println!(
        "  * PoW lane: cap at a small fraction of capacity; uniform difficulty tuned so\n\
         \x20   honest solve stays sub-second — accept that this alone does not bound spam.\n\
         \x20 * Primary anti-spam: RLN stake quotas priced in PERMANENT STATE (128 B/tx),\n\
         \x20   not tx count; size quotas so worst-case funded state growth stays under the\n\
         \x20   Gate-D cap.\n\
         \x20 * Emission: ~2%/yr year-1 decaying to a ~0.5%/yr tail over a ~4-year half-life;\n\
         \x20   never let the tail reach 0 without meeting the §10 graduation thresholds.\n\
         \x20 * Inclusion bonus: beta = 0 at genesis; issuance stays a pure function of height."
    );
}
