# Gate-A Findings: Real STARK Proving Benchmark

*Source: `bench/circuit-bench` — a real Plonky3 v0.6.1 STARK on BabyBear (D1) with
a Poseidon2 commitment scheme (D3). Run with `cd bench/circuit-bench && cargo run
--release`. These are measured numbers on desktop-class hardware, single-thread
(Radix2Bowers DFT), not estimates.*

## What was measured

A real prove→verify cycle over `KeccakAir` (N Keccak-f permutations), a
deliberately **pessimistic** proxy for the spend circuit's dominant cost (a
depth-32 Poseidon2 Merkle-membership path ≈ 40 hash compressions). Keccak's AIR
is far *wider* (~2,600 columns) than a dedicated Poseidon2 circuit would be, so
these numbers overstate both prove time and proof size.

| Keccak perms | prove | verify | proof size |
|---:|---:|---:|---:|
| 16 | 0.61 s | 88 ms | 1,623 KB |
| 64 | 2.62 s | 88 ms | 1,723 KB |
| 256 | 9.85 s | 93 ms | 1,836 KB |
| 1,024 | 40.2 s | 99 ms | 1,967 KB |
| 4,096 | 168.6 s | 104 ms | 2,112 KB |

Marginal cost ≈ **42 ms per Keccak permutation**; proof size grows
**logarithmically** (~1.6 → 2.1 MB across a 256× trace increase); verification is
flat at **~0.1 s**.

## The two findings the data forces (honest read)

1. **Proof size is the binding Gate-A constraint, not prove time.** At ~1.6–2.1 MB
   this blows past the 250 KB target — for two compounding reasons: KeccakAir is
   ~2,600 columns wide, and `FriParameters::new_benchmark` tunes for prover speed,
   not proof size. Consequences, now evidence-backed rather than assumed:
   - the spend circuit **must** be a narrow, dedicated **Poseidon2** AIR (~10× fewer
     columns than Keccak), not a wide general one;
   - FRI parameters must be **size-tuned** (fewer, larger-blowup queries) for the
     real circuit;
   - **proof aggregation / recursion (engineering plan §6.3, WP-aggregation) is
     confirmed NOT optional** — it is on the critical path to a shippable proof size.

2. **Prove time is in the right order of magnitude but unproven on mobile.** ~1.6 s
   for a spend-equivalent (~40 hashes) on desktop *with the wide proxy*; a narrow
   Poseidon2 circuit should be ≈10× cheaper, but the ≤ 2 s **phone** KPI still
   requires an on-device run (WP8) before it can be claimed. This benchmark is the
   desktop baseline, not the mobile answer.

## What this retires, and what it doesn't

- **Retired:** "can we build and run a real post-quantum STARK on this stack at
  all?" — yes; the BabyBear + Poseidon2 + FRI toolchain proves and verifies real
  proofs, and the harness produces reproducible KPIs.
- **Reframed:** the Gate-A risk is specifically **proof size + aggregation**, and
  a **narrow Poseidon2 spend circuit** — not general feasibility. That is a sharper,
  more actionable statement of the risk than the plan started with.
- **Still open (WP6b/WP8):** the actual spend AIR (membership + nullifier + range +
  balance, constraints C1–C8), size-tuned FRI params, recursion, and on-device
  mobile measurement. The dev prover remains the stand-in until that lands.

## Reproduce / extend

`bench/circuit-bench` is a standalone crate (excluded from the main workspace so
Plonky3's large dependency tree doesn't slow core CI). Next steps for whoever
picks up WP6b: swap `KeccakAir` for a `p3-poseidon2-air` Poseidon2 AIR to get the
narrow-circuit numbers, then add a size-tuned `FriParameters` variant and compare.
