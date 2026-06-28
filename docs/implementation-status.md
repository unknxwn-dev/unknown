# Implementation Status

*Last updated: June 2026. Tracks the Rust prototype in `crates/` against the
work packages in [`engineering-plan.md`](engineering-plan.md).*

## What runs today

A complete **shielded-payment pipeline over a single sequencer** (engineering
plan Phase 1) compiles, is tested, and runs end to end:

```
cargo test --all          # all passing
cargo run --bin unknown-devnet   # full lifecycle demo
cargo clippy --all-targets       # clean (warnings denied)
cargo run --release -p unknown-circuit-spend --bin gate-a-bench   # Gate-A KPIs
```

The pipeline now hashes commitments/nullifiers/Merkle nodes with **Poseidon2
over BabyBear** (decision D3) via the shared `unknown-poseidon` crate — the same
hash the **real Plonky3 FRI STARK** (`circuit-spend`) proves. The full
**2-in/2-out spend statement (C1–C7)** proves and verifies, a WP6d knockout
harness shows every constraint is load-bearing, and an end-to-end test
(`circuit-spend/tests/pipeline.rs`) takes a real note through the real tree and
**verifies it under the frozen `SpendVerifier`**. See
[`poseidon-migration.md`](poseidon-migration.md) and the Gate-A KPI report
([`gate-a-report.md`](gate-a-report.md)). The single-sequencer devnet still runs
on the dev prover pending the wallet/node wiring (migration doc, step 5).

The devnet demo performs a genesis funding, a private transfer Alice→Bob, a
checkpoint with validator reward minting, wallet scanning by trial-decryption,
and a **chained spend** Bob→Carol of a just-received note — with the ledger
seeing only commitments, nullifiers, ciphertexts, and proofs. Balances and
recipients exist only inside the wallets, and the public supply audit
(`Σ mints − Σ burns`) holds at every checkpoint.

## Crate map (→ work package)

| Crate | WP | Status | Notes |
|---|---|---|---|
| `interfaces` | WP0 | ✅ | Frozen cross-crate types, constants, `SpendVerifier`, wire arities |
| `primitives` | WP1 | ✅ | Domain-separated BLAKE3 hashing + KDF (rho/binding/keys), central context registry, golden tests |
| `poseidon` | WP1 | ✅ | Shared **Poseidon2-over-BabyBear** protocol hash (D3): permutation (cross-checked vs Plonky3), sponge, compression, digest pack/unpack — one source for circuit + pipeline |
| `keys` | WP2 | ✅ | Seed→key tree, **hybrid X25519 + ML-KEM-768** keys, address codec, zeroization |
| `notes` | WP3 | ✅ | Note/**Poseidon2** commitment+nullifier, dummy notes, rho derivation, binding tests |
| `tree` | WP4 | ✅ (in-memory) | Append-only depth-32 **Poseidon2** Merkle tree, anchors + validity window, proptests. RocksDB backend pending |
| `encryption` | WP5 | ✅ | 1273-byte hybrid ciphertexts, trial decryption + batch scan, tamper tests |
| `prover-dev` | WP6 | ⚠ dev stand-in | Native spend-statement checker (C1–C9) = executable circuit spec; `check_spend_statement` is what the real circuit must enforce |
| `circuit-spend` | WP6a/6b/6d | ✅ circuit / 🔶 pipeline swap pending | Plonky3 FRI STARK over BabyBear + Poseidon2 (D1/D2/D3). WP6a gadgets (all sound + tested): Poseidon2 permutation (cross-checked vs Plonky3), depth-32 Merkle verifier (**C1**), rate-8 sponge hash (**C2/C5**), balance/range/dummy AIR (**C4/C6/C7**); plus the Poseidon2 workload + Gate-A KPI harness. **WP6b:** `spend` is the full **2-in/2-out statement (C1–C7)** in one STARK (`prove_spend`/`verify_spend`; mint/coinbase too). **WP6d:** `knockout` mutation harness asserts every constraint family is load-bearing and isolatable. **Bridge:** `StarkSpendVerifier` implements the frozen `SpendVerifier` over packed Poseidon2 digests (round-trip tested). **Remaining:** make the rest of the pipeline emit Poseidon2 digests (BLAKE3→Poseidon2 migration) to use it for real txs |
| `tx` | WP9 | ✅ | `TxV1` fixed-layout codec, binding digest, malleability + uniformity tests, stateless validation |
| `state` | WP10 | ✅ (in-memory) | Checkpoint state machine, nullifier set, reward minting, supply audit, deterministic-replay test |
| `emission` | WP15 | ✅ | Float-free `E(h)` decay-to-tail schedule, weight-proportional distribution, β=0 |
| `antispam-pow` | WP16a | ✅ (hashcash) | Uniform-difficulty PoW with the EquiX solve/verify interface |
| `wallet` | WP14 | ✅ | Note management, input selection, transfer builder, scan, spend-marking |
| `node` | WP13 | ✅ (demo) | Integrated single-sequencer devnet binary + lifecycle test |

## Deliberately not yet built (and why)

These are sequenced behind gates in the engineering plan, not overlooked:

- **STARK spend circuit (WP6b/6d) — built, and now wired to the pipeline hash.**
  `circuit-spend::spend` is the full uniform 2-in/2-out statement (C1–C7); the
  WP6d `knockout` harness proves each family is load-bearing; `StarkSpendVerifier`
  implements the frozen `SpendVerifier`; and `notes`/`tree` now compute the same
  Poseidon2 digests (via `unknown-poseidon`), so a real transaction verifies end
  to end (`tests/pipeline.rs`). Remaining items are tracked in
  [`poseidon-migration.md`](poseidon-migration.md): reconcile the ownership model
  for arbitrary addresses (currently `addr_tag == nk`), freeze the Poseidon2
  constants to `specs/vectors/`, set the real `PROOF_BUCKET` + version bump, and
  wire the wallet/node to build witnesses and use `StarkSpendVerifier` in place
  of the dev prover. Output `rho` is also not yet derived from the input
  nullifier (a documented v0 simplification).
- **DAG-BFT consensus (WP11)** — the state machine already consumes a *total
  order* of transactions, which is exactly what AlephBFT/Mysticeti produce. The
  single sequencer is a stand-in for that ordering service.
- **Persistence (RocksDB), P2P (libp2p), gRPC (tonic)** — WP10/12/13 backends;
  the logic they wrap is implemented and tested in-memory behind the same shapes.
- **Quota anti-spam (WP16b), proof aggregation, FMD scanning** — Phase 3 / scale.

## How the pieces enforce the design's privacy claims

- *No visible sender/receiver/amount*: `TxV1` carries only nullifiers,
  commitments, ciphertexts, PoW, and a proof; `tx::tests::all_txs_same_size`
  checks wire uniformity.
- *No double-spend / no inflation, without seeing contents*: the state machine
  rejects duplicate nullifiers (`double_spend_rejected_within_and_across_checkpoints`)
  and the spend statement enforces `Σin + mint = Σout` (`prover-dev`
  `imbalanced_value_rejected`), all over opaque inputs.
- *Mandatory privacy*: there is no transparent transaction type in the codebase —
  the only path to move value is a shielded `TxV1`.
- *Post-quantum confidentiality from genesis*: every note ciphertext is hybrid
  X25519 + ML-KEM-768 (`encryption`), so recorded traffic resists
  harvest-now-decrypt-later.

## Next actions

1. **Done:** Plonky3 Gate-A benchmark of the spend statement's STARK cost
   (prove time, proof size, verify throughput) — see `gate-a-report.md`.
2. Fuse `circuit-spend`'s balance AIR and Poseidon2 workload into one spend AIR
   (bind hashes → public I/O, Merkle-to-anchor), then implement `SpendVerifier`
   and the WP6d knockout/mutation harness against `check_spend_statement`.
3. Bench the same statement on Stwo (M31) for the Gate-A bake-off; package the
   mobile prover (WP8) for the phone prove-time figure.
4. Swap the in-memory tree/state for RocksDB-backed implementations behind the
   existing traits; integrate an AlephBFT instance feeding `apply_checkpoint`.
