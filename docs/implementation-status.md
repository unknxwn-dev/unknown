# Implementation Status

*Last updated: June 2026. Tracks the Rust prototype in `crates/` against the
work packages in [`engineering-plan.md`](engineering-plan.md).*

## What runs today

A complete **shielded-payment pipeline over a single sequencer** (Phase 1) plus
the **deterministic BFT-DAG consensus core** (Phase 2, WP11) and the
**anti-counterfeiting knockout harness** (WP6d) compile, are tested, and run:

```
cargo test --all                 # 52 tests, all passing
cargo run --bin unknown-devnet   # full private-payment lifecycle demo
cargo run --bin unknown-sim      # economics / spam / emission analysis (WP17)
cargo clippy --all-targets       # clean (warnings denied)
```

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
| `primitives` | WP1 | ✅ | Domain-separated BLAKE3 hashing + KDF, central context registry, golden tests |
| `keys` | WP2 | ✅ | Seed→key tree, **hybrid X25519 + ML-KEM-768** keys, address codec, zeroization |
| `notes` | WP3 | ✅ | Note/commitment/nullifier, dummy notes, rho derivation, binding tests |
| `tree` | WP4 | ✅ (in-memory) | Append-only depth-32 Merkle tree, anchors + validity window, proptests. RocksDB backend pending |
| `encryption` | WP5 | ✅ | 1273-byte hybrid ciphertexts, trial decryption + batch scan, tamper tests |
| `prover-dev` | WP6 | ⚠ dev stand-in | Native spend-statement checker (C1–C9) = executable circuit spec. **STARK prover is the next major piece**; `check_spend_statement` is what it must enforce |
| `knockout` | WP6d | ✅ | Mutation harness: 13 targeted violations of C1–C8, each asserted caught — the invisible-inflation tripwire (incl. the C7 balance/inflation check) |
| `tx` | WP9 | ✅ | `TxV1` fixed-layout codec, binding digest, malleability + uniformity tests, stateless validation |
| `state` | WP10 | ✅ (in-memory) | Checkpoint state machine, nullifier set, reward minting, supply audit, deterministic-replay test |
| `consensus` | WP11 | ✅ (model) | Deterministic BFT-DAG ordering model + Gate-C adversarial tests: replica agreement, order-independence, single-winner double-spend, cross-round replay rejection, partition-heal, byzantine-drop. Async AlephBFT/libp2p integration still to come |
| `emission` | WP15 | ✅ | Float-free `E(h)` decay-to-tail schedule, weight-proportional distribution, β=0 |
| `antispam-pow` | WP16a | ✅ (hashcash) | Uniform-difficulty PoW with the EquiX solve/verify interface |
| `antispam-quota` | WP16b | ✅ (core) | RLN-style anonymous rate limiting: stake→quota, per-slot rate nullifiers, and Shamir secret-recovery slashing on slot reuse. Primary feeless defence; wire/circuit integration pending |
| `wallet` | WP14 | ✅ | Note management, input selection, transfer builder, scan, spend-marking |
| `node` | WP13 | ✅ (demo) | Integrated single-sequencer devnet binary + lifecycle test |
| `sim` | WP17 | ✅ | Off-chain economics: PoW spam squeeze, emission/inflation/validator-revenue calibration, mint-farming check |

## Deliberately not yet built (and why)

These are sequenced behind gates in the engineering plan, not overlooked:

- **STARK spend circuit (WP6b)** — the dev prover is honest about being
  insecure (a tag over public inputs, see its module docs). Replacing it is
  Gate-A work and the single largest remaining task. The interface
  (`SpendVerifier`) and the constraint spec (`check_spend_statement`) are
  already frozen, so the swap is localized.
- **Async DAG-BFT integration (WP11/WP12)** — the *consensus contract* (a
  committed total order → identical state on every replica) is implemented and
  adversarially tested in `consensus` against the Gate-C criteria. What remains
  is wiring a real AlephBFT/Mysticeti instance over libp2p to produce that order
  across networked nodes; the ledger side is done.
- **Persistence (RocksDB), P2P (libp2p), gRPC (tonic)** — WP10/12/13 backends;
  the logic they wrap is implemented and tested in-memory behind the same shapes.
- **Quota-lane wire integration** — the RLN quota core (`antispam-quota`) is
  implemented and tested; what remains is carrying its rate proof in `TxV1`
  (a second anti-spam tag) and enforcing it in the state machine with a
  `QuotaRegistry`, alongside the ZK proof that the nullifier derives from a
  staked quota note.
- **Proof aggregation, FMD/OMR scanning, out-of-band delivery** — Phase 3 / scale.

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

1. Stand up the Plonky3/Stwo benchmark of `check_spend_statement` as a circuit
   (Gate A KPIs: phone prove time, proof size, verify throughput).
2. Swap the in-memory tree/state for RocksDB-backed implementations behind the
   existing traits.
3. Integrate an AlephBFT instance feeding `Ledger::apply_checkpoint`.
