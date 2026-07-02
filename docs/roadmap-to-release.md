# Roadmap to release

*Companion to [`implementation-status.md`](implementation-status.md) (what runs
today) and [`engineering-plan.md`](engineering-plan.md) (the work packages).
This is the ordered path from the current single-sequencer prototype to a
launchable network, with the gates that must close before each step.*

## Where we are

A complete shielded-payment pipeline runs end to end over a single sequencer
with a **real** Plonky3 FRI STARK spend circuit (Poseidon2 over BabyBear, tall
layout, ~185 KB proofs — Gate-A compliant). Notes, tree, tx, state, wallet, and
emission are implemented and tested in-memory behind frozen interfaces. What
remains is (a) closing the authentication gap found in the security review,
(b) replacing the single sequencer with BFT consensus, and (c) the
persistence / networking / hardening needed to run untrusted nodes.

## Gate 0 — authentication correctness (blocker)

Close before any shared deployment, because it is a soundness/liveness gap, not
a scaling item.

- **F-1: bind `enc_outputs` into the spend proof.** Absorb the ciphertexts (or
  their hash) as circuit witness, expose `binding_digest` as a checked public
  input, and enforce it in `StarkSpendVerifier::verify`. Regenerate Poseidon2
  golden vectors; this is a consensus break and takes the freeze process. Ship
  with the regression test from the security review (mutate `enc_outputs`,
  re-solve PoW, assert rejection).
- **Interim mitigation:** forbid `difficulty_bits = 0` on any non-test network;
  drop or document `anchor.height` in `binding_digest`.
- **F-2:** document and test the dummy-`rho` uniform-sampling invariant.
- **F-3:** release-checklist item — no production binary may link `DevVerifier`.

**Exit:** the malleability regression test passes, and a differential fuzz of
`check_spend_statement` (the C1–C9 spec) against the STARK verifier finds no
divergence over N random witnesses.

## Gate A — proving KPIs on real hardware

Mostly closed on host; the open item is the phone measurement.

- Prove ≤ 2 s on a mid-range phone (host is far under budget; WP8 delivers the
  on-device figure).
- Proof ≤ 250 KB — **met** (185 KB tall layout).
- Verify ≥ 500 /s/core via FRI batch verification across a checkpoint's
  transactions (`verify_batch`); single-proof verify is below target on one
  core by design.

**Exit:** phone prove time recorded in `gate-a-report.md`; batch verify
throughput measured at a realistic checkpoint size.

## Gate B — consensus and determinism

The state machine already consumes a *total order* of transactions, which is
exactly what a BFT ordering service produces.

- Integrate an AlephBFT (or Mysticeti-class) instance feeding
  `Ledger::apply_checkpoint`.
- Prove deterministic replay across nodes: identical ordered input ⇒ identical
  state root (the in-memory `deterministic_replay` test is the seed; extend it
  to the networked path).
- Define the anchor validity window and checkpoint cadence under real ordering.

**Exit:** a multi-node testnet reaches agreement on state roots across a
partition-and-heal.

## Gate C — persistence and networking

The logic is implemented in-memory behind the same shapes; this is backend
work.

- RocksDB-backed `CommitmentTree` and nullifier set behind the existing traits
  (WP10/WP4).
- libp2p transaction/checkpoint gossip (WP12); tonic gRPC for wallet/node RPC
  (WP13).
- Crash-recovery: reconstruct the sealed anchor set and nullifier set from
  disk; verify against a replay.

**Exit:** a node restarts mid-checkpoint and resumes to the same state root;
a fresh node syncs from genesis over the network.

## Gate D — economic and anti-spam hardening

- Anti-spam quota lane (WP16b) alongside the PoW lane; calibrate PoW difficulty
  so it is a real malleability/DoS barrier (see Gate 0 interim note).
- Emission parameters reviewed against the emission spec; supply audit wired
  into the node's checkpoint summary as a hard invariant, not just a test.

**Exit:** sustained-spam simulation stays within block/latency budgets; supply
audit holds across a long replay.

## Gate E — external review and launch hardening

- Independent audit of the spend circuit and the PQ-KEM note encryption.
- Fuzzing of the wire codec and the stateless validator; property tests for the
  tree and state machine promoted to the release suite.
- Key-management and wallet-recovery story documented for end users.

**Exit:** audit findings resolved; testnet run under adversarial load without
consensus or accounting faults.

## Critical path

```
Gate 0 (auth fix) ─┬─> Gate B (consensus) ─> Gate C (persistence/net) ─┐
Gate A (phone KPI)─┘                                                    ├─> Gate E ─> launch
                                             Gate D (anti-spam/economics)┘
```

Gate 0 and Gate A are independent and can proceed in parallel now; both must
close before a shared testnet. Gate D can develop alongside B/C but calibrates
against the consensus and networking that B/C provide.
