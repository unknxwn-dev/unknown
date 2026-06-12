# Project Plan: Post-Quantum, Feeless, Mandatory-Private Shielded DAG L1

*Companion to [`feasibility-analysis.md`](feasibility-analysis.md). Last updated: June 2026.*

## 0. Guiding principles

1. **De-risk the seams first.** The four novel seams (anchors-on-DAG, feeless anti-spam with
   hidden balances, PQ proving performance, scan/state scaling) are attacked in order of
   kill-probability. Nothing else gets built until the current gate's question is answered.
2. **Benchmarks gate design, not the reverse.** Every phase ends in a go/no-go gate with
   numeric criteria and a pre-named fallback. No "we'll optimize later" for client proving.
3. **Buy, don't build** for proof systems, consensus cores, PQ libraries, hashing, and
   networking. **Build** only the spend circuit, the anchor/checkpoint state machine, the quota
   mechanism, and the wallet.
4. **Uniformity is a feature.** Every transaction has identical shape, size class, and anti-spam
   difficulty. Any feature that breaks uniformity needs an explicit privacy review.
5. **Specs before code; adversaries before features.** Each component ships with its threat model.
6. **Feeless for users from day one; never unpaid security from day one.** Nano-style
   third-party-funded infrastructure is a destination state, not a genesis security model
   (`specs/emission.md`).

---

## 1. Phase overview

| Phase | Title | Duration | Kills the question… | Gate |
|---|---|---|---|---|
| 0 | Specs & benchmarks | Weeks 1–8 | "Is PQ client proving fast enough at all?" | **A** |
| 1 | Cryptographic core | Months 2–7 | "Does the full shielded tx lifecycle work end-to-end?" | **B** |
| 2 | DAG consensus integration | Months 7–11 | "Do anchors + nullifiers survive real concurrency?" | **C** |
| 3 | Feeless mechanics | Months 10–14 | "Does spam resistance hold without fees or visible balances?" | **D** |
| 4 | Hardening & public testnet | Months 14–20 | "Does it survive other people?" | **E** |
| 5 | Mainnet path | 20+ | Launch readiness | — |

Phases 2/3 overlap deliberately (different workstreams). Total to public testnet: ~18–20 months
with the team in §5; mainnet realistically year 3.

---

## 2. Phase detail

### Phase 0 — Specs & benchmarks (weeks 1–8, no product code)

**Deliverables**

- `specs/notes.md` — note structure, commitment/nullifier derivation, key hierarchy
  (spend/view/detection keys), address encoding with version bytes.
- `specs/anchors.md` — **the anchor-window spec**: checkpoint cadence, validity window W,
  deterministic commitment-insertion order, conflict resolution on duplicate nullifiers,
  behavior under equivocation. This is the most novel artifact; write it first.
- `specs/threat-model.md` — adversaries: spammer (state-growth attacker), deanonymizer
  (ledger + network), counterfeiter (circuit/soundness), quantum archivist
  (harvest-now-decrypt-later), byzantine validators.
- `specs/emission.md` — issuance schedule and reward-distribution rule (v0 drafted: fixed
  per-checkpoint emission `E(h)` decaying to a tail, stake/participation-weighted base stream,
  capped quota-backed inclusion bonus; per-tx minting rejected — mint-farming analysis inside).
- **Benchmark harness** (`bench/`): the candidate 2-in/2-out spend relation implemented in
  Plonky3, Stwo, and Miden VM; measured on x86 laptop, ARM laptop, mid-range Android.
- **Economics simulation** (`sim/`): spam attacker budget vs. quota/PoW parameters; state-growth
  curves at 10/100/1,000 TPS; emission/dilution model for validator funding, including
  mint-farming/ledger-stuffing profitability across `specs/emission.md` parameters
  (calibrates `E_0`, half-life `H`, tail `E_tail`, inclusion-bonus cap `β`).

**Gate A (go/no-go):**

- Client proof generation for the spend relation **≤ 2 s on a mid-range phone, ≤ 0.5 s on a
  laptop**, proof **≤ 250 KB**, node verification **≥ 500 proofs/s/core** in at least one stack.
- *Fallback if missed:* (a) reduce circuit (1-in/2-out + note-merge txs), (b) delegate proving to
  user-chosen servers with blinding (privacy cost — needs design), (c) park PQ proofs: launch
  with a transparent-setup EC system (Halo2-class) + PQ *encryption*, with a committed migration
  pool (§6.1 of the feasibility doc explains why encryption can't wait but soundness can).

### Phase 1 — Cryptographic core: "shielded payments over a single sequencer" (months 2–7)

**Scope:** one Rust workspace, no networking beyond localhost.

- Spend circuit (winning stack from Gate A): membership proof against MMR anchor, nullifier PRF,
  in-circuit Σin = Σout with 64-bit range checks, binding hash over tx body.
- Note encryption: hybrid X25519 + ML-KEM-768 → HKDF → XChaCha20-Poly1305 (libcrux).
- Single-node sequencer: mempool → checkpoint sealing → anchor publication → nullifier set.
- EquiX per-tx PoW (stub difficulty).
- CLI wallet: key generation, address encoding, scan (trial decryption), receive, prove, spend,
  balance recovery from seed.
- Golden test vectors for every primitive (these become the spec's normative appendix).

**Gate B:** full lifecycle demo (mint → pay → chained pay) with all Gate-A KPIs holding in the
integrated system, plus: wallet scan ≥ 5,000 tx/s/core (laptop); spend-after-receive latency
≤ 2 checkpoint intervals; tx wire size ≤ 300 KB; mutation tests on the circuit (every constraint,
when removed, is caught by a failing test — first line of counterfeit defense).

### Phase 2 — DAG consensus integration (months 7–11)

- Integrate a Mysticeti- or AlephBFT-class implementation (evaluate: Sui's mysticeti crate,
  AlephBFT crate, commonware primitives) — vertices carry opaque tx batches.
- Anchors sealed at commits per `specs/anchors.md`; sliding validity window; deterministic
  insertion order from commit sequence.
- Adversarial harness: double-spend races across validators, equivocating vertices, stale-anchor
  floods, checkpoint-boundary spends.
- 4–10 node WAN testnet (3+ regions).

**Gate C:** zero safety violations under the adversarial harness (model-checked anchor spec +
chaos testing); p50 finality ≤ 1 s, p99 ≤ 3 s WAN; sustained ≥ 1,000 tx/s with proof
verification on; new-node sync from checkpoints without replaying pruned proofs.
*Fallback if DAG integration stalls:* single-leader BFT (CometBFT-class) with the same anchor
spec — the privacy/feeless pillars don't depend on the DAG; speed claims get tempered.

### Phase 3 — Feeless mechanics & economics (months 10–14, overlaps Phase 2)

- Shielded **quota pool**: stake-locked quota notes; per-epoch rate nullifiers
  PRF(quota_key, epoch, k); RLN-style slashing for reuse; sponsorship flow (transferable small
  quota notes); PoW fallback lane capped at a fixed fraction of capacity.
- Emission per `specs/emission.md`: per-checkpoint `E(h)` with smooth decay to tail; shielded
  coinbase with **public amounts** to validators; stake/participation base stream + capped
  quota-backed inclusion bonus (launchable at β = 0); staking + delegation; supply-audit
  endpoint (Σ mints − Σ burns).
- Per-vertex/per-checkpoint **proof aggregation** (recursive folding) and proof pruning after
  finality; state-weight accounting per quota.
- **Spam game days:** red team funded to break it with the economics sim's worst-case budgets.

**Gate D:** network remains usable (p99 honest-tx finality ≤ 5 s) under the modeled worst-case
spam budget for 72 h; state growth under attack ≤ agreed cap; quota bootstrap demonstrated (new
user with zero stake completes first tx ≤ 60 s via PoW lane or sponsorship).
*Fallback:* enable Plan-B **uniform in-circuit burn** (constant F enforced in the proof — no fee
field, no fee market, uniformity preserved) and re-run the game days.

### Phase 4 — Hardening & public testnet (months 14–20)

- External audits: circuit (two independent firms), consensus, PQ integration, wallet.
- Formal verification of the constraint system's balance/no-counterfeit properties; model
  checking of the anchor state machine.
- Transport privacy: Dandelion++ at minimum; Tor submission support; timing/shape uniformity
  review; Nym/mixnet integration scoped as post-mainnet.
- FMD detection keys for light wallets; out-of-band note delivery as a wallet option; viewing
  keys / payment-disclosure proofs.
- Incentivized public testnet with bug bounties; versioning/turnstile machinery exercised by a
  practice migration (pool v0 → v1).

**Gate E:** audits closed; practice migration completed; 30-day incentivized testnet without
safety incidents; wallet UX review (address size, QR flows, recovery) signed off.

### Phase 5 — Mainnet path (months 20+)

Genesis/distribution design (out of scope here, decide early for legal review), validator
onboarding, emission activation, mixnet roadmap, lattice-SNARK migration watch (LaBRADOR/
Greyhound class — revisit yearly for the proof-size upgrade pool).

---

## 3. Workstreams (run in parallel across phases)

| Workstream | Owns | Phase center of gravity |
|---|---|---|
| **Circuits & crypto** | spend circuit, hashes, KEM integration, aggregation | 0–1, 3 |
| **Consensus & state** | DAG-BFT integration, anchors, nullifier set, pruning, sync | 2 |
| **Mechanism design** | quotas, PoW lane, emission, simulations, game days | 0, 3 |
| **Wallet & UX** | keys, scanning, addresses, HW-wallet (WOTS+-in-circuit), disclosure | 1, 4 |
| **Networking & privacy** | gossip, Dandelion++/Tor, uniformity, light clients | 2, 4 |
| **Security & assurance** | threat models, mutation/fuzz/formal, audits, bounties | all, peaks 4 |

## 4. KPI summary (targets that define success)

| Metric | Target | Set at |
|---|---|---|
| Client proving (mid-range phone) | ≤ 2 s | Gate A |
| Proof size | ≤ 250 KB pre-aggregation | Gate A |
| Node verification | ≥ 500 proofs/s/core | Gate A |
| Wallet scan rate | ≥ 5,000 tx/s/core | Gate B |
| Finality (WAN, p50 / p99) | ≤ 1 s / ≤ 3 s | Gate C |
| Sustained throughput | ≥ 1,000 tx/s verified | Gate C |
| Honest finality under max-budget spam | p99 ≤ 5 s for 72 h | Gate D |
| Permanent state per tx | ~128 B + bounded ciphertext horizon | Gate D |
| New-user first tx (no stake) | ≤ 60 s | Gate D |

## 5. Team & skills (minimum credible)

- 2× ZK/circuit engineers (STARK internals, one with mobile-perf experience)
- 2× distributed-systems engineers (BFT/DAG consensus)
- 1× cryptographer (PQ, protocol design; reviews everything)
- 1× mechanism-design/economics researcher (can be part-time + advisors)
- 1× wallet/UX engineer
- 1× security engineer (fuzzing, formal methods liaison, audit wrangling)
- Advisors: shielded-protocol veteran (Zcash/Penumbra lineage), mixnet/network-privacy specialist

~7 FTE core. Smaller teams should narrow Phase 1 to the circuit + wallet and lean harder on
existing consensus implementations.

## 6. Top risks → owning gate

| Risk (rank from feasibility doc §10) | Owned by gate | Pre-named fallback |
|---|---|---|
| PQ client proving too slow | A | smaller circuit / delegated proving / EC-proofs+PQ-encryption launch |
| Feeless spam economics fail | D | uniform in-circuit burn (Plan B) |
| Anchor/finality flaw | C | single-leader BFT with same anchor spec |
| Scanning at scale | B→D | FMD default-on; out-of-band delivery; OMR/PIR research track |
| Invisible inflation | B, 4 | mutation tests, dual implementations, formal verification, turnstiles |
| Network-layer deanonymization | 4 | Dandelion++/Tor minimum; mixnet post-mainnet |

## 7. Immediate next actions (first two weeks)

1. Draft `specs/anchors.md` v0 — the design's most novel claim, cheapest to falsify on paper.
2. Stand up the proving benchmark harness; implement the spend relation in Plonky3 first;
   collect laptop + Android numbers.
3. Write the spam-economics notebook: attacker cost curves for PoW-only, quota-only, hybrid.
4. Pick and pin the PQ library (libcrux vs. RustCrypto ml-kem) with a tiny encrypt/scan benchmark.
5. Decide the working name and license; open issues mirroring §2 gate criteria so progress is
   legible.
