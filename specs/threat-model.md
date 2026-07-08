# Threat Model (v0)

*Adversaries the design must withstand, their goals, the defence, and where it is
enforced (spec + code). Phase-0 deliverable (engineering plan §11 Phase 0). "✅"
= modelled and tested in the prototype; "◑" = designed, integration pending;
"○" = deferred behind a later gate.*

## Assets

Confidentiality of sender, receiver, amount, and transaction graph; soundness of
supply (no inflation); liveness of honest payments; integrity of finality.

## 1. Counterfeiter — mint money invisibly

**Goal:** forge a spend that creates value inside the shielded pool (undetectable
post-hoc — the worst failure, feasibility §9/§10 risk 5).
**Defence:** the spend statement enforces membership, ownership, correct
nullifier derivation, range, and balance `Σin + mint = Σout` (constraints
C1–C8). Every constraint is proven load-bearing by the mutation harness.
**Enforced:** `specs/notes.md` §3/§6; `prover-dev::check_spend_statement`;
`crates/knockout` (13 mutations, incl. C7 inflation & C1 forgery). ✅ for the
statement; ◑ soundness awaits the STARK circuit replacing the dev prover.
**Residual:** circuit/proof-system soundness bugs → dual implementations, formal
verification, versioned pools + turnstiles bound blast radius (feasibility §6.5/§9).

## 2. Double-spender — spend one note twice

**Goal:** race two spends of the same note past finality.
**Defence:** global nullifier set; the first spend in committed order wins, all
others rejected; the set persists across the anchor window so old nullifiers stay
spent. Only the note owner can produce the race (attacker-only, no honest
contention).
**Enforced:** `specs/anchors.md` §3/§8; `state::apply_checkpoint`;
`consensus` (single-winner + cross-round-replay tests). ✅

## 3. Ledger deanonymizer — learn who/whom/how-much

**Goal:** recover sender, receiver, amount, or link transactions from ledger data.
**Defence:** mandatory shielding — the only transaction type carries just
nullifiers, commitments, hybrid-PQ ciphertexts, and a proof; uniform size/shape;
no transparent pool to drain the anonymity set; no amounts except public
mint/burn.
**Enforced:** `specs/notes.md` §4/§5; `tx::TxV1` (uniformity test). ✅ at the
ledger layer.
**Residual:** statistical timing/graph analysis at scale → out-of-band delivery
& FMD reduce on-chain footprint (○, feasibility §8).

## 4. Quantum archivist — harvest now, decrypt later

**Goal:** record ciphertexts today, decrypt when a CRQC exists.
**Defence:** hybrid X25519 + ML-KEM-768 note encryption from genesis;
confidentiality holds if either leg is unbroken. Cannot be retrofitted to past
data, so it is mandatory at launch.
**Enforced:** `specs/notes.md` §4; `crates/encryption` (roundtrip/tamper tests).
✅ Soundness-side PQ (hash commitments + STARK) closes the inflation vector too
once the circuit lands (feasibility §6.1). ◑

## 5. Spammer — exhaust permanent state / bandwidth for free

**Goal:** in a feeless system, flood cheap transactions; the real target is
*permanent* nullifier/commitment state, not bandwidth (feasibility §7.3).
**Defence:** dual anti-spam. Primary: RLN stake quotas priced toward permanent
state, with rate nullifiers and slash-on-reuse. Fallback: capped, uniform-
difficulty PoW for stakeless bootstrap. The sim shows PoW alone cannot bound
state growth — hence quotas are primary.
**Enforced:** `specs/emission.md` §7; `crates/antispam-quota` (rate-limit +
slashing tests, ✅ core), `crates/antispam-pow` (✅), `crates/sim` (spam squeeze).
◑ wire integration into `TxV1`/state pending.

## 6. Inflator via emission — bend monetary policy / mint-farm

**Goal:** mint money by manufacturing transactions, or force excess issuance.
**Defence:** total issuance is a pure function of checkpoint height (`E(h)`),
independent of transaction count; inclusion bonus β = 0 at genesis; any future
bonus is a capped share of a fixed total. Genesis schedule is an absolute
ceiling; increases need the emergency constitutional process.
**Enforced:** `specs/emission.md` §3–§5/§10; `crates/emission`; `crates/sim`
(mint-farming check). ✅

## 7. Byzantine validators — fork, censor, or halt

**Goal:** cause honest nodes to disagree on state, reorg a committed anchor, or
stall.
**Defence:** deterministic-finality BFT-DAG — a committed checkpoint is final (no
reorg, so no dead proofs / forked nullifier set). Invalid transactions are
dropped without desynchronizing replicas; partitions heal to a canonical state.
Requires < ⅓ byzantine stake.
**Enforced:** `specs/anchors.md` §6; `crates/consensus` (agreement, byzantine-
drop, partition-heal tests). ✅ for the model; ○ async AlephBFT/Mysticeti + full
censorship-resistance analysis pending.
**Residual:** stake-acquisition attacks by price-indifferent (e.g. state-level)
adversaries → bonded/slashed/paid validators raise capital cost; emission funds
security while the volunteer ecosystem is immature (`specs/emission.md` §7).

## 8. Network-layer deanonymizer — link by IP/timing

**Goal:** correlate transaction submission to a network origin.
**Defence:** Dandelion++ stem/fluff, Tor submission, uniform tx size/timing.
**Enforced:** designed only. ○ (feasibility §10 risk 6) — ledger privacy without
transport privacy fails against targeted adversaries; this is explicitly out of
the v0 prototype scope and must precede any mainnet.

## 9. Light-client server — learn a wallet's notes

**Goal:** a scanning/oblivious-sync server learns which outputs a wallet owns.
**Defence:** bulk-streaming only (no per-note/per-nullifier queries); FMD
detection keys; OMR/PIR and out-of-band delivery for scale.
**Enforced:** `docs/engineering-plan.md` §3.6 (privacy rule); FMD/OMR ○
(feasibility §8).

## Assumptions

Secure key storage on the client; a correct, sound proof system (the v0 dev
prover is explicitly NOT sound — it exists to exercise the pipeline); honest
majority (< ⅓ byzantine) of validator stake; a functioning anonymizing transport
before mainnet.
