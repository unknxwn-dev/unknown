# Anchor Specification (v0)

*Status: normative for the v0 prototype. The single most novel artifact in the
design (engineering plan §7, feasibility §4): how shielded membership proofs are
anchored on a concurrent, deterministic-finality ledger. Implemented by
`crates/tree` and `crates/state`; exercised by `crates/consensus`.*

## 1. The anchor problem

A shielded spend proves that the note it consumes exists in the note-commitment
tree, without revealing which note. That membership proof is made against a
specific tree root — the **anchor**. On a linear chain every block defines one
current anchor. On a concurrent DAG, transactions are built against slightly
different views of the tree, so "the current root" is not well defined at
creation time. This spec resolves that.

## 2. Objects

- **Commitment tree** — append-only Merkle tree, fixed depth `TREE_DEPTH = 32`,
  domain-separated hash (BLAKE3 in v0, Poseidon2 at circuit integration). Leaves
  are output note commitments in commit order. Capacity 2^32 notes.
- **Anchor** — `{ height: u64, root: [u8;32] }`: the tree root sealed at a given
  checkpoint height.
- **Validity window** — `ANCHOR_WINDOW = 1024` checkpoints. A transaction may
  reference any anchor sealed within the last `ANCHOR_WINDOW` checkpoints.
- **Nullifier set** — global, ever-growing, exact-membership set of spent-note
  nullifiers.

## 3. Checkpoint lifecycle (normative)

Consensus (WP11) delivers a **committed total order** of transactions per
checkpoint, identical on every honest node. For checkpoint height `h = prev + 1`:

1. **Validate** each transaction in commit order:
   1. its anchor MUST be currently valid (§4);
   2. it MUST pass stateless validation (structure, anti-spam, proof);
   3. none of its nullifiers may already be in the nullifier set, nor appear
      earlier in this same checkpoint.
   The first transaction to present a given nullifier wins; later conflicting
   ones are rejected. This makes double-spends **attacker-only races** — only
   the note owner can produce two spends of one note — so honest users never
   contend (feasibility §4).
2. **Commit** the accepted transactions' effects in commit order:
   - insert all their nullifiers into the nullifier set;
   - append all their output commitments to the tree, in commit order
     (deterministic: commit order = insertion order = leaf position order).
3. **Mint** validator rewards (public amounts) as note commitments appended
   after the transaction outputs (`specs/emission.md`).
4. **Seal** the new root as the anchor for `h`; evict anchors older than
   `ANCHOR_WINDOW` from the accepted set.

Determinism requirement: applying the same committed order to two replicas MUST
produce byte-identical roots and nullifier sets (tested:
`consensus::submission_order_does_not_change_committed_state`,
`state::deterministic_replay`).

## 4. Anchor validity

A transaction's anchor `a` is valid at height `h` iff `a` was sealed at some
height `h'` with `h - h' < ANCHOR_WINDOW`, and `a.root` equals the root actually
sealed at `h'`. Verifiers keep the last `ANCHOR_WINDOW` sealed anchors; an anchor
outside that set (too old, or never sealed / forged root) is rejected
(`RejectReason::StaleOrUnknownAnchor`; tested `state::stale_anchor_rejected`).

Because the tree is **append-only**, a proof made against an older sealed root
stays valid as the tree grows: the older root authenticates a prefix of the
current leaves, and the note's authentication path against that prefix does not
change (tested `tree::witness_survives_appends`). The window bounds how far back
verifiers must retain anchors, not how long a note remains spendable.

## 5. Chained-spend latency (consequence to design for)

A note received in checkpoint `h` (its commitment sealed into anchor `h`) becomes
spendable only once a wallet can build a membership proof against a sealed
anchor — i.e., from checkpoint `h` onward. Spending a just-received note
therefore incurs **one checkpoint interval** of latency. At sub-second
checkpoint cadence this is sub-second; it MUST be reflected in wallet UX
(the prototype demonstrates a chained spend across consecutive checkpoints:
`node::full_lifecycle_demo_succeeds`).

## 6. Why deterministic finality is required

If an anchor could be reorged (rolled back), every in-flight proof made against
it would become invalid and the nullifier set would fork — a note could appear
spent on one branch and unspent on another. The design therefore mandates a
**deterministic-finality BFT-DAG** (AlephBFT / Mysticeti class): once a
checkpoint is committed it is final. This rules out probabilistic (Nakamoto /
PoW-DAG) consensus for v1 (feasibility §4). Under BFT finality:

- an equivocating or byzantine proposer cannot cause honest replicas to seal
  different anchors (the committed order is agreed);
- an invalid transaction is dropped without desynchronizing replicas
  (tested `consensus::byzantine_invalid_proof_is_dropped_without_breaking_agreement`);
- a partition heals by replaying the reconciled canonical order, reaching the
  same state (tested `consensus::partition_then_heal_converges`).

## 7. Parameters

| Parameter | v0 value | Rationale / revisit |
|---|---|---|
| `TREE_DEPTH` | 32 | 2^32 note capacity; revisit if lifetime output count could exceed it |
| `ANCHOR_WINDOW` | 1024 checkpoints | Retention vs. how stale a wallet's anchor may be at submission; tune with real submission-latency data (Gate C) |
| checkpoint cadence | set by consensus | Gate C measurement; trades finality latency vs. chained-spend latency |

## 8. Security notes

- **Anchor forgery** is prevented by verifiers checking the referenced root
  against their own sealed anchor set — a proof against a root that was never
  sealed is rejected regardless of the proof's validity.
- **Cross-window replay** of a spent nullifier is prevented by the global
  nullifier set, which is independent of the anchor window: a nullifier stays
  spent forever even after its anchor leaves the window (tested
  `consensus::spent_nullifier_cannot_be_replayed_next_round`).
- **Grinding the anchor** gives an attacker nothing: all sealed anchors within
  the window are equally valid, and the note's membership is fixed once sealed.

## 9. Open items (before mainnet)

1. `ANCHOR_WINDOW` sizing from measured submission-to-commit latency
   distributions on a WAN testnet (Gate C).
2. Tiered / frontier-only anchor retention so verifiers need not store full
   historical roots (Penumbra TCT precedent).
3. Formal model-check of §3–§4 under adversarial commit orders and
   equivocation (engineering plan §12 item 2).
