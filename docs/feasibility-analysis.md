# Feasibility Analysis: a Post-Quantum, Feeless, Mandatory-Private Shielded DAG L1

*Last updated: June 2026*

## 1. Verdict

**The architecture is technically feasible, but it is a research project, not an engineering
project.** Every individual component exists in production somewhere:

- mandatory shielded pools (Penumbra, Iron Fish, Monero)
- the commitment/nullifier note model (Zcash, derived from the Zerocash paper)
- high-throughput DAG-BFT consensus (Mysticeti/Sui, AlephBFT/Aleph Zero, Narwhal/Bullshark)
- feeless operation with protocol anti-spam (Nano, pre-2025 IOTA)
- post-quantum primitives (ML-KEM, ML-DSA, SLH-DSA; STARK/FRI proof systems)

**No deployed system combines all four pillars** (mandatory privacy + feeless + DAG + PQ-ready).
The novelty — and all of the risk — lives at the *seams* between the pillars:

1. **The anchor problem** — shielded membership proofs need globally-agreed Merkle roots; DAGs
   deliberately avoid a single linear history (§4).
2. **Feeless anti-spam without visible balances** — every production feeless design (Nano's
   balance-bucketed prioritization, IOTA's Mana) depends on *public* balances, which mandatory
   privacy destroys (§7).
3. **PQ proof sizes vs. DAG throughput** — hash-based proofs are 50–200 KB each; at high TPS this
   forces aggregation/pruning into the core design (§6).
4. **Wallet scanning at scale** — mandatory privacy means every wallet trial-decrypts every
   transaction; at DAG throughput this breaks without FMD/OMR/out-of-band delivery (§8).

Each seam has known research directions but no off-the-shelf solution. A realistic estimate for a
credible mainnet is **3–5 years with a specialist team**; a meaningful prototype that retires the
biggest unknowns is achievable in **6–12 months** (§10).

---

## 2. Prior art map

| Project / paper | Shielded notes | Mandatory privacy | DAG / fast ledger | Feeless | PQ posture | Notes |
|---|---|---|---|---|---|---|
| **Zerocash** (Ben-Sasson et al., IEEE S&P 2014) | ✅ origin of the model | ✅ (in paper) | ❌ blocks | ❌ | ❌ | The foundational design: commitments, nullifiers, zk proof of balance |
| **Zcash** (Sapling/Orchard, Halo 2) | ✅ | ❌ optional (transparent pool dominates) | ❌ | ❌ | ❌ EC (Pallas/Vesta); **Tachyon** roadmap adds PQ key exchange + PIR | Most mature shielded engineering; turnstiles, unified addresses, viewing keys |
| **Zcash Project Tachyon** (Bowe, 2025–) | ✅ | — | ❌ | ❌ | partial | Out-of-band note delivery, oblivious sync services, wallets keep their own non-spend proofs. Directly answers §8/§9 problems |
| **Penumbra** (mainnet 2024) | ✅ | ✅ **everything shielded** | ❌ CometBFT | ❌ | ❌ EC | Closest living relative: mandatory multi-asset shielded pool, tiered commitment tree with multi-anchor validity, fuzzy message detection design |
| **Iron Fish** (2023) | ✅ Sapling-derived | ✅ all txs shielded | ❌ PoW blocks | ❌ | ❌ | Proof that an all-shielded L1 ships; public fees remain a metadata leak |
| **Monero** (+ FCMP++ rollout ~2026) | ❌ ring/decoy model → FCMP++ full-chain membership | ✅ | ❌ | ❌ | ❌ | After FCMP++ the *ledger* anonymity set ≈ whole chain; fees and EC assumptions remain |
| **Nano** | ❌ transparent | ❌ | ✅ block-lattice | ✅ | ❌ | Feeless + per-account chains. Cautionary tales: 2021 spam incident; spam defense now buckets by **public balance** — unavailable to us |
| **IOTA** | ❌ | ❌ | ✅ Tangle → Mysticeti ("Rebased", 2025) | ✅ → ❌ (Rebased added gas) | partial (historical claims) | Abandoned feelessness under spam/economics pressure — a data point, not a refutation |
| **Aleph Zero** | partial (Shielder/zkOS, opt-in) | ❌ | ✅ AlephBFT DAG | ❌ | ❌ | DAG-BFT + ZK privacy in one stack; privacy became an opt-in app layer, not ledger-mandatory |
| **Aleo** | ✅ records | ❌ optional public | ❌ | ❌ | ❌ | Private programmability, client-side proving at scale (relevant ops experience) |
| **Miden** (Polygon spin-out) | ✅ note-based | ❌ | ❌ rollup | ❌ | ✅ STARK stack | Closest *cryptographic* stack: notes + client-side STARK proving + hash commitments |
| **Avalanche** (Team Rocket 2019) | ❌ | ❌ | ✅ conflict-set DAG consensus | ❌ | ❌ | The conflict-set formalism maps perfectly onto nullifier double-spends (§4) |
| **FastPay / Sui owned-object path / Linera** | ❌ | ❌ | ✅ consensusless consistent broadcast | ❌ | ❌ | Shielded notes are single-spender objects → payments don't need total ordering (§4) |
| **Abelian, QRL** | partial / ❌ | ❌ | ❌ | ❌ | ✅ lattice / hash sigs | Existence proofs for PQ chains; neither is feeless, DAG, or fully shielded |
| **Semaphore / RLN** (PSE) | — | — | — | — | ✅ hash-based | Anonymous rate-limiting with slashing: the load-bearing primitive for feeless anti-spam (§7) |
| **OMR (Liu–Tromer), FMD (Beck et al.)** | — | — | — | — | OMR: FHE-based | The two main answers to "mandatory privacy forces everyone to scan everything" (§8) |

**Reading of the map:** the column pattern shows the four pillars are pairwise compatible in
production (mandatory-shielded + BFT = Penumbra; DAG + feeless = Nano/old-IOTA; notes + PQ-style
hash stack = Miden) but the full conjunction is unoccupied. The closest near-misses are Penumbra
(add DAG consensus, remove fees, swap crypto) and Aleph Zero (make privacy mandatory at the ledger
level, remove fees, swap crypto).

---

## 3. Architecture sketch under analysis

```text
Transaction (uniform shape, e.g. padded 2-in/2-out "action"):
{
  anchor_ref:          recent sealed commitment-tree root (within validity window W)
  nullifiers:          [nf_1, nf_2]              // 32 B each, hash-based PRF outputs
  note_commitments:    [cm_1, cm_2]              // 32 B each, hash commitments
  zk_proof:            STARK proof               // ~50–200 KB today; prunable after finality
  encrypted_outputs:   [ct_1, ct_2]              // ML-KEM-768 hybrid, ~1.2–1.4 KB each
  anti_spam_proof:     RLN quota proof | EquiX PoW
  version:             pool/proof-system/encryption version bytes
}
```

The proof's public inputs: `anchor_ref`, `nullifiers`, `note_commitments`, a binding hash over the
entire transaction body (anti-malleability), and — only for mint/burn/migration transactions — a
public value-balance amount (§9).

The proof's statement (informally): *"I know notes opening `cm_in` that exist in the tree at
`anchor_ref`, whose spend keys I hold; `nullifiers` are correctly derived from those notes;
`note_commitments` are well-formed; sum of input values = sum of output values; all values are
64-bit; the anti-spam quota element is correctly derived."*

Nodes verify the proof, check nullifier-freshness against the global set, check the anti-spam
proof, and order via DAG consensus. They learn nothing else. This matches the Zerocash/Orchard
verification model; nothing about it intrinsically requires blocks.

---

## 4. Is a DAG compatible with shielded notes?

**Yes — and the fit is better than for transparent DAGs — with two real frictions.**

### Why the fit is good

1. **Shielded transactions are naturally order-independent.** A shielded tx carries its own
   authority (the proof) and conflicts with another tx *only* if they reveal the same nullifier.
   There are no account sequence numbers, no shared mutable balances, no contention between honest
   transactions. This is exactly the workload DAG consensus is best at.
2. **Nullifier = conflict key.** Avalanche-style conflict-set consensus and DAG-BFT dedup both need
   a cheap, deterministic conflict predicate. "Same nullifier" is a perfect one: equality of a
   32-byte string. Crucially, only the note's owner can produce two transactions spending the same
   note — so double-spend races are *attacker-only*; honest users never experience conflict
   latency. (This is the FastPay/Sui-owned-object observation transposed to notes.)
3. **No content-visible MEV.** Everything is encrypted, so there is nothing to front-run and no
   incentive to manipulate fine-grained ordering. DAG protocols' weak/fuzzy intra-round ordering —
   a liability for transparent DeFi chains — is harmless here.
4. **Receiving is passive.** In a note model the recipient posts nothing (the sender creates the
   output commitment). This deletes Nano's receive-block spam surface and halves the "account
   chain" machinery.

### Friction 1: the anchor problem (the main design seam)

Membership proofs are made against a commitment-tree root ("anchor"). In a linear chain, every
block defines one. In a DAG, txs are created concurrently against slightly different views.

Resolution (combining Penumbra's multi-anchor validity with DAG-BFT commits):

- The DAG-BFT consensus (Mysticeti/AlephBFT-class) produces a **committed sequence of
  checkpoints** at sub-second cadence. Each checkpoint deterministically appends that round's new
  commitments to the global tree (commit order = insertion order) and seals a new anchor.
- A transaction may reference **any anchor within a sliding window W** (e.g., last few thousand
  checkpoints). Verifiers accept the proof if the anchor is in the window.
- An **append-only tree (MMR / tiered commitment tree)** makes old anchors "extendable": a proof
  against an old root stays meaningful because the tree only grows.
- Consequence: a freshly received note becomes spendable only after its commitment lands in a
  sealed checkpoint — one checkpoint interval of added latency (sub-second to seconds) for chained
  spends. Acceptable; must be in the spec from day one.

This **requires deterministic finality**. If an anchor can reorg, in-flight proofs against it die
and the nullifier set becomes ambiguous. That rules out Nakamoto-style probabilistic PoW DAGs
(Kaspa-class) for v1 and points firmly at **validator-based DAG-BFT** (Mysticeti, AlephBFT,
Narwhal/Bullshark lineage: sub-second commit latency, 10k–100k+ TPS in lab settings).

### Friction 2: the global nullifier set

Nullifier-freshness is an inherently global check (one ever-growing set, exact membership). That is
easy under total-order-at-checkpoint BFT (each checkpoint atomically admits a batch and rejects
duplicates) and miserable under purely probabilistic consensus. Again: DAG-BFT, not PoW-DAG.

### What to avoid: the block-lattice specifically

Nano's *per-account chains* are precisely the metadata structure this design must not have. The
right shape is a **DAG of opaque transaction batches** (Narwhal-style DAG mempool feeding BFT
commits), where vertices carry `{nullifiers, commitments, ciphertexts, proofs}` and no
account-shaped structure exists at all. "Block-lattice speed" is achievable without the lattice:
the speed comes from parallel, leaderless data dissemination + cheap conflict detection, both of
which the note model gives you for free.

---

## 5. Cryptographic stack

| Component | Recommended primitive | PQ status | Size / cost notes |
|---|---|---|---|
| Commitments, nullifier PRF, Merkle hashing | Poseidon2 / Rescue-Prime (in-circuit), Blake3 (out-of-circuit), 256-bit params | ✅ symmetric/hash (Grover-only) | 32 B each; nullifier = PRF(nk, note position/ρ) |
| Commitment accumulator | Append-only MMR or tiered commitment tree, depth ≥ 32 | ✅ | Old-anchor proofs remain valid (append-only) |
| ZK proof system | STARK/FRI stack: Plonky3, Stwo, Winterfell, or Miden VM; hand-rolled spend circuit, not a general zkVM | ✅ hash-based (transparent setup — no toxic waste) | Proof ~50–200 KB; verify ~ms; client proving: est. sub-second (laptop) to seconds (phone) for a dedicated 2-in/2-out circuit — **benchmark first (MVP KPI #1)** |
| (watchlist) | Lattice SNARKs: LaBRADOR, Greyhound PCS | ✅ Module-SIS | ~16 KB proofs for 2^20-gate relations but **linear-time verification** today — not yet usable for chain verification; revisit yearly |
| Note encryption | Hybrid X25519 **+ ML-KEM-768** → HKDF → XChaCha20-Poly1305 (or AES-256-GCM) | ✅ hybrid from genesis | ML-KEM-768 ct = 1088 B → ~1.2–1.4 KB per output ciphertext; ML-KEM-512 (768 B) if margin acceptable |
| Addresses | Encoded {ML-KEM pk, detection key, spend-verification commitment} + version byte | ✅ | **~1.3–1.7 KB addresses** (ML-KEM-768 pk alone = 1184 B). Fits in a QR code (≤ ~3 KB) but UX-noticeable. No cheap DH-style diversified addresses (§6) |
| Spend authorization | Inside the proof: knowledge of spend key (hash preimage relation). For hardware-wallet delegation: WOTS+/hash-based one-time sig **verified in-circuit** (hashing is cheap in STARKs) | ✅ | Avoids needing any standalone PQ account signature |
| Consensus signatures | ML-DSA-65 (validators); SLH-DSA for long-lived/governance keys | ✅ | ML-DSA sig = 3309 B; no BLS-style aggregation → certificates of 2f+1 sigs get large (~100 validators ⇒ ~200+ KB/cert); mitigations: committees, cert pruning after checkpoint proof, or STARK-aggregated signature validity (research) |
| Anti-spam | EquiX-class asymmetric client-puzzle PoW (Tor's DoS defense) and/or RLN over shielded stake (§7) | ✅ hash-based | Verify ≪ solve; difficulty must be **uniform** to avoid fingerprinting |
| Value balance | Entirely in-circuit: Σin = Σout (+ public mint/burn term), 64-bit range checks | ✅ | **No Pedersen homomorphism in PQ-land** — see §6 |
| Network privacy (out of ledger scope, required in practice) | Dandelion++ at minimum; Tor/Nym integration; uniform tx sizes & timing batching | partial (PQ onion routing immature) | Ledger privacy without network privacy is theater for targeted adversaries |

---

## 6. How post-quantum readiness changes the design

PQ is not a primitive swap; it reshapes the architecture in five ways.

### 6.1 The asymmetric-deadline rule (the most important PQ insight)

- **Confidentiality breaks retroactively.** Ciphertexts recorded on a public ledger today can be
  harvested now and decrypted when a CRQC exists. For a chain whose entire value proposition is
  privacy, **PQ (hybrid) note encryption is mandatory at genesis** — it cannot be retrofitted for
  past transactions.
- **Soundness breaks prospectively, but invisibly.** If the proof system's or commitment scheme's
  binding assumption falls, an attacker forges spend proofs → **undetectable inflation inside a
  shielded pool**. Migration via versioned pools/turnstiles is possible *before* the break, but
  because counterfeiting in a shielded pool is invisible, the safety margin must be generous.
  Avoid Pedersen-style DL-binding commitments entirely (Zcash's standing quantum exposure);
  hash-binding commitments and hash-based proofs from genesis close this hole permanently.

Practical conclusion: **hash-based commitments + STARK proofs + hybrid ML-KEM encryption at
genesis**; treat smaller PQ proof systems (lattice SNARKs) as a versioned upgrade path. This also
eliminates trusted setup.

### 6.2 Lost elliptic-curve conveniences (each needs a designed replacement)

| EC trick (Zcash/Monero) | PQ replacement | Cost |
|---|---|---|
| Pedersen-homomorphic value commitments balancing across independently-built "actions" | Single proof per transaction covering all inputs/outputs in-circuit | Loses trustless multi-party tx composition (CoinJoin-style assembly); fine for payments |
| DH-based stealth/diversified addresses (one key → unlimited unlinkable addresses, one scan key) | Derive multiple ML-KEM keypairs from a seed; each extra published address adds a trial-decapsulation per tx scanned | Address unlinkability becomes a *cost knob*, not free |
| Re-randomizable signatures (RedDSA spend-auth) | Spend-auth inside the circuit; WOTS+-in-circuit for HW wallets | More circuit constraints |
| BLS aggregation in consensus | ML-DSA multi-sig certs (big) or proof-aggregated certs | Bandwidth |

### 6.3 Size budget (why aggregation is non-optional)

Per-tx on the wire: proof 50–200 KB + 2 ciphertexts ~2.6 KB + ~128 B of commitments/nullifiers.
At even 100 TPS that is 5–20 MB/s of proof traffic. Therefore the protocol must, from day one:

- **Prune proofs after finality.** A proof's job ends at verification; finality certificates attest
  it happened. Permanent state per tx is ~128 B (nullifiers + commitments) plus ciphertext
  retention policy. Archival nodes need not keep proofs.
- **Aggregate/recursively fold proofs per DAG vertex or checkpoint** (validators verify many tx
  proofs, emit one folded proof; new nodes sync from checkpoint proofs rather than replaying).
  This is the Mina/Tachyon("Ragu") direction and is the second-biggest engineering line item after
  the spend circuit itself.

### 6.4 Scanning costs go up

ML-KEM trial-decapsulation is tens of µs/op: at 10 TPS a phone scans comfortably; at 1,000 TPS
(86M tx/day) per-key scanning is tens of minutes of CPU per day — broken. See §8.

### 6.5 Crypto-agility mechanics

Versioned **pools** with **turnstiles** (Zcash's Sprout→Sapling precedent): migrations reveal only
per-pool aggregate flows and cap the damage of any pool-specific break; version bytes in
addresses, note formats, proof identifiers; a consensus-level registry of allowed
{proof-system, KEM, hash} suites with sunset heights.

---

## 7. Feelessness: spam resistance and incentives

### 7.1 Honest accounting

"Feeless" never means costless; it means costs move:

- **Inflation-funded validation** — holders pay via dilution (emission to validators).
- **User-paid PoW** — users pay in joules and latency.
- **Stake-locked quotas** — users pay opportunity cost of locked capital.
- **External subsidy** — wallets/exchanges/merchants pay (fragile, centralizing).

The design should pick the first three deliberately and say so.

### 7.2 The hidden-balance constraint (the key novelty pressure)

Production feeless anti-spam leans on visible economic weight: Nano buckets transactions by
**account balance**; IOTA's Mana derived from **visible holdings**. Mandatory privacy deletes
these tools. The replacement must prove economic weight *in zero knowledge*:

**Primary: RLN-style anonymous stake quotas.**
A user locks stake into a shielded quota pool. Each epoch, a transaction carries a proof: *"I hold
a quota note of weight ≥ s; this is my k-th transaction this epoch (k ≤ quota(s)),"* with a
**rate nullifier = PRF(quota_key, epoch, k)** — reuse of (epoch, k) is detectable and slashable
(RLN's Shamir-share trick even allows anonymous slashing). All hash-based, PQ-fine, and it reuses
the exact note machinery the chain already has — quota credits *are* notes in a parallel pool.

**Fallback lane: asymmetric per-tx PoW (EquiX-class)** for stakeless users, capped at a small
fraction of capacity, with uniform difficulty (variable difficulty fingerprints senders).
Nano's 2021 incident shows pure PoW loses to botnets/GPUs — hence *fallback*, not primary.

**Bootstrap problem:** new users have no stake → sponsored quota notes (merchants/exchanges/
wallets hand out small quota notes — they're just notes), the PoW lane, and the fact that
**receiving requires no quota at all** (passive in a note model).

### 7.3 Spam's real target is state, not bandwidth

Each transaction permanently adds ~128 B (nullifiers + commitments) that can never be pruned
(nullifiers must be checkable forever; the tree is append-only). At a sustained 1,000 TPS that is
~4 TB/year of unprunable state *with zero marginal cost to a spammer* unless quotas price it.
Quotas must therefore be denominated in **state-weight, not just tx-count**. Research directions
for the long term: nullifier-set sharding by epoch, oblivious-sync services with wallet-held
non-spend proofs (Tachyon's model — wallets prove their own notes unspent, relieving nodes), and
ciphertext retention horizons (prunable after a wallet-sync window, fully prunable if out-of-band
delivery is the norm).

### 7.4 Validator incentives without fees

- DAG-BFT PoS validators paid by **protocol emission**, disinflating to a small tail
  (~0.5–1 %/yr; Monero's tail emission is the social precedent). Delegation for broad
  participation. Optional treasury stream (Zcash dev-fund precedent — note its governance
  friction).
- Security argument is the standard BFT-PoS one (corrupting ⅓ of stake must cost more than the
  attack yields); without fee revenue, *all* security budget is dilution — model it explicitly.
- A useful synergy: with no fee market and encrypted content there is **no MEV**, so validator
  revenue is fully protocol-defined — no hidden-incentive drift toward order manipulation.

### 7.5 Usage-coupled emission ("mint a reward per transaction, decaying with height")

An attractive-sounding refinement: each transaction mints a small reward to the node that
processes it, with the per-tx mint decaying on a schedule — users stay feeless, node operators
get paid in proportion to work, inflation is bounded like a halving schedule.

The mechanics are easy in this design (checkpoint sequence number is the "block height" analogue;
mint amounts are public for supply audit; reward notes are shielded with public amounts). The
economics are the trap:

- **Mint farming.** If including a transaction mints new money, the includer profits from
  *creating* transactions. A validator can stuff the ledger with self-dealing txs (or split the
  mint with colluding users as a kickback) at near-zero marginal cost. The profit condition is
  `mint_per_tx > attacker's marginal cost per tx`; for a validator self-including, that cost is
  only the anti-spam cost (PoW joules / quota opportunity), which the protocol wants to keep low
  for honest users. Either the mint is large enough to fund nodes — and stuffing is profitable —
  or it is below spam cost — and it underfunds nodes. There is no comfortable middle that stays
  stable as hardware and token price move.
- **Endogenous money supply.** Total issuance becomes a function of traffic, i.e.
  attacker-influenceable. Monetary policy should not have an adversarial input.
- **Guaranteed-maximal state growth.** Stuffing converts emission into *permanent* ledger bytes
  (nullifiers + commitments are unprunable) — the worst possible resource to subsidize. This is
  why no major chain mints per-transaction; Bitcoin's subsidy is deliberately per-*block*,
  independent of tx count.

**The fix that keeps the intent:** fix total emission per checkpoint and let transaction
inclusion affect only its *split* between validators:

- `E(h) = E_tail + (E_0 − E_tail) · 2^(−h/H)` — smooth decay by checkpoint height `h` with
  half-life `H`, to a **tail floor, not zero** (a feeless chain has no fee market to take over
  the security budget; decay-to-zero is how it dies).
- Distribute most of `E(h)` (≥ 80 %) by stake × consensus participation.
- Optionally distribute a small capped share (≤ 20 %) as an **inclusion bonus** weighted by the
  quota-backed transactions each validator's committed vertices carried (first-commit
  attribution). Because the total is fixed, stuffing can only redistribute a bounded pool among
  validators while paying real quota costs — it cannot inflate supply, and the junk-traffic
  equilibrium is bounded by the bonus pool size.
- Smooth decay beats step halvings: no revenue cliffs, no validator-exit shocks at the steps.

Note also that "node provider" can only mean *validator* at the protocol level — RPC/wallet
infrastructure is not protocol-visible. Those operators are reached through delegation (run or
back a validator) or treasury grants, not through the emission rule.

Full mechanism draft: [`../specs/emission.md`](../specs/emission.md).

### 7.6 Plan B worth keeping in the back pocket

A **uniform, protocol-fixed, in-circuit burn**: the circuit enforces Σin = Σout + F with constant
F, invisibly (no fee field, no fee market, no fee fingerprinting — every tx still looks identical).
It is not feeless, but it preserves every privacy/uniformity property, adds deflationary pressure
against emission, and gives spam a price denominated in the asset itself. If feeless economics
fail under adversarial testing, this is the minimal retreat.

---

## 8. The scanning problem (mandatory privacy's scaling tax)

With no transparent pool and no address reuse signals, **every wallet must consider every
transaction**. Options, in increasing ambition:

1. **Trial decryption** (status quo): fine at Nano-like real loads (tens of TPS), breaks at
   hundreds-to-thousands of TPS, and light clients leak everything to their servers.
2. **Fuzzy Message Detection** (Penumbra's design): detection keys with tunable false-positive
   rates; cheap, leaks statistical hints — a good middle setting.
3. **Oblivious Message Retrieval / PIR**: cryptographically clean, server does heavy
   (FHE/PIR) work — costs are falling; Tachyon explicitly bets on PIR + PQ key exchange.
4. **Out-of-band note delivery** (Tachyon's other bet): the sender transmits the note directly to
   the recipient (payment channel/URI/messaging); the chain stores only commitments. Deletes
   scanning *and* most ciphertext storage; changes UX (payments need a delivery channel, plus a
   recovery story for lost messages).

Recommended posture: design the chain so ciphertexts are **optional and prunable** (out-of-band
capable from genesis), ship trial-decryption + FMD first, and track OMR/PIR for light clients.

---

## 9. Supply auditability under mandatory privacy

Mandatory privacy must not mean unauditable supply:

- **Mints (emission) and burns have public amounts** — the minted note is shielded, the amount is
  not. Total supply = Σ public mints − Σ public burns, verifiable by anyone.
- **Per-pool turnstiles** on version migrations bound any single pool's undetected-inflation blast
  radius.
- Multiple independent circuit implementations + formal verification of the constraint system
  (counterfeiting bugs are invisible post-hoc — Zcash's 2018 BCTV14 vulnerability is the warning).
- Wallet-level **viewing keys / payment-disclosure proofs** give users opt-in selective disclosure
  (audits, exchanges) without protocol-level transparency.

---

## 10. Risks, ranked

1. **Client-side PQ proving performance** (phones especially). The whole UX hangs on a dedicated
   spend circuit proving in ~a second on mid-range hardware. *Mitigations:* hand-rolled circuit
   (not zkVM), Poseidon2/Monolith arithmetization, benchmark before any other work.
2. **Feeless spam & state-growth economics.** The strongest sustained adversarial pressure;
   Nano 2021 and IOTA's retreat from feelessness are the precedents. *Mitigations:* state-weight
   quotas (RLN), PoW fallback lane, explicit attacker-budget simulations, Plan-B burn (§7.6).
3. **Anchor/finality correctness on the DAG.** A reorged anchor is catastrophic (dead proofs,
   ambiguous nullifier set). *Mitigations:* deterministic-finality DAG-BFT only; the
   anchor-window spec is the first document to write and model-check.
4. **Scanning/light-client privacy at scale** (§8).
5. **Invisible inflation** from circuit/proof-system bugs (§9).
6. **Network-layer deanonymization** (timing, IP). Ledger privacy without transport privacy
   fails against targeted adversaries; mixnet integration is heavy. Uniform tx shape/size helps.
7. **PQ UX regressions:** ~1.5 KB addresses, no cheap diversified addresses, bigger QR codes.
8. **Consensus-cert bandwidth** under ML-DSA (no BLS aggregation).
9. **Ecosystem/regulatory:** mandatory-privacy assets face delisting pressure (Monero
   precedent); plan for DEX-first liquidity and wallet-level selective disclosure.
10. **Team risk:** the union of required specialties (STARK circuits, BFT consensus, PQ crypto,
    P2P anonymity, mechanism design) is the real constraint. Every seam you keep novel is a
    seam you must staff.

---

## 11. Minimum viable prototype

**Phase 0 — specs & adversarial models (4–8 weeks, no code):**
anchor-window + conflict-resolution spec; spam/state-growth economic simulation (attacker budget
vs. quota/PoW parameters); note/tx format with version bytes; threat model document.

**Phase 1 — "shielded payments over a single sequencer" (3–6 months):**
- Rust. Dedicated 2-in/2-out spend circuit in **Plonky3/Stwo or Miden VM**; Poseidon2
  commitments/nullifiers; MMR commitment tree; in-circuit balance + range checks.
- Hybrid **X25519+ML-KEM-768** output ciphertexts (audited libs: libcrux / RustCrypto ml-kem).
- **EquiX** per-tx PoW stub; single-node sequencer that seals checkpoints/anchors; CLI wallet
  that scans, receives, proves, spends.
- **Exit KPIs (the go/no-go data):** prover time (laptop & mid-range phone), proof size, node
  verify throughput/core, tx bytes on wire, wallet scan rate (tx/s/core), spend-after-receive
  latency.

**Phase 2 — real DAG consensus (2–4 months):**
swap sequencer for a **Mysticeti/AlephBFT-class DAG-BFT** (reuse an existing implementation);
anchors at commits; nullifier-conflict handling exercised with adversarial double-spend tests;
4–10 node WAN testnet; measure finality latency vs. anchor-window size.

**Phase 3 — feeless mechanics (2–3 months):**
RLN quota pool over shielded stake (epoch rate-nullifiers, slashing); emission + staking;
per-vertex proof aggregation (recursive folding); proof pruning after finality; spam game-days.

**Buy, don't build:** proof system (Plonky3/Stwo/Miden/RISC Zero), consensus core (Mysticeti or
AlephBFT implementations), ML-KEM/ML-DSA (libcrux, PQClean bindings), hashing (Poseidon2 crates),
networking (libp2p or commonware). **Build:** the spend circuit, the anchor/checkpoint state
machine, the quota mechanism, the wallet.

(Deliberately deferred: programmability/smart contracts, bridges, governance, mixnet transport.)

---

## 12. Research agenda before implementation

1. **PQ-ZK benchmarks** for the candidate spend circuit across Plonky3 / Stwo / Miden / RISC Zero:
   prove time (incl. mobile), proof size, verify time, recursion cost. Lattice-SNARK watchlist
   (LaBRADOR/Greyhound: ~16 KB proofs, linear-time verify — unusable today, promising later).
2. **Anchor-window formal spec** and its interaction with DAG commit rules; checkpoint cadence vs.
   chained-spend latency; model-check safety under equivocation.
3. **Feeless mechanism design:** RLN quota economics with hidden stake; state-weight pricing;
   bootstrap/sponsorship; PoW-lane game theory; simulate Nano-2021-class attacks.
4. **Note discovery at scale:** ML-KEM trial-decryption throughput; FMD false-positive tuning;
   OMR/PIR cost curves; out-of-band delivery protocol + abuse/recovery cases (track Tachyon).
5. **PQ key & address hierarchy:** seed-derived multi-address scheme and its scan-cost trade-off;
   viewing-key granularity (incoming/outgoing/full); WOTS+-in-circuit hardware-wallet flow;
   address encoding size UX.
6. **Value-balance circuit without homomorphic commitments**; multi-asset extension; public
   mint/burn interface; turnstile accounting.
7. **State lifecycle:** proof pruning after finality; ciphertext retention horizons; nullifier-set
   sharding / wallet-held non-spend proofs (Tachyon's oblivious sync) for long-term node relief.
8. **Consensus certificates under ML-DSA:** committee sizes, cert sizes, STARK-aggregated
   signature-validity proofs.
9. **Transport privacy:** Dandelion++ vs. Tor vs. Nym for submission; PQ onion routing maturity.
10. **Upgrade machinery:** versioned pools, turnstiles, suite registry, sunset schedules.

---

## 13. Novelty assessment

**As components: nothing new. As a combination: genuinely unoccupied territory, with real research
content at the seams.**

- The note model is Zerocash (2014). DAG-BFT is Narwhal/Mysticeti/Aleph (2019–2024). Feeless
  anti-spam is Nano/IOTA/RLN. The PQ toolbox is NIST-standardized (ML-KEM/ML-DSA/SLH-DSA) plus
  STARK/FRI. Anyone claiming pillar-level novelty here would be wrong.
- But the four-way conjunction does not exist in production or, to my knowledge, in the
  literature as a worked design. The defensible novel contributions — each plausibly publishable —
  are exactly the seams: **(a)** anchor management for shielded membership proofs on a concurrent
  DAG with deterministic finality; **(b)** anonymous, state-weight-denominated rate limiting that
  replaces balance-visible spam defenses under mandatory privacy; **(c)** a fully PQ shielded
  transaction format (addresses, delivery, spend-auth, balance) with its UX trade-offs worked
  through; **(d)** scan/state scaling for a mandatory-private high-throughput ledger.
- Honest positioning: *"a novel synthesis with four research problems"* — which is what most
  credible "new architecture" L1s actually are. The differentiated claim vs. the field:
  **more private than Monero at the ledger level** (full-pool anonymity set + hidden amounts with
  no decoy statistics — though FCMP++ narrows this gap), **more private than Zcash in practice**
  (no transparent pool to drain the anonymity set), **faster than both** (DAG-BFT finality),
  **feeless unlike all of them**, and **PQ-private from genesis, which none of them are** (the
  retroactive-decryption argument in §6.1 is the sharpest marketing-and-engineering fact in the
  whole design).

---

## 14. Key references

- Zerocash: Ben-Sasson, Chiesa, Garman, Green, Miers, Tromer, Virza — *Zerocash: Decentralized
  Anonymous Payments from Bitcoin*, IEEE S&P 2014.
- Zcash protocol spec + Orchard/Halo 2 documentation; Project Tachyon overview & roadmap
  (tachyon.z.cash; Sean Bowe's *Tachyon: Scaling Zcash with Oblivious Synchronization*).
- Penumbra protocol docs (multi-asset shielded pool, tiered commitment tree, fuzzy message
  detection, flow encryption).
- Mysticeti (Sui), Narwhal & Bullshark, AlephBFT papers; Avalanche (Team Rocket, 2019);
  FastPay (Baudet et al., 2020).
- Rate-Limiting Nullifiers (PSE/Semaphore documentation); Tor's EquiX proof-of-work DoS defense.
- Oblivious Message Retrieval (Liu & Tromer, ePrint 2021/1256); Fuzzy Message Detection
  (Beck, Len, Miers, Green, CCS 2021).
- NIST FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA).
- LaBRADOR (CRYPTO 2023) and Greyhound (CRYPTO 2024) lattice proof systems; zksecurity.xyz
  explainer *Proofs on a Leash*.
- Monero FCMP++ design materials; Nano spam post-mortems (2021); IOTA Rebased (2025) economics.
- *Monero's Decentralized P2P Exchanges: Functionality, Adoption, and Privacy Risks*
  (arXiv:2505.02392) — documents privacy-coin liquidity migrating to P2P/DEX venues under
  regulatory delisting pressure (supports the DEX-first liquidity mitigation in §10, risk 9).
