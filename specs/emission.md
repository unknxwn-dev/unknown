# Emission Specification (v0 draft)

*Status: draft for discussion. Companion analysis: [`../docs/feasibility-analysis.md`](../docs/feasibility-analysis.md) §7.5.*

## Thesis

**Feeless for users from day one; never unpaid security from day one.**

The protocol launches with a minimal security emission because validator security must exist
before third-party infrastructure incentives exist. The long-term goal is to reduce emission as
the network proves that wallets, merchants, RPC providers, privacy organizations, and other
beneficiaries independently operate reliable infrastructure. Zero emission is permitted as an end
state — but only after measurable validator-independence, geographic-diversity,
capacity-headroom, and attack-resilience thresholds are met. The network must be *capable* of
surviving on Nano-style external incentives without ever *depending* on them at launch.

**Scope note:** emission funds validator security only — it is not the feeless design's binding
constraint. That constraint is anti-spam: spam attacks **permanent private state**, not just
bandwidth, and Nano's balance-bucket prioritization does not port (it requires public balances).
The replacement is native to the shielded system — private quota notes, epoch nullifiers,
anonymous rate limits, state-weight pricing, a capped fallback PoW lane — specified in the
feasibility analysis §7.2–7.3 and the forthcoming anti-spam spec.

## 1. Goals

1. Users pay no transaction fees, ever.
2. Validators ("node providers" at the protocol level) are paid for processing transactions.
3. Issuance decreases over time on a predictable schedule ("height"-keyed), with bounded
   long-run inflation.
4. Total supply remains publicly auditable despite mandatory privacy.
5. The reward rule must not make it profitable to manufacture transactions (no "mint farming"),
   and must not let traffic — an adversarial input — set the money supply.

## 2. Definitions

- **Checkpoint height `h`** — the sequence number of a committed DAG checkpoint (the analogue of
  block height; this chain has no blocks).
- **Epoch** — a fixed number of checkpoints; validator-set and quota changes apply at epoch
  boundaries.
- **Quota-backed transaction** — a tx whose anti-spam proof is an RLN stake-quota proof (as
  opposed to the PoW fallback lane).

## 3. Issuance schedule

Total new issuance at checkpoint `h`:

```
E(h) = E_tail + (E_0 − E_tail) · 2^(−h / H)
```

- `E_0` — initial emission per checkpoint (calibrated so year-1 inflation ≈ target, TBD).
- `H` — half-life in checkpoints (TBD; on the order of 2–4 years of checkpoints).
- `E_tail` — perpetual tail floor (calibrated to ~0.5–1 %/yr at maturity, TBD).

Design choices, deliberately:

- **Smooth exponential decay, not step halvings.** Halvings create validator-revenue cliffs and
  exit shocks; a continuous curve has the same long-run issuance without the discontinuities.
- **Tail floor, not zero.** This chain has no fee market to inherit the security budget when
  issuance ends. Emission decaying to zero in a feeless design is a scheduled shutdown of
  security. The tail is the permanent payment for consensus, bandwidth, and state service.
- **`E(h)` is a pure function of `h`.** Every node computes the same value; issuance is
  *exogenous* — no transaction count, traffic level, or validator behavior can change the total
  amount of money created. (See §5 for why.)

## 4. Distribution rule

`E(h)` is split into two streams:

```
E(h) = B(h) + I(h)        with  I(h) ≤ β · E(h),   β ≤ 0.2  (TBD)
```

**Base stream `B(h)` (≥ 80 %):** divided among the checkpoint's active validators pro-rata to
`stake × participation`, where participation is measured from consensus artifacts already being
produced (vertices/attestations committed in the window). This is the security payment; it does
not depend on transaction content or count.

**Inclusion bonus `I(h)` (≤ 20 %; β = 0 at genesis, activation criteria in §10):** divided among
validators pro-rata to the number of **quota-backed** transactions first included in each
validator's committed vertices at height `h`.

- *Attribution:* a transaction counts once, for the validator whose committed vertex first
  contains it in commit order (deterministic under BFT total order; duplicates ignored).
- *Only quota-backed txs count.* Each counted tx therefore carries a real, protocol-visible
  economic cost to its creator (locked-stake opportunity cost), so manufacturing countable
  traffic is costly by construction.
- *Why a bonus at all:* it routes extra revenue toward validators that actually carry user
  traffic (bandwidth, verification, state work), which is the legitimate kernel of the
  "mint per transaction" idea.

## 5. Why not mint per transaction directly (design rationale)

The naive rule — "each tx mints `m(h)` to its includer, `m(h)` decaying with height" — fails
three ways:

1. **Mint farming.** Including a tx creates money for the includer, so the includer profits from
   creating txs. A validator self-including (or splitting the mint with colluding users) pays
   only the anti-spam cost per tx. The rule is stable only if `m(h) <` the *cheapest* anti-spam
   cost — at which point it underfunds validators; any higher and the rational strategy is to
   saturate the chain. There is no stable middle as hardware costs and token price drift.
2. **Endogenous supply.** Total issuance becomes a function of traffic, i.e. of adversarial
   behavior. Monetary policy must not have an attacker-controlled input.
3. **Subsidized permanent state.** Every farmed tx adds unprunable bytes (nullifiers,
   commitments) forever. Per-tx minting pays attackers to maximize the one resource the protocol
   most needs to conserve. (Bitcoin's subsidy is per-block, independent of tx count, for exactly
   this family of reasons.)

The fixed-total/bounded-bonus rule in §4 preserves the intent — node operators are paid, partly
in proportion to traffic carried, on a decaying schedule — while making stuffing a zero-sum,
quota-cost-bearing redistribution of a small bounded pool rather than a money pump. Worst-case
junk traffic is bounded by `β` and by quota prices; if game-day simulations (plan Gate D) show
even that margin is abused, set `β = 0` and the rule degrades cleanly to pure base emission.

## 6. Reward payment mechanics (privacy + auditability)

- Each validator registers a **reward address** (its shielded address) in the validator registry.
- At checkpoint `h`, the reward descriptor is canonical and computable by every node:
  `[(validator_id, amount_i)]` with `Σ amount_i = E(h)`.
- Rewards are minted as **shielded notes with public amounts** (shielded-coinbase pattern): the
  note commitment enters the tree like any other; the amount and recipient-validator are public
  in the checkpoint, because issuance must be auditable.
- Once a reward note is *spent onward*, it re-enters the uniform shielded anonymity set like any
  other note.
- **Supply audit invariant:** total supply at height `h` = `Σ_{k ≤ h} E(k)` − Σ public burns.
  Anyone can verify it from headers alone.

## 7. Alternative model considered: zero emission, third-party incentives only (Nano model)

The fully feeless *and* rewardless alternative: no issuance to anyone; nodes and validators are
run by parties whose incentive is the network's existence — merchants and payment processors who
want free private payments, wallet vendors who need infrastructure for their users, privacy
organizations, and individuals. Nano has operated this way since 2015 and is the existence proof.
Bitcoin and Monero *full nodes* (non-mining) already work this way everywhere.

**The useful distinction: full nodes vs. consensus validators.** Volunteer-run full nodes are a
solved problem and a design *requirement* regardless of emission policy (see cost engineering
below). The contested question is only whether the 2f+1 BFT **validators** — who must lock keys,
stay online, and carry the safety of finality — can be volunteer-run.

**Why it is more fragile for this chain than for Nano:**

1. **Bootstrapping inversion.** Third-party incentives scale with adoption, but security is
   needed *before* adoption — at genesis there are no merchants, processors, or wallet vendors
   with skin in the game yet. Nano bootstrapped in a 2015-era environment with trivial node
   costs; that path is not reproducible for a PQ-shielded BFT chain in 2026.
2. **Higher structural costs.** Verifying 50–200 KB STARK proofs, storing ML-KEM ciphertexts,
   and running ML-DSA-signed BFT is 10–100× Nano's per-tx cost. Volunteer models work when
   costs are trivial; if zero-emission is ever the goal, "node cheapness" becomes a protocol
   KPI, not an optimization (see below).
3. **The most reliable third-party operator class is structurally absent.** In Nano's model,
   exchanges are anchor representatives. Mandatory-privacy assets face exchange delisting
   pressure (Monero precedent) — the strongest pillar of the third-party model is exactly the
   party least likely to participate here.
4. **The adversary model is wrong for costless security.** A mandatory-privacy chain invites
   state-level adversaries who are indifferent to token price. Nano's security argument
   ("an attacker with that much weight destroys the value of their own holdings") is an
   economic-rationality argument; it has no force against sabotage- or censorship-motivated
   attackers. Bonded, slashed, *paid* validators raise the capital cost of acquiring attack
   weight; costless delegated weight (no locking, no slashing, no yield) is cheapest to capture
   precisely for the adversaries this chain should worry about most.
5. **Capacity under attack.** Unpaid infrastructure is provisioned at minimum viable capacity
   and upgraded slowly — Nano's 2021 spam incident degraded the network for weeks partly for
   this reason. A revenue stream is also a crisis-response lever.

**Mandatory-privacy-specific wrinkles** (apply to any delegated-weight scheme here, paid or not):
Nano-style voting weight is *public balance delegation* — a privacy leak this chain cannot have.
Delegation must be private: shielded delegation notes whose per-validator *aggregate* weight is
public while individual delegations stay hidden (Penumbra's private-staking design is the
precedent), with epoch-scoped delegation nullifiers preventing the same hidden value from being
delegated twice. This machinery is needed for §4's base stream anyway; it is emission-independent.

**What zero-emission buys:** genuinely fixed supply (strong monetary story), zero dilution, no
"who gets the emission" governance surface, simpler spec.

**Decision: treat the Nano model as a *destination*, not a starting point.** Core design
principle: *Nano-style zero-reward infrastructure is a destination state, not a genesis security
model.*

```
Phase 1: bootstrap security with protocol emission (genesis schedule E(h))
Phase 2: reduce emission as adoption-funded infrastructure demonstrably grows
Phase 3: optional zero-emission end state, once validator independence is proven
```

- Genesis with the small decaying-to-tail emission of §3 — security must be bought while the
  ecosystem that could volunteer it does not yet exist.
- Engineer node costs to volunteer levels as a protocol KPI from day one: full node on a
  ~$20/month VPS, validator on a ~$300/month server at design-load TPS. This requires the
  already-planned proof pruning after finality, per-checkpoint proof aggregation, and
  prunable/out-of-band ciphertexts (at modest real-world load, ~tens of TPS, permanent state is
  ~100 GB/year — volunteer territory *only if* ciphertext pruning is real).
- **Governance rule — decrease-easy, increase-hard.** Under normal governance, emission
  parameters can only decrease. An emergency increase requires a separate constitutional
  process: a long activation delay, a stake supermajority, a published public security report
  justifying the increase, an automatic sunset clause (the increase reverts unless re-approved),
  and a hard cap — **the genesis schedule `E(h)` remains an absolute ceiling forever**, so the
  maximum-possible-supply curve is known from genesis regardless of any emergency. This keeps
  monetary credibility (max supply fixed at genesis) without the self-imposed death of a network
  that gets attacked before its volunteer ecosystem matures.
- Phase 3 (tail → 0) is reachable only through the measurable thresholds in §10 — it is a
  graduation the network earns, not a promise it starts with.

## 8. Out of scope for the emission rule

- **RPC / wallet-infrastructure operators** are not protocol-visible and cannot be paid by this
  rule. Paths for them: run or back a validator (delegation), or treasury grants if a treasury
  stream is adopted (separate decision; Zcash dev-fund precedent and its governance friction
  noted in the feasibility analysis).
- **Delegator reward splitting** (validator commission) — epoch-level accounting layered on the
  base stream; spec'd with staking.

## 9. Parameters to fix (with the economics simulation)

| Parameter | Meaning | Calibration question |
|---|---|---|
| `E_0` | initial per-checkpoint emission | target year-1 inflation %; validator break-even at N validators |
| `H` | half-life | how fast revenue may shrink before validator exit (model, don't guess) |
| `E_tail` | perpetual floor | minimum security budget vs. long-run dilution tolerance |
| `β` | inclusion-bonus cap | largest share for which simulated stuffing stays unprofitable / immaterial |
| checkpoint cadence | sets `E_0` granularity | from consensus measurements (plan Gate C) |

## 10. Decisions and open questions

**Resolved — inclusion bonus at genesis: `β = 0`.** Launch with pure base emission; activate the
bonus by parameter change only when all of the following hold:

- (a) quota markets have enough observed price history to calibrate the stuffing-profitability
  bound (the safety condition `bonus share obtainable < quota cost paid` is uncheckable before
  quota prices exist);
- (b) game-days replaying real traffic show stuffing unprofitable at the proposed `β` with a
  comfortable (≥ 5×) margin;
- (c) activation requires no circuit or note-format change (a design constraint on the
  implementation: the bonus is checkpoint-level accounting only).

Rationale: a young network is most stuffable exactly when it is least defended and its token
price is most volatile; early validators don't need usage-coupling (`E(h)` is at its maximum and
real traffic is minimal, so the bonus would differentiate almost nothing while maximizing the
incentive to fake traffic); and the asymmetry favors starting off — adding a reward stream later
is an upgrade, removing one later is a fight with whoever profits from it.

**Resolved — emission governance: decrease-easy, increase-hard** (see §7). The genesis schedule
`E(h)` is an absolute ceiling that can never be raised. Under normal governance, parameters may
only decrease, and only when third-party incentive coverage is demonstrated at each step.
Emergency restoration (back up toward, never above, the genesis ceiling) requires the
constitutional process of §7: long delay, stake supermajority, public security report, automatic
sunset, hard cap. Phase-3 graduation (tail → 0) requires the network to have met **measurable
thresholds** across four categories before the step is even votable:

- **validator independence** — e.g., no single operator, organization, or hosting provider above
  a fixed share of voting weight; multiple independent client implementations in use;
- **geographic / jurisdictional diversity** — validator distribution across regions and legal
  regimes above defined minimums;
- **capacity headroom** — demonstrated sustained operation at a multiple of observed peak load
  in public load tests, funded entirely by the then-current (reduced) emission;
- **attack resilience** — a public game-day record showing spam and partition scenarios survived
  at the reduced emission level.

Open:

1. Participation measurement: vertices committed vs. attestation completeness — which is harder
   to game at the margin?
2. Interaction with slashing: are emission shares forfeited for the epoch of an offense?
3. Turn the four threshold categories above into numeric values (weights, region counts, load
   multiples, game-day pass criteria) with the economics simulation — thresholds must be fixed
   *before* any reduction step, not negotiated during one.
4. Emergency-process parameters: activation delay length, supermajority fraction, sunset
   duration — and who may convene it (validator quorum? token-holder petition?).
