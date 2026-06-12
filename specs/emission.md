# Emission Specification (v0 draft)

*Status: draft for discussion. Companion analysis: [`../docs/feasibility-analysis.md`](../docs/feasibility-analysis.md) §7.5.*

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

**Inclusion bonus `I(h)` (≤ 20 %, optional — may launch with β = 0):** divided among validators
pro-rata to the number of **quota-backed** transactions first included in each validator's
committed vertices at height `h`.

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

## 7. Out of scope for the emission rule

- **RPC / wallet-infrastructure operators** are not protocol-visible and cannot be paid by this
  rule. Paths for them: run or back a validator (delegation), or treasury grants if a treasury
  stream is adopted (separate decision; Zcash dev-fund precedent and its governance friction
  noted in the feasibility analysis).
- **Delegator reward splitting** (validator commission) — epoch-level accounting layered on the
  base stream; spec'd with staking.

## 8. Parameters to fix (with the economics simulation)

| Parameter | Meaning | Calibration question |
|---|---|---|
| `E_0` | initial per-checkpoint emission | target year-1 inflation %; validator break-even at N validators |
| `H` | half-life | how fast revenue may shrink before validator exit (model, don't guess) |
| `E_tail` | perpetual floor | minimum security budget vs. long-run dilution tolerance |
| `β` | inclusion-bonus cap | largest share for which simulated stuffing stays unprofitable / immaterial |
| checkpoint cadence | sets `E_0` granularity | from consensus measurements (plan Gate C) |

## 9. Open questions

1. Should `β > 0` at genesis, or introduced later once quota markets have observable prices?
2. Participation measurement: vertices committed vs. attestation completeness — which is harder
   to game at the margin?
3. Interaction with slashing: are emission shares forfeited for the epoch of an offense?
4. Should the tail be revisitable by governance, or constitutionally fixed? (Predictability vs.
   adaptability; Monero's tail emission is fixed-by-norm.)
