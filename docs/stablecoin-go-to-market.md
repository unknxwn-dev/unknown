# Stablecoin Network — Testnet Readiness, Bank Pitch & Business Model

*Status: strategy. Companion to [`stablecoin-bank-api-plan.md`](stablecoin-bank-api-plan.md)
and the draft [`/v1` OpenAPI contract](stablecoin-bank-api-openapi.yaml).
Answers three questions: what "testnet ready" actually means here, what to put in
front of a bank to show how easy moving money is, and how the business makes money
if "it's just an API that moves money."*

---

## 1. The one distinction that decides everything: two different "testnets"

Before any roadmap, separate two things that are constantly conflated. Pitching the
wrong one to a bank kills the deal.

**Testnet A — the L1's own public testnet.** This is Gate E in
[`plan.md`](plan.md): real STARK prover, DAG-BFT consensus, persistence, P2P,
two independent circuit audits, a 30-day incentivized public testnet. That is
**~18–20 months with a ~7-FTE team**, and the current `crates/` prototype is at
Phase 1 of it — single sequencer, in-memory, and an *explicitly insecure dev prover*
(`prover-dev` says so in its own module docs). This track is real but far, and no
bank pitch should depend on it being finished.

**Testnet B — a bank-facing sandbox that moves test money.** This is what you
actually need to pitch. A partner gets a sandbox key and moves test money end to
end — deposit → mint → transfer → redeem → payout — in an afternoon, against a
*simulated* bank and a *labeled-insecure* ledger. **This is achievable in weeks,
not months, and it is decoupled from L1 maturity.**

> The strategic error to avoid: believing you must finish the cryptographic L1
> before you can show a bank anything. You must not. Banks evaluating you judge the
> **API ergonomics, the reconciliation/backing proof, and the compliance story** —
> not your consensus internals. Build Testnet B now; let Testnet A mature underneath it.

### 1.1 A decision you should make consciously

Because the L1 is years from production, there are two ways to sequence the product:

- **Ride your own chain from day one.** Sandbox and later mainnet both run on the
  bespoke L1. Coherent story ("our chain"), but go-to-market is chained to the
  hardest technology and its audit timeline.
- **Launch the product on a proven settlement layer first, migrate to your L1 at its
  mainnet.** The stablecoin + API + compliance stack is chain-agnostic (§3 of the
  API plan makes the bank connector and the chain client separate components). You
  can ship real money movement sooner on a boring, audited base and swap the
  settlement layer later behind the same API.

Recommendation: **decouple.** Build the gateway and API against an abstract
`Ledger` interface. Point it at the current devnet for the sandbox demo, keep the
option to point it at an established chain for the first revenue, and treat "runs on
our own L1" as the destination, not the entry ticket. This is a decision to make
explicitly, not by default — see §7.

---

## 2. What to build for the pitch-ready sandbox (Testnet B)

Goal: a partner self-serves a sandbox and completes the full money-movement lifecycle
without talking to a human. Everything here rides on the current single-sequencer
devnet (or a stub ledger) behind the `Ledger` interface — **no real fiat, no real
KYC, clearly labeled sandbox.**

| Component | What it does in the sandbox | Effort |
|---|---|---|
| **Gateway core** | The mint/redeem/reconcile loop from the API plan §3, wired to the devnet. Holds a sandbox issuer key. | M |
| **Simulated bank connector** | Implements the `BankConnector` trait with instant, deterministic "settlement" and a test-money faucet. One real rail comes later. | S |
| **`/v1` API subset** | `customers`, `deposits`, `redemptions`, `transfers`, `assets/{id}/supply`, webhooks. Idempotency keys, `202`+webhook async pattern, signed webhooks. | M |
| **Reconciliation dashboard** | Live per-coin view: reserve balance == internal ledger == on-chain circulating supply. Zero-drift is the trust artifact. | M |
| **Sandbox self-serve + docs** | Hosted OpenAPI docs, a Postman/curl "quickstart," instant sandbox keys, webhook tester. | M |
| **Compliance stubs** | KYC states (`pending/approved/blocked`) and a Travel-Rule payload field wired but mocked — enough to *show* the model. Real providers come later. | S |

Deliberately **not** in the sandbox: the real STARK prover, real bank rails, real
KYC/sanctions vendors, multi-region consensus. Each is labeled as a production
prerequisite so nobody mistakes the demo for a live system.

### 2.1 The one honest boundary you must never cross in a pitch

The current prover is insecure by design. The sandbox is a **functional and UX
demo**, not a security demo. Say so plainly. The moment a slide implies the demo is
production-secure, a competent bank's diligence will catch the `prover-dev` module
docs and you lose all credibility. The correct framing: *"the money-movement
experience and compliance model are real and you can integrate against them today;
the settlement layer underneath is on the audited-mainnet track described in
`plan.md`."*

---

## 3. The pitch: showing a bank/customer how easy it is to move money

Banks and fintech partners diligence five things. The demo should nail the first
three; the last two are the parallel legal track (§5 of the API plan).

1. **Backing & reconciliation** — can I prove 1:1 at any instant? → the dashboard.
2. **Compliance visibility** — can I see the flows I'm legally required to see? → the
   disclosure model (this is the gating technical dependency, see §3.2).
3. **Integration effort** — days, not months? → the "three calls" quickstart.
4. **Regulatory posture** — licensed? attested? → legal track.
5. **Redemption guarantee** — can my customer always get fiat back? → reserve policy.

### 3.1 The "three calls to move money" demo

The whole pitch is that a partner integrates in an afternoon. Make that literal — the
end-to-end path is a short, readable sequence:

```
# 1. Onboard a customer and provision a shielded account
POST /v1/customers            → { id, kyc: "approved" (sandbox) }
POST /v1/customers/{id}/accounts → { account_id, address }

# 2. Move fiat in → coin appears (mint)
POST /v1/deposits { customer, asset: "coinUSD", amount: 10000 }
     → reserve details + reference code
# (sandbox faucet "settles" the wire; webhook fires)
← webhook deposit.settled → mint.confirmed  { onchain_tx }

# 3. Move value, cross-currency, then cash out (transfer + redeem)
POST /v1/transfers  { from, to, asset: "coinUSD", amount: 5000 }
POST /v1/redemptions{ customer, asset: "coinEUR", amount, bank_account }
     → burn + payout   ← webhook payout.sent
```

Three logical steps, integer minor units, everything async-with-webhooks. A partner's
engineer runs this from the Postman collection before the sales call ends. That *is*
the product's differentiation versus correspondent banking, where the same flow is
days of SWIFT messages and reconciliation.

### 3.2 The compliance gate — do not skip this

The L1 is **mandatory-private**. No regulated bank will integrate with rails where the
issuer cannot see stablecoin flows. The selective-disclosure work (WP-S3 in the API
plan: exportable per-account viewing keys + payment-disclosure proofs + Travel-Rule
IVMS-101 messaging) is therefore **the single gating technical dependency for the
whole bank story.** In the sandbox it can be stubbed to *show* the model, but it must
be genuinely built before any real integration. Privacy-from-the-public,
auditability-to-authorized-parties is the line to hold — and it must be demonstrable,
not just asserted, in diligence.

---

## 4. Mapping to the real testnet (Testnet A)

The stablecoin-specific work packages from the API plan slot onto the existing gates
in `plan.md` — they are not a separate project:

| Stablecoin WP | Rides on gate | Why there |
|---|---|---|
| **WP-S1** multi-asset notes (`asset_id`, per-asset balance in the circuit) | Phase 1 / Gate B | It's a change to the note + spend statement, which Gate B already exercises end to end. |
| **WP-S2** issuer-authorized mint/burn + per-asset supply audit | Phase 3 / Gate D | Emission/supply-audit machinery lives here; issuer keys extend it. |
| **WP-S3** viewing keys + disclosure proofs | Phase 4 / Gate E | Disclosure/light-wallet keys are already Phase-4 scope; formalize export. |
| Gateway + `/v1` API + connectors | parallel, off-chain | Not consensus-critical; develops against the sandbox, rebases on real multi-asset support. |

So the sequence is: **sandbox now (weeks) → real disclosure + multi-asset on the L1's
own gate timeline (months) → production issuance once the L1 hits an audited mainnet
(or on a proven chain sooner, per the §1.1 decision).**

---

## 5. How the business makes money

This is the crux, and the intuition "it's just an API that moves money, so where's
the revenue?" has a clean answer: **you don't primarily make money on the money
moving — you make it on the money sitting still, and on the spread when it crosses
currencies.** Five engines, in rough order of how much they matter at scale.

### Engine 1 — Reserve float (the big one, passive)

Every coin in circulation is backed 1:1 by fiat you hold. You hold that fiat in
short-dated government securities / insured deposits and **keep the yield.** The
customer's balance is your working capital.

- Mechanic: $100 in → mint 100 coinUSD → the $100 reserve earns ~4–5% → you keep it.
- Scale: **$100M average circulating supply × ~4% net ≈ $4M/yr** at near-zero
  marginal cost. $1B float ≈ $40M/yr. This is essentially how Circle and Tether earn
  the overwhelming majority of their revenue.
- Why it answers your question directly: this scales with **balances held**, not
  transactions. A "feeless" chain and a free API are *fine* — the float is the engine.
- Caveats to design around: yield-sharing rules differ by regime (e.g. EU MiCA
  restricts paying interest to holders), and yield falls when rates fall — so don't
  make float your *only* engine.

### Engine 2 — Cross-currency FX spread (the differentiated one, active)

This is *why five coins instead of one.* With five pegged currencies you are a
settlement/FX layer. Every cross-currency movement (coinUSD → coinEUR) crosses a
spread you set — say **10–50 bps, versus the 100–300 bps** banks charge on retail FX
and the multi-day cost of correspondent banking.

- Scale: **$500M/yr cross-currency volume × 25 bps ≈ $1.25M/yr.**
- It doubles as the headline pitch: *"move money cross-border in seconds at 20 bps,
  not three days at 3%."* The revenue engine and the sales story are the same fact.

### Engine 3 — Mint/redeem & API transaction fees (B2B pricing)

Standard SaaS-style monetization on the API: a small bps or flat fee on fiat
on/off-ramp, per-transaction or tiered-volume API pricing, and a monthly platform
minimum. Often **waived for anchor partners** specifically to grow the float in
Engine 1 — you give away the movement to capture the balances.

### Engine 4 — Banking-as-a-Service / white-label licensing (the moat)

License the gateway + API + compliance stack to banks and fintechs so they can issue
their *own* branded coin on your rails. Platform fee + per-transaction + a share of
*their* float. Highest-margin and most defensible line: you become **infrastructure**
rather than an issuer competing with your own customers. This is the line that turns a
product into a platform.

### Engine 5 — Premium / enterprise

SLAs, dedicated redemption liquidity, advanced compliance and reporting, priority
support, custom rails. Standard enterprise upsell on top of the above.

### The summary sentence for the pitch

> **Money in motion (Engines 2–3) funds operations; money at rest (Engine 1) is where
> profit compounds; licensing the rails (Engine 4) is the moat.** The API being simple
> is a *feature* for adoption — the revenue lives in the reserve and the FX layer
> underneath it, not in the complexity of the call.

---

## 6. Sequenced roadmap

| Phase | Deliverable | Exit criterion |
|---|---|---|
| **G0 — Decide** | §1.1 chain decision; pick the 5 pegs; pick sandbox rail to simulate | Written decision; no open "which chain / which currencies" |
| **G1 — Sandbox core** | Gateway + simulated bank + `/v1` subset on the devnet, one coin | Automated e2e: faucet-in → mint → transfer → burn → payout, reconciler at zero drift |
| **G2 — Pitch surface** | Dashboard + hosted docs + Postman quickstart + self-serve sandbox keys | An external engineer completes the three-call flow unaided |
| **G3 — Five coins + FX** | All five sandbox coins; cross-currency transfer with a quoted spread | Cross-currency demo shows the spread; per-coin reconciliation holds |
| **G4 — Real compliance** | Real KYC/sanctions vendor + Travel-Rule messaging + disclosure (WP-S3) built for real | Gateway reconstructs a tagged account's history from its viewing key alone |
| **G5 — One real rail** | One production bank connector (e.g. USD) + licensing in progress | First real mint against a real reserve account, limited pilot |
| **G6 — Real L1 / mainnet** | Migrate settlement to the audited L1 (or chosen base) per §1.1 | Production issuance on the audited settlement layer |

G0–G3 are the **weeks-to-a-few-months** pitch track. G4–G6 are the
**regulated-production** track and run against the L1's Gate D/E timeline in `plan.md`.

---

## 7. Decisions to make now

1. **Own chain vs. proven base first (§1.1).** The biggest sequencing decision.
   Recommendation: decouple — build against an abstract `Ledger`, demo on the devnet,
   keep the option to launch first revenue on a proven chain.
2. **Which five pegs.** Determines banking partners, rails, and licensing scope. Decide
   before G1 — it's the largest external dependency.
3. **Direct-to-consumer vs. partner-only.** Do end-users hit the API, or only licensed
   institutions? Partner-only is the cleaner regulatory posture and a faster pitch.
4. **Where the revenue emphasis sits at launch.** Float-first (grow balances, give away
   movement) vs. fee-first (charge per transaction)? This shapes pricing and the pitch.
5. **Does the stablecoin layer need mandatory privacy at all?** Optionally-transparent
   stablecoin notes would dramatically simplify the bank-comfort and compliance effort
   while the native coin stays fully shielded. Large positioning decision, worth
   deciding before WP-S1 freezes the note format.
