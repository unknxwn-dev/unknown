# Stablecoin Bank-Integration API — Plan

*Status: proposal. Covers how a five-coin stablecoin network built on this
chain connects to banks, what has to change on-chain, and the design of the
off-chain API gateway that does the connecting. The first concrete `/v1`
contract draft lives in [`stablecoin-bank-api-openapi.yaml`](stablecoin-bank-api-openapi.yaml).*

---

## 1. The mental model: a stablecoin never talks to a bank directly

This is the core concept to internalize before any code is written.

A blockchain (this one included) cannot call a bank. Banks cannot call a
blockchain. The thing that "links" them is an **off-chain service you run**,
usually called an **issuance gateway** (or mint/redeem service). It is an
ordinary backend application with two faces:

```
            fiat side                              chain side
  ┌──────┐  ISO 20022 / Open Banking   ┌─────────────────┐   gRPC/RPC   ┌────────┐
  │ Bank │ ◄─────────────────────────► │ Issuance Gateway│ ◄──────────► │  Node  │
  └──────┘   (REST + webhooks)         │  (your backend) │  mint/burn/  └────────┘
                                       └─────────────────┘  transfer txs
                                               ▲
                                               │  Bank-Integration API (REST)
                                               ▼
                                     partner banks / fintechs / PSPs
```

The invariant the gateway maintains is simple:

> **Every unit of stablecoin in circulation is matched 1:1 by fiat sitting in
> a reserve bank account.**

Concretely:

- **Mint (deposit → coin).** A customer wires $100 to your reserve account.
  The bank notifies the gateway (webhook or statement polling). The gateway
  verifies the funds settled, then submits a **mint transaction** on-chain
  crediting 100 coin-USD to the customer's address.
- **Burn (coin → withdrawal).** A customer sends 100 coin-USD to the
  gateway's redemption address (or calls a redeem endpoint). The gateway
  submits a **burn transaction** destroying the coins, then instructs the
  bank (payment API) to wire $100 out to the customer's registered account.

That's the whole link. Everything else in this document is making that loop
safe, auditable, multi-currency, and consumable by partner banks.

Five coins = five fiat pegs (e.g. USD, EUR, GBP, NGN, JPY — pick yours) =
five reserve accounts (possibly at different banks) and one shared gateway
that tags every operation with an `asset_id`.

---

## 2. What must change on this chain (prerequisites)

The current prototype is a **single-asset**, mandatory-private ledger:
`Note { value, addr_tag, rho, rseed }` has no asset field, `TxV1.mint_value`
mints only the native coin, and emission is protocol-controlled. Three
on-chain work items are prerequisites for any stablecoin:

### 2.1 Multi-asset notes (WP-S1)

- Add `asset_id: [u8; 32]` to `Note` and fold it into the note commitment
  (new domain-separated field in `NOTE_COMMITMENT` hashing, mirroring how
  Zcash ZSA / Orchard added asset bases).
- The spend statement (`check_spend_statement`, C1–C9) gains a constraint:
  **value balance holds per asset** — `Σin + mint = Σout` for each
  `asset_id` independently, with no cross-asset mixing inside the proof.
- Wire format: `TxV1` grows a per-asset public mint/burn slot; wire-size
  uniformity tests (`all_txs_same_size`) must still pass so txs stay
  indistinguishable.
- The five stablecoins are five well-known `asset_id`s registered at genesis
  of the asset registry; the native coin keeps asset_id 0.

### 2.2 Issuer-authorized mint/burn (WP-S2)

Native-coin emission is protocol-minted at checkpoints. Stablecoins are
different: **only the issuer (the gateway's key) may mint or burn them**, in
any amount, because supply must track the bank reserve, not a schedule.

- Introduce an `IssuerKey` per asset_id (registered in the asset registry;
  key rotation supported).
- A stablecoin mint/burn tx carries a signature (ML-DSA + Ed25519 hybrid,
  consistent with the chain's PQ posture) from the issuer key over the
  binding digest. The state machine rejects unsigned issuance.
- Public supply audit extends naturally: `Σ mints − Σ burns` **per asset**
  is public on-chain even though individual balances stay shielded. This
  per-asset circulating supply is exactly the number banks and auditors will
  compare against reserve attestations — it falls out of the existing
  supply-audit machinery for free.

### 2.3 Compliance visibility: viewing keys and disclosure (WP-S3)

Hard truth: **no regulated bank will integrate with a chain where the issuer
itself cannot see stablecoin flows.** Mandatory privacy for users can stay,
but the stablecoin layer needs selective disclosure:

- **Per-account viewing keys** (the wallet's trial-decryption machinery
  already implies an incoming-viewing-key structure — formalize export of
  it): a customer shares their viewing key with the gateway at KYC
  onboarding, so the gateway can see *that customer's* stablecoin history,
  and nothing else.
- **Payment disclosures**: sender-generated proof that "tx X paid amount V
  of asset A to address Y" (decryption of a single note + opening), for
  Travel-Rule style transfers between VASPs.
- Design principle: privacy from *the public*, auditability to *authorized
  parties chosen by the key holder*. Users who never touch the stablecoins
  are unaffected.

Without WP-S3, sections 3–5 are unbuildable in a regulated context. It is
the gating work item.

---

## 3. The Issuance Gateway (new off-chain service)

A new repository/workspace member (suggested: `gateway/`, outside `crates/`
since it's a service, not a protocol crate). Rust (axum/tonic) keeps the
stack uniform, but this component is chain-adjacent, not consensus-critical
— any well-run backend stack works.

### 3.1 Internal components

| Component | Responsibility |
|---|---|
| **Reserve monitor** | Watches the five reserve bank accounts (webhooks where the bank offers them, statement polling — camt.053/052 — where it doesn't). Matches incoming credits to expected deposits via reference codes. |
| **Minter/burner** | Holds the issuer keys (in an HSM / KMS, never on disk). Submits mint txs after settled deposits, burn txs on redemptions. Enforces the 1:1 invariant with a **reconciliation ledger** (double-entry: every on-chain mint has a matching bank credit row). |
| **Payment initiator** | Sends outbound wires for redemptions via the bank's payment API (pain.001 / Open Banking payment initiation / local rails per currency). |
| **Chain client** | Wallet + node RPC: builds shielded txs, scans with the gateway's viewing keys, tracks confirmations/checkpoints. |
| **KYC/AML module** | Onboarding (identity verification via a provider — Sumsub/Persona/Alloy class), sanctions screening on every mint/redeem, transaction-monitoring rules, Travel Rule messaging (IVMS 101) for VASP-to-VASP transfers. |
| **Reconciler** | Continuous three-way check: bank balance == internal ledger == on-chain circulating supply, per asset. Any drift halts issuance for that asset and alarms. |

### 3.2 Ledger discipline

The gateway keeps its own **double-entry ledger** as the source of truth for
in-flight operations (deposit seen but not yet minted; burn confirmed but
wire not yet sent). On-chain supply and bank statements are the two external
checks against it. Never derive state by re-reading the bank statement ad hoc.

---

## 4. The Bank-Integration API (what partners consume)

This is the product surface a partner bank or fintech integrates with. REST
+ JSON, OAuth2 client-credentials (mTLS for high-tier partners), versioned
under `/v1`. The G1/G2 sandbox subset is specified in
[`stablecoin-bank-api-openapi.yaml`](stablecoin-bank-api-openapi.yaml).

### 4.1 Endpoints (v1 surface)

```
# Assets
GET  /v1/assets                        → the five coins: id, currency, peg, status
GET  /v1/assets/{id}/supply            → on-chain circulating supply + last attestation

# Customers (the partner's end-users, KYC'd)
POST /v1/customers                     → create + start KYC
GET  /v1/customers/{id}                → status (pending / approved / blocked)
POST /v1/customers/{id}/accounts       → provision a shielded address + register viewing key

# Minting (fiat in → coin out)
POST /v1/deposits                      → returns reserve-account details + unique reference code
GET  /v1/deposits/{id}                 → detected / settled / minted (+ on-chain tx ref)

# Redemption (coin in → fiat out)
POST /v1/redemptions                   → amount, asset, destination bank account (pre-registered)
GET  /v1/redemptions/{id}              → burn status + payment status

# Transfers (on-chain, between customers of integrated partners)
POST /v1/transfers                     → gateway-mediated shielded transfer w/ Travel Rule payload
GET  /v1/transfers/{id}

# Webhooks (partner registers URLs)
  deposit.settled, mint.confirmed, redemption.burned,
  payout.sent, payout.failed, customer.kyc_updated

# Reporting
GET  /v1/reports/reconciliation?asset=&date=   → daily supply-vs-reserve statement
```

### 4.2 Non-negotiable API mechanics

- **Idempotency keys** on every POST (`Idempotency-Key` header). Banks retry;
  a retried mint request must not mint twice.
- **Amounts as integer minor units + currency code**, never floats.
- **Asynchronous by design**: every money-moving call returns `202` with a
  resource id; completion arrives via webhook (signed, with replay
  protection) and is pollable.
- **Strict state machines** per resource
  (`deposit: expected → detected → settled → minted`), append-only audit log
  of every transition, exportable per partner.
- **Rate limits + per-partner asset allowlists** (a partner licensed for EUR
  only never sees the NGN coin).

### 4.3 Bank-side rails (per currency)

| Peg | Likely rail | Integration mode |
|---|---|---|
| USD | Fedwire/ACH via a BaaS or direct API bank (Column/Cross River class) | REST APIs + webhooks |
| EUR | SEPA SCT/Inst | Open Banking (Berlin Group) or bank host-to-host ISO 20022 |
| GBP | FPS/CHAPS | UK Open Banking |
| Others | Local rails | Usually SFTP + ISO 20022 files (pain.001 out, camt.053 in) |

Design the gateway's bank connector as a **trait per rail**
(`BankConnector: initiate_payment, fetch_statement, verify_settlement`) so
each of the five currencies plugs in a different implementation without
touching mint/burn logic.

---

## 5. Compliance & legal track (runs in parallel, gates launch)

Not code, but on the critical path — banks diligence this before touching
the API:

1. **Licensing** per jurisdiction: e-money/stablecoin issuer regimes (EU
   MiCA EMT, US state MTLs or a national trust charter, UK EMI, etc.).
2. **Reserve management policy**: segregated accounts, high-quality liquid
   assets only, bankruptcy-remoteness.
3. **Monthly third-party attestations** of reserve vs. on-chain supply —
   publish via `GET /v1/assets/{id}/supply`. The per-asset public supply
   audit from WP-S2 is your evidence.
4. **AML program**: KYC tiers, sanctions screening, Travel Rule (the WP-S3
   disclosure mechanism is what makes this technically possible on a
   shielded chain).

---

## 6. Phased roadmap

| Phase | Deliverable | Exit criterion |
|---|---|---|
| **S0 — Spec** | Multi-asset note format, issuer-key scheme, disclosure design written as specs (like `specs/emission.md`) | Specs reviewed; no wire-format unknowns |
| **S1 — Chain support** | WP-S1 + WP-S2 implemented behind the existing frozen interfaces; per-asset supply audit in devnet demo | `cargo test --all` green incl. per-asset balance + unauthorized-mint-rejected tests |
| **S2 — Disclosure** | WP-S3: exportable viewing keys + payment disclosure proofs | Gateway can reconstruct a tagged account's full stablecoin history from viewing key alone |
| **S3 — Gateway core** | Issuance gateway with **one** coin (USD), **one** sandbox bank connector, mint/redeem loop on devnet | Automated e2e: simulated wire-in → mint → transfer → burn → wire-out, reconciler at zero drift |
| **S4 — Partner API** | `/v1` REST surface + webhooks + idempotency + sandbox environment for partners | An external test client completes the full lifecycle without human help |
| **S5 — Five coins** | Remaining four connectors + per-asset config; reconciliation across all five | 30 days of continuous reconciliation, zero drift, on testnet |
| **S6 — Launch** | Licensing + attestation live, first partner bank in production | First real mint against a real reserve account |

Sequencing note: S1/S2 (chain) and S3/S4 (gateway) can proceed in parallel
after S0 — the gateway can develop against the current single-asset devnet
with a stubbed `asset_id`, then rebase on real multi-asset support.

---

## 7. Open questions

1. **Which five pegs?** Determines banking partners, rails, and licensing
   scope — the single biggest external dependency. Decide first.
2. **Issuer decentralization**: single issuer key per asset at launch is
   pragmatic; do we want threshold issuance (t-of-n signers) before mainnet?
3. **Direct redemption vs. partner-only**: do end-users hit the API, or only
   integrated institutions (cleaner regulatory posture)?
4. **Does the stablecoin layer need mandatory privacy at all**, or should
   stablecoin notes be *optionally* transparent to simplify bank comfort
   while the native coin stays fully shielded? This is a product/positioning
   decision with large compliance-effort implications either way.
