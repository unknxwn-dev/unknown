# Mainnet Readiness Roadmap

*How the `unknown` prototype becomes a production Layer-1: a
post-quantum-ready, feeless, mandatory-private shielded DAG. Continues
[`plan.md`](plan.md) (phases M0–M5 to public testnet) through to launch.
Companion detail lives in [`engineering-plan.md`](engineering-plan.md) (work
packages), [`implementation-status.md`](implementation-status.md) (what's built),
and [`gate-a-findings.md`](gate-a-findings.md) (real proving data).*

---

## 0. What "mainnet-ready" means here (and why the bar is higher)

A mandatory-private chain cannot be graded like a transparent one. Three
properties make launch irreversible in ways Bitcoin/Ethereum launches were not:

1. **Inflation is invisible.** A soundness bug in the spend circuit mints money
   inside the shielded pool with no observable symptom (feasibility §9). There is
   no "someone noticed a weird balance" backstop. Supply integrity must be
   *proven*, not monitored.
2. **Privacy breaks are retroactive and permanent.** Ciphertexts recorded at
   genesis are decryptable forever if the encryption is wrong; a metadata leak in
   the wire format or transport deanonymizes history that can never be re-hidden.
3. **No fee market to lean on.** Feeless means the only defences against spam and
   the only validator security budget are the ones baked into the protocol at
   genesis; there is no emergency "raise fees" lever.

Consequence: mainnet-ready = **soundness, privacy, liveness, and economic
stability each independently audited, each demonstrated under sustained
adversarial load, each with working upgrade + emergency machinery** — before a
single unit of real value exists on the chain.

---

## 1. Honest baseline (where the prototype stands)

Green, tested, and pushed today (19 crates, ~70 tests, CI green):

- **Real:** shielded note model, hybrid PQ note encryption, the spend statement
  C1–C8 + its knockout/anti-inflation harness, the full private-payment lifecycle,
  emission, the feeless dual anti-spam lane (PoW + RLN quota wired end-to-end),
  durable persistence, a deterministic BFT-DAG consensus *model* with the Gate-C
  safety properties, and a real Plonky3 STARK proving benchmark.
- **Stand-ins (NOT production):** the spend prover is a dev tag (not sound, not
  zero-knowledge); consensus is an in-process model (no async networking); there
  is no gRPC/P2P/light-client/transport-privacy layer; economic parameters are
  placeholders.

Everything below is about turning the stand-ins into the real thing and proving
it holds.

---

## 2. Launch-blocking gaps, ranked by what they put at risk

| # | Gap | Risk if shipped without it | Owner workstream |
|---|---|---|---|
| 1 | Real STARK spend circuit (sound + ZK) | **Invisible inflation / theft** | WS-A |
| 2 | Formal verification of the constraint system | Invisible inflation | WS-A |
| 3 | ZK proof binding quota rate-nullifier to a staked note | Spam bypass (unbounded state) | WS-A |
| 4 | Real async BFT consensus + safe finality | Forks → dead proofs, ambiguous nullifier set | WS-B |
| 5 | Transport privacy (network-layer) | Deanonymization despite ledger privacy | WS-E |
| 6 | Economic parameters finalized under adversarial sim | Spam collapse / validator underfunding | WS-F |
| 7 | Independent audits + bug bounty | Any of the above, undetected | WS-G |
| 8 | Node/RPC/light-client + wallet UX + mobile proving | Unusable / centralizing | WS-C, WS-D |
| 9 | Upgrade + emergency machinery (turnstiles, versioning) | Cannot fix a break post-launch | WS-H |
| 10 | Genesis, distribution, monitoring, incident response, legal | Launch chaos / legal exposure | WS-I |

The ordering is deliberate: **1–3 can silently destroy the money supply**, so they
are the deepest and get the most assurance. 4–5 destroy the core value
proposition. The rest are necessary but conventional.

---

## 3. Workstreams

Each lists concrete deliverables and the **exit criterion** that lets it be
called done for mainnet.

### WS-A — Cryptographic core (the critical path)

- **Real spend circuit (WP6b):** a dedicated Poseidon2 AIR enforcing C1–C8
  (membership, ownership, nullifier derivation, range, balance, binding), replacing
  the dev prover behind the frozen `SpendVerifier` interface. Gate-A data says to
  optimize for **proof size** (narrow circuit, size-tuned FRI) as much as speed.
- **Proof aggregation / recursion:** per-checkpoint folding so per-tx proofs are
  pruned after finality and new nodes sync from succinct checkpoint proofs
  (confirmed non-optional by `gate-a-findings.md`).
- **Quota ZK proof (WP16b completion):** prove the rate-nullifier derives from a
  sufficiently-staked quota note *without revealing which* — the unlinkability
  obligation the wire format is already designed around.
- **Mobile proving (WP8):** on-device prove-time on a named mid-range phone.
- **Formal verification:** machine-checked proof that the constraint system admits
  no value-creating witness (e.g., Lean/Coq model of the balance + membership
  relations, or an equivalence check against a reference spec). Dual independent
  circuit implementations cross-checked on shared vectors.
- **Crypto-agility plumbing:** versioned pools + turnstiles wired so a future
  primitive break is survivable (Zcash Sprout→Sapling precedent).

*Exit:* real proofs verify on-chain; phone prove ≤ 2 s and proof ≤ 250 KB
(post-aggregation); knockout + differential + formal checks all pass; two audits
of the circuit closed.

### WS-B — Consensus & networking

- Integrate a production **DAG-BFT** (AlephBFT or Mysticeti class) over the
  existing committed-order contract; the ledger side is done and tested.
- **libp2p** transport: gossip for tx/vertices/checkpoints, request-response for
  batch fetch and checkpoint sync, peer scoring, eclipse resistance.
- Deterministic-finality anchoring wired to real commits; `specs/anchors.md`
  model-checked under equivocation and partition.
- Validator set management, staking, delegation (private delegation per
  Penumbra precedent), slashing execution, and reward distribution on-chain.
- State sync from checkpoint proofs; nullifier-set growth management.

*Exit:* multi-region validator testnet sustains target TPS with p50 finality
≤ 1 s / p99 ≤ 3 s; zero safety violations under a chaos + adversarial harness;
partition-heal and validator-set-change exercised repeatedly.

### WS-C — Node, RPC & light clients

- gRPC/tonic node API per `engineering-plan.md` §3.6 (submit, anchors, compact
  checkpoint stream, cert fetch) — **bulk-streaming only**, no per-note queries.
- Archival vs. pruned node modes; proof pruning after finality.
- Light-client protocol (FMD-based scanning; OMR/PIR track for scale).
- Metrics, structured logs, health/readiness endpoints.

*Exit:* a light wallet syncs and transacts against public infra without leaking
which outputs interest it; pruned nodes run within the volunteer cost budget
(~$20/mo full node, per `specs/emission.md` §7).

### WS-D — Wallet & UX

- Production wallet: HD seed, PQ address encoding, resumable scanning, spend
  orchestration with mobile proving, change management, note consolidation.
- Hardware-wallet path (WOTS+-in-circuit spend auth).
- Viewing keys / payment-disclosure proofs for audits and exchanges.
- Recovery UX, especially if out-of-band note delivery is enabled.

*Exit:* an external UX review signs off on address size, QR flows, recovery, and
proving latency on real devices.

### WS-E — Transport privacy

- Dandelion++ stem/fluff for submission (minimum bar).
- Tor submission support; uniform tx size/timing already enforced at the wire.
- Mixnet (Nym-class) integration scoped — likely post-launch but the threat must
  be documented and the interfaces reserved.

*Exit:* `specs/threat-model.md` §8 downgraded from ○ to at least ◑ with a
deployed defence; a red-team network-analysis exercise finds no trivial
submission-origin correlation.

### WS-F — Economics finalization

- Turn `crates/sim` into the parameter-setting authority: fix `E_0`, half-life,
  `E_tail`, quota `STAKE_PER_SLOT`, PoW difficulty, `EPOCH_LENGTH`, `ANCHOR_WINDOW`
  from measured data.
- Adversarial **spam game-days** at the modeled worst-case budget (Gate D):
  honest-tx p99 finality ≤ 5 s for 72 h; bounded state growth; zero-stake
  first-tx ≤ 60 s.
- Validator-funding stress: model dilution vs. security budget across adoption
  curves; decide β (inclusion bonus) stays 0 at genesis (it does — §10 of the
  emission spec).

*Exit:* a published parameter memo with reproducible sim runs; game-days survived
at agreed thresholds; Plan-B in-circuit burn implemented and shelved (activatable
if feeless economics fail).

### WS-G — Security assurance

- **≥ 2 independent audits** of the circuit; audits of consensus, PQ integration,
  wallet, and networking.
- Continuous fuzzing (every decoder + the stateless entrypoint) and the nightly
  knockout/mutation harness gating release branches.
- Formal methods where they pay (constraint system, anchor state machine).
- Public **bug bounty** with meaningful payouts, running through the incentivized
  testnet and indefinitely after.
- Supply-chain: `cargo-deny` (already in CI), `cargo vet`/`crev`, reproducible
  builds, signed releases.

*Exit:* all audit criticals/highs closed or formally accepted; bounty open with no
unresolved criticals for a defined quiet period before launch.

### WS-H — Governance & upgrade machinery

- Versioned proof systems, address formats, note formats, and a consensus suite
  registry with sunset heights.
- Turnstiles between pool versions (bounds any single break's blast radius).
- On-chain governance for parameter changes; the emission **decrease-easy /
  increase-hard** rule and its emergency constitutional process (`specs/emission.md`
  §7, §10) implemented and rehearsed.
- A practiced pool migration (v0 → v1) on testnet.

*Exit:* a full upgrade + a simulated emergency-emission-increase rehearsed on a
public testnet without incident.

### WS-I — Genesis & launch operations

- Genesis distribution design (decide early — drives legal review): allocation,
  vesting, initial validator set, treasury (if any).
- Monitoring/alerting (supply-audit endpoint watched continuously — the one
  invariant that catches an inflation event), dashboards, on-call rotation.
- Incident response runbook, including a coordinated-halt procedure and the
  emergency-upgrade path.
- Legal/regulatory posture: mandatory-privacy assets face delisting pressure
  (Monero precedent, arXiv:2505.02392) — plan for **DEX-first liquidity** and
  wallet-level selective disclosure. Jurisdiction and entity structure.
- Documentation, validator onboarding guides, and ecosystem/wallet partners.

*Exit:* genesis file finalized and independently reproduced; runbooks rehearsed;
legal sign-off; monitoring proven to fire on a simulated supply anomaly.

---

## 4. Phased timeline (continues plan.md M0–M5)

Indicative; the critical path is WS-A. Assumes the specialist team of
`plan.md` §5, scaled up.

| Milestone | Focus | Duration (indicative) |
|---|---|---|
| **M6 — Sound core** | Real spend circuit + aggregation + quota ZK; dev prover retired | 6–10 mo |
| **M7 — Real network** | Async BFT + libp2p + RPC + state sync; internal multi-region testnet | 4–6 mo (overlaps M6) |
| **M8 — Testnet-1 (internal)** | Full stack integrated; economics sim → parameters; wallet + mobile proving | 3 mo |
| **M9 — Testnet-2 (incentivized public)** | Public validators + users, bug bounty live, transport privacy, spam game-days | 4–6 mo |
| **M10 — Audits + formal** | ≥2 circuit audits, consensus/crypto/wallet audits, formal verification; fix cycles | 4–6 mo (overlaps M9) |
| **M11 — Testnet-3 (mainnet dress rehearsal)** | Frozen candidate; long-running (≥90 days); upgrade + emergency rehearsals; genesis dry-run | 3–4 mo |
| **M12 — Mainnet launch** | Go/no-go gate cleared; genesis; guarded ramp | — |
| **Post-launch** | Mixnet, OMR/PIR light clients, lattice-SNARK migration watch, decentralization ratchet | ongoing |

Realistic elapsed time from today to mainnet: **~2.5–3.5 years**, dominated by
WS-A and the audit/testnet cycles. This is normal for a novel shielded L1 and
should not be compressed by skipping assurance.

---

## 5. Launch go/no-go gate (all must be true)

**Soundness**
- [ ] Real spend circuit live; dev prover fully removed from the build.
- [ ] Knockout + differential (dual-impl) + formal constraint checks pass.
- [ ] ≥2 independent circuit audits closed; no open critical/high.
- [ ] Supply-audit invariant monitored and proven to alert on a simulated anomaly.

**Privacy**
- [ ] Wire format + transport reviewed; no known deanonymization vector.
- [ ] Hybrid PQ encryption audited; harvest-now-decrypt-later closed at genesis.
- [ ] Quota ZK proof enforces unlinkability; no per-staker linkage on the wire.

**Liveness / consensus**
- [ ] Deterministic finality; anchor state machine model-checked.
- [ ] ≥90-day public testnet with no safety incident; chaos/adversarial suite green.
- [ ] Validator-set changes, slashing, partition-heal all exercised on testnet.

**Economics**
- [ ] Parameters fixed from sim + game-day data; Gate-D thresholds met for 72 h.
- [ ] Plan-B in-circuit burn implemented and on the shelf.

**Operations / governance**
- [ ] Upgrade + emergency-emission rehearsed on testnet.
- [ ] Genesis reproduced independently; runbooks + on-call ready; legal sign-off.
- [ ] Bug bounty open, no unresolved criticals for the pre-launch quiet period.

Any unchecked box = no launch. There is no partial launch for a shielded chain.

---

## 6. Risks specific to the launch itself

1. **Circuit soundness is the whole ballgame.** Over-invest here; it is the only
   bug class with no post-hoc detection. Formal verification is not optional.
2. **Proof size / aggregation** could force UX or decentralization compromises if
   it lands worse than hoped — the Gate-A benchmark already flagged this; keep it
   on the critical path, not an afterthought.
3. **Validator bootstrap under emission-only security** — the network is most
   attackable when youngest (`specs/emission.md` §7). Consider a guarded launch
   (known validator set, capped throughput) that decentralizes on a ratchet.
4. **Regulatory delisting** shaping liquidity from day one — DEX-first, selective
   disclosure, and jurisdiction choice must be decided before genesis, not after.
5. **Transport privacy lag** — if the mixnet isn't ready, be explicit that
   network-layer anonymity is partial at launch and set user expectations honestly.

---

## 7. Team & budget shape (beyond plan.md §5)

Scaling the ~7-FTE prototype team toward launch: add a second ZK/circuit
engineer and a formal-methods specialist (the soundness critical path), 1–2 more
distributed-systems engineers (async BFT + networking), a mobile engineer
(proving), a devops/SRE for testnet + monitoring, and part-time
security-audit-management, mechanism-design, legal/regulatory, and
developer-relations. Budget the audits (multiple, circuit-heavy — expensive) and
a funded bug bounty as first-class line items, not afterthoughts.

---

## 8. Immediate next 90 days (start here)

1. **Kick off WS-A:** build the real Poseidon2 spend AIR in Plonky3, targeting the
   size-tuned-FRI configuration the Gate-A benchmark pointed to; wire it behind
   `SpendVerifier` and run it against the existing knockout battery.
2. **Stand up a real 4–7 node async BFT testnet** (WS-B) reusing the tested
   ledger/anchor/consensus-contract code; measure finality on a real WAN.
3. **Turn `crates/sim` into the parameter authority** (WS-F): produce a first
   candidate parameter set and a spam game-day harness.
4. **Engage audit firms early** for scoping (WS-G) so circuit review slots are
   booked against the WS-A timeline.
5. **Decide genesis/distribution and legal posture** (WS-I) — it gates everything
   downstream and has the longest external lead time.

The single highest-leverage action remains the real spend circuit: it retires the
one risk that can silently destroy the chain, and its proof-size behavior shapes
consensus, node cost, and wallet UX downstream.
