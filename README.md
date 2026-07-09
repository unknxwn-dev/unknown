# unknown

Design exploration for a **post-quantum-ready, feeless, mandatory-private shielded DAG L1** — a
cryptocurrency that combines:

- mandatory privacy (no transparent addresses, balances, amounts, or transaction graph)
- a Zerocash-style shielded note model (commitments + nullifiers + zero-knowledge proofs)
- a DAG / BFT-DAG ledger for high throughput and sub-second finality
- no user-visible transaction fees, with protocol-level spam resistance
- crypto-agility toward post-quantum primitives (hash-based proofs, ML-KEM, ML-DSA)

## Status

**Phase 1 + consensus core run.** A shielded-payment pipeline over a single
sequencer, a deterministic BFT-DAG consensus core with adversarial double-spend
tests, and an anti-counterfeiting mutation harness are implemented in Rust under
`crates/` — 52 passing tests, plus a devnet demo and an economics simulator:

```sh
cargo test --all                  # all green (52 tests)
cargo run --bin unknown-devnet    # genesis → private transfer → chained spend
cargo run --bin unknown-sim       # spam / emission / mint-farming analysis
```

See [`docs/implementation-status.md`](docs/implementation-status.md) for the
crate-by-crate map against the engineering plan, and what is intentionally
deferred (the STARK circuit, DAG-BFT consensus, persistence/P2P backends).

## Design documents

Start here:

- [`docs/feasibility-analysis.md`](docs/feasibility-analysis.md) — full architecture feasibility
  analysis: prior art, DAG/shielded-note compatibility, cryptographic stack, post-quantum design
  rules, feeless spam economics, risk ranking, MVP plan, and open research questions.
- [`docs/plan.md`](docs/plan.md) — phased project plan: gates with numeric go/no-go criteria,
  workstreams, KPIs, team shape, risk-to-gate mapping, and immediate next actions.
- [`docs/mainnet-roadmap.md`](docs/mainnet-roadmap.md) — the path from prototype to production
  launch: launch-blocking gaps ranked by risk, nine workstreams with exit criteria, the
  milestone timeline, the go/no-go launch gate, and the next-90-days list.
- [`docs/engineering-plan.md`](docs/engineering-plan.md) — agent-ready work breakdown: which
  repositories provide base code and in what mode (dependency / embed / design-only), pinned
  technical decisions, workspace layout, frozen interface contracts, wire formats, the spend
  circuit statement, 18 work packages with acceptance tests, and milestone→gate mapping.
- [`specs/emission.md`](specs/emission.md) — issuance schedule, reward distribution, and the
  emission governance model (decrease-easy / increase-hard, zero-emission as earned end state).
- [`specs/anchors.md`](specs/anchors.md) — normative anchor spec: how shielded membership proofs
  are anchored on a concurrent deterministic-finality ledger (the design's central seam).
- [`specs/notes.md`](specs/notes.md) — normative note/key/address/ciphertext spec.
- [`specs/threat-model.md`](specs/threat-model.md) — adversaries, defences, and where each is
  enforced (spec + code), with prototype coverage marked.
- [`specs/vectors/core.md`](specs/vectors/core.md) — frozen golden vectors (cross-implementation
  conformance target).
- [`docs/implementation-status.md`](docs/implementation-status.md) — what the `crates/` prototype
  builds today, mapped to engineering-plan work packages.
