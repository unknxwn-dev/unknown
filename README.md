# unknown

Design exploration for a **post-quantum-ready, feeless, mandatory-private shielded DAG L1** — a
cryptocurrency that combines:

- mandatory privacy (no transparent addresses, balances, amounts, or transaction graph)
- a Zerocash-style shielded note model (commitments + nullifiers + zero-knowledge proofs)
- a DAG / BFT-DAG ledger for high throughput and sub-second finality
- no user-visible transaction fees, with protocol-level spam resistance
- crypto-agility toward post-quantum primitives (hash-based proofs, ML-KEM, ML-DSA)

## Status

**Phase 1 prototype runs.** A complete shielded-payment pipeline over a single
sequencer is implemented in Rust under `crates/`, with 44 passing tests and an
end-to-end devnet demo:

```sh
cargo test --all                  # all green
cargo run --bin unknown-devnet    # genesis → private transfer → chained spend
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
- [`docs/engineering-plan.md`](docs/engineering-plan.md) — agent-ready work breakdown: which
  repositories provide base code and in what mode (dependency / embed / design-only), pinned
  technical decisions, workspace layout, frozen interface contracts, wire formats, the spend
  circuit statement, 18 work packages with acceptance tests, and milestone→gate mapping.
- [`specs/emission.md`](specs/emission.md) — issuance schedule, reward distribution, and the
  emission governance model (decrease-easy / increase-hard, zero-emission as earned end state).
- [`docs/implementation-status.md`](docs/implementation-status.md) — what the `crates/` prototype
  builds today, mapped to engineering-plan work packages.
- [`docs/stablecoin-bank-api-plan.md`](docs/stablecoin-bank-api-plan.md) — plan for a five-coin
  stablecoin layer with a bank-integration API: mint/redeem gateway architecture, required
  on-chain changes (multi-asset notes, issuer keys, selective disclosure), API surface, and
  phased roadmap.
