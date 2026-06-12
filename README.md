# unknown

Design exploration for a **post-quantum-ready, feeless, mandatory-private shielded DAG L1** — a
cryptocurrency that combines:

- mandatory privacy (no transparent addresses, balances, amounts, or transaction graph)
- a Zerocash-style shielded note model (commitments + nullifiers + zero-knowledge proofs)
- a DAG / BFT-DAG ledger for high throughput and sub-second finality
- no user-visible transaction fees, with protocol-level spam resistance
- crypto-agility toward post-quantum primitives (hash-based proofs, ML-KEM, ML-DSA)

## Status

Pre-implementation research. Start here:

- [`docs/feasibility-analysis.md`](docs/feasibility-analysis.md) — full architecture feasibility
  analysis: prior art, DAG/shielded-note compatibility, cryptographic stack, post-quantum design
  rules, feeless spam economics, risk ranking, MVP plan, and open research questions.
- [`docs/plan.md`](docs/plan.md) — phased project plan: gates with numeric go/no-go criteria,
  workstreams, KPIs, team shape, risk-to-gate mapping, and immediate next actions.
