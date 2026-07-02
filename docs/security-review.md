# Security review — shielded-payment prototype

*Reviewed at PR #1 head (`d37b4f7`, tx wire version 2). Scope: the Rust
prototype in `crates/`, focused on the transaction-authentication path
(`tx`, `circuit-spend`, `prover-dev`, `state`). The proof system itself
(Plonky3 FRI soundness) and the PQ-KEM construction are out of scope; this
review covers how the pipeline *uses* them.*

The prototype is internally consistent and well-tested (124 passing tests,
clippy clean). This review records one real malleability finding introduced
by the dev-prover → STARK swap, plus lower-severity observations and a few
properties that are correctly enforced.

## F-1 (Medium) — the STARK verifier does not bind the ciphertexts or anchor height

> **Status: FIXED** (tx wire version 3). The binding digest is now carried in
> the spend circuit's public values as 16 × 16-bit limbs
> (`circuit_spend::spend::SpendPublic::binding`). No AIR constraint reads
> them; `p3_uni_stark` absorbs all public values into the Fiat–Shamir
> challenger before sampling challenges, so a proof generated for one binding
> digest fails verification under any other. `StarkSpendVerifier::verify` now
> feeds `pi.binding_digest` into the public vector, and the wallet proves over
> the tx body's real digest. Regression tests:
> `wallet::tests::ciphertext_replacement_is_rejected` (mutates `enc_outputs`
> and `anchor.height`, re-solves PoW, asserts rejection),
> `tall_spend::tests::tampered_binding_digest_is_rejected`, and
> `verifier::tests::tampered_binding_digest_is_rejected`. This was a consensus
> break: `TX_VERSION` bumped 2→3 and the golden vectors regenerated
> (`specs/vectors/consensus-v3.json`). The analysis below is kept as the
> record of the vulnerable v2 behaviour.

**Where:** `crates/circuit-spend/src/verifier.rs` (`StarkSpendVerifier::verify`),
against `crates/tx/src/lib.rs` (`TxV1::binding_digest`, `to_public_inputs`,
`validate_stateless`).

**What.** A `TxV1` authenticates its fields through two channels:

- the **proof**, whose public inputs the verifier reconstructs from the tx, and
- the **proof-of-work**, which is solved over `TxV1::binding_digest()`.

`binding_digest()` covers `anchor.height`, `anchor.root`, the nullifiers, the
output commitments, **and the encrypted outputs** (`enc_outputs`). The dev
prover bound all of this: `DevVerifier` recomputes its tag over
`SpendPublicInputs::encode()`, which includes `binding_digest`, `anchor.height`
and `mint_value` (`crates/prover-dev/src/lib.rs`, `dev_tag`; `crates/interfaces/src/lib.rs`,
`SpendPublicInputs::encode`).

The real `StarkSpendVerifier` that replaced it reconstructs only

```
root       = pi.anchor.root
nullifiers = pi.nullifiers
out_cms    = pi.commitments
mint       = pi.mint_value
```

and verifies the STARK over exactly those (`SpendPublic` in
`circuit-spend/src/spend.rs`). It never reads `pi.binding_digest` or
`pi.anchor.height`. So the swap silently **dropped `enc_outputs` and
`anchor.height` from the proof-authenticated set**; they are now bound *only*
by the PoW.

The doc comment on `TxV1::binding_digest` still asserts the opposite ("the
proof's public inputs contain it, so any mutation of a bound field invalidates
both"). That invariant no longer holds and is corrected in this change.

**Impact.** An attacker who observes an in-flight transaction can replace its
`enc_outputs` with arbitrary bytes, re-solve the PoW at the current difficulty,
and broadcast the variant. The nullifiers, commitments and proof are unchanged,
so it still verifies and still spends the same inputs and creates the same
output commitments — but the recipient receives undecryptable ciphertext. The
note's value lands at a valid commitment the recipient cannot open (they never
learn `rho`/`rseed`/`value`), so it is unspendable by them until the *sender*
retransmits the openings out of band. This is a griefing / censorship
malleability vector, not theft or inflation: the value is not stolen, but
delivery is broken and the transaction is malleable (its wire bytes differ
while its effect is unchanged, which also complicates tx-id tracking).

The cost is one PoW grind at the network difficulty. In the devnet and test
configuration `difficulty_bits = 0` (`state::Ledger::genesis`, all callers),
so the PoW binding is vacuous and the attack is free.

**Fix (implemented — see status above).** Bind `binding_digest` into the
proof as a public value. Two designs were considered: (a) absorb
`enc_outputs` into the circuit and constrain their hash — sound but heavy
(~80 additional Poseidon2 rows, and the digest would have to move off BLAKE3);
(b) carry the digest as *unconstrained* public values and rely on Fiat–Shamir
transcript binding — the challenger observes the public values before any
challenge is sampled, so the proof is cryptographically bound to them exactly
as it is to the constrained ones. (b) was implemented: it costs nothing in
trace size and matches how the constrained public inputs are already
authenticated (their binding to the *witness* is the constraints' job; their
binding to the *proof* is the transcript's). Note that with (b) the digest
stays BLAKE3 and out-of-circuit, which is fine because nothing about it needs
to be proven — only committed to.

## F-2 (Low) — dummy inputs share the spender key and their nullifiers enter the global set

**Where:** `circuit-spend/src/tall_spend.rs` (nullifier binding `Q_NF0/Q_NF1`
is ungated by `dummy`), `state/src/lib.rs` (`apply_checkpoint` inserts every
`tx.nullifiers`).

A dummy input still produces a bound nullifier `nf = H(nk ‖ rho)` derived from
the *real* spender's `nk` (C3 forces `addr_tag = Poseidon2(nk)` and `nk` is
constant across the trace). The state machine inserts both nullifiers into the
committed set unconditionally. This is safe **only** as long as a wallet never
reuses a dummy `rho` that later collides with a real note's `rho` for the same
key: a collision would make the dummy's nullifier pre-consume the real note's,
silently blocking a future genuine spend. Real-note `rho` is derived
(`rho_transfer`) while dummy `rho` is wallet-chosen, so honest wallets are fine
at ~2⁻¹²⁸, but the invariant "dummy `rho` is sampled uniformly and never
derived from `rho_transfer`" is load-bearing and should be stated where dummies
are constructed, with a test. (For comparison, Zcash Orchard gives dummy notes
a *random spending key* precisely so a dummy nullifier cannot be constrained to
the real key's domain.)

## F-3 (Informational) — the dev prover is intentionally unsound

`prover-dev` is a tag over public inputs, not a proof; it is loudly documented
as INSECURE/DEV-ONLY and exists to exercise the pipeline. Flagged only so the
release checklist ensures no build path can select `DevVerifier` in a
non-test binary. `check_spend_statement` (the C1–C9 executable spec) is the
permanent, load-bearing part and should remain the oracle the STARK is
differentially tested against.

## Correctly enforced (verified, no action)

- **Proof-bucket padding is canonical.** Both verifiers deserialize the real
  proof and require the remaining bucket bytes to be exactly zero
  (`StarkSpendVerifier::verify` rejects non-zero `rest`; `DevVerifier` rejects
  non-zero padding), so a proof blob has one accepted encoding. `TxV1::decode`
  rejects trailing bytes and truncation, and `validate_stateless` checks the
  bucket length before doing any work.
- **Nullifier canonicalization.** `validate_stateless` requires
  `nullifiers[0] < nullifiers[1]` (strictly ascending), which also rejects a
  duplicate nullifier within a single transaction; the prover canonicalizes
  inputs to the same order.
- **Wire uniformity (D9).** Every `TxV1` encodes to the same length regardless
  of contents (`tx::tests::all_txs_same_size`); there are no optional fields.
- **No double-spend / no inflation over opaque inputs.** The state machine
  rejects duplicate nullifiers within and across checkpoints, and the balance
  constraint (C7) enforces `Σ in + mint = Σ out` with a public mint.

## Priority

1. **F-1** — ~~bind the digest into the proof~~ **done** (transcript binding,
   tx v3). Still outstanding: forbid `difficulty_bits = 0` on any shared
   network (defence in depth; the PoW remains the anti-spam lane).
2. **F-2** — document and test the dummy-`rho` sampling invariant.
3. **F-3** — add a release-checklist item asserting no production binary links
   `DevVerifier`.
