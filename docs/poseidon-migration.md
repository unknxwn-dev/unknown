# BLAKE3 → Poseidon2 digest migration

Decision D3 makes the in-circuit hash Poseidon2 over BabyBear. For the STARK
spend circuit to verify real transactions, the pipeline's commitments,
nullifiers, and Merkle tree must be computed with that same hash. This document
records what was migrated, how the circuit and pipeline are kept in lock-step,
and what remains.

## Done

- **`unknown-poseidon`** — the single source of truth: frozen Poseidon2 round
  constants, the host permutation (S-box `x^7`), rate-8 sponge, 2-to-1
  compression, digest `pack`/`unpack` to the 32-byte wire form, the
  byte→field mapping, and value byte-limbs. Its permutation is cross-checked
  against Plonky3's reference Poseidon2 AIR for the same constants.
- **`circuit-spend`** sources its AIR constants from `unknown-poseidon`, so the
  in-circuit and out-of-circuit hashes are the *same function*, not two copies.
- **`notes`** — `commitment = Poseidon2(value-limbs ‖ addr_tag ‖ rho ‖ rseed)`
  (4 rate-8 blocks); `nullifier = Poseidon2(nk ‖ rho)` (2 blocks). Byte-array
  fields map to field elements via `unknown-poseidon`; the digest packs back to
  `[u8; 32]`, so the `Commitment`/`Nullifier` interface types are unchanged.
- **`tree`** — node hash is Poseidon2 compression of the two packed child
  digests; the empty leaf is the all-zero digest. This is exactly the
  in-circuit Merkle relation (C1).
- **`circuit-spend::spend`** commitment is aligned to 4 blocks (adds `rseed`)
  so it matches `Note::commitment` byte-for-byte.
- **End-to-end proof** — `circuit-spend/tests/pipeline.rs` builds real
  `unknown_notes::Note`s, commits them into the real `unknown_tree`, proves the
  spend, and shows the circuit's public values equal the pipeline's Poseidon2
  digests (anchor root, nullifiers, output commitments) **and** that
  `StarkSpendVerifier` (the frozen `SpendVerifier`) accepts the proof.

The rest of the pipeline (`tx`, `state`, `wallet`, `node`, `encryption`) is
hash-agnostic and unchanged; the devnet demo and supply audit still pass. `rho`
derivation, dummy-note entropy, the tx binding digest, and key derivation
remain domain-separated BLAKE3 (they never appear in-circuit as preimages).

## Ownership model (done)

`keys` derives `addr_tag = Poseidon2(nk)` and the circuit's C3 enforces exactly
that: a per-input tag sponge hashes the witness `nk` and binds the result to the
note's `addr_tag`, while the nullifier uses the same `nk`. So real
`unknown_keys`-style notes (arbitrary addresses) verify — the end-to-end test
builds inputs with `addr_tag = Poseidon2(nk)` and they pass. The old v0
`addr_tag == nk` shortcut is gone (it would have published `nk`).

## Constants frozen (done)

The 141 round constants are frozen in `specs/vectors/poseidon2.json` and loaded
from there by `unknown-poseidon::constants()` (no longer seed-derived at
runtime). The seed generator of record survives as `derive_from_seed()`, the
`freeze_constants` example regenerates the file, and the
`frozen_constants_match_generator` test fails if the committed file ever drifts
from the generator. `golden_vectors` pins concrete sponge/compress digests as a
consensus tripwire. The constants permute identically to before (the circuit and
pipeline are byte-for-byte unchanged); cross-checking against an *independent*
Poseidon2 reference (plan WP1) is the remaining hardening.

## Remaining

1. **Independent constant cross-check.** Verify `poseidon2.json` against a
   second, non-Plonky3 Poseidon2 implementation (plan WP1) before mainnet.
2. **Version byte + golden vectors.** Bump the note/tx format version and
   regenerate frozen vectors (this is a consensus break, by design).
3. **Tall-layout refactor + `PROOF_BUCKET`.** The fused spend proof is
   currently **5.4 MB** — 20× over the 250 KB Gate-A KPI — because the AIR uses
   a wide single-row layout that opens ~22k FRI columns (see
   `docs/gate-a-report.md`). Rebuild the AIR in the standard tall layout (one
   Poseidon2 perm per row), *then* set the real proof bucket (≈150 KiB) in
   `interfaces` and bump the transaction version (currently the dev value 192).
   The bucket is deliberately left unbumped until the layout is fixed.
4. **Wallet/state wiring.** Have the wallet build the circuit witness from its
   notes + tree witnesses (the `tests/pipeline.rs` flow) and have the node use
   `StarkSpendVerifier` in place of the dev verifier once 1–4 land.
