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

## Remaining

1. **Ownership model.** The circuit enforces `addr_tag == nk` (C3). The
   end-to-end test uses notes built that way. To support arbitrary addresses,
   reconcile `keys`' `addr_tag` derivation with the circuit (either make the
   address tag equal the nullifier key, or extend C3 to check the real
   derivation `addr_tag = H(ask, nk)` in-circuit). This is a design decision.
2. **Freeze the constants.** `unknown-poseidon::constants()` derives from a
   fixed seed; freeze the 141 field values into `specs/vectors/poseidon2.json`
   and cross-check against a second reference (plan WP1), then load from there.
3. **Version byte + golden vectors.** Bump the note/tx format version and
   regenerate frozen vectors (this is a consensus break, by design).
4. **`PROOF_BUCKET`.** Set the real STARK proof bucket (≈150 KiB) in
   `interfaces` and bump the transaction version (currently the dev value 192).
5. **Wallet/state wiring.** Have the wallet build the circuit witness from its
   notes + tree witnesses (the `tests/pipeline.rs` flow) and have the node use
   `StarkSpendVerifier` in place of the dev verifier once 1–4 land.
