# Note & Key Specification (v0)

*Normative for the v0 prototype. Implemented by `crates/keys`, `crates/notes`,
`crates/encryption`; golden values in `specs/vectors/core.md`. Hashes are
domain-separated BLAKE3 in v0, migrating to Poseidon2 over BabyBear at circuit
integration (decision D3), which bumps the format version.*

## 1. Key hierarchy

From a 32-byte `seed` (BIP-39 derivable):

```
sk       = KDF("unknown.v0.key.sk",  seed)      spending key (root authority)
ask      = KDF("unknown.v0.key.ask", sk)        spend-authorizing key
nk       = KDF("unknown.v0.key.nk",  sk)        nullifier key
addr_tag = H("unknown.v0.key.addrtag", ask)     recipient tag bound into notes
x25519   = KDF("unknown.v0.key.x25519", sk)     classical KEM secret
kem      = ML-KEM-768 FromSeed(KDF("unknown.v0.key.kemseed", sk) ‖
                               KDF("unknown.v0.key.kemseed2", sk))   (64-byte seed)
```

`KDF` is BLAKE3's `derive_key`; `H` is the domain-separated multi-part hash.
ML-KEM keygen is the standardized deterministic `FromSeed` (FIPS-203), so the
whole hierarchy is reproducible from `seed` with no stored randomness.

### Viewing keys (selective disclosure)

- **Incoming viewing key** = `{x25519 secret, ML-KEM decapsulation key,
  addr_tag}`. Detects and decrypts received notes; cannot spend or detect spends.
- **Full viewing key** = incoming + `nk`. Adds spentness detection (can compute
  nullifiers of its own notes).

Neither viewing key can create a valid spend (that needs `sk` inside the proof),
so they are safe to hand to auditors/exchanges — the protocol-level analogue of
feasibility §9's payment-disclosure.

## 2. Address

`version(0x00) ‖ x25519_pk(32) ‖ ML-KEM-768_pk(1184) ‖ addr_tag(32)`, plus a
4-byte BLAKE3 checksum, encoded as `unk1<hex>`. ≈ 1.25 KB raw / ≈ 2.5 KB text —
the PQ address-size UX cost (feasibility §6.2). bech32m is unusable at this
length (its checksum is defined only for short data), hence hex + explicit
checksum.

## 3. Note

```
Note { value: u64 (< 2^62), addr_tag: [32], rho: [32], rseed: [32] }
commitment = H("unknown.v0.note.cm", value_le ‖ addr_tag ‖ rho ‖ rseed)
nullifier  = H("unknown.v0.note.nf", nk ‖ rho)          (needs nk — spend side)
```

- `addr_tag` binds the note to the recipient's spend authority (checked in the
  circuit as constraint C3).
- `rho` is a per-note nonce guaranteeing global nullifier uniqueness:
  - transfer outputs: `rho = H("unknown.v0.note.rho.transfer", first_nf ‖ i)`
    where `first_nf` is the canonical (smallest) input nullifier and `i` the
    output index;
  - mint/coinbase outputs: `rho = H("unknown.v0.note.rho.mint", height ‖ i)`.
  Because a transfer's outputs are bound to a consumed nullifier (unique once
  accepted), and mints to a checkpoint height + index, no two honest notes ever
  share `rho`, so no two share a nullifier.
- **Dummy notes** (`value = 0`, random tags/nonces) pad every transaction to the
  uniform 2-in/2-out shape; their membership check is bypassed (constraint C4)
  and they must carry zero value.

## 4. Output ciphertext (1273 bytes)

`epk_x25519(32) ‖ ML-KEM_ct(1088) ‖ AEAD(137 plaintext + 16 tag)`. The AEAD key
derives from BOTH shared secrets:

```
key ‖ nonce = H("unknown.v0.enc.aead",  x25519_ss ‖ mlkem_ss ‖ epk ‖ mlkem_ct ‖ addr_tag)
plaintext   = version(1) ‖ value(8) ‖ rho(32) ‖ rseed(32) ‖ memo(64)
AEAD        = ChaCha20-Poly1305
```

Hybrid rule: confidentiality holds if *either* the X25519 or the ML-KEM leg is
unbroken — so recorded ciphertext resists harvest-now-decrypt-later from genesis
(feasibility §6.1). A recipient recovers a note by trial-decrypting; success =
valid AEAD tag, from which it reconstructs `Note{value, addr_tag=self, rho,
rseed}` and checks the on-chain commitment.

## 5. Uniformity

Every transfer is byte-identical in shape (2 inputs, 2 outputs, fixed ciphertext
and proof sizes; decision D9). There are no optional fields and no cleartext that
varies with contents, so two transactions differ only in their opaque bytes.

## 6. Value & supply

`value` is `u64` atomic units, total supply `< 2^62`. Balance is enforced
entirely in-circuit (`Σ inputs + public_mint = Σ outputs`, constraint C7) — there
is no homomorphic value commitment (no elliptic-curve reliance; feasibility §6.2).
Only mint (emission) and burn carry public amounts, keeping supply auditable
(`specs/emission.md`, feasibility §9).

## 7. Open items

1. Poseidon2 arithmetization of §1/§3 hashes at circuit integration (D3),
   with regenerated golden vectors.
2. Seed-derived *diversified* addresses (multiple unlinkable addresses from one
   seed) and their scan-cost trade-off (feasibility §6.2, research item 5).
3. Memo size (64 B v0) vs. UX (decision D10).
