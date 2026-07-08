# Golden Vectors — core (v0)

*Frozen consensus-critical values (engineering plan §6.1). These are the
cross-implementation conformance target: any reimplementation MUST reproduce
them exactly. Changing a value is a consensus break and requires a reviewed
format-version bump. Regenerate after an intentional change with
`cargo run -p unknown-testkit --bin gen-vectors`; `tests/vectors.rs` asserts the
current code matches this list.*

All values are lowercase hex of 32-byte outputs.

| label | value |
|---|---|
| `hash.empty` | `c2a104be21d0ab76b2c14b77d004f74d15ade7ccbe1e1745f74fedf4b7fa72ac` |
| `hash.abc` | `84bbfc9f200bdb08000107218b32a869d30561b53f19f23a477051c46261e8aa` |
| `ds.note_cm_x` | `e28ea56198065fff9c1cf8e6597d434141061aa22fd7cd8d8bcc7e7f82559931` |
| `ds.nullifier_x` | `a199dcb350592683a0b9d66f2df2ca3cc18dddf357ec85ad6712abdd44e96f71` |
| `key.ask` | `391ecb7e34e98d8727b9aa7d8588c356c119a4b806b7c1f420bb7757d444d260` |
| `key.nk` | `6f9643ecd6a2c34e22fa290b0c298d601bc8567b50e2931b734160fc2067947d` |
| `key.addr_tag` | `246fa87cb761d5f18d4c5aa323b6480d28539dcd68fc16b0a3f603836d9ab4f4` |
| `note.commitment` | `0be054fe80a1c15cc4ca91b197ac225d38f6ef19b63f4e99443082751ff5175a` |
| `note.nullifier` | `d37e92577fbb9b940488a70c8e40ae7d50f7b0c731fd4ea5bec97ff87c1d2f21` |

Inputs (for reimplementers):

- `hash.*`, `ds.*` use the domain-separated multi-part BLAKE3 of `primitives`:
  `derive_key(context)` keyed hasher, each part length-prefixed (u64 LE).
  Contexts: `hash.*` use `"unknown.v0.test"`; `ds.note_cm_x` uses
  `"unknown.v0.note.cm"`; `ds.nullifier_x` uses `"unknown.v0.note.nf"`; single
  part `b"x"` (and `hash.abc` = parts `b"a", b"b", b"c"`; `hash.empty` = no parts).
- `key.*` derive from seed `[0x01; 32]`: `sk = KDF("unknown.v0.key.sk", seed)`,
  then `ask = KDF("unknown.v0.key.ask", sk)`, `nk = KDF("unknown.v0.key.nk", sk)`,
  `addr_tag = H("unknown.v0.key.addrtag", ask)`.
- `note.*` for the note `{value: 100, addr_tag: key.addr_tag, rho: [9;32],
  rseed: [8;32]}`: commitment = `H("unknown.v0.note.cm", value_le ‖ addr_tag ‖
  rho ‖ rseed)`; nullifier = `H("unknown.v0.note.nf", nk ‖ rho)`.

The hash migrates from BLAKE3 to Poseidon2 over BabyBear at circuit integration
(decision D3); that migration regenerates this file under a new version.
