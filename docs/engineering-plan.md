# Engineering Plan — Agent-Ready Work Breakdown

*Companion to [`plan.md`](plan.md) (phases/gates) and [`feasibility-analysis.md`](feasibility-analysis.md)
(architecture rationale). This document is the build instruction set: what to write, what to reuse
from which repositories, what to change, and how to verify each piece. Work packages (WP) are
sized and isolated so independent coding agents can execute them in parallel against frozen
interface contracts. Last updated: June 2026.*

---

## 0. How to use this document (agent orchestration)

1. **WP0 must complete first.** It freezes the workspace layout, the `unknown-interfaces` crate
   (every cross-WP type and trait), CI, and the golden-vector framework. Everything else codes
   against those contracts.
2. Each WP lists: objective → upstream code → exactly what to build/change → interfaces touched →
   acceptance tests → estimated size → parallelism. An agent should be able to start from the WP
   text plus the linked specs alone.
3. **Never change a frozen interface inside a feature WP.** Interface changes are their own WP
   (WP-IFC) requiring explicit sign-off, because they invalidate parallel work.
4. Anything marked **⚠ CRYPTO-REVIEW** ships behind a `#[cfg(feature = "unreviewed")]` gate until
   a cryptographer signs off. Agents may implement, must not enable by default.
5. Target toolchain: stable Rust (pin in `rust-toolchain.toml`), edition 2024. `unsafe_code`
   denied workspace-wide except in explicitly listed FFI crates.

---

## 1. Base-code strategy

### 1.1 Why we do NOT fork nano-node (read this before reaching for it)

[`nanocurrency/nano-node`](https://github.com/nanocurrency/nano-node) is the obvious instinct
("feeless DAG that works") and the wrong base, because every load-bearing layer is incompatible:

| Layer | Nano | This design | Reusable? |
|---|---|---|---|
| Language | C++ | Rust (entire ZK/PQ ecosystem is Rust) | ❌ |
| Ledger model | per-account chains, public balances | shielded notes, commitments + nullifiers | ❌ (account chains are the metadata leak we exist to remove) |
| Consensus | Open Representative Voting, no deterministic finality | DAG-BFT with deterministic checkpoints (anchors require it) | ❌ |
| Tx validation | Ed25519 sig + balance check | STARK proof verification | ❌ |
| Anti-spam | PoW + **public-balance** bucket prioritization | quota notes + epoch nullifiers + state-weight pricing | ❌ (depends on visible balances) |
| Crypto | Blake2/Ed25519 | Poseidon2/STARK/ML-KEM/ML-DSA | ❌ |

A fork would keep <5 % of the code while inheriting 100 % of the legacy. **What we take from Nano
instead is operational knowledge** (see Appendix A.1): bootstrap strategies, ledger
pruning/compaction experience, vote/traffic economy under feelessness, and the 2021 spam
post-mortems — required reading for WP16/WP17 owners.

### 1.2 Reuse matrix (the actual base code)

Modes: **DEP** = cargo dependency, used as-is · **EMB** = embed via its extension traits (our
implementations of its interfaces) · **DSN** = design/reference only, reimplement ·
**BENCH** = used only in benchmarks/comparisons.

| Repo | What it gives us | Mode | License | What we change / implement |
|---|---|---|---|---|
| [Plonky3/Plonky3](https://github.com/Plonky3/Plonky3) | STARK toolkit: fields (BabyBear/Goldilocks/M31), FRI, Poseidon2 AIR, lookups | **DEP** | MIT/Apache-2.0 | Nothing upstream. We write our AIRs (WP6) against its traits; pin a commit, vendor if churn hurts |
| [starkware-libs/stwo](https://github.com/starkware-libs/stwo) | Circle-STARK prover (M31), fastest-prover candidate | **BENCH** (Gate A bake-off) | Apache-2.0 | None; benchmark same statement for comparison |
| [Cardinal-Cryptography/AlephBFT](https://github.com/Cardinal-Cryptography/AlephBFT) | Production DAG-BFT atomic broadcast as an embeddable library with explicit extension traits | **EMB** | Apache-2.0 | We implement its `DataProvider`, `FinalizationHandler`, `Network`, `Keychain`/`MultiKeychain` traits (WP11). No fork expected; session/epoch wiring is ours |
| [MystenLabs/sui](https://github.com/MystenLabs/sui) (`consensus/` subtree, `consensus-core`) | Mysticeti DAG-BFT (higher throughput, sub-second commits) | **DSN now, EMB later** | Apache-2.0 | Phase-2+ performance upgrade path if AlephBFT limits us; extraction is real work — do not start here |
| [cryspen/libcrux](https://github.com/cryspen/libcrux) (`libcrux-ml-kem`) | Formally verified ML-KEM-768 | **DEP** | Apache-2.0 | Wrap with zeroizing newtypes (WP5); ACVP vector tests |
| [RustCrypto/KEMs](https://github.com/RustCrypto/KEMs), [RustCrypto/signatures](https://github.com/RustCrypto/signatures) | `ml-kem` (cross-check), `ml-dsa`, `slh-dsa` | **DEP** | MIT/Apache-2.0 | `ml-dsa` is pre-1.0: pin exact version, run NIST ACVP vectors in CI, interop-test against libcrux/PQClean |
| [dalek-cryptography/curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) (`x25519-dalek`) | Classical half of hybrid KEM | **DEP** | BSD-3 | None |
| [RustCrypto/AEADs](https://github.com/RustCrypto/AEADs) (`chacha20poly1305`) | XChaCha20-Poly1305 | **DEP** | MIT/Apache-2.0 | None |
| [BLAKE3-team/BLAKE3](https://github.com/BLAKE3-team/BLAKE3) | Out-of-circuit hashing, KDF tree | **DEP** | CC0/Apache-2.0 | Domain-separation wrappers only |
| [tpo/core/arti](https://gitlab.torproject.org/tpo/core/arti) (`equix` crate; GitHub mirror [torproject/arti](https://github.com/torproject/arti)) | Pure-Rust EquiX (Tor's asymmetric DoS PoW) | **DEP** | MIT/Apache-2.0 | Challenge binding to tx digest (WP16). **Do not** link [tevador/equix](https://github.com/tevador/equix) C original (LGPL) — license check in CI |
| [zcash/librustzcash](https://github.com/zcash/librustzcash) (`zcash_note_encryption`), [zcash/orchard](https://github.com/zcash/orchard) | Note-encryption framing, circuit discipline, key-tree patterns | **DSN** | MIT/Apache-2.0 | Reimplement over our field/KEM; copy the *trait shapes* and test-vector discipline |
| [zcash/incrementalmerkletree](https://github.com/zcash/incrementalmerkletree) | Append-only tree + witness ("bridgetree") design | **DSN** | MIT/Apache-2.0 | Reimplement over Poseidon2/BabyBear (WP4) |
| [penumbra-zone/penumbra](https://github.com/penumbra-zone/penumbra) | Closest whole-system reference: tiered commitment tree, view/spend service split, gRPC shapes, private staking design | **DSN** | MIT/Apache-2.0 | Their crypto is decaf377-specific; lift architecture, not code |
| [libp2p/rust-libp2p](https://github.com/libp2p/rust-libp2p) | gossipsub, request-response, kademlia, QUIC | **DEP** | MIT | Custom behaviours + Dandelion++ on top (WP12) |
| [rust-rocksdb/rust-rocksdb](https://github.com/rust-rocksdb/rust-rocksdb) | Persistent KV for nullifier set / tree / notes | **DEP** | Apache-2.0 | Column-family layout ours (WP10). [cberner/redb](https://github.com/cberner/redb) acceptable fallback if build pain |
| [hyperium/tonic](https://github.com/hyperium/tonic) | gRPC node/wallet API | **DEP** | MIT | Proto definitions ours (WP13) |
| [tokio-rs/turmoil](https://github.com/tokio-rs/turmoil) | Deterministic network simulation | **DEP** (tests) | MIT | Consensus adversarial tests (WP11) |
| [rust-bitcoin/rust-bech32](https://github.com/rust-bitcoin/rust-bech32), [rust-bitcoin/rust-bip39](https://github.com/rust-bitcoin/rust-bip39) | Address encoding, seed phrases | **DEP** | MIT/Apache-2.0 | HRP + version bytes ours |
| [risc0/risc0](https://github.com/risc0/risc0), [succinctlabs/sp1](https://github.com/succinctlabs/sp1) | zkVM baselines | **BENCH** | Apache-2.0 | Gate-A comparison only — expected too heavy for phone proving |
| [0xMiden/miden-vm](https://github.com/0xMiden/miden-vm) (formerly 0xPolygonMiden) | Note-script model, STARK stack patterns | **DSN/BENCH** | MIT | Reference for note semantics + a third Gate-A datapoint |
| [vacp2p/zerokit](https://github.com/vacp2p/zerokit) | RLN reference implementation (BN254/circom) | **DSN** | MIT | Port the *scheme* (epoch external nullifier, Shamir slashing) into our STARK circuit (WP16b) |
| [iron-fish/ironfish](https://github.com/iron-fish/ironfish) | All-shielded L1 ops reference | **DSN** | MPL-2.0 | Reading only (MPL — keep out of dependency tree) |
| [nanocurrency/nano-node](https://github.com/nanocurrency/nano-node) | Operational lessons | **DSN** | BSD-3 | None (see §1.1) |

### 1.3 Pinned technical decisions (defaults; revisit only at named gates)

| ID | Decision | Default | Revisit |
|---|---|---|---|
| D1 | Proof field | **BabyBear** (31-bit, Plonky3-native, Poseidon2 support, RISC0/SP1-proven) | Gate A (vs. M31/Stwo, Goldilocks) |
| D2 | Proof system | **Plonky3 FRI STARK**, blowup/params from Gate A sweep | Gate A |
| D3 | In-circuit hash | **Poseidon2** over BabyBear (width 16) | Gate A |
| D4 | Consensus core | **AlephBFT (EMB)**; Mysticeti extraction as upgrade path | Gate C |
| D5 | Hybrid KEM | **X25519 + ML-KEM-768**, combiner per §4.4 | audit |
| D6 | Consensus sigs | **ML-DSA-65** (`ml-dsa` crate, ACVP-tested) | audit |
| D7 | Storage | **RocksDB** | Gate B if build friction |
| D8 | Serialization | hand-written fixed-layout little-endian (consensus objects); `prost` only at RPC boundary | frozen at WP0 |
| D9 | Tx shape | uniform **2-in/2-out**, proofs padded to fixed bucket size | Gate A sets bucket |
| D10 | Memo size | 64 B v1 (vs. Zcash 512 B) — ciphertext budget | Gate B UX review |
| D11 | Values | u64 atomic units, total supply < 2^63 | genesis params |
| D12 | Address encoding | bech32m, HRP `unk`, leading version byte | testnet feedback |

---

## 2. Workspace decomposition

```
unknown/
├── Cargo.toml                  # workspace; [workspace.lints] deny unsafe_code
├── rust-toolchain.toml
├── deny.toml                   # cargo-deny: license allowlist, ban LGPL/MPL deps
├── crates/
│   ├── interfaces/             # WP0  frozen types & traits (NO deps on other crates here)
│   ├── primitives/             # WP1  field re-exports, Poseidon2 params, blake3 DS, encoding
│   ├── keys/                   # WP2  seed→key tree, addresses, viewing/detection keys
│   ├── notes/                  # WP3  note struct, commitment, nullifier, dummy notes
│   ├── tree/                   # WP4  append-only commitment MMR, anchors, witnesses
│   ├── encryption/             # WP5  hybrid KEM note ciphertexts, trial decryption
│   ├── circuit-gadgets/        # WP6a Poseidon2/Merkle/range/digest AIR gadgets
│   ├── circuit-spend/          # WP6b spend statement AIR + prover/verifier glue
│   ├── circuit-mint/           # WP6c coinbase/mint statement (public amount)
│   ├── knockout/               # WP6d constraint-mutation test harness
│   ├── prover-ffi/             # WP8  UniFFI/JNI bindings for mobile benching (unsafe allowed)
│   ├── tx/                     # WP9  wire format, stateless validation pipeline, builder
│   ├── state/                  # WP10 checkpoint state machine, nullifier set, supply, pruning
│   ├── emission/               # WP15 E(h) schedule, reward descriptors
│   ├── antispam-pow/           # WP16a EquiX lane
│   ├── antispam-quota/         # WP16b quota notes + epoch nullifiers (Phase 3)
│   ├── consensus/              # WP11 AlephBFT embedding, checkpoints, certificates
│   ├── p2p/                    # WP12 libp2p behaviours, sync, Dandelion++
│   ├── node/                   # WP13 binary: assembly, gRPC, metrics, config
│   ├── wallet/                 # WP14 scanning, note DB, spend orchestration, CLI
│   └── testkit/                # shared fixtures, golden-vector loader, proptest strategies
├── bench/                      # criterion + mobile bench app (Gate A artifacts)
├── sim/                        # WP17 economics & spam simulations (Python/uv or evcxr)
├── ops/                        # WP18 docker-compose testnet, chaos & load harness
├── specs/                      # normative; golden vectors live in specs/vectors/
└── docs/
```

Dependency DAG (build order; ⇒ = depends on):

```
WP0 ⇒ {WP1}
WP1 ⇒ {WP2, WP3, WP4, WP5, WP6a}
WP3 ⇒ {WP6b, WP9}     WP4 ⇒ {WP6b, WP10}     WP6a ⇒ {WP6b, WP6c}
WP6b ⇒ {WP6d, WP8, WP9}
{WP5, WP9} ⇒ WP14      {WP9, WP10} ⇒ WP11 ⇒ WP12 ⇒ WP13
WP15 ⇒ WP10            WP16a ⇒ WP9            WP16b ⇒ {WP9, WP15}
WP13 ⇒ WP18            WP17 independent (informs WP15/16 params)
```

Maximal parallel lanes after WP1: **(a)** WP2+WP3+WP5 (crypto plumbing), **(b)** WP4 (tree),
**(c)** WP6a→6b (circuits), **(d)** WP17 (sim), **(e)** WP16a (PoW). Consensus lane (WP11/12)
starts from interface stubs immediately using mock state.

---

## 3. Interface contracts (frozen at WP0)

### 3.1 Core types (crate `interfaces`, no logic, no heavy deps)

```rust
pub struct F(pub u32);                      // BabyBear element (D1), canonical reduced form
pub struct Digest(pub [u8; 32]);            // blake3 or Poseidon2-sponge output, context-tagged
pub struct Commitment(pub [F; 8]);          // note commitment (256-bit as 8 limbs)
pub struct Nullifier(pub [F; 8]);
pub struct AnchorId { pub height: u64 }     // checkpoint height
pub struct Anchor { pub id: AnchorId, pub root: Commitment }
pub struct Amount(pub u64);                 // < 2^63 enforced at genesis params

pub trait CommitmentTree {
    fn append(&mut self, cm: Commitment) -> Position;
    fn root(&self) -> Commitment;
    fn witness(&self, pos: Position) -> Option<MerklePath>;   // depth = TREE_DEPTH (32)
    fn checkpoint(&mut self, id: AnchorId) -> Anchor;
}

pub trait NullifierSet {
    fn insert_batch(&mut self, height: u64, nfs: &[Nullifier]) -> Vec<DupReport>;
    fn contains(&self, nf: &Nullifier) -> bool;
}

pub trait SpendProver {                      // implemented by circuit-spend, mocked in tests
    fn prove(&self, w: SpendWitness, pi: SpendPublicInputs) -> Result<ProofBytes, ProveError>;
}
pub trait SpendVerifier {
    fn verify(&self, pi: &SpendPublicInputs, proof: &ProofBytes) -> Result<(), VerifyError>;
    fn verify_batch(&self, items: &[(SpendPublicInputs, ProofBytes)]) -> Result<(), VerifyError>;
}

pub trait CheckpointStateMachine {           // implemented by `state`, driven by `consensus`
    fn apply(&mut self, ordered: &[TxV1]) -> CheckpointSummary;  // dedups nfs, appends cms
    fn seal(&mut self, height: u64) -> SealedCheckpoint;         // anchor + supply + reward descriptor
}
```

### 3.2 Transaction wire format `TxV1` (canonical, fixed-layout, little-endian)

| Field | Bytes | Notes |
|---|---|---|
| `version` | 1 | `0x01` |
| `anchor_height` | 8 | must be within window `W` of current height |
| `anchor_root` | 32 | must match sealed anchor at that height |
| `nullifiers[2]` | 64 | sorted ascending (canonicalization) |
| `commitments[2]` | 64 | output note commitments |
| `enc_outputs[2]` | 2 × 1273 | see §3.4 layout |
| `antispam_tag` | 1 | `0x01` = EquiX, `0x02` = quota (Phase 3) |
| `antispam_body` | 40 (EquiX) / 96 (quota) | EquiX: 16 B solution ‖ 8 B nonce ‖ 16 B pad |
| `proof` | `PROOF_BUCKET` (fixed per version, set at Gate A; est. 64–192 KiB) | zero-padded; padding bytes MUST be zero |

`binding_digest = blake3_keyed("unk.tx.v1", all fields except proof)` — a public input of the
proof; any mutation invalidates it (anti-malleability). **Uniformity rule:** every `TxV1` is
byte-identical in shape; no optional fields, ever (D9).

### 3.3 Spend statement v1 (for the circuit agents) — ⚠ CRYPTO-REVIEW

Key schedule strawman (normative version to be fixed in `specs/notes.md`, WP2):

```
sk            32-byte seed leaf
ask = P2("unk.ask", sk)        # spend authorizing key (field elems)
nk  = P2("unk.nk",  sk)        # nullifier key
ivk_kem       ML-KEM-768 keypair derived via blake3-KDF(seed, "unk.kem", index)
addr = bech32m("unk", ver ‖ kem_pk ‖ dtk ‖ P2("unk.addr", ask, nk))
note  = { value: u64, addr_tag: P2("unk.tag", ak_recv), rho: [F;8], rseed: [F;8] }
cm    = P2("unk.cm", value, addr_tag, rho, rseed)
nf    = P2("unk.nf", nk, rho)
rho_out[i] = P2("unk.rho", nf_in[0], i)     # global uniqueness via consumed nullifier
```

Public inputs: `anchor_root, nf[2], cm_out[2], binding_digest, value_balance_public (=0 for
transfers), epoch`.
Witness: input notes + Merkle paths + positions + `sk`; output notes; dummy flags.

Constraints:

| # | Constraint |
|---|---|
| C1 | For each non-dummy input: `cm_in = P2(...note fields...)` and MerkleVerify(cm_in, path) = `anchor_root` |
| C2 | `nf_i = P2("unk.nf", nk, rho_i)`, with `nk` derived from witnessed `sk` (spend authority) |
| C3 | `addr_tag` of each input note matches keys derived from `sk` (ownership) |
| C4 | Dummy flag `d ∈ {0,1}`; if `d=1` then `value=0` and C1 is bypassed via selector |
| C5 | Each output: `cm_out = P2(...)`, `rho_out` per derivation rule |
| C6 | Range: every value decomposes into 8×8-bit limbs (lookup), `< 2^63` total |
| C7 | Balance: `Σ v_in + value_balance_public = Σ v_out` |
| C8 | `binding_digest` recomputed in-circuit over public fields equals the public input |
| C9 | (Phase 3) quota leaf membership + epoch rate-nullifier derivation |

`circuit-mint` (WP6c) is the same skeleton with no inputs, one output, and
`value_balance_public = mint amount` (public, per emission schedule).

### 3.4 Output ciphertext layout (1273 B)

```
epk_x25519        32 B
mlkem_ct          1088 B          # ML-KEM-768 encapsulation
aead_ct           137 B + 16 B tag
  plaintext: ver(1) ‖ value(8) ‖ rho(32) ‖ rseed(32) ‖ memo(64)
key = HKDF-BLAKE3( x25519_ss ‖ mlkem_ss, info = "unk.dh.v1" ‖ epk ‖ mlkem_ct ‖ cm )
```

Hybrid rule: both shared secrets concatenated **in fixed order** into the KDF (IND-CCA of either
leg suffices). ⚠ CRYPTO-REVIEW the combiner against the latest hybrid-KEM guidance.

### 3.5 Checkpoint state machine (normative pseudocode, WP10)

```
on consensus_commit(batch_seq):                      # total order from WP11
    for tx in batch_seq:
        if any nf in tx.nullifiers already in NF_SET or seen_this_checkpoint: mark REJECTED; continue
        if tx.anchor_height < height - W:            REJECTED (stale anchor)
        verify antispam, then proof (batched):       else REJECTED
        ACCEPTED: stage nfs; stage cms (commit order)

on seal(height):
    NF_SET.insert_batch(staged_nfs)
    for cm in staged_cms: TREE.append(cm)
    anchor = TREE.checkpoint(height)
    rewards = emission::descriptor(height, validator_set)   # public amounts
    mint reward notes via circuit-mint path
    cert = collect ML-DSA sigs over (height, anchor, nf_root, supply, prev_cert)
    prune proofs for checkpoints older than PRUNE_DEPTH     # permanent state ≈ 128 B/tx
```

### 3.6 gRPC surface (WP13; shapes inspired by Penumbra's view/app split)

```
SubmitTx(TxV1) → {accepted | rejected(reason)}
GetAnchors(range) → [Anchor]                       # for tx building
StreamCompactCheckpoints(from_height)              # (height, [(cm, enc_output)], nf_bloom?)
GetCheckpointCert(height) → Cert                   # sync/light-client verification
GetParams() → genesis/consensus params
```

**Privacy rule:** no per-note or per-nullifier query endpoints — bulk streaming only, so light
clients never reveal which outputs interest them. (Nullifier-status queries leak; wallets infer
spentness locally from streamed data.)

---

## 4. Work packages

> Sizes: S < 1 kLOC, M 1–3 kLOC, L 3–8 kLOC, XL > 8 kLOC (tests included; estimates, not promises).

**WP0 — Workspace, interfaces, CI** · size M · blocks all
Build: workspace per §2; `interfaces` crate per §3.1; CI (fmt, clippy `-D warnings`, test,
`cargo-deny` with license allowlist banning LGPL/MPL in deps, ACVP/golden-vector jobs); golden
vector framework (`testkit`): vectors live in `specs/vectors/*.json`, every crypto crate has a
`vectors` test target. Acceptance: empty impls compile workspace-wide; CI green; a sample vector
round-trips.

**WP1 — Primitives** · size M · after WP0
Build: BabyBear re-exports + canonical encoding to/from bytes; Poseidon2 instantiation (width 16,
params generated + frozen into `specs/vectors/poseidon2.json`; cross-check against Plonky3's and
an independent reference implementation); blake3 domain-separation wrappers
(`digest(ctx, bytes)`); fixed-layout encode/decode derive-helpers. Acceptance: Poseidon2 vectors
match two independent implementations; encode/decode fuzz (cargo-fuzz) finds no panics.

**WP2 — Keys & addresses** · size M · after WP1 · parallel lane (a)
Build: seed (bip39) → blake3-KDF key tree per §3.3; ML-KEM keypair derivation (deterministic from
seed leaf — check `ml-kem`/libcrux APIs for seeded keygen; if absent, derive via DRBG from leaf
⚠ CRYPTO-REVIEW); viewing-key struct (incoming: kem_sk + tag-check material; full: + nk);
bech32m address codec with version byte; zeroize everywhere. Acceptance: deterministic
re-derivation from seed; address vectors frozen; key material never `Debug`-printed
(compile-time deny via custom lint/test).

**WP3 — Notes** · size S · after WP1 · lane (a)
Build: note struct, commitment, nullifier, `rho` derivation, dummy-note constructor per §3.3.
Acceptance: commitment/nullifier vectors frozen; property: distinct (note, nk) ⇒ distinct nf
(statistical test over random sampling).

**WP4 — Commitment tree** · size M · after WP1 · lane (b)
Upstream design: `zcash/incrementalmerkletree` (bridgetree), Penumbra TCT docs.
Build: append-only Merkle tree depth 32 over Poseidon2; positions; witnesses that remain valid
across appends (old-anchor proofs per feasibility §4); checkpoint/anchor registry with window W;
RocksDB persistence adapter (behind trait, in-memory impl for tests). Acceptance: property tests
vs. naive O(n) model (proptest, 10^5 ops); witness-after-append validity; persistence
crash-recovery test.

**WP5 — Note encryption** · size M · after WP1/WP2 · lane (a)
Upstream: `libcrux-ml-kem` (primary), `ml-kem` (cross-check in tests), `x25519-dalek`,
`chacha20poly1305`. Build: §3.4 exactly; batch trial-decryption API
(`scan(&[EncOutput], &IncomingViewingKey) -> Vec<Hit>`) with rayon parallelism; decaps
throughput bench. Acceptance: round-trip vectors; cross-implementation KEM agreement; bench
report (target: ≥ 20k trial-decaps/s/core — measure, this number is a Gate-B input).

**WP6a — Circuit gadgets** · size L · after WP1 · lane (c)
Upstream: Plonky3 (`p3-poseidon2`, `p3-fri`, lookup utilities).
Build: reusable AIR chips: Poseidon2 permutation, Merkle-path verify (depth 32), 8-bit-limb
range decomposition with lookup, in-circuit sponge for `binding_digest`, boolean selectors.
Acceptance: each gadget has a standalone soundness test (valid witness passes, mutated witness
fails) + completeness fuzz.

**WP6b — Spend circuit** · size L · after WP3/4/6a
Build: assemble §3.3 statement; native witness builder from wallet types; prover + verifier glue;
parameter sweep harness (blowup, FRI queries, hash) emitting the **Gate-A report**
(prove time laptop/phone, proof size, verify throughput). Acceptance: knockout suite (WP6d) at
100 % kill rate; Gate-A KPI table produced for ≥ 2 param sets; same statement benched on Stwo
(and optionally Miden/RISC0) for the bake-off.

**WP6c — Mint circuit** · size S · after WP6a · **WP6d — Knockout harness** · size M
6d builds the constraint-mutation framework: programmatically disable/weaken each constraint
family and assert at least one test catches it (this is the anti-counterfeiting CI line —
feasibility §10 risk 5). Runs nightly, blocks release branches.

**WP8 — Mobile prover packaging** · size M · after WP6b
Build: `prover-ffi` with UniFFI (Kotlin bindings); minimal Android bench app (or documented
Termux fallback) producing Gate-A phone numbers on a named mid-range reference device.
Acceptance: CI artifact = APK + benchmark JSON.

**WP9 — Tx pipeline** · size M · after WP3/WP6b stubs
Build: `TxV1` codec (§3.2) with canonicalization rules (sorted nullifiers, zero-padding checks);
stateless validation (format → antispam → proof verify, batched); tx builder (wallet side:
select notes, pick anchor, build witness, call prover, encrypt outputs). Acceptance: codec fuzz;
malleability tests (every byte flip ⇒ reject); uniformity test (all built txs identical size).

**WP10 — State machine** · size L · after WP4/WP9
Build: §3.5 exactly; RocksDB column families (`nf`, `tree`, `anchors`, `certs`, `meta`); supply
accounting (Σ mints − Σ burns invariant check on every seal); proof pruning; deterministic replay
(same ordered input ⇒ identical state root) test across 2 independent runs. Acceptance: replay
determinism; dup-nullifier rejection incl. intra-checkpoint races; crash-recovery mid-seal.

**WP11 — Consensus adapter** · size L · after WP9/WP10 (stubs ok) · lane (e)
Upstream: AlephBFT. Build: implementations of `DataProvider` (our batch digests),
`FinalizationHandler` (feed §3.5), `Network` (over WP12 transport; in-proc for tests),
`Keychain`/`MultiKeychain` over **ML-DSA-65** (certificate = vector of sigs + bitmap, threshold
2f+1 — no aggregation, committee ≤ 64 at first); batch availability layer (pull-by-digest with
retries — AlephBFT orders digests, full batch bytes are our responsibility); session/epoch
rotation; checkpoint cadence (seal every k finalized units or t ms). Acceptance: turmoil suite —
double-spend race across nodes converges to one ACCEPTED; equivocating member tolerated;
partition heal replays to identical roots; 4-node WAN-latency-model commit p50 < 1 s.

**WP12 — P2P** · size L · after WP11 interfaces
Upstream: rust-libp2p (QUIC, gossipsub, request-response, identify, kademlia).
Build: topics (`tx/1`, `vertex/1`, `ckpt/1`); request-response protocols `batch-fetch/1`,
`ckpt-sync/1`; peer scoring (invalid-proof submission ⇒ ban); **Dandelion++** stem/fluff for tx
submission (stem over a privacy subgraph, fluff into gossipsub; timing jitter). Acceptance:
10-node docker net propagates 1k tx/s; eclipse-resistance smoke tests; Dandelion stem paths
verified by packet capture in sim.

**WP13 — Node binary** · size M · after WP10–12
Build: config (TOML genesis: params, validator set, `E_0/H/E_tail`, W, PROUF_BUCKET…); service
assembly; §3.6 gRPC via tonic; prometheus metrics; structured logs. Acceptance: single-node
devnet runs the full lifecycle from `ops/` script; compact-stream served to wallet.

**WP14 — Wallet** · size L · after WP5/WP9/WP13
Build: scanning engine consuming `StreamCompactCheckpoints` (parallel trial-decrypt, resumable
cursor); encrypted note DB (sqlite via `rusqlite` or redb); spentness tracking via streamed
nullifiers matched locally; spend orchestration (anchor selection within W, witness fetch from
local tree mirror, prove, submit via Dandelion entry); CLI: `keygen | address | balance | send |
history | export-viewing-key`. Acceptance: end-to-end devnet demo mint→pay→chained-pay
(Gate B); scan throughput report; recovery-from-seed integration test.

**WP15 — Emission** · size S · after WP10
Build: `E(h)` fixed-point schedule per `specs/emission.md` §3 (integer math only, vectors
frozen); base-stream distribution (stake×participation weights from consensus metadata); reward
descriptor + mint-note creation via WP6c; supply audit endpoint. Acceptance: schedule vectors;
Σ-invariant property test; β=0 enforced (inclusion bonus structurally absent until activation).

**WP16a — PoW lane** · size S · after WP9 — arti `equix`; challenge = `binding_digest`; uniform
difficulty param; verify-fast path in stateless validation. Acceptance: solve/verify benches;
difficulty uniformity test (no per-sender variance anywhere in code).
**WP16b — Quota lane (Phase 3)** · size L · after WP15 + `specs/antispam.md` (write spec first —
the zerokit RLN scheme transposed: quota notes in a parallel pool, epoch external nullifier,
`k ≤ quota(s)` counter, slash-on-reuse). ⚠ CRYPTO-REVIEW. Gate-D owner.

**WP17 — Simulations** · size M · independent
Build: `sim/` (Python+uv or Rust notebooks): spam-attacker budget vs. PoW/quota params;
state-growth curves; emission calibration (`E_0`, `H`, `E_tail` candidates → recommendation doc);
mint-farming check for any future β>0. Acceptance: parameter recommendation memo with
reproducible runs (feeds genesis TOML + Gate D criteria).

**WP18 — Testnet ops** · size M · after WP13
Build: docker-compose 4/7/10-node topologies with WAN latency shaping (tc/netem); chaos harness
(kill/partition/clock-skew); load generator (target sustained 1k tx/s with real proofs — needs a
prover farm container); Grafana dashboards. Acceptance: Gate-C measurement runs scripted and
reproducible.

---

## 5. Milestones → gates (from `plan.md`)

| Milestone | Contents | Gate criteria (numeric, from plan.md §2/§4) |
|---|---|---|
| **M0** (wk 4–6) | WP0–WP3 merged, vectors frozen v0 | CI green; vectors cross-checked |
| **M1** (wk 8–12) | WP6a/6b/8 bake-off report | **Gate A:** phone prove ≤ 2 s, proof ≤ 250 KB, verify ≥ 500/s/core — else trigger D1/D2 fallbacks (smaller statement / delegated proving / EC-proofs+PQ-encryption launch) |
| **M2** (mo 5–7) | WP4/5/9/10/13/14 single-sequencer devnet | **Gate B:** full lifecycle; scan ≥ 5k tx/s/core; knockout 100 %; tx ≤ 300 KB |
| **M3** (mo 9–11) | WP11/12/18 multi-node testnet | **Gate C:** zero safety violations under turmoil+chaos; p50 ≤ 1 s / p99 ≤ 3 s; ≥ 1k tx/s verified; pruned-proof sync works |
| **M4** (mo 12–14) | WP15/16/17 + game days | **Gate D:** 72 h worst-case spam with honest p99 ≤ 5 s; state cap held; zero-stake first tx ≤ 60 s |
| **M5** (mo 15–20) | audits, formal models, public testnet | **Gate E** per plan.md |

---

## 6. Testing & assurance (non-negotiable per WP)

1. **Golden vectors** in `specs/vectors/` are the single source of truth; CI fails on any drift;
   vectors regenerable only via a versioned generator with reviewer sign-off.
2. **Knockout/mutation** (WP6d) nightly on circuits — the inflation-bug tripwire.
3. **Property tests** (proptest) for tree/state/codec against naive models.
4. **Fuzzing** (cargo-fuzz) on every decoder and the stateless validation entrypoint.
5. **Deterministic distributed tests** (turmoil) for consensus; chaos (WP18) for integration.
6. **ACVP/NIST vectors** for ML-KEM/ML-DSA in CI; cross-implementation agreement tests.
7. **Supply-chain:** `cargo-deny` (licenses + advisories), lockfile committed, third-party crate
   review list for anything touching keys; `cargo vet`/`cargo crev` optional but recommended.
8. **No floating point** anywhere in consensus/state/emission code (CI grep gate).

---

## 7. Open engineering decisions (need data, owner = first agent to touch)

1. Deterministic ML-KEM keygen from seed (WP2): confirm seeded API in libcrux/ml-kem; else DRBG
   derivation design note. ⚠ CRYPTO-REVIEW
2. PROOF_BUCKET size & FRI params (Gate A output).
3. AlephBFT session length / validator-set handoff details (WP11 spike, week 1: build their
   examples, write `docs/notes/alephbft-embedding.md`).
4. RocksDB vs redb after WP4/WP10 persistence benches.
5. Memo 64 B vs larger (D10) after wallet UX trial.
6. Batch availability: gossip full batches vs digest+pull under 1k tx/s load (WP12 measurement).

## Appendix A — Required reading per workstream

- **A.1 Nano lessons (WP11/12/16/17 owners):** Nano docs on Open Representative Voting and spam
  ("work" + balance-bucket/LRU prioritization — note both depend on public balances), 2021 spam
  incident post-mortems, ledger pruning discussions. Source: docs.nano.org + nano-node wiki.
- **A.2 Shielded engineering (WP2–6/14):** Zcash protocol spec §3–4 (notes, commitments,
  nullifiers), `zcash_note_encryption` API docs, Orchard book (action structure, binding),
  Penumbra protocol docs (TCT, view services, compact blocks, private staking for WP16b/15).
- **A.3 Consensus (WP11):** AlephBFT README + `examples/`, Aleph paper, Mysticeti paper
  (upgrade path), Narwhal/Bullshark paper (DAG-mempool framing).
- **A.4 Anti-spam (WP16):** RLN spec (rate-limiting nullifier, vacp2p), Semaphore docs
  (external nullifier pattern), Tor EquiX/proposal 327.
- **A.5 PQ (WP5/WP11):** FIPS 203/204 summaries, hybrid-KEM combiner guidance (e.g.
  X25519MLKEM768 in TLS), libcrux ML-KEM docs.
