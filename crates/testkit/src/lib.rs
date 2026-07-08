//! Golden-vector fixtures (WP0 / engineering plan §6.1).
//!
//! `vectors()` computes the canonical, consensus-critical values from the
//! current code. The frozen expected outputs live in `specs/vectors/core.md`
//! and are asserted by `tests/vectors.rs`. Any drift fails CI: these values are
//! a hard consensus boundary and may only change via a reviewed format-version
//! bump (§6.1). The list is also the cross-implementation conformance target
//! for any non-Rust reimplementation.

use unknown_keys::SpendingKey;
use unknown_notes::Note;
use unknown_primitives::{ds, hash_parts};

/// (label, hex) pairs of frozen values, in a stable order.
pub fn vectors() -> Vec<(String, String)> {
    let mut v = Vec::new();
    let mut push = |k: &str, bytes: &[u8]| v.push((k.to_string(), hex::encode(bytes)));

    // Hash / domain separation.
    push("hash.empty", &hash_parts("unknown.v0.test", &[]));
    push(
        "hash.abc",
        &hash_parts("unknown.v0.test", &[b"a", b"b", b"c"]),
    );
    push("ds.note_cm_x", &hash_parts(ds::NOTE_COMMITMENT, &[b"x"]));
    push("ds.nullifier_x", &hash_parts(ds::NULLIFIER, &[b"x"]));

    // Key hierarchy from a fixed seed.
    let sk = SpendingKey::from_seed(&[1u8; 32]);
    push("key.ask", &sk.ask());
    push("key.nk", &sk.nk());
    push("key.addr_tag", &sk.addr_tag());

    // Note commitment and nullifier for a fixed note.
    let note = Note {
        value: 100,
        addr_tag: sk.addr_tag(),
        rho: [9u8; 32],
        rseed: [8u8; 32],
    };
    push("note.commitment", &note.commitment().0);
    push("note.nullifier", &note.nullifier(&sk.nk()).0);

    v
}
