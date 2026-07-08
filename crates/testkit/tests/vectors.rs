//! Golden-vector conformance (WP0 / §6.1). Frozen values mirror
//! `specs/vectors/core.md`; drift here is a consensus break and fails CI.

use unknown_testkit::vectors;

/// The frozen expected values. MUST equal `specs/vectors/core.md`. Regenerate
/// both together with `cargo run -p unknown-testkit --bin gen-vectors` only as a
/// reviewed, version-bumped change.
const FROZEN: &[(&str, &str)] = &[
    (
        "hash.empty",
        "c2a104be21d0ab76b2c14b77d004f74d15ade7ccbe1e1745f74fedf4b7fa72ac",
    ),
    (
        "hash.abc",
        "84bbfc9f200bdb08000107218b32a869d30561b53f19f23a477051c46261e8aa",
    ),
    (
        "ds.note_cm_x",
        "e28ea56198065fff9c1cf8e6597d434141061aa22fd7cd8d8bcc7e7f82559931",
    ),
    (
        "ds.nullifier_x",
        "a199dcb350592683a0b9d66f2df2ca3cc18dddf357ec85ad6712abdd44e96f71",
    ),
    (
        "key.ask",
        "391ecb7e34e98d8727b9aa7d8588c356c119a4b806b7c1f420bb7757d444d260",
    ),
    (
        "key.nk",
        "6f9643ecd6a2c34e22fa290b0c298d601bc8567b50e2931b734160fc2067947d",
    ),
    (
        "key.addr_tag",
        "246fa87cb761d5f18d4c5aa323b6480d28539dcd68fc16b0a3f603836d9ab4f4",
    ),
    (
        "note.commitment",
        "0be054fe80a1c15cc4ca91b197ac225d38f6ef19b63f4e99443082751ff5175a",
    ),
    (
        "note.nullifier",
        "d37e92577fbb9b940488a70c8e40ae7d50f7b0c731fd4ea5bec97ff87c1d2f21",
    ),
];

#[test]
fn golden_vectors_match_frozen() {
    let computed = vectors();
    assert_eq!(
        computed.len(),
        FROZEN.len(),
        "vector set size changed; update specs/vectors/core.md and FROZEN together"
    );
    for ((label, got), (flabel, want)) in computed.iter().zip(FROZEN) {
        assert_eq!(label, flabel, "vector order/label drift");
        assert_eq!(
            got, want,
            "CONSENSUS-BREAKING drift in `{label}`: got {got}, frozen {want}. \
             If intentional, bump the format version and regenerate specs/vectors/core.md."
        );
    }
}
