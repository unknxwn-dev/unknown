//! Golden vectors for the v3 consensus format (`specs/vectors/consensus-v3.json`).
//!
//! Pins every consensus-critical derivation the wallet/node stack performs:
//! address-tag derivation, note commitment + nullifier (Poseidon2), the
//! commitment-tree root, and the wire-format constants (tx version, proof
//! bucket, encoded length). If any of these change, this test fails — a
//! deliberate consensus tripwire.
//!
//! To regenerate after an intentional consensus break:
//!
//! ```text
//! cargo test -p unknown-wallet --test golden_v3 -- --ignored regenerate
//! ```

use serde_json::{json, Value};
use unknown_antispam_pow::PowSolution;
use unknown_encryption::encrypt_note;
use unknown_interfaces::{Anchor, PROOF_BUCKET};
use unknown_keys::SpendingKey;
use unknown_notes::Note;
use unknown_tree::CommitmentTree;
use unknown_tx::{TxV1, TX_VERSION};
use unknown_wallet::Wallet;

const FROZEN: &str = include_str!("../../../specs/vectors/consensus-v3.json");

/// Compute the vectors from fixed inputs. This is the generator of record;
/// the committed JSON is its pinned output.
fn compute() -> Value {
    let sk = SpendingKey::from_seed(&[1u8; 32]);
    let tag = sk.addr_tag();
    let nk = sk.nk();

    let note = Note {
        value: 123_456_789,
        addr_tag: tag,
        rho: [7u8; 32],
        rseed: [8u8; 32],
    };
    let cm = note.commitment();
    let nf = note.nullifier(&nk);

    let mut tree = CommitmentTree::new();
    let empty_root = tree.root();
    for delta in 0..3u64 {
        let n = Note {
            value: note.value + delta,
            ..note
        };
        tree.append(n.commitment());
    }
    let root3 = tree.root();

    // Wire-format shape: a well-formed tx's total encoded length.
    let enc = encrypt_note(&note, &sk.address(), &[0u8; 64], [3u8; 32]);
    let tx = TxV1 {
        anchor: Anchor {
            height: 0,
            root: root3,
        },
        nullifiers: [nf, nf],
        commitments: [cm, cm],
        enc_outputs: [enc.clone(), enc],
        pow: PowSolution { nonce: 0 },
        proof: vec![0u8; PROOF_BUCKET],
    };

    json!({
        "format": "unknown consensus vectors",
        "tx_version": TX_VERSION,
        "proof_bucket": PROOF_BUCKET,
        "tx_encoded_len": tx.encoded_len(),
        "addr_tag_seed_01": hex::encode(tag),
        "note_commitment": hex::encode(cm.0),
        "note_nullifier": hex::encode(nf.0),
        "tree_root_empty": hex::encode(empty_root),
        "tree_root_3_leaves": hex::encode(root3),
        "wallet_address_seed_01": Wallet::from_seed(&[1u8; 32]).address().encode(),
    })
}

#[test]
fn consensus_vectors_are_frozen() {
    let frozen: Value = serde_json::from_str(FROZEN).expect("consensus-v3.json parses");
    let computed = compute();
    assert_eq!(
        computed,
        frozen,
        "consensus derivations drifted from specs/vectors/consensus-v3.json.\n\
         If this break is intentional, regenerate with:\n\
         cargo test -p unknown-wallet --test golden_v3 -- --ignored regenerate\n\
         computed:\n{}",
        serde_json::to_string_pretty(&computed).unwrap()
    );
}

/// Regenerator (run explicitly; see module docs).
#[test]
#[ignore]
fn regenerate() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../specs/vectors/consensus-v3.json"
    );
    let json = serde_json::to_string_pretty(&compute()).unwrap();
    std::fs::write(path, json + "\n").expect("write consensus-v3.json");
}
