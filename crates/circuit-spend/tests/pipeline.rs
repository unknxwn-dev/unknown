//! End-to-end: a *real* pipeline transaction verifies through the STARK
//! `SpendVerifier`.
//!
//! This is the payoff of the BLAKE3→Poseidon2 migration. It builds genuine
//! `unknown_notes::Note`s, commits them into the real `unknown_tree`
//! commitment tree, then proves the spend with the circuit and checks that
//! (a) the circuit's public values are *exactly* the pipeline's Poseidon2
//! digests (anchor root, nullifiers, output commitments), and (b) the frozen
//! `StarkSpendVerifier` accepts the proof. Because the circuit and the pipeline
//! share `unknown_poseidon`, the two sides agree byte-for-byte.

use unknown_circuit_spend::field::Val;
use unknown_circuit_spend::spend::{InputNote, OutputNote, PathStep, SpendAir};
use unknown_circuit_spend::verifier::{prove_to_interface, StarkSpendVerifier};
use unknown_interfaces::{MerklePath, SpendVerifier, TREE_DEPTH};
use unknown_notes::Note;
use unknown_poseidon as poseidon;
use unknown_tree::CommitmentTree;

fn map(b: [u8; 32]) -> [Val; 8] {
    poseidon::bytes_to_field(b)
}

fn to_path(w: &MerklePath) -> Vec<PathStep> {
    (0..TREE_DEPTH)
        .map(|l| (poseidon::unpack(w.siblings[l]), (w.position >> l) & 1 == 1))
        .collect()
}

#[test]
fn real_pipeline_tx_verifies_through_stark_spend_verifier() {
    // A real spender: addr_tag == nk (the circuit's ownership model).
    let nk = [7u8; 32];
    let in0 = Note {
        value: 600,
        addr_tag: nk,
        rho: [11u8; 32],
        rseed: [12u8; 32],
    };
    let in1 = Note {
        value: 400,
        addr_tag: nk,
        rho: [13u8; 32],
        rseed: [14u8; 32],
    };
    let out0 = Note {
        value: 700,
        addr_tag: [21u8; 32],
        rho: [22u8; 32],
        rseed: [23u8; 32],
    };
    let out1 = Note {
        value: 300,
        addr_tag: [31u8; 32],
        rho: [32u8; 32],
        rseed: [33u8; 32],
    };

    // Commit the inputs into the real Poseidon2 commitment tree.
    let mut tree = CommitmentTree::new();
    let p0 = tree.append(in0.commitment());
    let p1 = tree.append(in1.commitment());
    let anchor = tree.seal(0);
    let w0 = tree.witness(p0).unwrap();
    let w1 = tree.witness(p1).unwrap();

    // Build the circuit witness from the real notes (fields mapped to the
    // field-element representation the circuit hashes).
    let air = SpendAir::new_seeded();
    let inputs = [
        InputNote {
            value: in0.value,
            addr_tag: map(in0.addr_tag),
            rho: map(in0.rho),
            rseed: map(in0.rseed),
            path: to_path(&w0),
            dummy: false,
        },
        InputNote {
            value: in1.value,
            addr_tag: map(in1.addr_tag),
            rho: map(in1.rho),
            rseed: map(in1.rseed),
            path: to_path(&w1),
            dummy: false,
        },
    ];
    let outputs = [
        OutputNote {
            value: out0.value,
            addr_tag: map(out0.addr_tag),
            rho: map(out0.rho),
            rseed: map(out0.rseed),
        },
        OutputNote {
            value: out1.value,
            addr_tag: map(out1.addr_tag),
            rho: map(out1.rho),
            rseed: map(out1.rseed),
        },
    ];

    let (pi, proof) = prove_to_interface(&air, map(nk), &inputs, &outputs, 0, anchor.height);

    // The circuit's public values ARE the pipeline's Poseidon2 digests.
    assert_eq!(
        pi.anchor.root, anchor.root,
        "circuit root != tree anchor root"
    );
    assert_eq!(pi.nullifiers[0].0, in0.nullifier(&nk).0);
    assert_eq!(pi.nullifiers[1].0, in1.nullifier(&nk).0);
    assert_eq!(pi.commitments[0].0, out0.commitment().0);
    assert_eq!(pi.commitments[1].0, out1.commitment().0);

    // The frozen SpendVerifier accepts the real transaction.
    StarkSpendVerifier::new()
        .verify(&pi, &proof)
        .expect("real pipeline transaction verifies under the STARK SpendVerifier");
}
