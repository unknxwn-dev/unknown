//! Development prover/verifier (stands in for WP6 STARK circuit).
//!
//! ⚠ INSECURE — DEV ONLY. This is NOT zero-knowledge and NOT sound against a
//! malicious prover: the "proof" is a domain-separated tag over the public
//! inputs, which anyone can compute. Its purpose is to let the tx / state /
//! consensus / wallet pipeline run and be tested end to end TODAY while the
//! real STARK prover (engineering plan WP6) is built behind the same
//! `SpendVerifier` interface.
//!
//! The load-bearing, permanent part of this crate is [`check_spend_statement`]
//! — the native encoding of spend constraints C1–C9 (§3.3). That function is
//! the executable specification the STARK circuit must enforce, and it is what
//! the knockout/mutation harness (WP6d) attacks. Swapping the prover does not
//! change it.

use unknown_interfaces::{
    Commitment, Nullifier, ProveError, SpendPublicInputs, VerifyError, MAX_MONEY, PROOF_BUCKET,
    TX_INPUTS, TX_OUTPUTS,
};
use unknown_notes::{rho_transfer, Note};
use unknown_primitives::{ds, hash_parts};
use unknown_tree::verify_path;

#[derive(Clone)]
pub struct InputWitness {
    pub note: Note,
    pub path: unknown_interfaces::MerklePath,
    pub is_dummy: bool,
}

/// Full witness for a transfer (engineering plan §3.3).
#[derive(Clone)]
pub struct SpendWitness {
    pub spender_nk: [u8; 32],
    pub spender_addr_tag: [u8; 32],
    pub inputs: Vec<InputWitness>, // length TX_INPUTS
    pub outputs: Vec<Note>,        // length TX_OUTPUTS
    pub mint_value: u64,           // 0 for pure transfers
    pub binding_digest: [u8; 32],
}

/// Canonicalize a witness by sorting inputs ascending by nullifier. The wire
/// format sorts nullifiers (tx.rs), so the prover must use the same order or
/// the node's recomputed public inputs won't match the proof. Call this
/// before [`public_inputs`] / [`prove`]; both assume the canonical order.
pub fn canonicalize(w: &mut SpendWitness) {
    let nk = w.spender_nk;
    w.inputs.sort_by_key(|i| i.note.nullifier(&nk).0);
}

/// Derive the public inputs a witness commits to (nullifiers, commitments).
/// Assumes `w` is already canonicalized. Returns them so the verifier and tx
/// builder agree byte-for-byte.
pub fn public_inputs(w: &SpendWitness, anchor: unknown_interfaces::Anchor) -> SpendPublicInputs {
    let nullifiers: Vec<Nullifier> = w
        .inputs
        .iter()
        .map(|i| i.note.nullifier(&w.spender_nk))
        .collect();
    let commitments: Vec<Commitment> = w.outputs.iter().map(|o| o.commitment()).collect();
    SpendPublicInputs {
        anchor,
        nullifiers,
        commitments,
        binding_digest: w.binding_digest,
        mint_value: w.mint_value,
    }
}

/// Executable specification of constraints C1–C9. Returns `Ok` iff the
/// witness satisfies the spend statement for the given public inputs.
pub fn check_spend_statement(w: &SpendWitness, pi: &SpendPublicInputs) -> Result<(), ProveError> {
    use ProveError::Unsatisfied;

    // Shape (uniformity rule D9).
    if w.inputs.len() != TX_INPUTS || w.outputs.len() != TX_OUTPUTS {
        return Err(Unsatisfied("C0: wrong input/output arity"));
    }
    if pi.nullifiers.len() != TX_INPUTS || pi.commitments.len() != TX_OUTPUTS {
        return Err(Unsatisfied("C0: public input arity"));
    }
    if pi.binding_digest != w.binding_digest {
        return Err(Unsatisfied("C8: binding digest mismatch"));
    }

    let mut value_in: u128 = 0;
    for (i, input) in w.inputs.iter().enumerate() {
        // C4: dummy flag well-formed; dummies carry no value.
        if input.is_dummy && input.note.value != 0 {
            return Err(Unsatisfied("C4: dummy note must have zero value"));
        }
        // C6: range — every value < 2^62.
        if input.note.value >= MAX_MONEY {
            return Err(Unsatisfied("C6: input value out of range"));
        }
        if !input.is_dummy {
            // C1: membership in the tree at the anchor root.
            if !verify_path(&input.note.commitment(), &input.path, &pi.anchor.root) {
                return Err(Unsatisfied("C1: membership proof invalid"));
            }
            // C3: ownership — note tag matches the spender's authority.
            if input.note.addr_tag != w.spender_addr_tag {
                return Err(Unsatisfied("C3: note not owned by spender"));
            }
        }
        // C2: nullifier correctly derived from the spender's nullifier key.
        if input.note.nullifier(&w.spender_nk) != pi.nullifiers[i] {
            return Err(Unsatisfied("C2: nullifier derivation mismatch"));
        }
        value_in += input.note.value as u128;
    }

    // C5: output commitments and rho derivation.
    let first_nf = pi.nullifiers[0];
    let mut value_out: u128 = 0;
    for (i, out) in w.outputs.iter().enumerate() {
        if out.value >= MAX_MONEY {
            return Err(Unsatisfied("C6: output value out of range"));
        }
        if out.commitment() != pi.commitments[i] {
            return Err(Unsatisfied("C5: output commitment mismatch"));
        }
        // Transfer outputs must use rho bound to the first input nullifier.
        if w.mint_value == 0 && out.rho != rho_transfer(&first_nf, i as u8) {
            return Err(Unsatisfied("C5: output rho derivation invalid"));
        }
        value_out += out.value as u128;
    }

    // C6: mint value range.
    if w.mint_value as u128 >= MAX_MONEY as u128 {
        return Err(Unsatisfied("C6: mint value out of range"));
    }

    // C7: balance. Inputs + public mint == outputs.
    if value_in + w.mint_value as u128 != value_out {
        return Err(Unsatisfied("C7: value imbalance"));
    }

    Ok(())
}

fn dev_tag(pi: &SpendPublicInputs) -> [u8; 32] {
    hash_parts(ds::DEV_PROOF, &[&pi.encode()])
}

/// Produce a dev proof. Fails if the witness does not satisfy the statement,
/// so honest provers never emit proofs for invalid spends.
pub fn prove(
    w: &SpendWitness,
    anchor: unknown_interfaces::Anchor,
) -> Result<(SpendPublicInputs, Vec<u8>), ProveError> {
    let mut w = w.clone();
    canonicalize(&mut w);
    let pi = public_inputs(&w, anchor);
    check_spend_statement(&w, &pi)?;
    let mut proof = dev_tag(&pi).to_vec();
    proof.resize(PROOF_BUCKET, 0); // uniform bucket padding (D9)
    Ok((pi, proof))
}

pub struct DevVerifier;

impl unknown_interfaces::SpendVerifier for DevVerifier {
    fn verify(&self, pi: &SpendPublicInputs, proof: &[u8]) -> Result<(), VerifyError> {
        if proof.len() != PROOF_BUCKET {
            return Err(VerifyError::Malformed);
        }
        // Padding bytes must be zero (canonicalization).
        if proof[32..].iter().any(|&b| b != 0) {
            return Err(VerifyError::Malformed);
        }
        let expected = dev_tag(pi);
        if proof[..32] == expected {
            Ok(())
        } else {
            Err(VerifyError::Invalid)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unknown_interfaces::{Anchor, SpendVerifier};
    use unknown_keys::SpendingKey;
    use unknown_notes::rho_transfer;
    use unknown_tree::CommitmentTree;

    /// Build a valid 1-real-input, 1-real-output (+dummies) transfer and its
    /// surrounding tree. Returns (witness, anchor).
    fn valid_transfer() -> (SpendWitness, Anchor) {
        let sk = SpendingKey::from_seed(&[1u8; 32]);
        let nk = sk.nk();
        let tag = sk.addr_tag();

        // A real input note worth 100, placed in the tree.
        let input = Note {
            value: 100,
            addr_tag: tag,
            rho: [9; 32],
            rseed: [8; 32],
        };
        let mut tree = CommitmentTree::new();
        let pos = tree.append(input.commitment());
        let _dummy_pos = tree.append(Note::dummy([7; 32]).commitment());
        let anchor = tree.seal(0);
        let path = tree.witness(pos).unwrap();

        let dummy_in = Note::dummy([5; 32]);
        let inputs = vec![
            InputWitness {
                note: input,
                path,
                is_dummy: false,
            },
            InputWitness {
                note: dummy_in,
                path: tree.witness(0).unwrap(), // unused for dummy
                is_dummy: true,
            },
        ];

        // Compute first nullifier to derive output rho.
        let first_nf = input.nullifier(&nk);
        let recipient_tag = SpendingKey::from_seed(&[2u8; 32]).addr_tag();
        let out0 = Note {
            value: 100,
            addr_tag: recipient_tag,
            rho: rho_transfer(&first_nf, 0),
            rseed: [1; 32],
        };
        let out1 = Note {
            value: 0,
            addr_tag: tag,
            rho: rho_transfer(&first_nf, 1),
            rseed: [2; 32],
        };

        let w = SpendWitness {
            spender_nk: nk,
            spender_addr_tag: tag,
            inputs,
            outputs: vec![out0, out1],
            mint_value: 0,
            binding_digest: [3u8; 32],
        };
        (w, anchor)
    }

    #[test]
    fn valid_witness_proves_and_verifies() {
        let (w, anchor) = valid_transfer();
        let (pi, proof) = prove(&w, anchor).expect("valid witness proves");
        DevVerifier.verify(&pi, &proof).expect("dev proof verifies");
    }

    #[test]
    fn imbalanced_value_rejected() {
        let (mut w, anchor) = valid_transfer();
        w.outputs[0].value = 101; // create money from nothing
                                  // recompute commitment via prove() path -> should fail C7
        let err = prove(&w, anchor).unwrap_err();
        assert_eq!(err, ProveError::Unsatisfied("C7: value imbalance"));
    }

    #[test]
    fn forged_membership_rejected() {
        let (mut w, anchor) = valid_transfer();
        // Replace the real note with one not in the tree.
        w.inputs[0].note = Note {
            value: 100,
            addr_tag: w.spender_addr_tag,
            rho: [42; 32],
            rseed: [1; 32],
        };
        let err = prove(&w, anchor).unwrap_err();
        assert_eq!(err, ProveError::Unsatisfied("C1: membership proof invalid"));
    }

    #[test]
    fn stealing_someone_elses_note_rejected() {
        let (mut w, anchor) = valid_transfer();
        w.spender_addr_tag = SpendingKey::from_seed(&[77u8; 32]).addr_tag();
        let err = prove(&w, anchor).unwrap_err();
        // Either ownership (C3) or membership (C1) catches it; both are fatal.
        assert!(matches!(err, ProveError::Unsatisfied(_)));
    }

    #[test]
    fn verifier_rejects_tampered_public_inputs() {
        let (w, anchor) = valid_transfer();
        let (mut pi, proof) = prove(&w, anchor).unwrap();
        pi.mint_value += 1;
        assert_eq!(DevVerifier.verify(&pi, &proof), Err(VerifyError::Invalid));
    }

    #[test]
    fn verifier_rejects_nonzero_padding() {
        let (w, anchor) = valid_transfer();
        let (pi, mut proof) = prove(&w, anchor).unwrap();
        proof[PROOF_BUCKET - 1] = 1;
        assert_eq!(DevVerifier.verify(&pi, &proof), Err(VerifyError::Malformed));
    }
}
