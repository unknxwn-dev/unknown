//! Constraint knockout / mutation harness (WP6d).
//!
//! The nightmare failure of a shielded chain is *invisible inflation*: a
//! soundness bug lets someone mint money inside the pool and no observer can
//! tell (feasibility §9, §10 risk 5). The defence is to prove that every
//! constraint in the spend statement is load-bearing — that removing or
//! violating it is caught.
//!
//! This harness takes a valid witness, applies a battery of targeted
//! mutations (each violating one constraint C1–C8 from
//! [`unknown_prover_dev::check_spend_statement`]), and asserts every mutation
//! is rejected. It is the executable form of "every constraint, when removed,
//! is caught by a failing test" (engineering plan Gate B). When the STARK
//! circuit replaces the dev prover, this same battery runs against it.

use unknown_interfaces::{Anchor, MerklePath, SpendPublicInputs, MAX_MONEY, TREE_DEPTH};
use unknown_keys::SpendingKey;
use unknown_notes::{rho_transfer, Note};
use unknown_prover_dev::{check_spend_statement, public_inputs, InputWitness, SpendWitness};
use unknown_tree::CommitmentTree;

/// Outcome of one knockout entry.
#[derive(Debug, Clone)]
pub struct Knockout {
    pub mutation: &'static str,
    pub expected_constraint: &'static str,
    /// True iff the harness got the outcome it wanted (mutation rejected, or
    /// the baseline accepted).
    pub passed: bool,
    /// The constraint message that fired, if any.
    pub fired: Option<String>,
}

/// A canonical valid spend: real input worth 100 (in the tree) + a dummy,
/// paying 70 out with 30 change. Returned already canonicalized so the
/// baseline satisfies the statement.
fn baseline() -> (SpendWitness, SpendPublicInputs, Anchor) {
    let sk = SpendingKey::from_seed(&[1u8; 32]);
    let nk = sk.nk();
    let tag = sk.addr_tag();

    let input = Note {
        value: 100,
        addr_tag: tag,
        rho: [9; 32],
        rseed: [8; 32],
    };
    let mut tree = CommitmentTree::new();
    let pos = tree.append(input.commitment());
    tree.append(Note::dummy([7; 32]).commitment());
    let anchor = tree.seal(0);
    let path = tree.witness(pos).unwrap();

    let inputs = vec![
        InputWitness {
            note: input,
            path,
            is_dummy: false,
        },
        InputWitness {
            note: Note::dummy([5; 32]),
            path: empty_path(),
            is_dummy: true,
        },
    ];

    let mut nfs: Vec<_> = inputs.iter().map(|i| i.note.nullifier(&nk)).collect();
    nfs.sort_by(|a, b| a.0.cmp(&b.0));
    let first_nf = nfs[0];

    let recipient_tag = SpendingKey::from_seed(&[2u8; 32]).addr_tag();
    let out0 = Note {
        value: 70,
        addr_tag: recipient_tag,
        rho: rho_transfer(&first_nf, 0),
        rseed: [1; 32],
    };
    let out1 = Note {
        value: 30,
        addr_tag: tag,
        rho: rho_transfer(&first_nf, 1),
        rseed: [2; 32],
    };

    let mut w = SpendWitness {
        spender_nk: nk,
        spender_addr_tag: tag,
        inputs,
        outputs: vec![out0, out1],
        mint_value: 0,
        binding_digest: [3u8; 32],
    };
    unknown_prover_dev::canonicalize(&mut w);
    let pi = public_inputs(&w, anchor);
    (w, pi, anchor)
}

fn empty_path() -> MerklePath {
    MerklePath {
        position: 0,
        siblings: [[0u8; 32]; TREE_DEPTH],
    }
}

/// Expect a mutated (w, pi) to be REJECTED.
fn expect_reject(
    mutation: &'static str,
    expected: &'static str,
    w: &SpendWitness,
    pi: &SpendPublicInputs,
) -> Knockout {
    match check_spend_statement(w, pi) {
        Ok(()) => Knockout {
            mutation,
            expected_constraint: expected,
            passed: false,
            fired: None,
        },
        Err(e) => Knockout {
            mutation,
            expected_constraint: expected,
            passed: true,
            fired: Some(format!("{e}")),
        },
    }
}

/// Run the full mutation battery. Every entry must have `passed == true`.
pub fn run_knockouts() -> Vec<Knockout> {
    let mut out = Vec::new();

    // The baseline must be VALID, else the whole harness is meaningless.
    {
        let (w, pi, _) = baseline();
        let ok = check_spend_statement(&w, &pi).is_ok();
        out.push(Knockout {
            mutation: "baseline (must be valid)",
            expected_constraint: "none",
            passed: ok,
            fired: if ok {
                None
            } else {
                Some("baseline unexpectedly rejected".into())
            },
        });
    }

    // C1: corrupt the Merkle authentication path -> membership fails.
    {
        let (mut w, pi, _) = baseline();
        let idx = w.inputs.iter().position(|i| !i.is_dummy).unwrap();
        w.inputs[idx].path.siblings[0][0] ^= 0xFF;
        out.push(expect_reject(
            "C1: corrupted membership path",
            "C1",
            &w,
            &pi,
        ));
    }

    // C1: reference an anchor root that was never sealed.
    {
        let (w, mut pi, _) = baseline();
        pi.anchor.root = [0xAB; 32];
        out.push(expect_reject("C1: forged anchor root", "C1", &w, &pi));
    }

    // C2: tamper a published nullifier so it no longer matches the witness.
    {
        let (w, mut pi, _) = baseline();
        pi.nullifiers[0].0[0] ^= 0xFF;
        out.push(expect_reject("C2: tampered nullifier", "C2", &w, &pi));
    }

    // C3: claim ownership with the wrong spend authority (tag mismatch).
    {
        let (mut w, pi, _) = baseline();
        w.spender_addr_tag = SpendingKey::from_seed(&[99u8; 32]).addr_tag();
        out.push(expect_reject("C3: wrong owner tag", "C3", &w, &pi));
    }

    // C4: a dummy input carrying value (would smuggle unbacked value in).
    {
        let (mut w, _, anchor) = baseline();
        let d = w.inputs.iter().position(|i| i.is_dummy).unwrap();
        w.inputs[d].note.value = 1_000;
        let pi = public_inputs(&w, anchor); // recompute so only C4 is the violation
        out.push(expect_reject("C4: dummy with value", "C4", &w, &pi));
    }

    // C6: an input value out of range.
    {
        let (mut w, _, anchor) = baseline();
        let r = w.inputs.iter().position(|i| !i.is_dummy).unwrap();
        w.inputs[r].note.value = MAX_MONEY;
        let pi = public_inputs(&w, anchor);
        out.push(expect_reject("C6: input value out of range", "C6", &w, &pi));
    }

    // C6: an output value out of range.
    {
        let (mut w, _, anchor) = baseline();
        w.outputs[0].value = MAX_MONEY;
        let pi = public_inputs(&w, anchor);
        out.push(expect_reject(
            "C6: output value out of range",
            "C6",
            &w,
            &pi,
        ));
    }

    // C5: output commitment doesn't match the published one.
    {
        let (w, mut pi, _) = baseline();
        pi.commitments[0].0[0] ^= 0xFF;
        out.push(expect_reject(
            "C5: mismatched output commitment",
            "C5",
            &w,
            &pi,
        ));
    }

    // C5: output rho not derived from the canonical first nullifier.
    {
        let (mut w, _, anchor) = baseline();
        w.outputs[0].rho = [0x42; 32];
        let pi = public_inputs(&w, anchor); // commitment matches; rho rule violated
        out.push(expect_reject(
            "C5: bad output rho derivation",
            "C5",
            &w,
            &pi,
        ));
    }

    // C7: value imbalance — outputs exceed inputs (minting from nothing).
    {
        let (mut w, _, anchor) = baseline();
        w.outputs[0].value += 1; // 71 + 30 > 100
        let pi = public_inputs(&w, anchor); // commitments consistent; only balance breaks
        out.push(expect_reject(
            "C7: value imbalance (inflation)",
            "C7",
            &w,
            &pi,
        ));
    }

    // C8: binding digest in public inputs disagrees with the witness.
    {
        let (w, mut pi, _) = baseline();
        pi.binding_digest[0] ^= 0xFF;
        out.push(expect_reject("C8: binding digest mismatch", "C8", &w, &pi));
    }

    // C0: wrong arity — a malicious prover witnessing 1 input while claiming 2.
    {
        let (mut w, _, _) = baseline();
        w.inputs.truncate(1);
        let (_, pi_full, _) = baseline();
        out.push(expect_reject(
            "C0: input arity mismatch",
            "C0",
            &w,
            &pi_full,
        ));
    }

    out
}

/// True iff every knockout got its intended outcome.
pub fn all_caught() -> bool {
    run_knockouts().iter().all(|k| k.passed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_constraint_is_load_bearing() {
        let results = run_knockouts();
        let failures: Vec<String> = results
            .iter()
            .filter(|k| !k.passed)
            .map(|k| format!("{} (expected {})", k.mutation, k.expected_constraint))
            .collect();
        assert!(
            failures.is_empty(),
            "knockout coverage gaps — potential inflation holes:\n{}",
            failures.join("\n")
        );
        assert!(
            results.len() >= 13,
            "knockout battery unexpectedly small: {}",
            results.len()
        );
    }

    #[test]
    fn expected_constraint_fires_where_isolable() {
        // For cleanly-isolated mutations, assert the SPECIFIC constraint fired.
        for k in run_knockouts() {
            if let Some(msg) = &k.fired {
                if matches!(k.expected_constraint, "C2" | "C7" | "C8" | "C4") {
                    assert!(
                        msg.contains(k.expected_constraint),
                        "{}: expected {} but got: {}",
                        k.mutation,
                        k.expected_constraint,
                        msg
                    );
                }
            }
        }
    }
}
