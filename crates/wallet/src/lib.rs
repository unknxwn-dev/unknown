//! Wallet: scanning, note management, transaction building (WP14).
//!
//! Decoupled from ledger internals: it tracks its own notes and builds
//! transactions given an anchor and a witness-lookup callback (the node
//! provides witnesses; engineering plan §3.6 forbids per-note queries, so the
//! integrated node feeds witnesses for positions the wallet already knows from
//! scanning its own outputs).
//!
//! Proving is the real thing: the wallet maps its notes and tree witnesses to
//! the tall STARK spend circuit's witness and produces a `PROOF_BUCKET`-padded
//! proof that [`unknown_circuit_spend::verifier::StarkSpendVerifier`] accepts.

use std::collections::HashSet;
use unknown_antispam_pow::{solve, PowSolution};
use unknown_circuit_spend::spend::{InputNote, OutputNote};
use unknown_circuit_spend::tall_spend::TallSpendAir;
use unknown_circuit_spend::verifier::prove_to_interface;
use unknown_encryption::{encrypt_note, try_decrypt, EncryptedOutput};
use unknown_interfaces::{Anchor, MerklePath, Nullifier, TREE_DEPTH, TX_INPUTS, TX_OUTPUTS};
use unknown_keys::{Address, SpendingKey};
use unknown_notes::{rho_transfer, Note, MEMO_LEN};
use unknown_poseidon as poseidon;
use unknown_tx::TxV1;

#[derive(Clone, Debug)]
pub struct NoteRecord {
    pub note: Note,
    pub position: u64,
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum WalletError {
    #[error("insufficient funds: have {have}, need {need}")]
    InsufficientFunds { have: u64, need: u64 },
    #[error("amount not coverable by {TX_INPUTS} notes; consolidate first")]
    TooManyInputsNeeded,
    #[error("missing witness for note at position {0}")]
    MissingWitness(u64),
    #[error("proof generation failed: {0}")]
    Prove(&'static str),
}

pub struct Wallet {
    sk: SpendingKey,
    unspent: Vec<NoteRecord>,
    seen_nullifiers: HashSet<Nullifier>,
}

impl Wallet {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            sk: SpendingKey::from_seed(seed),
            unspent: Vec::new(),
            seen_nullifiers: HashSet::new(),
        }
    }

    pub fn address(&self) -> Address {
        self.sk.address()
    }

    pub fn balance(&self) -> u64 {
        self.unspent.iter().map(|r| r.note.value).sum()
    }

    pub fn note_count(&self) -> usize {
        self.unspent.len()
    }

    /// Try to receive one on-chain output at a known tree position. Returns
    /// true if it decrypted to one of our notes.
    pub fn try_receive(&mut self, enc: &EncryptedOutput, position: u64) -> bool {
        let ivk = self.sk.incoming_viewing_key();
        if let Some(note) = try_decrypt(enc, &ivk) {
            // Ignore zero-value (dummy/change-to-self of 0) to keep the set tidy.
            if note.value > 0 {
                self.unspent.push(NoteRecord { note, position });
            }
            return true;
        }
        false
    }

    /// Process revealed nullifiers from a checkpoint: drop any of our notes
    /// that have been spent (by us or — impossible without our key — anyone).
    pub fn observe_nullifiers(&mut self, nullifiers: &[Nullifier]) {
        let nk = self.sk.nk();
        for nf in nullifiers {
            self.seen_nullifiers.insert(*nf);
        }
        self.unspent
            .retain(|r| !self.seen_nullifiers.contains(&r.note.nullifier(&nk)));
    }

    /// Select 1 or 2 unspent notes covering `amount`. Greedy: prefer a single
    /// note ≥ amount, else the two largest.
    fn select_inputs(&self, amount: u64) -> Result<Vec<NoteRecord>, WalletError> {
        let total = self.balance();
        if total < amount {
            return Err(WalletError::InsufficientFunds {
                have: total,
                need: amount,
            });
        }
        if let Some(r) = self
            .unspent
            .iter()
            .filter(|r| r.note.value >= amount)
            .min_by_key(|r| r.note.value)
        {
            return Ok(vec![r.clone()]);
        }
        let mut sorted = self.unspent.clone();
        sorted.sort_by_key(|r| std::cmp::Reverse(r.note.value));
        let pair: Vec<NoteRecord> = sorted.into_iter().take(TX_INPUTS).collect();
        if pair.iter().map(|r| r.note.value).sum::<u64>() < amount {
            return Err(WalletError::TooManyInputsNeeded);
        }
        Ok(pair)
    }

    /// Build a transfer of `amount` to `recipient`. Change returns to self.
    /// `witness_for` resolves a tree position to its authentication path
    /// against `anchor`.
    pub fn build_transfer<F>(
        &self,
        recipient: &Address,
        amount: u64,
        anchor: Anchor,
        witness_for: F,
        rng_seed: [u8; 32],
    ) -> Result<TxV1, WalletError>
    where
        F: Fn(u64) -> Option<MerklePath>,
    {
        let nk = self.sk.nk();
        let tag = self.sk.addr_tag();
        let selected = self.select_inputs(amount)?;
        let input_value: u64 = selected.iter().map(|r| r.note.value).sum();
        let change = input_value - amount;

        // Build the input notes, padding to TX_INPUTS with dummies. A dummy is
        // a zero-value note addressed to ourselves (the circuit's ownership
        // constraint C3 covers every input, dummies included) with fresh
        // per-transaction entropy, so its published nullifier is unlinkable
        // across transactions.
        let mut inputs: Vec<(Note, MerklePath, bool)> = Vec::with_capacity(TX_INPUTS);
        for r in &selected {
            let path = witness_for(r.position).ok_or(WalletError::MissingWitness(r.position))?;
            inputs.push((r.note, path, false));
        }
        let mut dummy_ctr = 0u8;
        while inputs.len() < TX_INPUTS {
            let dummy = Note {
                value: 0,
                addr_tag: tag,
                rho: derive_rseed(&rng_seed, 0xD0 ^ dummy_ctr),
                rseed: derive_rseed(&rng_seed, 0xE0 ^ dummy_ctr),
            };
            inputs.push((dummy, empty_path(), true));
            dummy_ctr += 1;
        }

        // Canonical order: the wire format sorts nullifiers ascending, and the
        // circuit binds nullifier i to input i — so sort inputs by nullifier.
        inputs.sort_by_key(|(note, _, _)| note.nullifier(&nk).0);
        let nfs: Vec<Nullifier> = inputs
            .iter()
            .map(|(note, _, _)| note.nullifier(&nk))
            .collect();
        let first_nf = nfs[0];

        let memo = [0u8; MEMO_LEN];
        let out_recipient = Note {
            value: amount,
            addr_tag: recipient.addr_tag,
            rho: rho_transfer(&first_nf, 0),
            rseed: derive_rseed(&rng_seed, 0),
        };
        let out_change = Note {
            value: change,
            addr_tag: tag,
            rho: rho_transfer(&first_nf, 1),
            rseed: derive_rseed(&rng_seed, 1),
        };
        let outputs = [out_recipient, out_change];

        // Encrypt outputs (change goes to our own address).
        let my_addr = self.sk.address();
        let enc0 = encrypt_note(
            &out_recipient,
            recipient,
            &memo,
            derive_rseed(&rng_seed, 10),
        );
        let enc1 = encrypt_note(&out_change, &my_addr, &memo, derive_rseed(&rng_seed, 11));

        // Compute binding digest over the (proof-independent) tx body, then prove.
        let commitments = [out_recipient.commitment(), out_change.commitment()];
        let sorted_nfs: [Nullifier; TX_OUTPUTS] = [nfs[0], nfs[1]];
        let partial = TxV1 {
            anchor,
            nullifiers: sorted_nfs,
            commitments,
            enc_outputs: [enc0.clone(), enc1.clone()],
            pow: PowSolution { nonce: 0 },
            proof: vec![0u8; unknown_interfaces::PROOF_BUCKET],
        };
        let binding = partial.binding_digest();

        // Map the witness to the STARK circuit's field representation and prove.
        let circuit_inputs: [InputNote; TX_INPUTS] = core::array::from_fn(|i| {
            let (note, path, dummy) = &inputs[i];
            InputNote {
                value: note.value,
                addr_tag: poseidon::bytes_to_field(note.addr_tag),
                rho: poseidon::bytes_to_field(note.rho),
                rseed: poseidon::bytes_to_field(note.rseed),
                path: (0..TREE_DEPTH)
                    .map(|l| {
                        (
                            poseidon::unpack(path.siblings[l]),
                            (path.position >> l) & 1 == 1,
                        )
                    })
                    .collect(),
                dummy: *dummy,
            }
        });
        let circuit_outputs: [OutputNote; TX_OUTPUTS] = core::array::from_fn(|j| OutputNote {
            value: outputs[j].value,
            addr_tag: poseidon::bytes_to_field(outputs[j].addr_tag),
            rho: poseidon::bytes_to_field(outputs[j].rho),
            rseed: poseidon::bytes_to_field(outputs[j].rseed),
        });
        let air = TallSpendAir::new_seeded();
        let (pi, mut proof) = prove_to_interface(
            &air,
            poseidon::bytes_to_field(nk),
            &circuit_inputs,
            &circuit_outputs,
            0,
            anchor.height,
        );
        // The circuit's public digests must equal the tx body we committed to.
        if pi.anchor.root != anchor.root
            || pi.nullifiers != sorted_nfs
            || pi.commitments != commitments
        {
            return Err(WalletError::Prove("circuit public values diverge from tx"));
        }
        // Pad to the uniform proof bucket (D9); the verifier requires the
        // padding to be all-zero.
        if proof.len() > unknown_interfaces::PROOF_BUCKET {
            return Err(WalletError::Prove("proof exceeds PROOF_BUCKET"));
        }
        proof.resize(unknown_interfaces::PROOF_BUCKET, 0);

        let pow = solve(&binding, 0); // dev difficulty 0; node enforces its param
        Ok(TxV1 {
            anchor,
            nullifiers: sorted_nfs,
            commitments,
            enc_outputs: [enc0, enc1],
            pow,
            proof,
        })
    }
}

fn empty_path() -> MerklePath {
    MerklePath {
        position: 0,
        siblings: [[0u8; 32]; unknown_interfaces::TREE_DEPTH],
    }
}

fn derive_rseed(seed: &[u8; 32], idx: u8) -> [u8; 32] {
    unknown_primitives::hash_parts("unknown.v0.wallet.rseed", &[seed, &[idx]])
}

#[cfg(test)]
mod tests {
    use super::*;
    use unknown_tree::CommitmentTree;

    #[test]
    fn end_to_end_transfer_verifies() {
        // Alice has a note worth 100 in the tree; she sends 30 to Bob.
        let alice = Wallet::from_seed(&[1u8; 32]);
        let bob = Wallet::from_seed(&[2u8; 32]);
        let alice_note = Note {
            value: 100,
            addr_tag: alice.address().addr_tag,
            rho: [9; 32],
            rseed: [8; 32],
        };

        let mut tree = CommitmentTree::new();
        let pos = tree.append(alice_note.commitment());
        let anchor = tree.seal(0);

        let mut alice = alice;
        alice.unspent.push(NoteRecord {
            note: alice_note,
            position: pos,
        });

        let tx = alice
            .build_transfer(&bob.address(), 30, anchor, |p| tree.witness(p), [42u8; 32])
            .expect("build transfer");

        // Node-side stateless validation passes under the real STARK verifier.
        use unknown_circuit_spend::verifier::StarkSpendVerifier;
        unknown_tx::validate_stateless(&tx, &StarkSpendVerifier::new(), 0).expect("tx valid");

        // Bob can receive output 0 (recipient); Alice receives change.
        let mut bob = bob;
        assert!(bob.try_receive(&tx.enc_outputs[0], 1));
        assert_eq!(bob.balance(), 30);

        let mut alice2 = Wallet::from_seed(&[1u8; 32]);
        assert!(alice2.try_receive(&tx.enc_outputs[1], 2));
        assert_eq!(alice2.balance(), 70);
    }

    #[test]
    fn insufficient_funds() {
        let alice = Wallet::from_seed(&[1u8; 32]);
        let bob = Wallet::from_seed(&[2u8; 32]);
        let tree = CommitmentTree::new();
        let anchor = Anchor {
            height: 0,
            root: tree.root(),
        };
        let err = alice
            .build_transfer(&bob.address(), 10, anchor, |p| tree.witness(p), [0u8; 32])
            .unwrap_err();
        assert_eq!(err, WalletError::InsufficientFunds { have: 0, need: 10 });
    }

    #[test]
    fn spending_marks_note_consumed() {
        let alice_note = Note {
            value: 50,
            addr_tag: Wallet::from_seed(&[1u8; 32]).address().addr_tag,
            rho: [1; 32],
            rseed: [2; 32],
        };
        let mut alice = Wallet::from_seed(&[1u8; 32]);
        alice.unspent.push(NoteRecord {
            note: alice_note,
            position: 0,
        });
        assert_eq!(alice.balance(), 50);
        let nf = alice_note.nullifier(&alice.sk.nk());
        alice.observe_nullifiers(&[nf]);
        assert_eq!(alice.balance(), 0);
    }
}
