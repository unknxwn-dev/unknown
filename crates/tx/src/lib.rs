//! Transaction wire format and stateless validation (WP9, §3.2).
//!
//! Every `TxV1` has identical shape and size (uniformity rule D9): 2 inputs,
//! 2 outputs, fixed-size encrypted payloads, fixed proof bucket. There are no
//! optional fields, so two transactions are indistinguishable on the wire
//! except by their opaque contents.

use unknown_antispam_pow::{verify as pow_verify, PowSolution};
use unknown_encryption::{EncryptedOutput, ENC_OUTPUT_LEN};
use unknown_interfaces::{
    Anchor, Commitment, Nullifier, SpendPublicInputs, SpendVerifier, PROOF_BUCKET, TX_INPUTS,
    TX_OUTPUTS,
};
use unknown_primitives::{ds, hash_parts};

const POW_BODY_LEN: usize = 8;

/// Wire-format version. v2: the proof bucket is the real 192 KiB tall-layout
/// STARK bucket (v1 carried the 192-byte dev-prover bucket). Consensus break,
/// by design — v1 encodings are rejected.
pub const TX_VERSION: u8 = 2;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TxV1 {
    pub anchor: Anchor,
    pub nullifiers: [Nullifier; TX_INPUTS],
    pub commitments: [Commitment; TX_OUTPUTS],
    pub enc_outputs: [EncryptedOutput; TX_OUTPUTS],
    pub pow: PowSolution,
    pub proof: Vec<u8>,
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum TxError {
    #[error("malformed transaction encoding")]
    Malformed,
    #[error("nullifiers not canonically sorted or duplicated")]
    NullifierOrder,
    #[error("anti-spam proof-of-work invalid")]
    PowInvalid,
    #[error("zero-knowledge proof invalid")]
    ProofInvalid,
    #[error("proof bucket size wrong")]
    ProofSize,
}

impl TxV1 {
    /// Digest binding every field except the proof and the PoW solution.
    /// The PoW commits to this digest and the proof's public inputs contain
    /// it, so any mutation of a bound field invalidates both (anti-malleability).
    pub fn binding_digest(&self) -> [u8; 32] {
        let mut parts: Vec<&[u8]> = Vec::new();
        let h = self.anchor.height.to_le_bytes();
        parts.push(&h);
        parts.push(&self.anchor.root);
        for nf in &self.nullifiers {
            parts.push(&nf.0);
        }
        for cm in &self.commitments {
            parts.push(&cm.0);
        }
        for e in &self.enc_outputs {
            parts.push(&e.bytes);
        }
        hash_parts(ds::TX_BINDING, &parts)
    }

    pub fn to_public_inputs(&self) -> SpendPublicInputs {
        SpendPublicInputs {
            anchor: self.anchor,
            nullifiers: self.nullifiers.to_vec(),
            commitments: self.commitments.to_vec(),
            binding_digest: self.binding_digest(),
            mint_value: 0, // wire transactions are always transfers
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(self.encoded_len());
        b.push(TX_VERSION);
        b.extend_from_slice(&self.anchor.height.to_le_bytes());
        b.extend_from_slice(&self.anchor.root);
        for nf in &self.nullifiers {
            b.extend_from_slice(&nf.0);
        }
        for cm in &self.commitments {
            b.extend_from_slice(&cm.0);
        }
        for e in &self.enc_outputs {
            b.extend_from_slice(&e.bytes);
        }
        b.push(0x01); // antispam tag: PoW lane
        b.extend_from_slice(&self.pow.to_bytes());
        b.extend_from_slice(&self.proof);
        b
    }

    pub fn encoded_len(&self) -> usize {
        1 + 8
            + 32
            + TX_INPUTS * 32
            + TX_OUTPUTS * 32
            + TX_OUTPUTS * ENC_OUTPUT_LEN
            + 1
            + POW_BODY_LEN
            + PROOF_BUCKET
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TxError> {
        let mut cur = 0usize;
        let take = |cur: &mut usize, n: usize| -> Result<&[u8], TxError> {
            let end = cur.checked_add(n).ok_or(TxError::Malformed)?;
            if end > bytes.len() {
                return Err(TxError::Malformed);
            }
            let s = &bytes[*cur..end];
            *cur = end;
            Ok(s)
        };

        if take(&mut cur, 1)?[0] != TX_VERSION {
            return Err(TxError::Malformed);
        }
        let height = u64::from_le_bytes(take(&mut cur, 8)?.try_into().unwrap());
        let root: [u8; 32] = take(&mut cur, 32)?.try_into().unwrap();
        let mut nullifiers = [Nullifier([0; 32]); TX_INPUTS];
        for nf in &mut nullifiers {
            nf.0 = take(&mut cur, 32)?.try_into().unwrap();
        }
        let mut commitments = [Commitment([0; 32]); TX_OUTPUTS];
        for cm in &mut commitments {
            cm.0 = take(&mut cur, 32)?.try_into().unwrap();
        }
        let enc_outputs: [EncryptedOutput; TX_OUTPUTS] = {
            let a = EncryptedOutput {
                bytes: take(&mut cur, ENC_OUTPUT_LEN)?.to_vec(),
            };
            let b = EncryptedOutput {
                bytes: take(&mut cur, ENC_OUTPUT_LEN)?.to_vec(),
            };
            [a, b]
        };
        if take(&mut cur, 1)?[0] != 0x01 {
            return Err(TxError::Malformed); // only PoW lane in v0
        }
        let pow = PowSolution::from_bytes(take(&mut cur, POW_BODY_LEN)?.try_into().unwrap());
        let proof = take(&mut cur, PROOF_BUCKET)?.to_vec();
        if cur != bytes.len() {
            return Err(TxError::Malformed); // trailing bytes
        }
        Ok(Self {
            anchor: Anchor { height, root },
            nullifiers,
            commitments,
            enc_outputs,
            pow,
            proof,
        })
    }
}

/// Stateless validation: everything checkable without ledger state
/// (§3.5 splits stateless vs. stateful). Order: cheap structural checks,
/// then PoW, then the expensive proof.
pub fn validate_stateless<V: SpendVerifier>(
    tx: &TxV1,
    verifier: &V,
    difficulty_bits: u32,
) -> Result<(), TxError> {
    if tx.proof.len() != PROOF_BUCKET {
        return Err(TxError::ProofSize);
    }
    // Canonicalization: nullifiers strictly ascending (also rejects dup within tx).
    if tx.nullifiers[0].0 >= tx.nullifiers[1].0 {
        return Err(TxError::NullifierOrder);
    }
    let binding = tx.binding_digest();
    if !pow_verify(&binding, &tx.pow, difficulty_bits) {
        return Err(TxError::PowInvalid);
    }
    let pi = tx.to_public_inputs();
    verifier
        .verify(&pi, &tx.proof)
        .map_err(|_| TxError::ProofInvalid)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tx() -> TxV1 {
        let enc = EncryptedOutput {
            bytes: vec![7u8; ENC_OUTPUT_LEN],
        };
        TxV1 {
            anchor: Anchor {
                height: 3,
                root: [1; 32],
            },
            nullifiers: [Nullifier([1; 32]), Nullifier([2; 32])],
            commitments: [Commitment([3; 32]), Commitment([4; 32])],
            enc_outputs: [enc.clone(), enc],
            pow: PowSolution { nonce: 0 },
            proof: vec![0u8; PROOF_BUCKET],
        }
    }

    #[test]
    fn codec_roundtrip() {
        let tx = sample_tx();
        let bytes = tx.encode();
        assert_eq!(bytes.len(), tx.encoded_len());
        let back = TxV1::decode(&bytes).unwrap();
        assert_eq!(tx, back);
    }

    #[test]
    fn all_txs_same_size() {
        // Uniformity: encoded length is independent of contents.
        let a = sample_tx();
        let mut b = sample_tx();
        b.anchor.height = u64::MAX;
        b.nullifiers = [Nullifier([9; 32]), Nullifier([10; 32])];
        assert_eq!(a.encode().len(), b.encode().len());
    }

    #[test]
    fn malleability_any_byte_flip_changes_binding() {
        let tx = sample_tx();
        let base = tx.binding_digest();
        let mut other = tx.clone();
        other.commitments[0].0[0] ^= 1;
        assert_ne!(base, other.binding_digest());
        let mut other2 = tx.clone();
        other2.enc_outputs[1].bytes[0] ^= 1;
        assert_ne!(base, other2.binding_digest());
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let tx = sample_tx();
        let mut bytes = tx.encode();
        bytes.push(0);
        assert_eq!(TxV1::decode(&bytes), Err(TxError::Malformed));
    }

    #[test]
    fn decode_rejects_truncation() {
        let tx = sample_tx();
        let bytes = tx.encode();
        assert_eq!(
            TxV1::decode(&bytes[..bytes.len() - 1]),
            Err(TxError::Malformed)
        );
    }

    #[test]
    fn unsorted_nullifiers_rejected() {
        use unknown_prover_dev::DevVerifier;
        let mut tx = sample_tx();
        tx.nullifiers = [Nullifier([5; 32]), Nullifier([1; 32])];
        assert_eq!(
            validate_stateless(&tx, &DevVerifier, 0),
            Err(TxError::NullifierOrder)
        );
    }
}
