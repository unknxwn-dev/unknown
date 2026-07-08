//! Transaction wire format and stateless validation (WP9, §3.2).
//!
//! Every `TxV1` has identical shape and size (uniformity rule D9): 2 inputs,
//! 2 outputs, fixed-size encrypted payloads, fixed proof bucket, and a
//! fixed-size anti-spam body. Two transactions are indistinguishable on the wire
//! except by their opaque contents and a single anti-spam **lane tag**.
//!
//! Anti-spam has two lanes (feasibility §7, specs/emission.md §7.2): `Pow` (a
//! hashcash puzzle, for stakeless bootstrap users) and `Quota` (an RLN
//! rate-proof against a staked quota note; the primary lane). The lane tag
//! leaks only which lane was used (staker vs. bootstrap); both bodies are
//! padded to the same length so transaction size never varies.

use unknown_antispam_pow::{verify as pow_verify, PowSolution};
use unknown_antispam_quota::{message_x, RateProof, RATE_PROOF_LEN};
use unknown_encryption::{EncryptedOutput, ENC_OUTPUT_LEN};
use unknown_interfaces::{
    Anchor, Commitment, Nullifier, SpendPublicInputs, SpendVerifier, PROOF_BUCKET, TX_INPUTS,
    TX_OUTPUTS,
};
use unknown_primitives::{ds, hash_parts};

/// Fixed anti-spam body size = max over lanes (quota is the larger, 56 bytes);
/// the PoW lane's 8-byte solution is zero-padded to this so tx size is uniform.
const ANTISPAM_BODY_LEN: usize = RATE_PROOF_LEN;
const POW_TAG: u8 = 0x01;
const QUOTA_TAG: u8 = 0x02;

/// Which anti-spam lane a transaction used.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AntiSpam {
    Pow(PowSolution),
    Quota(RateProof),
}

impl AntiSpam {
    fn tag(&self) -> u8 {
        match self {
            AntiSpam::Pow(_) => POW_TAG,
            AntiSpam::Quota(_) => QUOTA_TAG,
        }
    }

    /// Fixed-length body (zero-padded for the smaller PoW lane).
    fn body(&self) -> [u8; ANTISPAM_BODY_LEN] {
        let mut b = [0u8; ANTISPAM_BODY_LEN];
        match self {
            AntiSpam::Pow(sol) => b[..8].copy_from_slice(&sol.to_bytes()),
            AntiSpam::Quota(rp) => b.copy_from_slice(&rp.to_bytes()),
        }
        b
    }

    fn from_wire(tag: u8, body: &[u8; ANTISPAM_BODY_LEN]) -> Result<Self, TxError> {
        match tag {
            POW_TAG => {
                // Canonicalization: padding beyond the 8-byte solution must be zero.
                if body[8..].iter().any(|&x| x != 0) {
                    return Err(TxError::Malformed);
                }
                Ok(AntiSpam::Pow(PowSolution::from_bytes(
                    body[..8].try_into().unwrap(),
                )))
            }
            QUOTA_TAG => Ok(AntiSpam::Quota(RateProof::from_bytes(body))),
            _ => Err(TxError::Malformed),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TxV1 {
    pub anchor: Anchor,
    pub nullifiers: [Nullifier; TX_INPUTS],
    pub commitments: [Commitment; TX_OUTPUTS],
    pub enc_outputs: [EncryptedOutput; TX_OUTPUTS],
    pub antispam: AntiSpam,
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
    #[error("anti-spam quota rate-proof not bound to this transaction")]
    QuotaInvalid,
    #[error("zero-knowledge proof invalid")]
    ProofInvalid,
    #[error("proof bucket size wrong")]
    ProofSize,
}

impl TxV1 {
    /// Digest binding every field except the proof and the anti-spam body.
    /// Both the anti-spam artifact and the proof's public inputs commit to this
    /// digest, so any mutation of a bound field invalidates them (anti-malleability).
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
        b.push(1u8); // version
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
        b.push(self.antispam.tag());
        b.extend_from_slice(&self.antispam.body());
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
            + ANTISPAM_BODY_LEN
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

        if take(&mut cur, 1)?[0] != 1 {
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
        let tag = take(&mut cur, 1)?[0];
        let body: [u8; ANTISPAM_BODY_LEN] = take(&mut cur, ANTISPAM_BODY_LEN)?.try_into().unwrap();
        let antispam = AntiSpam::from_wire(tag, &body)?;
        let proof = take(&mut cur, PROOF_BUCKET)?.to_vec();
        if cur != bytes.len() {
            return Err(TxError::Malformed); // trailing bytes
        }
        Ok(Self {
            anchor: Anchor { height, root },
            nullifiers,
            commitments,
            enc_outputs,
            antispam,
            proof,
        })
    }
}

/// Stateless validation: everything checkable without ledger state
/// (§3.5 splits stateless vs. stateful). Order: cheap structural checks, then
/// anti-spam, then the expensive proof. The quota lane's rate-limiting and
/// slashing are STATEFUL (handled in `crates/state`); here we only bind the
/// rate proof's share to this transaction.
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
    match &tx.antispam {
        AntiSpam::Pow(sol) => {
            if !pow_verify(&binding, sol, difficulty_bits) {
                return Err(TxError::PowInvalid);
            }
        }
        AntiSpam::Quota(rp) => {
            // The Shamir share must evaluate at x = H(binding), binding the
            // rate proof to THIS transaction (else a proof could be replayed
            // onto a different tx body).
            if rp.x != message_x(&binding) {
                return Err(TxError::QuotaInvalid);
            }
        }
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
            antispam: AntiSpam::Pow(PowSolution { nonce: 0 }),
            proof: vec![0u8; PROOF_BUCKET],
        }
    }

    fn sample_quota_tx() -> TxV1 {
        let mut tx = sample_tx();
        tx.antispam = AntiSpam::Quota(RateProof {
            epoch: 5,
            rate_nullifier: [9; 32],
            x: 123,
            y: 456,
        });
        tx
    }

    #[test]
    fn codec_roundtrip_pow() {
        let tx = sample_tx();
        let bytes = tx.encode();
        assert_eq!(bytes.len(), tx.encoded_len());
        assert_eq!(TxV1::decode(&bytes).unwrap(), tx);
    }

    #[test]
    fn codec_roundtrip_quota() {
        let tx = sample_quota_tx();
        let bytes = tx.encode();
        assert_eq!(bytes.len(), tx.encoded_len());
        assert_eq!(TxV1::decode(&bytes).unwrap(), tx);
    }

    #[test]
    fn both_lanes_same_size() {
        // Uniformity: PoW and quota transactions are byte-length identical.
        assert_eq!(sample_tx().encode().len(), sample_quota_tx().encode().len());
    }

    #[test]
    fn all_txs_same_size() {
        let a = sample_tx();
        let mut b = sample_tx();
        b.anchor.height = u64::MAX;
        b.nullifiers = [Nullifier([9; 32]), Nullifier([10; 32])];
        assert_eq!(a.encode().len(), b.encode().len());
    }

    #[test]
    fn antispam_body_excluded_from_binding() {
        // Changing the anti-spam artifact must NOT change the binding digest
        // (else the PoW/quota proof, which commits to it, would be circular).
        let pow = sample_tx();
        let quota = sample_quota_tx();
        assert_eq!(pow.binding_digest(), quota.binding_digest());
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
    fn decode_rejects_nonzero_pow_padding() {
        let tx = sample_tx();
        let mut bytes = tx.encode();
        // The anti-spam body sits right after the 1-byte lane tag; flip a pad byte.
        let body_start = tx.encoded_len() - PROOF_BUCKET - ANTISPAM_BODY_LEN;
        bytes[body_start + 20] = 1; // within padding of the PoW lane
        assert_eq!(TxV1::decode(&bytes), Err(TxError::Malformed));
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
