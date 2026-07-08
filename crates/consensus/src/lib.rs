//! Deterministic BFT-DAG consensus model (WP11 core).
//!
//! A real deployment runs AlephBFT/Mysticeti over libp2p (engineering plan
//! WP11/WP12). That machinery produces one thing the ledger cares about: a
//! **committed total order** of transactions per checkpoint, identical on every
//! honest node. This crate models exactly that contract — without the async
//! networking — so the safety-critical interaction between consensus ordering
//! and the shielded state machine (nullifier conflicts, anchor sealing,
//! deterministic replay) can be tested directly.
//!
//! The commit rule here is "dedup this round's transactions and order them by
//! binding digest". Any deterministic function of the transaction set gives the
//! same guarantees; BFT's job is to make honest nodes agree on the *set* and a
//! *canonical order*, which is what we assume. The properties tested — agreement
//! across replicas, order-independence of submission, single-winner
//! double-spend resolution, cross-round replay rejection — are the Gate-C
//! criteria and do not depend on the specific ordering rule.

use unknown_emission::EmissionParams;
use unknown_interfaces::SpendVerifier;
use unknown_state::{CheckpointSummary, Ledger, RejectReason, ValidatorInfo};
use unknown_tx::TxV1;

/// Canonical commit order for a round: dedup by binding digest, then order by
/// it. This is the linearization every honest validator computes from the same
/// set (a BTreeMap keyed by digest iterates in digest order).
pub fn commit_order(submitted: &[TxV1]) -> Vec<TxV1> {
    let mut seen = std::collections::BTreeMap::new();
    for tx in submitted {
        seen.entry(tx.binding_digest())
            .or_insert_with(|| tx.clone());
    }
    seen.into_values().collect()
}

#[derive(Debug)]
pub struct RoundOutcome {
    pub height: u64,
    pub root: [u8; 32],
    pub accepted: usize,
    pub rejected: Vec<(usize, RejectReason)>,
    pub total_supply: u64,
    /// True iff every replica produced an identical anchor, accept count and
    /// supply — the BFT agreement / safety property.
    pub agreed: bool,
}

/// A cluster of validator replicas, each with an independent ledger, kept in
/// lockstep by feeding them the same committed order every round.
pub struct Cluster {
    replicas: Vec<Ledger>,
    genesis_supply: u64,
}

impl Cluster {
    pub fn new(
        n: usize,
        emission: EmissionParams,
        validators: Vec<ValidatorInfo>,
        difficulty_bits: u32,
        genesis_notes: &[(unknown_interfaces::Commitment, u64)],
    ) -> Self {
        let genesis_supply = genesis_notes.iter().map(|(_, v)| v).sum();
        let replicas = (0..n)
            .map(|_| Ledger::genesis(emission, validators.clone(), difficulty_bits, genesis_notes))
            .collect();
        Self {
            replicas,
            genesis_supply,
        }
    }

    pub fn genesis_supply(&self) -> u64 {
        self.genesis_supply
    }

    /// The current anchor all replicas agree on (replica 0 is representative;
    /// agreement is asserted every round).
    pub fn anchor(&self) -> unknown_interfaces::Anchor {
        self.replicas[0].current_anchor()
    }

    pub fn tree_witness(&self, pos: u64) -> Option<unknown_interfaces::MerklePath> {
        self.replicas[0].tree_witness(pos)
    }

    /// Commit one checkpoint: linearize the submitted transactions and apply
    /// the identical order to every replica, then check they agree.
    pub fn commit_round<V: SpendVerifier>(
        &mut self,
        submitted: &[TxV1],
        verifier: &V,
    ) -> RoundOutcome {
        let ordered = commit_order(submitted);
        let summaries: Vec<CheckpointSummary> = self
            .replicas
            .iter_mut()
            .map(|r| r.apply_checkpoint(&ordered, verifier))
            .collect();

        let first = &summaries[0];
        let agreed = summaries.iter().all(|s| {
            s.anchor.root == first.anchor.root
                && s.accepted == first.accepted
                && s.total_supply == first.total_supply
                && s.height == first.height
        });

        RoundOutcome {
            height: first.height,
            root: first.anchor.root,
            accepted: first.accepted,
            rejected: first.rejected.clone(),
            total_supply: first.total_supply,
            agreed,
        }
    }

    /// Audit supply on every replica (must all hold).
    pub fn audit(&self) -> bool {
        self.replicas
            .iter()
            .all(|r| r.audit_supply(self.genesis_supply))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unknown_antispam_pow::{solve, PowSolution};
    use unknown_encryption::{EncryptedOutput, ENC_OUTPUT_LEN};
    use unknown_interfaces::{Anchor, Commitment, Nullifier, SpendPublicInputs, PROOF_BUCKET};
    use unknown_primitives::{ds, hash_parts};
    use unknown_prover_dev::DevVerifier;

    fn params() -> EmissionParams {
        EmissionParams::new(1_000, 100, 50)
    }
    fn validators() -> Vec<ValidatorInfo> {
        vec![ValidatorInfo {
            weight: 1,
            addr_tag: [7; 32],
        }]
    }
    fn cluster(n: usize) -> Cluster {
        Cluster::new(
            n,
            params(),
            validators(),
            0,
            &[(Commitment([1; 32]), 1_000_000)],
        )
    }

    /// A structurally-valid dev-proof tx spending the given nullifiers against
    /// `anchor`. (Dev prover is intentionally not sound; we test ordering and
    /// conflict logic, which don't depend on proof soundness.)
    fn dev_tx(anchor: Anchor, nf_a: u8, nf_b: u8, salt: u8) -> TxV1 {
        let enc = EncryptedOutput {
            bytes: vec![salt; ENC_OUTPUT_LEN],
        };
        let nullifiers = [Nullifier([nf_a; 32]), Nullifier([nf_b; 32])];
        let commitments = [Commitment([salt; 32]), Commitment([salt ^ 0xF0; 32])];
        let mut tx = TxV1 {
            anchor,
            nullifiers,
            commitments,
            enc_outputs: [enc.clone(), enc],
            pow: PowSolution { nonce: 0 },
            proof: vec![0u8; PROOF_BUCKET],
        };
        let pi = SpendPublicInputs {
            anchor,
            nullifiers: nullifiers.to_vec(),
            commitments: commitments.to_vec(),
            binding_digest: tx.binding_digest(),
            mint_value: 0,
        };
        let mut proof = hash_parts(ds::DEV_PROOF, &[&pi.encode()]).to_vec();
        proof.resize(PROOF_BUCKET, 0);
        tx.proof = proof;
        tx.pow = solve(&tx.binding_digest(), 0);
        tx
    }

    #[test]
    fn all_replicas_agree_and_audit() {
        let mut c = cluster(5);
        let a = c.anchor();
        let outcome = c.commit_round(&[dev_tx(a, 1, 2, 10), dev_tx(a, 3, 4, 11)], &DevVerifier);
        assert!(outcome.agreed, "5 replicas must reach identical state");
        assert_eq!(outcome.accepted, 2);
        assert!(c.audit());
    }

    #[test]
    fn submission_order_does_not_change_committed_state() {
        // Two clusters, same transactions submitted in opposite orders, must
        // seal byte-identical roots (deterministic linearization).
        let a_tx = |anchor| dev_tx(anchor, 1, 2, 20);
        let b_tx = |anchor| dev_tx(anchor, 3, 4, 21);

        let mut c1 = cluster(1);
        let an1 = c1.anchor();
        let o1 = c1.commit_round(&[a_tx(an1), b_tx(an1)], &DevVerifier);

        let mut c2 = cluster(1);
        let an2 = c2.anchor();
        let o2 = c2.commit_round(&[b_tx(an2), a_tx(an2)], &DevVerifier);

        assert_eq!(
            o1.root, o2.root,
            "submission order must not affect committed root"
        );
        assert_eq!(o1.accepted, o2.accepted);
    }

    #[test]
    fn double_spend_has_exactly_one_winner_networkwide() {
        // Two conflicting txs sharing nullifier 9, delivered together (as if
        // gossiped to different validators). Exactly one is accepted, and every
        // replica agrees on which.
        let mut c = cluster(4);
        let a = c.anchor();
        let conflict_a = dev_tx(a, 9, 10, 30);
        let conflict_b = dev_tx(a, 9, 11, 31);
        let outcome = c.commit_round(&[conflict_a, conflict_b], &DevVerifier);
        assert!(outcome.agreed);
        assert_eq!(
            outcome.accepted, 1,
            "double-spend must yield a single winner"
        );
        assert_eq!(outcome.rejected.len(), 1);
        assert!(matches!(outcome.rejected[0].1, RejectReason::DoubleSpend));
    }

    #[test]
    fn spent_nullifier_cannot_be_replayed_next_round() {
        let mut c = cluster(3);
        let a = c.anchor();
        let first = c.commit_round(&[dev_tx(a, 40, 41, 50)], &DevVerifier);
        assert_eq!(first.accepted, 1);
        assert!(first.agreed);

        // Replay the same nullifiers against a fresh (valid) anchor next round.
        let a2 = c.anchor();
        let replay = c.commit_round(&[dev_tx(a2, 40, 41, 50)], &DevVerifier);
        assert_eq!(replay.accepted, 0, "committed nullifier must stay spent");
        assert!(matches!(replay.rejected[0].1, RejectReason::DoubleSpend));
        assert!(replay.agreed);
    }

    #[test]
    fn partition_then_heal_converges() {
        // Two clusters fed the same merged transaction set in opposite orders
        // must reach byte-identical state — modelling partition heal, where
        // the reconciled canonical order is what every node ends up applying.
        let mut healed = cluster(1);
        let ha = healed.anchor();
        let merged = healed.commit_round(
            &[dev_tx(ha, 60, 61, 70), dev_tx(ha, 62, 63, 71)],
            &DevVerifier,
        );
        assert_eq!(merged.accepted, 2);

        let mut mirror = cluster(1);
        let ma = mirror.anchor();
        let mirror_out = mirror.commit_round(
            &[dev_tx(ma, 62, 63, 71), dev_tx(ma, 60, 61, 70)],
            &DevVerifier,
        );
        assert_eq!(
            merged.root, mirror_out.root,
            "healed state must be canonical"
        );
    }

    #[test]
    fn byzantine_invalid_proof_is_dropped_without_breaking_agreement() {
        let mut c = cluster(3);
        let a = c.anchor();
        let good = dev_tx(a, 80, 81, 90);
        let mut bad = dev_tx(a, 82, 83, 91);
        bad.proof[0] ^= 0xFF; // corrupt the dev proof tag
        let outcome = c.commit_round(&[good, bad], &DevVerifier);
        assert!(outcome.agreed, "invalid tx must not desynchronize replicas");
        assert_eq!(outcome.accepted, 1, "only the valid tx is committed");
        assert!(outcome
            .rejected
            .iter()
            .any(|(_, r)| matches!(r, RejectReason::StatelessInvalid)));
    }
}
