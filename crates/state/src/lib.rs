//! Checkpoint state machine (WP10, engineering plan §3.5).
//!
//! Drives the ledger forward one committed checkpoint at a time. The consensus
//! layer (WP11) supplies a total order of transactions; this module applies
//! them deterministically: reject double-spends and stale anchors, append
//! output commitments, mint validator rewards with public amounts, seal a new
//! anchor. Replaying the same ordered input on any node yields an identical
//! state root (consensus safety depends on this).

use std::collections::HashSet;
use unknown_emission::{reward_descriptor, EmissionParams, RewardDescriptor};
use unknown_interfaces::{Anchor, Commitment, Nullifier, SpendVerifier};
use unknown_notes::{rho_mint, Note};
use unknown_tree::CommitmentTree;
use unknown_tx::{validate_stateless, TxV1};

#[derive(Clone, Debug)]
pub struct ValidatorInfo {
    pub weight: u64,
    /// Address tag reward notes are minted to (registered out of band).
    pub addr_tag: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RejectReason {
    StaleOrUnknownAnchor,
    DoubleSpend,
    StatelessInvalid,
}

#[derive(Debug)]
pub struct CheckpointSummary {
    pub height: u64,
    pub anchor: Anchor,
    pub accepted: usize,
    pub rejected: Vec<(usize, RejectReason)>,
    pub rewards: RewardDescriptor,
    pub total_supply: u64,
    /// Tree positions assigned to accepted transactions' output commitments,
    /// in commit order (TX_OUTPUTS per accepted tx). Lets the node map each
    /// accepted tx's encrypted outputs to positions for wallet scanning.
    pub output_positions: Vec<u64>,
}

pub struct Ledger {
    tree: CommitmentTree,
    nullifiers: HashSet<Nullifier>,
    height: u64,
    supply: u64,
    emission: EmissionParams,
    validators: Vec<ValidatorInfo>,
    difficulty_bits: u32,
}

impl Ledger {
    /// Create a ledger with a genesis allocation. `genesis_notes` are the
    /// initial spendable note commitments; their total value is the genesis
    /// supply. Seals anchor at height 0.
    pub fn genesis(
        emission: EmissionParams,
        validators: Vec<ValidatorInfo>,
        difficulty_bits: u32,
        genesis_notes: &[(Commitment, u64)],
    ) -> Self {
        let mut tree = CommitmentTree::new();
        let mut supply = 0u64;
        for (cm, value) in genesis_notes {
            tree.append(*cm);
            supply += value;
        }
        tree.seal(0);
        Self {
            tree,
            nullifiers: HashSet::new(),
            height: 0,
            supply,
            emission,
            validators,
            difficulty_bits,
        }
    }

    pub fn height(&self) -> u64 {
        self.height
    }
    pub fn total_supply(&self) -> u64 {
        self.supply
    }
    pub fn current_anchor(&self) -> Anchor {
        Anchor {
            height: self.height,
            root: self.tree.root(),
        }
    }
    pub fn nullifier_seen(&self, nf: &Nullifier) -> bool {
        self.nullifiers.contains(nf)
    }

    /// Apply one checkpoint of ordered transactions (§3.5).
    pub fn apply_checkpoint<V: SpendVerifier>(
        &mut self,
        ordered: &[TxV1],
        verifier: &V,
    ) -> CheckpointSummary {
        let next_height = self.height + 1;
        let mut staged_nf: Vec<Nullifier> = Vec::new();
        let mut staged_cm: Vec<Commitment> = Vec::new();
        let mut seen_this_checkpoint: HashSet<Nullifier> = HashSet::new();
        let mut accepted = 0usize;
        let mut rejected = Vec::new();

        for (i, tx) in ordered.iter().enumerate() {
            // Stateful: anchor must be sealed and within the validity window.
            if !self.tree.anchor_valid(&tx.anchor) {
                rejected.push((i, RejectReason::StaleOrUnknownAnchor));
                continue;
            }
            // Stateless: structure, PoW, proof.
            if validate_stateless(tx, verifier, self.difficulty_bits).is_err() {
                rejected.push((i, RejectReason::StatelessInvalid));
                continue;
            }
            // Double-spend: against committed set and within this checkpoint.
            let conflict = tx
                .nullifiers
                .iter()
                .any(|nf| self.nullifiers.contains(nf) || seen_this_checkpoint.contains(nf));
            if conflict {
                rejected.push((i, RejectReason::DoubleSpend));
                continue;
            }
            for nf in &tx.nullifiers {
                seen_this_checkpoint.insert(*nf);
                staged_nf.push(*nf);
            }
            for cm in &tx.commitments {
                staged_cm.push(*cm);
            }
            accepted += 1;
        }

        // Commit staged state in deterministic order.
        for nf in staged_nf {
            self.nullifiers.insert(nf);
        }
        let base = self.tree.len();
        let output_positions: Vec<u64> = (base..base + staged_cm.len() as u64).collect();
        for cm in staged_cm {
            self.tree.append(cm);
        }

        // Mint validator rewards (public amounts; supply audit invariant).
        let weights: Vec<u64> = self.validators.iter().map(|v| v.weight).collect();
        let rewards = reward_descriptor(&self.emission, next_height, &weights);
        for share in &rewards.shares {
            let v = &self.validators[share.validator_index as usize];
            let note = Note {
                value: share.amount,
                addr_tag: v.addr_tag,
                rho: rho_mint(next_height, share.validator_index as u8),
                rseed: rho_mint(next_height, 128 + share.validator_index as u8),
            };
            self.tree.append(note.commitment());
            self.supply += share.amount;
        }

        let anchor = self.tree.seal(next_height);
        self.height = next_height;

        CheckpointSummary {
            height: next_height,
            anchor,
            accepted,
            rejected,
            rewards,
            total_supply: self.supply,
            output_positions,
        }
    }

    /// Audit: supply equals genesis allocation plus all emission to date.
    pub fn audit_supply(&self, genesis_supply: u64) -> bool {
        let minted: u64 = (1..=self.height)
            .map(|h| self.emission.emission_at(h))
            .sum();
        self.supply == genesis_supply + minted
    }

    pub fn tree_witness(&self, position: u64) -> Option<unknown_interfaces::MerklePath> {
        self.tree.witness(position)
    }
    pub fn anchor_valid(&self, anchor: &Anchor) -> bool {
        self.tree.anchor_valid(anchor)
    }

    /// Persist the full permanent state (leaves + nullifiers + height + supply)
    /// as a crash-safe snapshot (WP10 durability). Production would persist
    /// per-checkpoint deltas; this snapshot is O(state) but simple and correct.
    pub fn persist(
        &self,
        store: &unknown_storage::Store,
    ) -> Result<(), unknown_storage::StoreError> {
        let leaves: Vec<(u64, Commitment)> = self
            .tree
            .leaves()
            .iter()
            .enumerate()
            .map(|(i, l)| (i as u64, Commitment(*l)))
            .collect();
        let nullifiers: Vec<Nullifier> = self.nullifiers.iter().copied().collect();
        store.commit_checkpoint(self.height, self.supply, &leaves, &nullifiers)
    }

    /// Rebuild a ledger from a persisted store after a restart. The commitment
    /// tree is rebuilt from leaves (root is deterministic in the leaves), the
    /// nullifier set reloaded, and the current anchor re-sealed so notes are
    /// immediately spendable-against. Anchor-window history beyond the current
    /// height is rebuilt going forward as new checkpoints seal.
    pub fn restore(
        store: &unknown_storage::Store,
        emission: EmissionParams,
        validators: Vec<ValidatorInfo>,
        difficulty_bits: u32,
    ) -> Result<Self, unknown_storage::StoreError> {
        let mut tree = store.load_tree()?;
        let height = store.meta("height")?.unwrap_or(0);
        let supply = store.meta("supply")?.unwrap_or(0);
        tree.seal(height);
        let nullifiers: HashSet<Nullifier> = store.load_nullifiers()?.into_iter().collect();
        Ok(Self {
            tree,
            nullifiers,
            height,
            supply,
            emission,
            validators,
            difficulty_bits,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unknown_antispam_pow::solve;
    use unknown_encryption::{EncryptedOutput, ENC_OUTPUT_LEN};
    use unknown_interfaces::PROOF_BUCKET;
    use unknown_prover_dev::DevVerifier;

    fn params() -> EmissionParams {
        EmissionParams::new(1_000, 100, 50)
    }
    fn validators() -> Vec<ValidatorInfo> {
        vec![ValidatorInfo {
            weight: 1,
            addr_tag: [200; 32],
        }]
    }

    /// A structurally-valid tx (dev proof) spending nothing real — used to
    /// exercise the state machine's accounting paths. We forge a matching dev
    /// proof so stateless validation passes; double-spend logic is what we test.
    fn dev_tx(anchor: Anchor, nf_a: u8, nf_b: u8) -> TxV1 {
        use unknown_interfaces::{Commitment, Nullifier, SpendPublicInputs};
        use unknown_primitives::{ds, hash_parts};
        let enc = EncryptedOutput {
            bytes: vec![0u8; ENC_OUTPUT_LEN],
        };
        let nullifiers = [Nullifier([nf_a; 32]), Nullifier([nf_b; 32])];
        let commitments = [Commitment([10; 32]), Commitment([11; 32])];
        let mut tx = TxV1 {
            anchor,
            nullifiers,
            commitments,
            enc_outputs: [enc.clone(), enc],
            pow: unknown_antispam_pow::PowSolution { nonce: 0 },
            proof: vec![0u8; PROOF_BUCKET],
        };
        // Forge the dev tag over the real public inputs (dev prover is not
        // sound; that's the point — see prover-dev docs).
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
    fn reward_minting_increases_supply_and_audits() {
        let mut led = Ledger::genesis(params(), validators(), 0, &[(Commitment([1; 32]), 5_000)]);
        assert_eq!(led.total_supply(), 5_000);
        let s1 = led.apply_checkpoint(&[], &DevVerifier);
        assert_eq!(s1.height, 1);
        assert_eq!(s1.total_supply, 5_000 + params().emission_at(1));
        let _ = led.apply_checkpoint(&[], &DevVerifier);
        assert!(
            led.audit_supply(5_000),
            "supply must equal genesis + emission"
        );
    }

    #[test]
    fn double_spend_rejected_within_and_across_checkpoints() {
        let mut led = Ledger::genesis(params(), validators(), 0, &[(Commitment([1; 32]), 5_000)]);
        let anchor = led.current_anchor();
        let tx = dev_tx(anchor, 1, 2);

        // Same nullifier twice in one checkpoint: first accepted, second rejected.
        let summary = led.apply_checkpoint(&[tx.clone(), tx.clone()], &DevVerifier);
        assert_eq!(summary.accepted, 1);
        assert_eq!(summary.rejected, vec![(1, RejectReason::DoubleSpend)]);

        // Replaying in a later checkpoint is also rejected (committed set).
        let anchor2 = led.current_anchor();
        let tx2 = dev_tx(anchor2, 1, 2); // same nullifiers, valid new anchor
        let summary2 = led.apply_checkpoint(&[tx2], &DevVerifier);
        assert_eq!(summary2.accepted, 0);
        assert_eq!(summary2.rejected, vec![(0, RejectReason::DoubleSpend)]);
    }

    #[test]
    fn stale_anchor_rejected() {
        let mut led = Ledger::genesis(params(), validators(), 0, &[(Commitment([1; 32]), 5_000)]);
        let bogus = Anchor {
            height: 999,
            root: [42; 32],
        };
        let tx = dev_tx(bogus, 1, 2);
        let summary = led.apply_checkpoint(&[tx], &DevVerifier);
        assert_eq!(
            summary.rejected,
            vec![(0, RejectReason::StaleOrUnknownAnchor)]
        );
    }

    #[test]
    fn persist_and_restore_roundtrips() {
        use unknown_storage::Store;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.redb");

        let mut led = Ledger::genesis(params(), validators(), 0, &[(Commitment([1; 32]), 5_000)]);
        let a = led.current_anchor();
        led.apply_checkpoint(&[dev_tx(a, 1, 2)], &DevVerifier);
        let a2 = led.current_anchor();
        led.apply_checkpoint(&[dev_tx(a2, 3, 4)], &DevVerifier);
        let (root, height, supply) = (led.current_anchor().root, led.height(), led.total_supply());

        {
            let store = Store::open(&path).unwrap();
            led.persist(&store).unwrap();
        }

        // New process would call restore(); simulate by reopening.
        let store = Store::open(&path).unwrap();
        let restored = Ledger::restore(&store, params(), validators(), 0).unwrap();
        assert_eq!(restored.height(), height);
        assert_eq!(restored.total_supply(), supply);
        assert_eq!(
            restored.current_anchor().root,
            root,
            "restored root must match original"
        );
        assert!(restored.nullifier_seen(&Nullifier([1; 32])));
        assert!(restored.nullifier_seen(&Nullifier([3; 32])));
        assert!(!restored.nullifier_seen(&Nullifier([9; 32])));

        // And the restored ledger continues consistently: a replayed nullifier
        // is still rejected as a double-spend.
        let mut restored = restored;
        let a3 = restored.current_anchor();
        let summary = restored.apply_checkpoint(&[dev_tx(a3, 1, 2)], &DevVerifier);
        assert_eq!(summary.accepted, 0);
        assert!(matches!(summary.rejected[0].1, RejectReason::DoubleSpend));
    }

    #[test]
    fn deterministic_replay() {
        let build = || {
            let mut led =
                Ledger::genesis(params(), validators(), 0, &[(Commitment([1; 32]), 5_000)]);
            let a = led.current_anchor();
            led.apply_checkpoint(&[dev_tx(a, 1, 2), dev_tx(a, 3, 4)], &DevVerifier);
            led.current_anchor().root
        };
        assert_eq!(build(), build(), "same input must yield identical root");
    }
}
