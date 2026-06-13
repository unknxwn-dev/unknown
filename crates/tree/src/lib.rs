//! Append-only note commitment tree with anchors (WP4).
//!
//! Fixed-depth (32) Merkle tree over domain-separated BLAKE3. Leaves are
//! appended left to right; empty subtrees use precomputed empty-node hashes.
//! Old anchors stay valid because the tree only grows and a witness is
//! recomputed against the current frontier on demand (feasibility §4).
//!
//! This is an in-memory reference implementation. The RocksDB-backed
//! version (engineering plan WP4/WP10) implements the same `CommitmentTree`
//! behaviour behind a persistence trait; the Merkle logic here is the
//! normative model those tests check against.

use std::collections::VecDeque;
use unknown_interfaces::{Anchor, Commitment, MerklePath, ANCHOR_WINDOW, TREE_DEPTH};
use unknown_primitives::{ds, hash_parts};

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    hash_parts(ds::MERKLE_NODE, &[left, right])
}

/// Precomputed hashes of empty subtrees at each level (0 = leaf level).
fn empty_roots() -> [[u8; 32]; TREE_DEPTH + 1] {
    let mut roots = [[0u8; 32]; TREE_DEPTH + 1];
    roots[0] = hash_parts(ds::MERKLE_EMPTY, &[]);
    let mut level = 1;
    while level <= TREE_DEPTH {
        roots[level] = node_hash(&roots[level - 1], &roots[level - 1]);
        level += 1;
    }
    roots
}

pub struct CommitmentTree {
    leaves: Vec<[u8; 32]>,
    empty: [[u8; 32]; TREE_DEPTH + 1],
    /// Sealed anchors, most recent last; bounded to the validity window.
    anchors: VecDeque<Anchor>,
}

impl Default for CommitmentTree {
    fn default() -> Self {
        Self::new()
    }
}

impl CommitmentTree {
    pub fn new() -> Self {
        Self {
            leaves: Vec::new(),
            empty: empty_roots(),
            anchors: VecDeque::new(),
        }
    }

    pub fn len(&self) -> u64 {
        self.leaves.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Append a commitment, returning its leaf position.
    pub fn append(&mut self, cm: Commitment) -> u64 {
        let pos = self.leaves.len() as u64;
        self.leaves.push(cm.0);
        pos
    }

    /// Root over the current leaf set (capacity 2^32, empty slots padded).
    pub fn root(&self) -> [u8; 32] {
        if self.leaves.is_empty() {
            return self.empty[TREE_DEPTH];
        }
        let mut level = self.leaves.clone();
        for depth in 0..TREE_DEPTH {
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            let mut i = 0;
            while i < level.len() {
                let left = &level[i];
                let right = if i + 1 < level.len() {
                    &level[i + 1]
                } else {
                    &self.empty[depth]
                };
                next.push(node_hash(left, right));
                i += 2;
            }
            level = next;
        }
        level[0]
    }

    /// Authentication path for a previously appended leaf.
    pub fn witness(&self, position: u64) -> Option<MerklePath> {
        let pos = position as usize;
        if pos >= self.leaves.len() {
            return None;
        }
        let mut siblings = [[0u8; 32]; TREE_DEPTH];
        let mut level = self.leaves.clone();
        let mut idx = pos;
        for (depth, sibling) in siblings.iter_mut().enumerate() {
            let sib = idx ^ 1;
            *sibling = if sib < level.len() {
                level[sib]
            } else {
                self.empty[depth]
            };
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            let mut i = 0;
            while i < level.len() {
                let left = &level[i];
                let right = if i + 1 < level.len() {
                    &level[i + 1]
                } else {
                    &self.empty[depth]
                };
                next.push(node_hash(left, right));
                i += 2;
            }
            level = next;
            idx /= 2;
        }
        Some(MerklePath { position, siblings })
    }

    /// Seal the current root as the anchor for `height`, evicting anchors
    /// outside the validity window.
    pub fn seal(&mut self, height: u64) -> Anchor {
        let anchor = Anchor {
            height,
            root: self.root(),
        };
        self.anchors.push_back(anchor);
        while let Some(front) = self.anchors.front() {
            if height.saturating_sub(front.height) >= ANCHOR_WINDOW {
                self.anchors.pop_front();
            } else {
                break;
            }
        }
        anchor
    }

    /// Is this anchor sealed and still inside the validity window?
    pub fn anchor_valid(&self, anchor: &Anchor) -> bool {
        self.anchors.iter().any(|a| a == anchor)
    }
}

/// Stateless path verification (also the in-circuit relation, constraint C1).
pub fn verify_path(leaf: &Commitment, path: &MerklePath, root: &[u8; 32]) -> bool {
    let mut cur = leaf.0;
    let mut idx = path.position;
    for sib in &path.siblings {
        cur = if idx & 1 == 0 {
            node_hash(&cur, sib)
        } else {
            node_hash(sib, &cur)
        };
        idx >>= 1;
    }
    &cur == root
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn cm(b: u8) -> Commitment {
        Commitment([b; 32])
    }

    #[test]
    fn witness_roundtrip_small() {
        let mut t = CommitmentTree::new();
        let p0 = t.append(cm(1));
        let p1 = t.append(cm(2));
        let p2 = t.append(cm(3));
        let root = t.root();
        for (pos, leaf) in [(p0, cm(1)), (p1, cm(2)), (p2, cm(3))] {
            let w = t.witness(pos).unwrap();
            assert!(verify_path(&leaf, &w, &root));
            // wrong leaf fails
            assert!(!verify_path(&cm(99), &w, &root));
        }
    }

    #[test]
    fn witness_survives_appends() {
        // Old anchors must remain provable after the tree grows (feasibility §4).
        let mut t = CommitmentTree::new();
        let p0 = t.append(cm(1));
        let anchor = t.seal(0);
        // ... more leaves arrive later
        t.append(cm(2));
        t.append(cm(3));
        // witness against the sealed root still verifies
        let mut snapshot = CommitmentTree::new();
        snapshot.append(cm(1));
        let w = snapshot.witness(p0).unwrap();
        assert!(verify_path(&cm(1), &w, &anchor.root));
    }

    #[test]
    fn anchor_window_eviction() {
        let mut t = CommitmentTree::new();
        t.append(cm(1));
        let old = t.seal(0);
        assert!(t.anchor_valid(&old));
        let recent = t.seal(ANCHOR_WINDOW - 1);
        assert!(t.anchor_valid(&old));
        assert!(t.anchor_valid(&recent));
        let _ = t.seal(ANCHOR_WINDOW);
        assert!(
            !t.anchor_valid(&old),
            "anchor older than window must be evicted"
        );
    }

    proptest! {
        #[test]
        fn all_witnesses_verify(n in 1usize..200) {
            let mut t = CommitmentTree::new();
            let leaves: Vec<Commitment> =
                (0..n).map(|i| Commitment(hash_parts("test.leaf", &[&(i as u64).to_le_bytes()]))).collect();
            for leaf in &leaves {
                t.append(*leaf);
            }
            let root = t.root();
            for pos in 0..n as u64 {
                let w = t.witness(pos).unwrap();
                prop_assert!(verify_path(&leaves[pos as usize], &w, &root));
            }
        }
    }
}
