//! Persistent ledger storage (WP10 backend) over redb.
//!
//! The in-memory `Ledger` (`crates/state`) holds the authoritative logic; this
//! crate makes the two pieces of permanent state durable across restarts:
//!
//!   * the **nullifier set** (spent-note markers — must be checkable forever), and
//!   * the **note-commitment tree leaves** (in position order).
//!
//! The commitment tree root is a deterministic function of its leaves, so a
//! node restarts by loading leaves and rebuilding the tree — no root is stored.
//! Everything else (proofs, ciphertexts) is prunable and not persisted here
//! (feasibility §6.3): permanent state is ~128 B/tx, exactly what lives in redb.

use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use unknown_interfaces::{Commitment, Nullifier};
use unknown_tree::CommitmentTree;

const NULLIFIERS: TableDefinition<&[u8], u64> = TableDefinition::new("nullifiers");
const LEAVES: TableDefinition<u64, &[u8]> = TableDefinition::new("leaves");
const META: TableDefinition<&str, u64> = TableDefinition::new("meta");

#[derive(thiserror::Error, Debug)]
pub enum StoreError {
    #[error("database error: {0}")]
    Db(String),
}

macro_rules! db_err {
    ($e:expr) => {
        $e.map_err(|e| StoreError::Db(e.to_string()))
    };
}

pub struct Store {
    db: Database,
}

impl Store {
    /// Open (creating if absent) a store at `path`.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, StoreError> {
        let db = db_err!(Database::create(path))?;
        // Ensure tables exist so reads on a fresh db don't error.
        let w = db_err!(db.begin_write())?;
        {
            db_err!(w.open_table(NULLIFIERS))?;
            db_err!(w.open_table(LEAVES))?;
            db_err!(w.open_table(META))?;
        }
        db_err!(w.commit())?;
        Ok(Self { db })
    }

    /// Persist one checkpoint's new permanent state in a single atomic write:
    /// appended leaves (with their positions), new nullifiers, and updated meta
    /// (height, supply). Crash-safe — either the whole checkpoint lands or none.
    pub fn commit_checkpoint(
        &self,
        height: u64,
        supply: u64,
        new_leaves: &[(u64, Commitment)],
        new_nullifiers: &[Nullifier],
    ) -> Result<(), StoreError> {
        let w = db_err!(self.db.begin_write())?;
        {
            let mut leaves = db_err!(w.open_table(LEAVES))?;
            for (pos, cm) in new_leaves {
                db_err!(leaves.insert(pos, cm.0.as_slice()))?;
            }
            let mut nfs = db_err!(w.open_table(NULLIFIERS))?;
            for nf in new_nullifiers {
                db_err!(nfs.insert(nf.0.as_slice(), height))?;
            }
            let mut meta = db_err!(w.open_table(META))?;
            db_err!(meta.insert("height", height))?;
            db_err!(meta.insert("supply", supply))?;
        }
        db_err!(w.commit())?;
        Ok(())
    }

    pub fn set_meta(&self, key: &str, value: u64) -> Result<(), StoreError> {
        let w = db_err!(self.db.begin_write())?;
        {
            let mut meta = db_err!(w.open_table(META))?;
            db_err!(meta.insert(key, value))?;
        }
        db_err!(w.commit())
    }

    pub fn meta(&self, key: &str) -> Result<Option<u64>, StoreError> {
        let r = db_err!(self.db.begin_read())?;
        let t = db_err!(r.open_table(META))?;
        Ok(db_err!(t.get(key))?.map(|v| v.value()))
    }

    pub fn contains_nullifier(&self, nf: &Nullifier) -> Result<bool, StoreError> {
        let r = db_err!(self.db.begin_read())?;
        let t = db_err!(r.open_table(NULLIFIERS))?;
        Ok(db_err!(t.get(nf.0.as_slice()))?.is_some())
    }

    pub fn nullifier_count(&self) -> Result<u64, StoreError> {
        let r = db_err!(self.db.begin_read())?;
        let t = db_err!(r.open_table(NULLIFIERS))?;
        Ok(db_err!(t.len())?)
    }

    /// Load all leaves in position order.
    pub fn load_leaves(&self) -> Result<Vec<[u8; 32]>, StoreError> {
        let r = db_err!(self.db.begin_read())?;
        let t = db_err!(r.open_table(LEAVES))?;
        let mut out = Vec::new();
        for item in db_err!(t.iter())? {
            let (_pos, cm) = db_err!(item)?;
            let bytes: [u8; 32] = cm
                .value()
                .try_into()
                .map_err(|_| StoreError::Db("bad leaf length".into()))?;
            out.push(bytes);
        }
        Ok(out)
    }

    /// Load every persisted nullifier (for rebuilding the in-memory set).
    pub fn load_nullifiers(&self) -> Result<Vec<Nullifier>, StoreError> {
        let r = db_err!(self.db.begin_read())?;
        let t = db_err!(r.open_table(NULLIFIERS))?;
        let mut out = Vec::new();
        for item in db_err!(t.iter())? {
            let (nf, _height) = db_err!(item)?;
            let bytes: [u8; 32] = nf
                .value()
                .try_into()
                .map_err(|_| StoreError::Db("bad nullifier length".into()))?;
            out.push(Nullifier(bytes));
        }
        Ok(out)
    }

    /// Rebuild the commitment tree from persisted leaves.
    pub fn load_tree(&self) -> Result<CommitmentTree, StoreError> {
        Ok(CommitmentTree::from_raw_leaves(&self.load_leaves()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cm(b: u8) -> Commitment {
        Commitment([b; 32])
    }
    fn nf(b: u8) -> Nullifier {
        Nullifier([b; 32])
    }

    #[test]
    fn survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.redb");

        // First session: write a checkpoint's state.
        {
            let s = Store::open(&path).unwrap();
            s.commit_checkpoint(
                1,
                5_000,
                &[(0, cm(10)), (1, cm(11)), (2, cm(12))],
                &[nf(1), nf(2)],
            )
            .unwrap();
        }

        // Second session: reopen and verify everything persisted.
        let s = Store::open(&path).unwrap();
        assert_eq!(s.meta("height").unwrap(), Some(1));
        assert_eq!(s.meta("supply").unwrap(), Some(5_000));
        assert!(s.contains_nullifier(&nf(1)).unwrap());
        assert!(s.contains_nullifier(&nf(2)).unwrap());
        assert!(!s.contains_nullifier(&nf(9)).unwrap());
        assert_eq!(s.nullifier_count().unwrap(), 2);
        assert_eq!(
            s.load_leaves().unwrap(),
            vec![[10u8; 32], [11u8; 32], [12u8; 32]]
        );
    }

    #[test]
    fn rebuilt_tree_root_matches_original() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.redb");

        // Build an in-memory tree and persist its leaves.
        let mut original = CommitmentTree::new();
        let leaves: Vec<Commitment> = (0..7).map(cm).collect();
        let pairs: Vec<(u64, Commitment)> =
            leaves.iter().map(|c| (original.append(*c), *c)).collect();
        let root_before = original.root();

        let s = Store::open(&path).unwrap();
        s.commit_checkpoint(1, 0, &pairs, &[]).unwrap();

        // Reload and confirm the rebuilt tree has the identical root.
        let rebuilt = s.load_tree().unwrap();
        assert_eq!(rebuilt.root(), root_before, "rebuilt tree root must match");
        assert_eq!(rebuilt.len(), 7);
    }

    #[test]
    fn incremental_checkpoints_accumulate() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("i.redb");
        let s = Store::open(&path).unwrap();
        s.commit_checkpoint(1, 100, &[(0, cm(1))], &[nf(1)])
            .unwrap();
        s.commit_checkpoint(2, 200, &[(1, cm(2))], &[nf(2)])
            .unwrap();
        assert_eq!(s.meta("height").unwrap(), Some(2));
        assert_eq!(s.meta("supply").unwrap(), Some(200));
        assert_eq!(s.nullifier_count().unwrap(), 2);
        assert_eq!(s.load_leaves().unwrap().len(), 2);
    }
}
