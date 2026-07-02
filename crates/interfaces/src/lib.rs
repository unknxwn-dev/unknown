//! Frozen cross-crate types and traits (engineering plan §3.1).
//!
//! NOTE on divergence from the plan document: `Commitment`/`Nullifier` are
//! represented as 32-byte digests rather than `[F; 8]` field-element arrays.
//! The byte layout is identical; the field-element view appears when the
//! STARK circuit (WP6) lands, together with the BLAKE3 → Poseidon2 swap for
//! in-circuit hashes. Tracked as decision D3 in docs/engineering-plan.md.

/// Merkle tree depth for the note commitment tree.
pub const TREE_DEPTH: usize = 32;

/// Anchor validity window: a tx may reference any sealed anchor within the
/// last `ANCHOR_WINDOW` checkpoints (feasibility analysis §4).
pub const ANCHOR_WINDOW: u64 = 1024;

/// Maximum money supply in atomic units (< 2^62 keeps all sums in range).
pub const MAX_MONEY: u64 = 1 << 62;

/// Uniform transfer shape (decision D9): always 2 inputs, 2 outputs.
pub const TX_INPUTS: usize = 2;
pub const TX_OUTPUTS: usize = 2;

/// Fixed proof bucket size (decision D9 uniformity): 192 KiB, sized for the
/// tall-layout STARK spend proof (~185.4 KB measured at Gate A, COMPACT FRI
/// profile — see docs/gate-a-report.md) plus headroom for encoding jitter.
/// Every transaction carries exactly this many proof bytes, zero-padded.
/// Changing it is a consensus break and bumps the transaction version.
pub const PROOF_BUCKET: usize = 192 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Commitment(pub [u8; 32]);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Nullifier(pub [u8; 32]);

/// A sealed checkpoint anchor: the commitment-tree root at a given height.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Anchor {
    pub height: u64,
    pub root: [u8; 32],
}

/// Authentication path for a leaf in the commitment tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerklePath {
    pub position: u64,
    pub siblings: [[u8; 32]; TREE_DEPTH],
}

/// Public inputs of the spend statement (engineering plan §3.3).
/// `mint_value` is zero for transfers and the public minted amount for
/// coinbase/mint transactions (supply auditability, feasibility §9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendPublicInputs {
    pub anchor: Anchor,
    pub nullifiers: Vec<Nullifier>,
    pub commitments: Vec<Commitment>,
    pub binding_digest: [u8; 32],
    pub mint_value: u64,
}

impl SpendPublicInputs {
    /// Canonical encoding used for proof binding. Fixed layout, little-endian.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(&self.anchor.height.to_le_bytes());
        out.extend_from_slice(&self.anchor.root);
        out.push(self.nullifiers.len() as u8);
        for nf in &self.nullifiers {
            out.extend_from_slice(&nf.0);
        }
        out.push(self.commitments.len() as u8);
        for cm in &self.commitments {
            out.extend_from_slice(&cm.0);
        }
        out.extend_from_slice(&self.binding_digest);
        out.extend_from_slice(&self.mint_value.to_le_bytes());
        out
    }
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum ProveError {
    #[error("witness does not satisfy the spend statement: {0}")]
    Unsatisfied(&'static str),
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum VerifyError {
    #[error("invalid proof")]
    Invalid,
    #[error("malformed proof encoding")]
    Malformed,
}

/// Proof bytes, padded to a fixed bucket per version (uniformity rule D9).
pub type ProofBytes = Vec<u8>;

/// Implemented by provers (dev MAC prover now; STARK prover at WP6).
/// The witness type is prover-specific; this trait sees only public inputs
/// plus an opaque, already-validated witness handle.
pub trait SpendVerifier {
    fn verify(&self, pi: &SpendPublicInputs, proof: &[u8]) -> Result<(), VerifyError>;
}

/// Compact per-checkpoint data streamed to wallets for scanning
/// (engineering plan §3.6: bulk streaming only, no per-note queries).
#[derive(Clone, Debug)]
pub struct CompactCheckpoint {
    pub anchor: Anchor,
    /// Output commitments in tree-insertion order, paired with their
    /// encrypted payloads (1273 bytes each, layout in §3.4).
    pub outputs: Vec<(Commitment, Vec<u8>)>,
    /// Nullifiers revealed in this checkpoint (for local spentness tracking).
    pub nullifiers: Vec<Nullifier>,
}
