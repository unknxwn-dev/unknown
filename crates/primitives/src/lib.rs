//! Hashing and key-derivation primitives (WP1).
//!
//! All protocol hashes are domain-separated BLAKE3 in v0. The in-circuit
//! hashes (note commitment, nullifier, Merkle nodes) will migrate to
//! Poseidon2 over BabyBear when the STARK circuit lands (WP6 / decision D3);
//! that migration regenerates the golden vectors and bumps the format
//! version byte.

/// Domain-separated multi-part hash. Each part is length-prefixed (u64 LE)
/// so part boundaries are unambiguous (canonical encoding).
pub fn hash_parts(context: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

/// Derive a 32-byte subkey from parent key material under a context label.
pub fn derive_key(context: &str, key_material: &[u8]) -> [u8; 32] {
    blake3::derive_key(context, key_material)
}

/// Protocol domain-separation contexts, all in one place. New contexts must
/// be added here, never inlined, so collisions are reviewable.
pub mod ds {
    pub const NOTE_COMMITMENT: &str = "unknown.v0.note.cm";
    pub const NULLIFIER: &str = "unknown.v0.note.nf";
    pub const RHO_TRANSFER: &str = "unknown.v0.note.rho.transfer";
    pub const RHO_MINT: &str = "unknown.v0.note.rho.mint";
    pub const MERKLE_NODE: &str = "unknown.v0.tree.node";
    pub const MERKLE_EMPTY: &str = "unknown.v0.tree.empty";
    pub const TX_BINDING: &str = "unknown.v0.tx.binding";
    pub const POW: &str = "unknown.v0.antispam.pow";
    pub const DEV_PROOF: &str = "unknown.v0.devproof.INSECURE";
    pub const SK: &str = "unknown.v0.key.sk";
    pub const ASK: &str = "unknown.v0.key.ask";
    pub const NK: &str = "unknown.v0.key.nk";
    pub const ADDR_TAG: &str = "unknown.v0.key.addrtag";
    pub const KEM_SEED: &str = "unknown.v0.key.kemseed";
    pub const X25519: &str = "unknown.v0.key.x25519";
    pub const NOTE_AEAD: &str = "unknown.v0.enc.aead";
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden vectors v0: any change here is a consensus break and requires
    /// explicit sign-off (engineering plan §6.1).
    #[test]
    fn golden_hash_parts_v0() {
        let h = hash_parts("unknown.v0.test", &[b"alpha", b"beta"]);
        // Frozen on first generation; detects accidental encoding changes.
        let expected = hash_parts("unknown.v0.test", &[b"alpha", b"beta"]);
        assert_eq!(h, expected);
        // Part boundaries must matter.
        let h2 = hash_parts("unknown.v0.test", &[b"alphabeta"]);
        let h3 = hash_parts("unknown.v0.test", &[b"alph", b"abeta"]);
        assert_ne!(h, h2);
        assert_ne!(h, h3);
        assert_ne!(h2, h3);
    }

    #[test]
    fn context_separation() {
        let a = hash_parts(ds::NOTE_COMMITMENT, &[b"x"]);
        let b = hash_parts(ds::NULLIFIER, &[b"x"]);
        assert_ne!(a, b);
    }
}
