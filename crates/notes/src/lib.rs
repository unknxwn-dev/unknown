//! Shielded note structure, commitments, nullifiers (WP3).
//!
//! Commitments and nullifiers are Poseidon2 over BabyBear (decision D3), via
//! the shared [`unknown_poseidon`] hash — byte-for-byte what the STARK spend
//! circuit proves. The note's byte-array fields are mapped to field elements
//! (`value` to 8 byte-limbs; the 32-byte `addr_tag`/`rho`/`rseed`/`nk` via the
//! canonical chunk decoding), and the resulting 8-element digest is packed back
//! to 32 bytes for the wire/interface types. `rho` derivation and dummy-note
//! entropy stay domain-separated BLAKE3 (they only feed the hash as field
//! material, never appear in-circuit as preimages).

use unknown_interfaces::{Commitment, Nullifier};
use unknown_poseidon as poseidon;
use unknown_primitives::{ds, hash_parts};

pub const MEMO_LEN: usize = 64; // decision D10

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Note {
    pub value: u64,
    /// Recipient tag, binds the note to an address's spend authority.
    pub addr_tag: [u8; 32],
    /// Globally unique note nonce; derivation rules below.
    pub rho: [u8; 32],
    /// Commitment randomness.
    pub rseed: [u8; 32],
}

impl Note {
    pub fn commitment(&self) -> Commitment {
        // cm = Poseidon2( value-limbs ‖ addr_tag ‖ rho ‖ rseed ), 4 rate-8 blocks.
        let digest = poseidon::sponge(&[
            poseidon::value_limbs(self.value),
            poseidon::bytes_to_field(self.addr_tag),
            poseidon::bytes_to_field(self.rho),
            poseidon::bytes_to_field(self.rseed),
        ]);
        Commitment(poseidon::pack(digest))
    }

    /// Nullifier requires the nullifier key `nk` (spend authority side).
    pub fn nullifier(&self, nk: &[u8; 32]) -> Nullifier {
        // nf = Poseidon2( nk ‖ rho ), 2 rate-8 blocks.
        let digest = poseidon::sponge(&[
            poseidon::bytes_to_field(*nk),
            poseidon::bytes_to_field(self.rho),
        ]);
        Nullifier(poseidon::pack(digest))
    }

    /// A dummy input note (value 0) used to pad transactions to the uniform
    /// 2-in shape. Its membership check is bypassed in the spend statement
    /// (constraint C4); it must never carry value.
    pub fn dummy(entropy: [u8; 32]) -> Self {
        Self {
            value: 0,
            addr_tag: hash_parts("unknown.v0.note.dummy.tag", &[&entropy]),
            rho: hash_parts("unknown.v0.note.dummy.rho", &[&entropy]),
            rseed: hash_parts("unknown.v0.note.dummy.rseed", &[&entropy]),
        }
    }
}

/// `rho` for transfer outputs: bound to the first input's nullifier, which
/// is globally unique once accepted (engineering plan §3.3).
pub fn rho_transfer(first_input_nf: &Nullifier, output_index: u8) -> [u8; 32] {
    hash_parts(ds::RHO_TRANSFER, &[&first_input_nf.0, &[output_index]])
}

/// `rho` for mint/coinbase outputs: bound to checkpoint height + index.
pub fn rho_mint(height: u64, output_index: u8) -> [u8; 32] {
    hash_parts(ds::RHO_MINT, &[&height.to_le_bytes(), &[output_index]])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(v: u64, b: u8) -> Note {
        Note {
            value: v,
            addr_tag: [b; 32],
            rho: [b.wrapping_add(1); 32],
            rseed: [b.wrapping_add(2); 32],
        }
    }

    #[test]
    fn commitment_binds_all_fields() {
        let n = note(5, 1);
        for variant in [
            Note { value: 6, ..n },
            Note {
                addr_tag: [9; 32],
                ..n
            },
            Note { rho: [9; 32], ..n },
            Note {
                rseed: [9; 32],
                ..n
            },
        ] {
            assert_ne!(n.commitment(), variant.commitment());
        }
    }

    #[test]
    fn nullifier_distinct_per_nk_and_rho() {
        let n = note(5, 1);
        assert_ne!(n.nullifier(&[1; 32]), n.nullifier(&[2; 32]));
        let m = Note { rho: [7; 32], ..n };
        assert_ne!(n.nullifier(&[1; 32]), m.nullifier(&[1; 32]));
    }

    #[test]
    fn rho_unique_per_index() {
        let nf = Nullifier([3; 32]);
        assert_ne!(rho_transfer(&nf, 0), rho_transfer(&nf, 1));
        assert_ne!(rho_mint(10, 0), rho_mint(11, 0));
    }
}
