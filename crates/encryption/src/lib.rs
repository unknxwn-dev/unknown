//! Hybrid post-quantum note encryption (WP5, engineering plan §3.4).
//!
//! Each output ciphertext is 1273 bytes:
//!   epk_x25519 (32) ‖ mlkem_ct (1088) ‖ aead_ct (137 + 16 tag)
//! The AEAD key is derived from BOTH a classical X25519 shared secret and an
//! ML-KEM-768 shared secret, so confidentiality holds as long as either leg
//! is unbroken (harvest-now-decrypt-later defence, feasibility §6.1).

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use unknown_keys::{Address, IncomingViewingKey, MLKEM_CT_LEN};
use unknown_notes::{Note, MEMO_LEN};
use unknown_primitives::{ds, hash_parts};

pub const PLAINTEXT_LEN: usize = 1 + 8 + 32 + 32 + MEMO_LEN; // 137
pub const AEAD_TAG_LEN: usize = 16;
pub const ENC_OUTPUT_LEN: usize = 32 + MLKEM_CT_LEN + PLAINTEXT_LEN + AEAD_TAG_LEN; // 1273
const NOTE_VERSION: u8 = 0;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EncryptedOutput {
    pub bytes: Vec<u8>, // exactly ENC_OUTPUT_LEN
}

impl EncryptedOutput {
    fn epk(&self) -> [u8; 32] {
        self.bytes[0..32].try_into().expect("len fixed")
    }
    fn mlkem_ct(&self) -> [u8; MLKEM_CT_LEN] {
        self.bytes[32..32 + MLKEM_CT_LEN]
            .try_into()
            .expect("len fixed")
    }
    fn aead_ct(&self) -> &[u8] {
        &self.bytes[32 + MLKEM_CT_LEN..]
    }
}

fn derive_aead(
    x25519_ss: &[u8; 32],
    mlkem_ss: &[u8; 32],
    epk: &[u8; 32],
    mlkem_ct: &[u8; MLKEM_CT_LEN],
    memo_tag: &[u8; 32],
) -> (Key, Nonce) {
    // Bind the key to both shared secrets and the full transcript.
    let k = hash_parts(
        ds::NOTE_AEAD,
        &[x25519_ss, mlkem_ss, epk, mlkem_ct, memo_tag],
    );
    let n = hash_parts("unknown.v0.enc.nonce", &[&k]);
    (*Key::from_slice(&k), *Nonce::from_slice(&n[..12]))
}

fn encode_plaintext(note: &Note, memo: &[u8; MEMO_LEN]) -> [u8; PLAINTEXT_LEN] {
    let mut pt = [0u8; PLAINTEXT_LEN];
    pt[0] = NOTE_VERSION;
    pt[1..9].copy_from_slice(&note.value.to_le_bytes());
    pt[9..41].copy_from_slice(&note.rho);
    pt[41..73].copy_from_slice(&note.rseed);
    pt[73..137].copy_from_slice(memo);
    pt
}

/// Encrypt a note to a recipient. `ephemeral_seed` must be unique per output
/// (the caller derives it from transaction randomness).
pub fn encrypt_note(
    note: &Note,
    recipient: &Address,
    memo: &[u8; MEMO_LEN],
    ephemeral_seed: [u8; 32],
) -> EncryptedOutput {
    // Ephemeral X25519.
    let eph_secret = x25519_dalek::StaticSecret::from(hash_parts(ds::X25519, &[&ephemeral_seed]));
    let epk = *x25519_dalek::PublicKey::from(&eph_secret).as_bytes();
    let x25519_ss = *eph_secret
        .diffie_hellman(&x25519_dalek::PublicKey::from(recipient.x25519_pk))
        .as_bytes();
    // ML-KEM encapsulation (independent randomness leg).
    let kem_seed = hash_parts(ds::KEM_SEED, &[&ephemeral_seed]);
    let (mlkem_ct, mlkem_ss) = recipient
        .kem_encapsulate(kem_seed)
        .expect("recipient address is well-formed");

    let (key, nonce) = derive_aead(&x25519_ss, &mlkem_ss, &epk, &mlkem_ct, &recipient.addr_tag);
    let pt = encode_plaintext(note, memo);
    let aead = ChaCha20Poly1305::new(&key);
    let ct = aead
        .encrypt(&nonce, pt.as_ref())
        .expect("aead encrypt cannot fail");

    let mut bytes = Vec::with_capacity(ENC_OUTPUT_LEN);
    bytes.extend_from_slice(&epk);
    bytes.extend_from_slice(&mlkem_ct);
    bytes.extend_from_slice(&ct);
    debug_assert_eq!(bytes.len(), ENC_OUTPUT_LEN);
    EncryptedOutput { bytes }
}

/// Trial-decrypt one output with an incoming viewing key. Returns the
/// recovered note on success (AEAD tag valid AND recovered commitment is
/// consistent with the recipient's address tag).
pub fn try_decrypt(ct: &EncryptedOutput, ivk: &IncomingViewingKey) -> Option<Note> {
    if ct.bytes.len() != ENC_OUTPUT_LEN {
        return None;
    }
    let epk = ct.epk();
    let mlkem_ct = ct.mlkem_ct();
    let x25519_ss = ivk.dh(&epk);
    let mlkem_ss = ivk.decapsulate(&mlkem_ct)?;
    let (key, nonce) = derive_aead(&x25519_ss, &mlkem_ss, &epk, &mlkem_ct, &ivk.addr_tag);
    let aead = ChaCha20Poly1305::new(&key);
    let pt = aead.decrypt(&nonce, ct.aead_ct()).ok()?;
    if pt.len() != PLAINTEXT_LEN || pt[0] != NOTE_VERSION {
        return None;
    }
    let value = u64::from_le_bytes(pt[1..9].try_into().ok()?);
    let rho: [u8; 32] = pt[9..41].try_into().ok()?;
    let rseed: [u8; 32] = pt[41..73].try_into().ok()?;
    Some(Note {
        value,
        addr_tag: ivk.addr_tag,
        rho,
        rseed,
    })
}

/// Batch trial-decryption (WP5 scan API). Returns indices that decrypted.
pub fn scan(outputs: &[EncryptedOutput], ivk: &IncomingViewingKey) -> Vec<(usize, Note)> {
    outputs
        .iter()
        .enumerate()
        .filter_map(|(i, ct)| try_decrypt(ct, ivk).map(|n| (i, n)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use unknown_keys::SpendingKey;

    fn memo() -> [u8; MEMO_LEN] {
        let mut m = [0u8; MEMO_LEN];
        m[..5].copy_from_slice(b"hello");
        m
    }

    #[test]
    fn roundtrip_to_intended_recipient() {
        let sk = SpendingKey::from_seed(&[3u8; 32]);
        let addr = sk.address();
        let note = Note {
            value: 42,
            addr_tag: addr.addr_tag,
            rho: [5; 32],
            rseed: [6; 32],
        };
        let ct = encrypt_note(&note, &addr, &memo(), [11u8; 32]);
        assert_eq!(ct.bytes.len(), ENC_OUTPUT_LEN);

        let ivk = sk.incoming_viewing_key();
        let recovered = try_decrypt(&ct, &ivk).expect("recipient can decrypt");
        assert_eq!(recovered, note);
        assert_eq!(recovered.commitment(), note.commitment());
    }

    #[test]
    fn wrong_recipient_cannot_decrypt() {
        let sk = SpendingKey::from_seed(&[3u8; 32]);
        let addr = sk.address();
        let note = Note {
            value: 42,
            addr_tag: addr.addr_tag,
            rho: [5; 32],
            rseed: [6; 32],
        };
        let ct = encrypt_note(&note, &addr, &memo(), [11u8; 32]);

        let other = SpendingKey::from_seed(&[99u8; 32]);
        assert!(try_decrypt(&ct, &other.incoming_viewing_key()).is_none());
    }

    #[test]
    fn tamper_fails() {
        let sk = SpendingKey::from_seed(&[3u8; 32]);
        let addr = sk.address();
        let note = Note {
            value: 42,
            addr_tag: addr.addr_tag,
            rho: [5; 32],
            rseed: [6; 32],
        };
        let mut ct = encrypt_note(&note, &addr, &memo(), [11u8; 32]);
        ct.bytes[ENC_OUTPUT_LEN - 1] ^= 1;
        assert!(try_decrypt(&ct, &sk.incoming_viewing_key()).is_none());
    }

    #[test]
    fn scan_finds_only_mine() {
        let me = SpendingKey::from_seed(&[1u8; 32]);
        let you = SpendingKey::from_seed(&[2u8; 32]);
        let my_addr = me.address();
        let your_addr = you.address();
        let mine = Note {
            value: 7,
            addr_tag: my_addr.addr_tag,
            rho: [1; 32],
            rseed: [2; 32],
        };
        let yours = Note {
            value: 9,
            addr_tag: your_addr.addr_tag,
            rho: [3; 32],
            rseed: [4; 32],
        };
        let outputs = vec![
            encrypt_note(&yours, &your_addr, &memo(), [20u8; 32]),
            encrypt_note(&mine, &my_addr, &memo(), [21u8; 32]),
        ];
        let hits = scan(&outputs, &me.incoming_viewing_key());
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, 1);
        assert_eq!(hits[0].1, mine);
    }
}
