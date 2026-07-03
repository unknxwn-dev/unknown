//! Key hierarchy and addresses (WP2, engineering plan §3.3 strawman).
//!
//! seed (32 bytes)
//!  └─ sk   = KDF("…key.sk", seed)            spending key
//!      ├─ ask = KDF("…key.ask", sk)          spend-authorizing key
//!      ├─ nk  = KDF("…key.nk",  sk)          nullifier key
//!      ├─ addr_tag = Poseidon2(nk)           recipient tag bound into notes
//!                                            (commits to nk; never reveals it)
//!      ├─ x25519 static secret = KDF("…key.x25519", sk)
//!      └─ ML-KEM-768 keypair from a 64-byte seed = KDF("…key.kemseed", sk)
//!
//! ⚠ CRYPTO-REVIEW: deterministic ML-KEM keygen uses the standardized 64-byte
//! seed keygen (`FromSeed`, FIPS-203 d‖z), derived from the spending key — no
//! RNG involved (open decision #1 in the engineering plan).

use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, KeyExport};
use ml_kem::{FromSeed, MlKem768};
use unknown_primitives::{derive_key, ds};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const MLKEM_PK_LEN: usize = 1184;
pub const MLKEM_CT_LEN: usize = 1088;
pub const ADDRESS_HRP: &str = "unk";
pub const ADDRESS_VERSION: u8 = 0;

pub type KemEncapsKey = ml_kem::EncapsulationKey<MlKem768>;
pub type KemDecapsKey = ml_kem::DecapsulationKey<MlKem768>;

fn shared_to_32(ss: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(ss);
    out
}

/// Root spending authority. Holds everything; keep it in one place so
/// zeroization is tractable.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SpendingKey {
    sk: [u8; 32],
}

impl SpendingKey {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            sk: derive_key(ds::SK, seed),
        }
    }

    pub fn ask(&self) -> [u8; 32] {
        derive_key(ds::ASK, &self.sk)
    }

    pub fn nk(&self) -> [u8; 32] {
        derive_key(ds::NK, &self.sk)
    }

    /// Recipient tag bound into notes: `addr_tag = Poseidon2(nk)`. Committing
    /// to the nullifier key (rather than publishing it) is what the spend
    /// circuit's ownership constraint (C3) checks — the spender proves knowledge
    /// of the `nk` whose hash is the note's tag. Publishing `nk` directly would
    /// let anyone compute the owner's nullifiers.
    pub fn addr_tag(&self) -> [u8; 32] {
        let nk_f = unknown_poseidon::bytes_to_field(self.nk());
        unknown_poseidon::pack(unknown_poseidon::sponge(&[nk_f]))
    }

    fn x25519_secret(&self) -> x25519_dalek::StaticSecret {
        x25519_dalek::StaticSecret::from(derive_key(ds::X25519, &self.sk))
    }

    /// Deterministic ML-KEM-768 keypair from the spending key. ⚠ CRYPTO-REVIEW
    /// (engineering plan open decision #1): uses the standardized 64-byte seed
    /// keygen (`FromSeed`), so no RNG is involved and derivation is reproducible.
    fn kem_keypair(&self) -> (KemDecapsKey, KemEncapsKey) {
        let mut seed_bytes = [0u8; 64];
        seed_bytes[..32].copy_from_slice(&derive_key(ds::KEM_SEED, &self.sk));
        seed_bytes[32..].copy_from_slice(&derive_key("unknown.v0.key.kemseed2", &self.sk));
        let seed: ml_kem::Seed = Array::try_from(&seed_bytes[..]).expect("64-byte seed");
        <MlKem768 as FromSeed>::from_seed(&seed)
    }

    pub fn address(&self) -> Address {
        let (_, ek) = self.kem_keypair();
        let pk_bytes = ek.to_bytes();
        Address {
            x25519_pk: *x25519_dalek::PublicKey::from(&self.x25519_secret()).as_bytes(),
            kem_pk: pk_bytes
                .as_slice()
                .try_into()
                .expect("ml-kem-768 pk is 1184 bytes"),
            addr_tag: self.addr_tag(),
        }
    }

    pub fn incoming_viewing_key(&self) -> IncomingViewingKey {
        let (dk, _) = self.kem_keypair();
        IncomingViewingKey {
            x25519_sk: self.x25519_secret(),
            kem_dk: dk,
            addr_tag: self.addr_tag(),
        }
    }

    pub fn full_viewing_key(&self) -> FullViewingKey {
        FullViewingKey {
            ivk: self.incoming_viewing_key(),
            nk: self.nk(),
        }
    }
}

/// Can detect and decrypt incoming notes; cannot spend or detect spentness.
pub struct IncomingViewingKey {
    pub(crate) x25519_sk: x25519_dalek::StaticSecret,
    pub(crate) kem_dk: KemDecapsKey,
    pub addr_tag: [u8; 32],
}

impl IncomingViewingKey {
    pub fn dh(&self, ephemeral_pk: &[u8; 32]) -> [u8; 32] {
        *self
            .x25519_sk
            .diffie_hellman(&x25519_dalek::PublicKey::from(*ephemeral_pk))
            .as_bytes()
    }

    pub fn decapsulate(&self, ct: &[u8; MLKEM_CT_LEN]) -> Option<[u8; 32]> {
        let ct = ml_kem::Ciphertext::<MlKem768>::try_from(ct.as_slice()).ok()?;
        let ss = self.kem_dk.decapsulate(&ct);
        Some(shared_to_32(ss.as_slice()))
    }
}

/// Incoming viewing plus spentness detection (nullifier key).
pub struct FullViewingKey {
    pub ivk: IncomingViewingKey,
    pub nk: [u8; 32],
}

/// Public payment address: version ‖ x25519 pk ‖ ML-KEM-768 pk ‖ addr_tag.
/// ~1.25 KB raw / ~2.5 KB hex-encoded — the PQ address-size UX cost (feasibility §6.2).
#[derive(Clone, PartialEq, Eq)]
pub struct Address {
    pub x25519_pk: [u8; 32],
    pub kem_pk: [u8; MLKEM_PK_LEN],
    pub addr_tag: [u8; 32],
}

impl core::fmt::Debug for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The 1184-byte ML-KEM key has no auto-Debug; show the encoded form.
        write!(f, "Address({})", self.encode())
    }
}

const ADDRESS_BODY_LEN: usize = 1 + 32 + MLKEM_PK_LEN + 32;
const ADDRESS_CHECKSUM_LEN: usize = 4;

impl Address {
    /// Encode as `unk1<hex>`. The ML-KEM public key makes the address ~1.25 KB
    /// (~2.5k hex chars) — the PQ address-size UX cost noted in the design
    /// (feasibility §6.2). bech32m's checksum is only defined for short data,
    /// so a length-unlimited hex encoding with a 4-byte BLAKE3 checksum is used.
    pub fn encode(&self) -> String {
        let mut data = Vec::with_capacity(ADDRESS_BODY_LEN + ADDRESS_CHECKSUM_LEN);
        data.push(ADDRESS_VERSION);
        data.extend_from_slice(&self.x25519_pk);
        data.extend_from_slice(&self.kem_pk);
        data.extend_from_slice(&self.addr_tag);
        let checksum = derive_key("unknown.v0.addr.checksum", &data);
        data.extend_from_slice(&checksum[..ADDRESS_CHECKSUM_LEN]);
        format!("{ADDRESS_HRP}1{}", hex::encode(&data))
    }

    pub fn decode(s: &str) -> Result<Self, AddressError> {
        let prefix = format!("{ADDRESS_HRP}1");
        let body = s.strip_prefix(&prefix).ok_or(AddressError::WrongHrp)?;
        let data = hex::decode(body).map_err(|_| AddressError::Malformed)?;
        if data.len() != ADDRESS_BODY_LEN + ADDRESS_CHECKSUM_LEN || data[0] != ADDRESS_VERSION {
            return Err(AddressError::Malformed);
        }
        let (payload, checksum) = data.split_at(ADDRESS_BODY_LEN);
        let expected = derive_key("unknown.v0.addr.checksum", payload);
        if checksum != &expected[..ADDRESS_CHECKSUM_LEN] {
            return Err(AddressError::Malformed);
        }
        Ok(Self {
            x25519_pk: payload[1..33].try_into().expect("len checked"),
            kem_pk: payload[33..33 + MLKEM_PK_LEN]
                .try_into()
                .expect("len checked"),
            addr_tag: payload[33 + MLKEM_PK_LEN..]
                .try_into()
                .expect("len checked"),
        })
    }

    /// Deterministic encapsulation to this address. `m_seed` is the 32-byte
    /// KEM message randomness; the caller derives it uniquely per output.
    pub fn kem_encapsulate(
        &self,
        m_seed: [u8; 32],
    ) -> Result<([u8; MLKEM_CT_LEN], [u8; 32]), AddressError> {
        let key = Array::try_from(self.kem_pk.as_slice()).map_err(|_| AddressError::Malformed)?;
        let ek = KemEncapsKey::new(&key).map_err(|_| AddressError::Malformed)?;
        let m: ml_kem::B32 = Array::try_from(&m_seed[..]).expect("32-byte message");
        let (ct, ss) = ek.encapsulate_deterministic(&m);
        Ok((
            ct.as_slice()
                .try_into()
                .expect("ml-kem-768 ct is 1088 bytes"),
            shared_to_32(ss.as_slice()),
        ))
    }
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum AddressError {
    #[error("malformed address")]
    Malformed,
    #[error("wrong human-readable prefix")]
    WrongHrp,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_from_seed() {
        let a = SpendingKey::from_seed(&[7u8; 32]).address();
        let b = SpendingKey::from_seed(&[7u8; 32]).address();
        assert_eq!(a, b);
        let c = SpendingKey::from_seed(&[8u8; 32]).address();
        assert_ne!(a, c);
    }

    #[test]
    fn address_roundtrip() {
        let addr = SpendingKey::from_seed(&[1u8; 32]).address();
        let s = addr.encode();
        assert!(s.starts_with("unk1"));
        let back = Address::decode(&s).unwrap();
        assert_eq!(addr, back);
    }

    #[test]
    fn kem_roundtrip() {
        let sk = SpendingKey::from_seed(&[2u8; 32]);
        let addr = sk.address();
        let ivk = sk.incoming_viewing_key();
        let (ct, ss_sender) = addr.kem_encapsulate([9u8; 32]).unwrap();
        let ss_recv = ivk.decapsulate(&ct).unwrap();
        assert_eq!(ss_sender, ss_recv);
    }
}
