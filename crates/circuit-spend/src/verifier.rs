//! Bridge from the STARK spend circuit to the frozen
//! [`unknown_interfaces::SpendVerifier`].
//!
//! The interface speaks 32-byte digests and a `u64` mint; the circuit speaks
//! Poseidon2 field-element digests (8 × BabyBear, decision D3). Each digest
//! packs losslessly into 32 bytes (4 little-endian bytes per element, since
//! every BabyBear value is < 2³¹), so [`StarkSpendVerifier`] unpacks the public
//! inputs, deserializes the proof, and runs the circuit verifier.
//!
//! This makes the STARK a drop-in `SpendVerifier` *for public inputs whose
//! digests are Poseidon2-packed*. Having the rest of the pipeline (notes, tree,
//! state, tx) produce such digests is the BLAKE3→Poseidon2 migration — a
//! separate, cross-crate change. [`prove_to_interface`] produces a matching
//! `(SpendPublicInputs, proof_bytes)` pair so the round trip is testable today.

use p3_field::integers::QuotientMap;
use p3_field::PrimeField32;
use p3_uni_stark::{setup_preprocessed, Proof};
use unknown_interfaces::{
    Anchor, Commitment, Nullifier, SpendPublicInputs, SpendVerifier, VerifyError,
};

use crate::field::{make_config, Config, FriProfile, Val};
use crate::spend::{binding_limbs, InputNote, OutputNote, SpendPublic, N_IN, N_OUT};
use crate::tall_spend::{prove_tall_spend, verify_tall_spend, TallSpendAir, HEIGHT};

/// Pack an 8-element Poseidon2 digest into 32 bytes (4 LE bytes per element).
pub fn pack(digest: [Val; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, v) in digest.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.as_canonical_u32().to_le_bytes());
    }
    out
}

/// Inverse of [`pack`].
pub fn unpack(bytes: [u8; 32]) -> [Val; 8] {
    core::array::from_fn(|i| {
        let x = u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap());
        Val::from_int(x)
    })
}

/// A `SpendVerifier` backed by the real STARK spend circuit (the tall layout,
/// `circuit-spend::tall_spend` — ~185 KB proofs, Gate-A compliant).
pub struct StarkSpendVerifier {
    air: TallSpendAir<Val>,
    config: Config,
    vk: p3_uni_stark::PreprocessedVerifierKey<Config>,
}

impl Default for StarkSpendVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl StarkSpendVerifier {
    pub fn new() -> Self {
        let air = TallSpendAir::new_seeded();
        let config = make_config(FriProfile::COMPACT);
        let degree_bits = HEIGHT.trailing_zeros() as usize;
        let (_pd, vk) = setup_preprocessed(&config, &air, degree_bits)
            .expect("tall spend AIR has preprocessed columns");
        Self { air, config, vk }
    }
}

impl SpendVerifier for StarkSpendVerifier {
    fn verify(&self, pi: &SpendPublicInputs, proof: &[u8]) -> Result<(), VerifyError> {
        if pi.nullifiers.len() != N_IN || pi.commitments.len() != N_OUT {
            return Err(VerifyError::Malformed);
        }
        let public = SpendPublic {
            root: unpack(pi.anchor.root),
            nullifiers: core::array::from_fn(|i| unpack(pi.nullifiers[i].0)),
            out_cms: core::array::from_fn(|j| unpack(pi.commitments[j].0)),
            mint: pi.mint_value,
            // Transcript-bound (F-1): the proof only verifies against the
            // binding digest it was generated for, which covers enc_outputs
            // and anchor.height.
            binding: binding_limbs(pi.binding_digest),
        };
        // Wire proofs are zero-padded to the fixed PROOF_BUCKET (D9). Require
        // the padding to be canonical (all zero) so a proof blob has exactly
        // one accepted encoding.
        let (proof, rest): (Proof<Config>, &[u8]) =
            postcard::take_from_bytes(proof).map_err(|_| VerifyError::Malformed)?;
        if !rest.iter().all(|&b| b == 0) {
            return Err(VerifyError::Malformed);
        }
        verify_tall_spend(&self.config, &self.air, &proof, &self.vk, &public)
            .map_err(|_| VerifyError::Invalid)
    }
}

/// Prove a spend and package the result in the frozen interface types, so a
/// caller (or test) can feed it straight to [`StarkSpendVerifier::verify`].
/// `binding_digest` is the tx binding digest ([`unknown_tx`]'s
/// `TxV1::binding_digest`), which the proof transcript commits to.
pub fn prove_to_interface(
    air: &TallSpendAir<Val>,
    nk: [Val; 8],
    inputs: &[InputNote; N_IN],
    outputs: &[OutputNote; N_OUT],
    mint: u64,
    anchor_height: u64,
    binding_digest: [u8; 32],
) -> (SpendPublicInputs, Vec<u8>) {
    let (_config, proof, _vk, public) =
        prove_tall_spend(air, nk, inputs, outputs, mint, binding_digest);
    let pi = SpendPublicInputs {
        anchor: Anchor {
            height: anchor_height,
            root: pack(public.root),
        },
        nullifiers: public
            .nullifiers
            .iter()
            .map(|n| Nullifier(pack(*n)))
            .collect(),
        commitments: public
            .out_cms
            .iter()
            .map(|c| Commitment(pack(*c)))
            .collect(),
        binding_digest,
        mint_value: mint,
    };
    let bytes = postcard::to_allocvec(&proof).expect("serialize proof");
    (pi, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::distr::StandardUniform;
    use rand::rngs::SmallRng;
    use rand::{RngExt, SeedableRng};
    use unknown_interfaces::TREE_DEPTH;

    fn digest(rng: &mut SmallRng) -> [Val; 8] {
        core::array::from_fn(|_| rng.sample(StandardUniform))
    }

    /// Balanced two-real-input transfer in one tree (as in the spend tests).
    fn case(seed: u64) -> ([Val; 8], [InputNote; N_IN], [OutputNote; N_OUT]) {
        let mut rng = SmallRng::seed_from_u64(seed);
        let nk = digest(&mut rng);
        let rho0 = digest(&mut rng);
        let rho1 = digest(&mut rng);
        let rs0 = digest(&mut rng);
        let rs1 = digest(&mut rng);
        let tag = unknown_poseidon::sponge(&[nk]);
        let commit = |v: u64, rho, rs| {
            unknown_poseidon::sponge(&[unknown_poseidon::value_limbs(v), tag, rho, rs])
        };
        let cm0 = commit(600, rho0, rs0);
        let cm1 = commit(400, rho1, rs1);
        let shared: Vec<_> = (1..TREE_DEPTH)
            .map(|_| (digest(&mut rng), rng.sample::<bool, _>(StandardUniform)))
            .collect();
        let mut p0 = vec![(cm1, false)];
        p0.extend(shared.iter().cloned());
        let mut p1 = vec![(cm0, true)];
        p1.extend(shared.iter().cloned());
        let inputs = [
            InputNote {
                value: 600,
                addr_tag: tag,
                rho: rho0,
                rseed: rs0,
                path: p0,
                dummy: false,
            },
            InputNote {
                value: 400,
                addr_tag: tag,
                rho: rho1,
                rseed: rs1,
                path: p1,
                dummy: false,
            },
        ];
        let outputs = [
            OutputNote {
                value: 700,
                addr_tag: digest(&mut rng),
                rho: digest(&mut rng),
                rseed: digest(&mut rng),
            },
            OutputNote {
                value: 300,
                addr_tag: digest(&mut rng),
                rho: digest(&mut rng),
                rseed: digest(&mut rng),
            },
        ];
        (nk, inputs, outputs)
    }

    #[test]
    fn pack_round_trips() {
        let mut rng = SmallRng::seed_from_u64(1);
        let d = digest(&mut rng);
        assert_eq!(unpack(pack(d)), d);
    }

    #[test]
    fn interface_round_trip_verifies() {
        let air = TallSpendAir::new_seeded();
        let (nk, inputs, outputs) = case(2);
        let (pi, proof) = prove_to_interface(&air, nk, &inputs, &outputs, 0, 0, [7u8; 32]);
        StarkSpendVerifier::new()
            .verify(&pi, &proof)
            .expect("STARK SpendVerifier accepts a valid proof");
    }

    #[test]
    fn tampered_public_input_is_rejected() {
        let air = TallSpendAir::new_seeded();
        let (nk, inputs, outputs) = case(3);
        let (mut pi, proof) = prove_to_interface(&air, nk, &inputs, &outputs, 0, 0, [7u8; 32]);
        pi.anchor.root[0] ^= 0x01; // corrupt the anchor
        assert_eq!(
            StarkSpendVerifier::new().verify(&pi, &proof),
            Err(VerifyError::Invalid)
        );
    }

    /// F-1 regression (interface level): mutating any field the binding digest
    /// covers — here modeled as the digest itself changing, as it would after
    /// an enc_outputs or anchor.height mutation — must invalidate the proof.
    #[test]
    fn tampered_binding_digest_is_rejected() {
        let air = TallSpendAir::new_seeded();
        let (nk, inputs, outputs) = case(5);
        let (mut pi, proof) = prove_to_interface(&air, nk, &inputs, &outputs, 0, 0, [7u8; 32]);
        pi.binding_digest[0] ^= 0x01;
        assert_eq!(
            StarkSpendVerifier::new().verify(&pi, &proof),
            Err(VerifyError::Invalid)
        );
    }

    #[test]
    fn malformed_proof_is_rejected() {
        let air = TallSpendAir::new_seeded();
        let (nk, inputs, outputs) = case(4);
        let (pi, _proof) = prove_to_interface(&air, nk, &inputs, &outputs, 0, 0, [7u8; 32]);
        assert_eq!(
            StarkSpendVerifier::new().verify(&pi, b"not a proof"),
            Err(VerifyError::Malformed)
        );
    }
}
