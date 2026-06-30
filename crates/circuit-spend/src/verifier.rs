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
use p3_uni_stark::Proof;
use unknown_interfaces::{
    Anchor, Commitment, Nullifier, SpendPublicInputs, SpendVerifier, VerifyError,
};

use crate::field::{make_config, Config, FriProfile, Val};
use crate::spend::{
    prove_spend, verify_spend, InputNote, OutputNote, SpendAir, SpendPublic, N_IN, N_OUT,
};

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

/// A `SpendVerifier` backed by the real STARK spend circuit.
pub struct StarkSpendVerifier {
    air: SpendAir<Val>,
    config: Config,
}

impl Default for StarkSpendVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl StarkSpendVerifier {
    pub fn new() -> Self {
        Self {
            air: SpendAir::new_seeded(),
            config: make_config(FriProfile::COMPACT_SHORT),
        }
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
        };
        let proof: Proof<Config> =
            postcard::from_bytes(proof).map_err(|_| VerifyError::Malformed)?;
        verify_spend(&self.config, &self.air, &proof, &public).map_err(|_| VerifyError::Invalid)
    }
}

/// Prove a spend and package the result in the frozen interface types, so a
/// caller (or test) can feed it straight to [`StarkSpendVerifier::verify`].
pub fn prove_to_interface(
    air: &SpendAir<Val>,
    nk: [Val; 8],
    inputs: &[InputNote; N_IN],
    outputs: &[OutputNote; N_OUT],
    mint: u64,
    anchor_height: u64,
) -> (SpendPublicInputs, Vec<u8>) {
    let (_config, proof, public) = prove_spend(air, nk, inputs, outputs, mint);
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
        binding_digest: [0u8; 32],
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
    fn case(air: &SpendAir<Val>, seed: u64) -> ([Val; 8], [InputNote; N_IN], [OutputNote; N_OUT]) {
        let mut rng = SmallRng::seed_from_u64(seed);
        let nk = digest(&mut rng);
        let rho0 = digest(&mut rng);
        let rho1 = digest(&mut rng);
        let rs0 = digest(&mut rng);
        let rs1 = digest(&mut rng);
        let tag = air.tag(nk);
        let cm0 = air.commit(600, tag, rho0, rs0);
        let cm1 = air.commit(400, tag, rho1, rs1);
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
        let air = SpendAir::new_seeded();
        let (nk, inputs, outputs) = case(&air, 2);
        let (pi, proof) = prove_to_interface(&air, nk, &inputs, &outputs, 0, 0);
        StarkSpendVerifier::new()
            .verify(&pi, &proof)
            .expect("STARK SpendVerifier accepts a valid proof");
    }

    #[test]
    fn tampered_public_input_is_rejected() {
        let air = SpendAir::new_seeded();
        let (nk, inputs, outputs) = case(&air, 3);
        let (mut pi, proof) = prove_to_interface(&air, nk, &inputs, &outputs, 0, 0);
        pi.anchor.root[0] ^= 0x01; // corrupt the anchor
        assert_eq!(
            StarkSpendVerifier::new().verify(&pi, &proof),
            Err(VerifyError::Invalid)
        );
    }

    #[test]
    fn malformed_proof_is_rejected() {
        let air = SpendAir::new_seeded();
        let (nk, inputs, outputs) = case(&air, 4);
        let (pi, _proof) = prove_to_interface(&air, nk, &inputs, &outputs, 0, 0);
        assert_eq!(
            StarkSpendVerifier::new().verify(&pi, b"not a proof"),
            Err(VerifyError::Malformed)
        );
    }
}
