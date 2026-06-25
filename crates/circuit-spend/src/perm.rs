//! WP6a gadget — in-circuit Poseidon2 permutation over BabyBear (width 16).
//!
//! This is the composable building block the fused spend circuit needs: a
//! Poseidon2 permutation whose input and output are bound to public values, and
//! whose intermediate state is laid out in columns *we* control — so later
//! gadgets can chain permutations (Merkle paths) and feed note fields in
//! (commitments, nullifiers). The audited `p3-poseidon2-air` proves *anonymous*
//! permutations and consumes the whole trace row, so it can't be wired into a
//! larger statement; this gadget can.
//!
//! Correctness is anchored two ways: (1) the round structure exactly mirrors
//! Plonky3's reference `generate_trace_rows_for_perm`, and (2) both the host
//! permutation and the AIR reuse the *same* audited
//! [`GenericPoseidon2LinearLayersBabyBear`] linear layers and the same round
//! constants — so a unit test cross-checks the host output against
//! `p3-poseidon2-air` for identical constants (see tests).
//!
//! S-box is `x^7` with no auxiliary registers, so constraints are degree 7;
//! that requires an LDE blowup ≥ 8 (the COMPACT FRI profile, `log_blowup = 3`).

use core::array;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::{
    GenericPoseidon2LinearLayersBabyBear as LL, BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS,
    BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16,
};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_uni_stark::{prove, verify, Proof};
use rand::distr::StandardUniform;
use rand::rngs::SmallRng;
use rand::{RngExt, SeedableRng};

use crate::field::{make_config, Config, FriProfile, Val};

/// Poseidon2 state width.
pub const WIDTH: usize = 16;
const HALF_FULL: usize = BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS;
const PARTIAL: usize = BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16;
const SBOX: u64 = 7;

// Column layout: committed input, then the full state after each round.
const INP_OFF: usize = 0;
const BF_OFF: usize = WIDTH;
const PF_OFF: usize = BF_OFF + HALF_FULL * WIDTH;
const EF_OFF: usize = PF_OFF + PARTIAL * WIDTH;
/// Total trace width of the permutation gadget.
pub const WIDTH_COLS: usize = EF_OFF + HALF_FULL * WIDTH;

/// Trace height: a power of two large enough for the COMPACT profile
/// (`log_height > log_final_poly_len + log_blowup = 1 + 3`).
pub const ROWS: usize = 32;

const fn bf(r: usize) -> usize {
    BF_OFF + r * WIDTH
}
const fn pf(r: usize) -> usize {
    PF_OFF + r * WIDTH
}
const fn ef(r: usize) -> usize {
    EF_OFF + r * WIDTH
}

/// Poseidon2 permutation AIR, parameterised by the field its round constants
/// live in (so the `Air` impl can tie them to the builder's field, mirroring
/// `p3-poseidon2-air`).
#[derive(Clone)]
pub struct Poseidon2PermAir<F> {
    begin: [[F; WIDTH]; HALF_FULL],
    partial: [F; PARTIAL],
    end: [[F; WIDTH]; HALF_FULL],
}

impl Poseidon2PermAir<Val> {
    /// Construct with deterministic round constants (production must freeze
    /// these to `specs/vectors/poseidon2.json`, WP1).
    pub fn new_seeded() -> Self {
        let mut rng = SmallRng::seed_from_u64(42);
        Self {
            begin: array::from_fn(|_| array::from_fn(|_| rng.sample(StandardUniform))),
            partial: array::from_fn(|_| rng.sample(StandardUniform)),
            end: array::from_fn(|_| array::from_fn(|_| rng.sample(StandardUniform))),
        }
    }

    /// Host evaluation of the permutation (witness generation / reference).
    /// Mirrors Plonky3's `generate_trace_rows_for_perm` with an `x^7` S-box.
    pub fn permute(&self, input: [Val; WIDTH]) -> [Val; WIDTH] {
        let mut s = input;
        LL::external_linear_layer(&mut s);
        for rc in &self.begin {
            for i in 0..WIDTH {
                s[i] = (s[i] + rc[i]).exp_const_u64::<SBOX>();
            }
            LL::external_linear_layer(&mut s);
        }
        for &rc in &self.partial {
            s[0] = (s[0] + rc).exp_const_u64::<SBOX>();
            LL::internal_linear_layer(&mut s);
        }
        for rc in &self.end {
            for i in 0..WIDTH {
                s[i] = (s[i] + rc[i]).exp_const_u64::<SBOX>();
            }
            LL::external_linear_layer(&mut s);
        }
        s
    }

    /// Fill the `WIDTH_COLS` permutation columns at the start of `dst` for a
    /// permutation of `input` (committed input, then state after each round).
    /// Shared by the standalone gadget and the Merkle gadget.
    pub(crate) fn fill_perm_row(&self, input: [Val; WIDTH], dst: &mut [Val]) {
        dst[INP_OFF..INP_OFF + WIDTH].copy_from_slice(&input);
        let mut s = input;
        LL::external_linear_layer(&mut s);
        for (r, rc) in self.begin.iter().enumerate() {
            for i in 0..WIDTH {
                s[i] = (s[i] + rc[i]).exp_const_u64::<SBOX>();
            }
            LL::external_linear_layer(&mut s);
            dst[bf(r)..bf(r) + WIDTH].copy_from_slice(&s);
        }
        for (r, &rc) in self.partial.iter().enumerate() {
            s[0] = (s[0] + rc).exp_const_u64::<SBOX>();
            LL::internal_linear_layer(&mut s);
            dst[pf(r)..pf(r) + WIDTH].copy_from_slice(&s);
        }
        for (r, rc) in self.end.iter().enumerate() {
            for i in 0..WIDTH {
                s[i] = (s[i] + rc[i]).exp_const_u64::<SBOX>();
            }
            LL::external_linear_layer(&mut s);
            dst[ef(r)..ef(r) + WIDTH].copy_from_slice(&s);
        }
    }

    /// Build the (row-replicated) trace for a single permutation of `input`.
    pub fn generate_trace(&self, input: [Val; WIDTH], rows: usize) -> RowMajorMatrix<Val> {
        assert!(rows.is_power_of_two());
        let mut row = vec![Val::ZERO; WIDTH_COLS];
        self.fill_perm_row(input, &mut row);
        let mut values = Vec::with_capacity(WIDTH_COLS * rows);
        for _ in 0..rows {
            values.extend_from_slice(&row);
        }
        RowMajorMatrix::new(values, WIDTH_COLS)
    }
}

/// Column offset of the permutation's committed input block.
pub(crate) const fn input_off() -> usize {
    INP_OFF
}

/// Column offset of the permutation's output state (first 8 elements are the
/// 2-to-1 compression output / truncated digest).
pub(crate) const fn output_off() -> usize {
    ef(HALF_FULL - 1)
}

/// Public values: the 16 input elements followed by the 16 output elements.
pub fn public_values(input: [Val; WIDTH], output: [Val; WIDTH]) -> Vec<Val> {
    input.into_iter().chain(output).collect()
}

impl<F: PrimeCharacteristicRing + Sync> BaseAir<F> for Poseidon2PermAir<F> {
    fn width(&self) -> usize {
        WIDTH_COLS
    }
    fn num_public_values(&self) -> usize {
        2 * WIDTH
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }
}

/// Read a 16-element state block from the row as builder expressions.
fn state_at<AB: AirBuilder>(local: &[AB::Var], off: usize) -> [AB::Expr; WIDTH] {
    array::from_fn(|i| local[off + i].into())
}

/// Constrain that the `WIDTH_COLS` permutation columns at the start of `local`
/// form a correct Poseidon2 permutation of their committed input block. Each
/// round constraint relates one committed state to the next; after asserting,
/// `s` is reset to the committed columns so each round stays degree 7 (not a
/// composed blow-up). Does NOT bind the input/output to anything — callers add
/// their own boundary constraints. Shared by the gadget and the Merkle AIR.
pub(crate) fn eval_perm_body<AB: AirBuilder>(
    air: &Poseidon2PermAir<AB::F>,
    builder: &mut AB,
    local: &[AB::Var],
    base: usize,
) {
    let mut s = state_at::<AB>(local, base + INP_OFF);
    LL::external_linear_layer(&mut s);

    for (r, rc) in air.begin.iter().enumerate() {
        for i in 0..WIDTH {
            let mut t = s[i].clone();
            t += rc[i].clone();
            s[i] = t.exp_const_u64::<SBOX>();
        }
        LL::external_linear_layer(&mut s);
        for i in 0..WIDTH {
            builder.assert_eq(local[base + bf(r) + i], s[i].clone());
        }
        s = state_at::<AB>(local, base + bf(r));
    }

    for (r, rc) in air.partial.iter().enumerate() {
        let mut t = s[0].clone();
        t += rc.clone();
        s[0] = t.exp_const_u64::<SBOX>();
        LL::internal_linear_layer(&mut s);
        for i in 0..WIDTH {
            builder.assert_eq(local[base + pf(r) + i], s[i].clone());
        }
        s = state_at::<AB>(local, base + pf(r));
    }

    for (r, rc) in air.end.iter().enumerate() {
        for i in 0..WIDTH {
            let mut t = s[i].clone();
            t += rc[i].clone();
            s[i] = t.exp_const_u64::<SBOX>();
        }
        LL::external_linear_layer(&mut s);
        for i in 0..WIDTH {
            builder.assert_eq(local[base + ef(r) + i], s[i].clone());
        }
        s = state_at::<AB>(local, base + ef(r));
    }
}

impl<AB: AirBuilder> Air<AB> for Poseidon2PermAir<AB::F> {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let pis: Vec<AB::PublicVar> = builder.public_values().to_vec();

        // Bind the committed input to the public input.
        for i in 0..WIDTH {
            builder.assert_eq(local[INP_OFF + i], pis[i]);
        }
        eval_perm_body(self, builder, local, 0);
        // Bind the final state to the public output.
        for i in 0..WIDTH {
            builder.assert_eq(local[output_off() + i], pis[WIDTH + i]);
        }
    }
}

/// Prove one permutation (input → its image). Uses COMPACT (blowup 8) since the
/// S-box gives degree-7 constraints.
pub fn prove_perm(
    air: &Poseidon2PermAir<Val>,
    input: [Val; WIDTH],
) -> (Config, Proof<Config>, Vec<Val>) {
    let config = make_config(FriProfile::COMPACT);
    let output = air.permute(input);
    let trace = air.generate_trace(input, ROWS);
    let pis = public_values(input, output);
    let proof = prove(&config, air, trace, &pis);
    (config, proof, pis)
}

/// Verify a permutation proof against its public input/output.
pub fn verify_perm(
    config: &Config,
    air: &Poseidon2PermAir<Val>,
    proof: &Proof<Config>,
    pis: &[Val],
) -> Result<(), String> {
    verify(config, air, proof, pis).map_err(|e| format!("{e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::borrow::Borrow;
    use p3_poseidon2_air::{generate_trace_rows, num_cols, Poseidon2Cols, RoundConstants};

    fn rand_state(seed: u64) -> [Val; WIDTH] {
        let mut rng = SmallRng::seed_from_u64(seed);
        array::from_fn(|_| rng.sample(StandardUniform))
    }

    /// The host permutation must match Plonky3's reference for identical
    /// constants — this validates the round structure and linear-layer use.
    #[test]
    fn host_matches_plonky3_reference() {
        let air = Poseidon2PermAir::new_seeded();
        let input = rand_state(7);
        let mine = air.permute(input);

        let rc =
            RoundConstants::<Val, WIDTH, HALF_FULL, PARTIAL>::new(air.begin, air.partial, air.end);
        let trace =
            generate_trace_rows::<Val, LL, WIDTH, SBOX, 0, HALF_FULL, PARTIAL>(vec![input], &rc, 0);
        let ncols = num_cols::<WIDTH, SBOX, 0, HALF_FULL, PARTIAL>();
        let cols: &Poseidon2Cols<Val, WIDTH, SBOX, 0, HALF_FULL, PARTIAL> =
            trace.values[..ncols].borrow();
        let theirs = cols.ending_full_rounds[HALF_FULL - 1].post;

        assert_eq!(mine, theirs, "host permutation diverges from Plonky3");
    }

    #[test]
    fn perm_proves_and_verifies() {
        let air = Poseidon2PermAir::new_seeded();
        let input = rand_state(1);
        let (config, proof, pis) = prove_perm(&air, input);
        verify_perm(&config, &air, &proof, &pis).expect("permutation proof verifies");
    }

    #[test]
    fn wrong_output_is_rejected() {
        let air = Poseidon2PermAir::new_seeded();
        let input = rand_state(2);
        let (config, proof, mut pis) = prove_perm(&air, input);
        // Tamper the claimed output.
        pis[WIDTH] += Val::ONE;
        assert!(verify_perm(&config, &air, &proof, &pis).is_err());
    }

    #[test]
    fn tampered_proof_is_rejected() {
        let air = Poseidon2PermAir::new_seeded();
        let input = rand_state(3);
        let (config, mut proof, pis) = prove_perm(&air, input);
        proof.degree_bits = proof.degree_bits.wrapping_add(1);
        assert!(verify_perm(&config, &air, &proof, &pis).is_err());
    }
}
