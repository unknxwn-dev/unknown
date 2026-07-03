//! Arithmetic spend constraints (C4/C6/C7) as a real, sound STARK AIR.
//!
//! This is the hand-written counterpart to the Poseidon2 workload in
//! [`crate::poseidon2`]. It enforces the spend statement's non-hash
//! constraints with genuine AIR constraints over BabyBear, proved and verified
//! with the same FRI config:
//!
//! - **C6 (range):** every value is < 2^62. Each value is carried in the trace
//!   as 64 boolean bits (8 byte-limbs × 8 bits); the two most-significant bits
//!   are constrained to zero.
//! - **C7 (balance):** `Σ v_in + mint = Σ v_out`, checked by schoolbook
//!   byte-limb addition with a carry chain that must terminate at zero. Because
//!   every limb sum and carry stays far below the BabyBear modulus, field
//!   equality is integer equality — so no value can be conjured (the
//!   anti-inflation property, feasibility §10 risk 5).
//! - **C4 (dummy):** a dummy input's value must be zero (`d_i · v_i = 0`), with
//!   `d_i` boolean.
//! - The public `mint` amount is bound into the trace, so the proof is about a
//!   specific minted value (supply auditability): for a transfer `mint = 0`,
//!   for coinbase it is the emission amount.
//!
//! Soundness here is real: tampering with any value, marking a non-zero input
//! dummy, or claiming the wrong mint all make proving fail (debug) or
//! verification reject. What is *not* yet bound is the link to the note
//! commitments/nullifiers — that requires fusing this AIR with the Poseidon2
//! hashing (the remaining WP6b work; see the crate docs).

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{prove, verify, Proof};

use crate::field::{make_config, Config, FriProfile, Val};

// ----- column layout -------------------------------------------------------
// All columns are booleans, which lets us assert_bool the entire row.

/// Logical values, in fixed order.
const IN0: usize = 0;
const IN1: usize = 1;
const MINT: usize = 2;
const OUT0: usize = 3;
const OUT1: usize = 4;
const N_VALUES: usize = 5;

const LIMBS: usize = 8; // bytes per value
const BITS: usize = 8; // bits per byte-limb

const N_VALUE_BITS: usize = N_VALUES * LIMBS * BITS; // 320 value bits
const D0: usize = N_VALUE_BITS; // dummy flag for IN0
const D1: usize = N_VALUE_BITS + 1; // dummy flag for IN1
const CARRY_OFF: usize = N_VALUE_BITS + 2; // 3 carry bits per limb follow
/// Carry bits per limb. Carries are *signed* (a per-digit output sum can
/// exceed the input sum), in `{-2..=3}`, encoded as 3 bits offset by +2.
const CARRY_BITS: usize = 3;
const CARRY_OFFSET: i64 = 2;
/// Total trace width.
pub const WIDTH: usize = CARRY_OFF + LIMBS * CARRY_BITS; // 346

/// Trace height. A power of two large enough for all FRI profiles, including
/// the high-blowup COMPACT one (`log_height > log_final_poly_len + log_blowup`).
pub const TRACE_ROWS: usize = 32;

/// Column index of bit `k` of byte-limb `j` of value `v`.
const fn bit(v: usize, j: usize, k: usize) -> usize {
    v * (LIMBS * BITS) + j * BITS + k
}

/// Column index of carry bit `b` of the signed carry out of byte-limb `j`.
const fn carry_bit(j: usize, b: usize) -> usize {
    CARRY_OFF + j * CARRY_BITS + b
}

// ----- witness / trace -----------------------------------------------------

/// Inputs to the balance statement. Values are atomic units (< 2^62).
#[derive(Clone, Copy, Debug)]
pub struct BalanceWitness {
    pub inputs: [u64; 2],
    pub mint: u64,
    pub outputs: [u64; 2],
    pub dummy: [bool; 2],
}

fn byte(v: u64, j: usize) -> u64 {
    (v >> (8 * j)) & 0xff
}

/// Field element of a byte value, built from bits (no `QuotientMap` needed).
fn byte_to_field(b: u64) -> Val {
    let mut acc = Val::ZERO;
    let mut pow = Val::ONE;
    for k in 0..BITS {
        if (b >> k) & 1 == 1 {
            acc += pow;
        }
        pow += pow;
    }
    acc
}

/// The public values the verifier supplies: the 8 byte-limbs of `mint`.
pub fn mint_public_values(mint: u64) -> Vec<Val> {
    (0..LIMBS).map(|j| byte_to_field(byte(mint, j))).collect()
}

/// Build the (row-replicated) execution trace for a witness.
pub fn generate_trace(w: &BalanceWitness, rows: usize) -> RowMajorMatrix<Val> {
    assert!(rows.is_power_of_two());
    let mut row = vec![Val::ZERO; WIDTH];

    let vals = [w.inputs[0], w.inputs[1], w.mint, w.outputs[0], w.outputs[1]];
    for (v, &val) in vals.iter().enumerate() {
        for j in 0..LIMBS {
            let b = byte(val, j);
            for k in 0..BITS {
                row[bit(v, j, k)] = Val::from_bool((b >> k) & 1 == 1);
            }
        }
    }
    row[D0] = Val::from_bool(w.dummy[0]);
    row[D1] = Val::from_bool(w.dummy[1]);

    // Schoolbook little-endian carry chain, balancing both sides to zero:
    //   (in_sum_j - out_sum_j) + carry_in = 256 * carry_out.
    // Carries are signed; we store `carry + 2` in 3 bits. Invalid witnesses
    // still produce a trace (the constraints then reject it).
    let mut carry: i64 = 0;
    for j in 0..LIMBS {
        let in_sum =
            byte(w.inputs[0], j) as i64 + byte(w.inputs[1], j) as i64 + byte(w.mint, j) as i64;
        let out_sum = byte(w.outputs[0], j) as i64 + byte(w.outputs[1], j) as i64;
        let new_carry = (in_sum - out_sum + carry).div_euclid(256);
        let off = new_carry + CARRY_OFFSET;
        row[carry_bit(j, 0)] = Val::from_bool(off & 1 == 1);
        row[carry_bit(j, 1)] = Val::from_bool((off >> 1) & 1 == 1);
        row[carry_bit(j, 2)] = Val::from_bool((off >> 2) & 1 == 1);
        carry = new_carry;
    }

    let mut values = Vec::with_capacity(WIDTH * rows);
    for _ in 0..rows {
        values.extend_from_slice(&row);
    }
    RowMajorMatrix::new(values, WIDTH)
}

// ----- AIR -----------------------------------------------------------------

/// The balance/range/selector AIR.
pub struct BalanceAir;

impl<F: PrimeCharacteristicRing + Sync> BaseAir<F> for BalanceAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        LIMBS
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new() // all constraints are single-row
    }
}

/// 2^k as an expression, built only from ONE/TWO (works for any builder field).
fn pow2<AB: AirBuilder>(k: usize) -> AB::Expr {
    let mut e = AB::Expr::ONE;
    for _ in 0..k {
        e *= AB::Expr::TWO;
    }
    e
}

/// Value `v`'s byte-limb `j` reconstructed from its 8 bit columns.
fn limb_expr<AB: AirBuilder>(row: &[AB::Var], v: usize, j: usize) -> AB::Expr {
    let mut acc = AB::Expr::ZERO;
    let mut coeff = AB::Expr::ONE;
    for k in 0..BITS {
        acc += row[bit(v, j, k)] * coeff.clone();
        coeff *= AB::Expr::TWO;
    }
    acc
}

impl<AB: AirBuilder> Air<AB> for BalanceAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let pis: Vec<AB::PublicVar> = builder.public_values().to_vec();

        // Every column is a boolean.
        for &cell in local {
            builder.assert_bool(cell);
        }

        // C6: each value < 2^62 (top two bits of the high byte are zero).
        for v in 0..N_VALUES {
            builder.assert_zero(local[bit(v, LIMBS - 1, 6)]);
            builder.assert_zero(local[bit(v, LIMBS - 1, 7)]);
        }

        // C4: a dummy input carries no value.
        for j in 0..LIMBS {
            builder.assert_zero(local[D0] * limb_expr::<AB>(local, IN0, j));
            builder.assert_zero(local[D1] * limb_expr::<AB>(local, IN1, j));
        }

        // C7: Σ v_in + mint = Σ v_out via byte-limb carry chain, balancing both
        // sides to zero. Carry out of limb j is `cb0 + 2·cb1 + 4·cb2 - 2`
        // (signed, in {-2..=3}); the final carry must be zero.
        let c256 = pow2::<AB>(8);
        let four = pow2::<AB>(2);
        let mut carry_in = AB::Expr::ZERO;
        for j in 0..LIMBS {
            let in_sum = limb_expr::<AB>(local, IN0, j)
                + limb_expr::<AB>(local, IN1, j)
                + limb_expr::<AB>(local, MINT, j);
            let out_sum = limb_expr::<AB>(local, OUT0, j) + limb_expr::<AB>(local, OUT1, j);
            let carry_out = local[carry_bit(j, 0)]
                + local[carry_bit(j, 1)] * AB::Expr::TWO
                + local[carry_bit(j, 2)] * four.clone()
                - AB::Expr::TWO;
            // in_sum + carry_in == out_sum + 256 * carry_out
            builder.assert_eq(
                in_sum + carry_in.clone(),
                out_sum + carry_out.clone() * c256.clone(),
            );
            carry_in = carry_out;
        }
        builder.assert_zero(carry_in); // no net imbalance

        // Bind the public mint amount.
        for (j, &p) in pis.iter().enumerate() {
            builder.assert_eq(limb_expr::<AB>(local, MINT, j), p);
        }
    }
}

// ----- prove / verify glue -------------------------------------------------

/// Prove a balance statement. Returns everything needed to verify.
pub fn prove_balance(
    profile: FriProfile,
    w: &BalanceWitness,
) -> (Config, BalanceAir, Proof<Config>, Vec<Val>) {
    let air = BalanceAir;
    let config = make_config(profile);
    let trace = generate_trace(w, TRACE_ROWS);
    let pis = mint_public_values(w.mint);
    let proof = prove(&config, &air, trace, &pis);
    (config, air, proof, pis)
}

/// Prove using a pre-built config and AIR (benchmarks exclude one-time setup).
pub fn prove_with(
    config: &Config,
    air: &BalanceAir,
    w: &BalanceWitness,
) -> (Proof<Config>, Vec<Val>) {
    let trace = generate_trace(w, TRACE_ROWS);
    let pis = mint_public_values(w.mint);
    let proof = prove(config, air, trace, &pis);
    (proof, pis)
}

/// Verify a balance proof against the public mint values.
pub fn verify_balance(
    config: &Config,
    air: &BalanceAir,
    proof: &Proof<Config>,
    pis: &[Val],
) -> Result<(), String> {
    verify(config, air, proof, pis).map_err(|e| format!("{e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_transfer_proves_and_verifies() {
        let w = BalanceWitness {
            inputs: [100, 50],
            mint: 0,
            outputs: [120, 30], // 150 in == 150 out
            dummy: [false, false],
        };
        let (config, air, proof, pis) = prove_balance(FriProfile::FAST, &w);
        verify_balance(&config, &air, &proof, &pis).expect("valid transfer verifies");
    }

    #[test]
    fn valid_mint_proves_and_verifies() {
        let w = BalanceWitness {
            inputs: [0, 0],
            mint: 1_000_000,
            outputs: [999_000, 1_000], // outputs == public mint
            dummy: [true, true],
        };
        let (config, air, proof, pis) = prove_balance(FriProfile::FAST, &w);
        verify_balance(&config, &air, &proof, &pis).expect("valid mint verifies");
    }

    #[test]
    fn verify_rejects_wrong_mint() {
        let w = BalanceWitness {
            inputs: [100, 50],
            mint: 0,
            outputs: [120, 30],
            dummy: [false, false],
        };
        let (config, air, proof, _pis) = prove_balance(FriProfile::FAST, &w);
        // Claim a non-zero mint that the trace does not encode.
        let wrong = mint_public_values(1);
        assert!(verify_balance(&config, &air, &proof, &wrong).is_err());
    }

    #[test]
    fn verify_rejects_tampered_proof() {
        let w = BalanceWitness {
            inputs: [100, 50],
            mint: 0,
            outputs: [120, 30],
            dummy: [false, false],
        };
        let (config, air, mut proof, pis) = prove_balance(FriProfile::FAST, &w);
        proof.degree_bits = proof.degree_bits.wrapping_add(1);
        assert!(verify_balance(&config, &air, &proof, &pis).is_err());
    }

    // The constraint checker (debug builds) catches invalid witnesses at prove
    // time — these are the anti-counterfeiting tripwires.

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "constraints")]
    fn inflation_is_rejected() {
        let w = BalanceWitness {
            inputs: [100, 0],
            mint: 0,
            outputs: [101, 0], // conjures 1 unit
            dummy: [false, false],
        };
        let _ = prove_balance(FriProfile::FAST, &w);
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "constraints")]
    fn out_of_range_value_is_rejected() {
        let big = 1u64 << 62; // == MAX_MONEY, not < 2^62
        let w = BalanceWitness {
            inputs: [big, 0],
            mint: 0,
            outputs: [big, 0], // balances, but violates C6 range
            dummy: [false, false],
        };
        let _ = prove_balance(FriProfile::FAST, &w);
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "constraints")]
    fn dummy_with_value_is_rejected() {
        let w = BalanceWitness {
            inputs: [100, 0],
            mint: 0,
            outputs: [100, 0], // balances, but in0 is marked dummy with value
            dummy: [true, false],
        };
        let _ = prove_balance(FriProfile::FAST, &w);
    }
}
