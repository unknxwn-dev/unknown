//! The full 2-in/2-out spend statement (C1–C7) in the **tall** layout — the
//! proof-size fix for the 5.4 MB wide fused proof (`docs/gate-a-report.md`).
//!
//! One Poseidon2 permutation per row, 86 real rows padded to height 128:
//!
//! ```text
//! per input i (39 rows):        per output j (4 rows):
//!   +0        tag sponge (nk)     +0..+3  cm sponge
//!   +1..+2    nf sponge (nk, rho)
//!   +3..+6    cm sponge (value, addr_tag, rho, rseed)
//!   +7..+38   Merkle path (leaf = cm digest)
//! ```
//!
//! Cross-row data flow uses three mechanisms, all within the two-row window:
//!
//! - **Adjacent chaining** (as in [`crate::tall`]): sponge capacity flows
//!   between consecutive absorb rows; the cm digest and each Merkle node flow
//!   into the next row's `dir`-selected input half.
//! - **Register columns** `nk`/`rho`/`tag`/`dummy` carry values that several
//!   non-adjacent rows need. `nk` is constant over the whole trace (one
//!   spender); the others are constant within an input's 39-row region
//!   (preprocessed `keep` selector) and re-bound where used: the tag sponge's
//!   digest is written to the `tag` register and read back as the cm sponge's
//!   `addr_tag` block (C3); `rho` ties the cm and nf sponges to one note;
//!   `dummy` gates the anchor binding (C1/C4).
//! - **A running accumulator** `acc[j]` (8 byte-limb columns) adds each value
//!   row's limbs with a preprocessed sign (+1 inputs, −1 outputs); the last
//!   row checks `acc + mint = 0` with the signed-carry byte equation (C7).
//!   Value rows also bit-decompose their limbs for the `< 2^62` range (C6).
//!
//! Public values are identical to the wide circuit's [`SpendPublic`]: anchor
//! root, two nullifiers, two output commitments, mint limbs. Preprocessed
//! selector columns mark which row binds which public digest.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::integers::QuotientMap;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{
    prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed, PreprocessedVerifierKey,
    Proof,
};
use unknown_interfaces::TREE_DEPTH;

use crate::field::{make_config, Config, FriProfile, Val};
use crate::hash::{CAP, DIGEST, RATE};
use crate::perm::{eval_perm_body, input_off, output_off, Poseidon2PermAir, WIDTH, WIDTH_COLS};
use crate::spend::{InputNote, Knockout, OutputNote, SpendPublic, N_IN, N_OUT};

const CM_BLOCKS: usize = 4;
const NF_BLOCKS: usize = 2;
const DEPTH: usize = TREE_DEPTH;
const LIMBS: usize = 8;
const BITS: usize = 8;

// ----- row map ---------------------------------------------------------------

/// Rows per input region: tag sponge, nf sponge, cm sponge, Merkle path.
const IN_ROWS: usize = 1 + NF_BLOCKS + CM_BLOCKS + DEPTH;
const REAL_ROWS: usize = N_IN * IN_ROWS + N_OUT * CM_BLOCKS;
/// Trace height (power of two).
pub const HEIGHT: usize = REAL_ROWS.next_power_of_two();

const fn in_row(i: usize) -> usize {
    i * IN_ROWS
}
const fn tag_row(i: usize) -> usize {
    in_row(i)
}
const fn nf_row(i: usize, b: usize) -> usize {
    in_row(i) + 1 + b
}
const fn cm_row(i: usize, b: usize) -> usize {
    in_row(i) + 1 + NF_BLOCKS + b
}
const fn mk_row(i: usize, l: usize) -> usize {
    in_row(i) + 1 + NF_BLOCKS + CM_BLOCKS + l
}
const fn out_row(j: usize, b: usize) -> usize {
    N_IN * IN_ROWS + j * CM_BLOCKS + b
}

// ----- column layout ---------------------------------------------------------

/// Merkle direction bit (this level's node is the right child).
const S_DIR: usize = WIDTH_COLS;
/// Registers: nk (whole trace), rho/tag/dummy (per input region).
const S_NK: usize = S_DIR + 1;
const S_RHO: usize = S_NK + DIGEST;
const S_TAG: usize = S_RHO + DIGEST;
const S_DUMMY: usize = S_TAG + DIGEST;
/// Running signed balance accumulator, one column per byte limb.
const S_ACC: usize = S_DUMMY + 1;
/// Bit decomposition of the current row's value limbs (value rows only).
const S_BIT: usize = S_ACC + LIMBS;
/// Signed balance carries (3 bits per limb, offset +2), used on the last row.
const S_CARRY: usize = S_BIT + LIMBS * BITS;
/// Total trace width.
pub const SPEND_COLS: usize = S_CARRY + LIMBS * 3;

const fn bit_col(j: usize, k: usize) -> usize {
    S_BIT + j * BITS + k
}
const fn carry_col(j: usize, b: usize) -> usize {
    S_CARRY + j * 3 + b
}

// ----- preprocessed selectors --------------------------------------------------

const Q_CHAIN_S: usize = 0; // sponge capacity chains into the next row
const Q_CHAIN_D: usize = 1; // output digest routes into next row's dir-half
const Q_START: usize = 2; // sponge start: input capacity is zero
const Q_NK: usize = 3; // this row absorbs nk (tag row, nf block 0)
const Q_RHO: usize = 4; // this row absorbs rho (nf block 1, cm block 2)
const Q_TAGOUT: usize = 5; // tag digest row: output -> tag register
const Q_TAGIN: usize = 6; // cm block 1: input == tag register (C3)
const Q_SIGN: usize = 7; // ±1 on value rows (inputs +, outputs −)
const Q_VAL: usize = 8; // value row: range bits (C6)
const Q_VALIN: usize = 9; // input value row: dummy ⇒ zero value (C4)
const Q_NF0: usize = 10; // binds nullifier 0 (C2)
const Q_NF1: usize = 11;
const Q_CM0: usize = 12; // binds output commitment 0 (C5)
const Q_CM1: usize = 13;
const Q_ROOT: usize = 14; // Merkle root row, bound unless dummy (C1)
const Q_KEEP: usize = 15; // rho/tag/dummy registers held into the next row
const Q_COLS: usize = 16;

// public-value offsets (same as the wide circuit's SpendPublic::to_vec)
const PI_ROOT: usize = 0;
const fn pi_nf(i: usize) -> usize {
    DIGEST + i * DIGEST
}
const fn pi_cm(j: usize) -> usize {
    DIGEST + N_IN * DIGEST + j * DIGEST
}
const PI_MINT: usize = DIGEST + (N_IN + N_OUT) * DIGEST;

/// The tall spend AIR.
#[derive(Clone)]
pub struct TallSpendAir<F> {
    perm: Poseidon2PermAir<F>,
    /// Constraint family to disable (knockout harness); `None` in production.
    pub knockout: Knockout,
}

impl TallSpendAir<Val> {
    pub fn new_seeded() -> Self {
        Self {
            perm: Poseidon2PermAir::new_seeded(),
            knockout: Knockout::None,
        }
    }

    /// Return a copy with one constraint family disabled (test harness only).
    pub fn with_knockout(&self, k: Knockout) -> Self {
        Self {
            perm: self.perm.clone(),
            knockout: k,
        }
    }

    fn value_block(value: u64) -> [Val; RATE] {
        unknown_poseidon::value_limbs(value)
    }

    /// Fill one sponge absorb row: rate ‖ chained capacity, permuted in place.
    /// Returns the output digest and capacity.
    fn absorb(
        &self,
        row: &mut [Val],
        block: [Val; RATE],
        cap: [Val; CAP],
    ) -> ([Val; DIGEST], [Val; CAP]) {
        let mut input = [Val::ZERO; WIDTH];
        input[..RATE].copy_from_slice(&block);
        input[RATE..].copy_from_slice(&cap);
        self.perm.fill_perm_row(input, &mut row[..WIDTH_COLS]);
        let out = output_off();
        (
            row[out..out + DIGEST].try_into().unwrap(),
            row[out + RATE..out + WIDTH].try_into().unwrap(),
        )
    }

    /// Build the trace and public values (same caller contract as the wide
    /// [`crate::spend::SpendAir::generate_trace`]).
    pub fn generate_trace(
        &self,
        nk: [Val; RATE],
        inputs: &[InputNote; N_IN],
        outputs: &[OutputNote; N_OUT],
        mint: u64,
    ) -> (RowMajorMatrix<Val>, SpendPublic) {
        let mut values = vec![Val::ZERO; HEIGHT * SPEND_COLS];
        macro_rules! rowm {
            ($r:expr) => {{
                let r: usize = $r;
                &mut values[r * SPEND_COLS..(r + 1) * SPEND_COLS]
            }};
        }

        let mut nullifiers = [[Val::ZERO; DIGEST]; N_IN];
        let mut anchor = [Val::ZERO; DIGEST];

        for (i, note) in inputs.iter().enumerate() {
            assert_eq!(note.path.len(), DEPTH);
            // Tag sponge: addr_tag = Poseidon2(nk) (C3).
            let (tag_digest, _) = self.absorb(rowm!(tag_row(i)), nk, [Val::ZERO; CAP]);
            // Nullifier sponge: nf = H(nk ‖ rho) (C2).
            let (_, cap) = self.absorb(rowm!(nf_row(i, 0)), nk, [Val::ZERO; CAP]);
            let (nf, _) = self.absorb(rowm!(nf_row(i, 1)), note.rho, cap);
            nullifiers[i] = nf;
            // Commitment sponge (C5 preimage).
            let blocks = [
                Self::value_block(note.value),
                note.addr_tag,
                note.rho,
                note.rseed,
            ];
            let mut cap = [Val::ZERO; CAP];
            let mut cm = [Val::ZERO; DIGEST];
            for (b, blk) in blocks.iter().enumerate() {
                let (d, c) = self.absorb(rowm!(cm_row(i, b)), *blk, cap);
                cm = d;
                cap = c;
            }
            // Merkle path: leaf = cm digest (C1).
            let mut cur = cm;
            for (l, &(sib, dir)) in note.path.iter().enumerate() {
                let r = rowm!(mk_row(i, l));
                let (left, right) = if dir { (sib, cur) } else { (cur, sib) };
                let mut input = [Val::ZERO; WIDTH];
                input[..DIGEST].copy_from_slice(&left);
                input[DIGEST..].copy_from_slice(&right);
                self.perm.fill_perm_row(input, &mut r[..WIDTH_COLS]);
                r[S_DIR] = Val::from_bool(dir);
                let out = output_off();
                cur = r[out..out + DIGEST].try_into().unwrap();
            }
            if !note.dummy {
                anchor = cur;
            }
            // Region registers: rho / tag / dummy on every row of the region.
            for r in in_row(i)..in_row(i) + IN_ROWS {
                let row = rowm!(r);
                row[S_RHO..S_RHO + DIGEST].copy_from_slice(&note.rho);
                row[S_TAG..S_TAG + DIGEST].copy_from_slice(&tag_digest);
                row[S_DUMMY] = Val::from_bool(note.dummy);
            }
            // Range bits of the value limbs, on the value row.
            let vrow = rowm!(cm_row(i, 0));
            for j in 0..LIMBS {
                let byte = (note.value >> (8 * j)) & 0xff;
                for k in 0..BITS {
                    vrow[bit_col(j, k)] = Val::from_bool((byte >> k) & 1 == 1);
                }
            }
        }

        let mut out_cms = [[Val::ZERO; DIGEST]; N_OUT];
        for (j, note) in outputs.iter().enumerate() {
            let blocks = [
                Self::value_block(note.value),
                note.addr_tag,
                note.rho,
                note.rseed,
            ];
            let mut cap = [Val::ZERO; CAP];
            for (b, blk) in blocks.iter().enumerate() {
                let (d, c) = self.absorb(rowm!(out_row(j, b)), *blk, cap);
                out_cms[j] = d;
                cap = c;
            }
            let vrow = rowm!(out_row(j, 0));
            for l in 0..LIMBS {
                let byte = (note.value >> (8 * l)) & 0xff;
                for k in 0..BITS {
                    vrow[bit_col(l, k)] = Val::from_bool((byte >> k) & 1 == 1);
                }
            }
        }

        // Padding rows are permutations of the zero state.
        for r in REAL_ROWS..HEIGHT {
            let row = rowm!(r);
            self.perm
                .fill_perm_row([Val::ZERO; WIDTH], &mut row[..WIDTH_COLS]);
        }

        // nk register: constant across the whole trace.
        for r in 0..HEIGHT {
            rowm!(r)[S_NK..S_NK + DIGEST].copy_from_slice(&nk);
        }

        // Balance accumulator: acc[0] = 0; acc[r+1] = acc[r] + sign(r)·limbs(r).
        let mut acc = [0i64; LIMBS];
        for r in 0..HEIGHT {
            let row = rowm!(r);
            for (j, &a) in acc.iter().enumerate() {
                // acc values stay small (≤ ~4·255 per limb) and may be negative.
                row[S_ACC + j] = if a >= 0 {
                    Val::from_int(a as u32)
                } else {
                    -Val::from_int((-a) as u32)
                };
            }
            let sign = row_sign(r);
            if sign != 0 {
                let v = value_of_row(inputs, outputs, r);
                for (j, a) in acc.iter_mut().enumerate() {
                    *a += sign as i64 * ((v >> (8 * j)) & 0xff) as i64;
                }
            }
        }

        // Signed balance carries on the last row: acc[j] + mint_j + c_{j-1} = 256·c_j.
        let last = rowm!(HEIGHT - 1);
        let mut carry: i64 = 0;
        for (j, &a) in acc.iter().enumerate() {
            let mint_j = ((mint >> (8 * j)) & 0xff) as i64;
            let nc = (a + mint_j + carry).div_euclid(256);
            let off = nc + 2;
            last[carry_col(j, 0)] = Val::from_bool(off & 1 == 1);
            last[carry_col(j, 1)] = Val::from_bool((off >> 1) & 1 == 1);
            last[carry_col(j, 2)] = Val::from_bool((off >> 2) & 1 == 1);
            carry = nc;
        }

        let public = SpendPublic {
            root: anchor,
            nullifiers,
            out_cms,
            mint,
        };
        (RowMajorMatrix::new(values, SPEND_COLS), public)
    }
}

/// The ±1 balance sign of a row (+1 input value rows, −1 output value rows).
fn row_sign(r: usize) -> i32 {
    for i in 0..N_IN {
        if r == cm_row(i, 0) {
            return 1;
        }
    }
    for j in 0..N_OUT {
        if r == out_row(j, 0) {
            return -1;
        }
    }
    0
}

/// The note value absorbed on a value row (trace-generation helper).
fn value_of_row(inputs: &[InputNote; N_IN], outputs: &[OutputNote; N_OUT], r: usize) -> u64 {
    for (i, note) in inputs.iter().enumerate() {
        if r == cm_row(i, 0) {
            return note.value;
        }
    }
    for (j, note) in outputs.iter().enumerate() {
        if r == out_row(j, 0) {
            return note.value;
        }
    }
    unreachable!("not a value row");
}

impl<F: PrimeCharacteristicRing + Sync + Send> BaseAir<F> for TallSpendAir<F> {
    fn width(&self) -> usize {
        SPEND_COLS
    }
    fn num_public_values(&self) -> usize {
        DIGEST * (1 + N_IN + N_OUT) + LIMBS
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        // input halves + dir (digest routing / capacity chaining), registers
        // (keep), accumulator (running sum).
        (input_off()..input_off() + WIDTH)
            .chain([S_DIR])
            .chain(S_NK..S_NK + DIGEST)
            .chain(S_RHO..S_RHO + DIGEST)
            .chain(S_TAG..S_TAG + DIGEST)
            .chain([S_DUMMY])
            .chain(S_ACC..S_ACC + LIMBS)
            .collect()
    }
    fn preprocessed_width(&self) -> usize {
        Q_COLS
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let mut v = vec![F::ZERO; HEIGHT * Q_COLS];
        let mut set = |r: usize, q: usize, val: F| v[r * Q_COLS + q] = val;

        for i in 0..N_IN {
            set(tag_row(i), Q_START, F::ONE);
            set(tag_row(i), Q_NK, F::ONE);
            set(tag_row(i), Q_TAGOUT, F::ONE);

            set(nf_row(i, 0), Q_START, F::ONE);
            set(nf_row(i, 0), Q_NK, F::ONE);
            set(nf_row(i, 0), Q_CHAIN_S, F::ONE);
            set(nf_row(i, 1), Q_RHO, F::ONE);
            set(nf_row(i, 1), if i == 0 { Q_NF0 } else { Q_NF1 }, F::ONE);

            set(cm_row(i, 0), Q_START, F::ONE);
            set(cm_row(i, 0), Q_SIGN, F::ONE);
            set(cm_row(i, 0), Q_VAL, F::ONE);
            set(cm_row(i, 0), Q_VALIN, F::ONE);
            set(cm_row(i, 1), Q_TAGIN, F::ONE);
            set(cm_row(i, 2), Q_RHO, F::ONE);
            for b in 0..CM_BLOCKS - 1 {
                set(cm_row(i, b), Q_CHAIN_S, F::ONE);
            }
            // cm digest routes into the first Merkle row; each Merkle row
            // routes into the next, except the last (the root row).
            set(cm_row(i, CM_BLOCKS - 1), Q_CHAIN_D, F::ONE);
            for l in 0..DEPTH - 1 {
                set(mk_row(i, l), Q_CHAIN_D, F::ONE);
            }
            set(mk_row(i, DEPTH - 1), Q_ROOT, F::ONE);

            // Registers held constant within the region (transitions between
            // consecutive region rows; the boundary row is left unset).
            for r in in_row(i)..in_row(i) + IN_ROWS - 1 {
                set(r, Q_KEEP, F::ONE);
            }
        }

        for j in 0..N_OUT {
            set(out_row(j, 0), Q_START, F::ONE);
            set(out_row(j, 0), Q_SIGN, -F::ONE);
            set(out_row(j, 0), Q_VAL, F::ONE);
            for b in 0..CM_BLOCKS - 1 {
                set(out_row(j, b), Q_CHAIN_S, F::ONE);
            }
            set(
                out_row(j, CM_BLOCKS - 1),
                if j == 0 { Q_CM0 } else { Q_CM1 },
                F::ONE,
            );
        }

        Some(RowMajorMatrix::new(v, Q_COLS))
    }
}

impl<AB: AirBuilder> Air<AB> for TallSpendAir<AB::F>
where
    AB::F: Send,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice().to_vec();
        let next = main.next_slice().to_vec();
        let prep = builder.preprocessed().clone();
        let q = prep.current_slice().to_vec();
        let pis: Vec<AB::PublicVar> = builder.public_values().to_vec();

        let inp = input_off();
        let out = output_off();

        // Every row is a valid Poseidon2 permutation of its committed input.
        eval_perm_body(&self.perm, builder, &local, 0);
        builder.assert_bool(local[S_DIR]);
        builder.assert_bool(local[S_DUMMY]);

        // Sponge starts: input capacity is the zero IV.
        for j in 0..CAP {
            builder.assert_zero(q[Q_START] * local[inp + RATE + j]);
        }
        // Sponge capacity chaining into the next absorb.
        for j in 0..CAP {
            let nxt: AB::Expr = next[inp + RATE + j].into();
            let cur: AB::Expr = local[out + RATE + j].into();
            builder.assert_zero(q[Q_CHAIN_S] * (nxt - cur));
        }
        // Digest routing: this row's output digest occupies the half the next
        // row's dir selects (cm digest → Merkle leaf; Merkle node → next level).
        let ndir: AB::Expr = next[S_DIR].into();
        for j in 0..DIGEST {
            let cur: AB::Expr = local[out + j].into();
            let nl: AB::Expr = next[inp + j].into();
            let nr: AB::Expr = next[inp + DIGEST + j].into();
            let want =
                (AB::Expr::ONE - ndir.clone()) * (nl - cur.clone()) + ndir.clone() * (nr - cur);
            builder.assert_zero(q[Q_CHAIN_D] * want);
        }

        // Registers. nk is constant over the whole trace (one spender, C3);
        // rho/tag/dummy are constant within an input's region.
        let trans = builder.is_transition();
        for j in 0..DIGEST {
            let d: AB::Expr = next[S_NK + j].into() - local[S_NK + j].into();
            builder.assert_zero(trans.clone() * d);
            let d: AB::Expr = next[S_RHO + j].into() - local[S_RHO + j].into();
            builder.assert_zero(q[Q_KEEP] * d);
            let d: AB::Expr = next[S_TAG + j].into() - local[S_TAG + j].into();
            builder.assert_zero(q[Q_KEEP] * d);
        }
        let d: AB::Expr = next[S_DUMMY].into() - local[S_DUMMY].into();
        builder.assert_zero(q[Q_KEEP] * d);

        // Absorb bindings: nk rows (tag + nf block 0) and rho rows (nf block 1
        // + cm block 2) absorb the registered values.
        for j in 0..RATE {
            let inj: AB::Expr = local[inp + j].into();
            builder.assert_zero(q[Q_NK] * (inj.clone() - local[S_NK + j].into()));
            builder.assert_zero(q[Q_RHO] * (inj - local[S_RHO + j].into()));
        }

        // C3 ownership: the tag sponge's digest is the registered tag, and the
        // cm sponge absorbs exactly that tag as the note's addr_tag.
        for j in 0..DIGEST {
            let o: AB::Expr = local[out + j].into();
            builder.assert_zero(q[Q_TAGOUT] * (o - local[S_TAG + j].into()));
        }
        if self.knockout != Knockout::C3 {
            for j in 0..RATE {
                let inj: AB::Expr = local[inp + j].into();
                builder.assert_zero(q[Q_TAGIN] * (inj - local[S_TAG + j].into()));
            }
        }

        // C6 range: on value rows the absorbed limbs are bit-decomposed bytes
        // and the top two bits of the high limb are zero (value < 2^62).
        for j in 0..LIMBS {
            for k in 0..BITS {
                builder.assert_bool(local[bit_col(j, k)]);
            }
        }
        if self.knockout != Knockout::C6 {
            for j in 0..LIMBS {
                let mut acc = AB::Expr::ZERO;
                let mut coeff = AB::Expr::ONE;
                for k in 0..BITS {
                    acc += local[bit_col(j, k)] * coeff.clone();
                    coeff *= AB::Expr::TWO;
                }
                let inj: AB::Expr = local[inp + j].into();
                builder.assert_zero(q[Q_VAL] * (inj - acc));
            }
            builder.assert_zero(q[Q_VAL] * local[bit_col(LIMBS - 1, 6)]);
            builder.assert_zero(q[Q_VAL] * local[bit_col(LIMBS - 1, 7)]);
        }

        // C4: a dummy input carries zero value.
        if self.knockout != Knockout::C4 {
            for j in 0..LIMBS {
                let inj: AB::Expr = local[inp + j].into();
                builder.assert_zero(q[Q_VALIN] * local[S_DUMMY] * inj);
            }
        }

        // C7 balance accumulator: acc starts at zero and adds sign·limbs on
        // value rows (sign is the preprocessed ±1; zero elsewhere).
        let first = builder.is_first_row();
        for j in 0..LIMBS {
            builder.assert_zero(first.clone() * local[S_ACC + j]);
            let nxt: AB::Expr = next[S_ACC + j].into();
            let cur: AB::Expr = local[S_ACC + j].into();
            let inj: AB::Expr = local[inp + j].into();
            builder.assert_zero(trans.clone() * (nxt - cur - q[Q_SIGN] * inj));
        }
        // Last row: acc + mint balances to zero via signed byte carries.
        let last = builder.is_last_row();
        for j in 0..LIMBS {
            for b in 0..3 {
                builder.assert_bool(local[carry_col(j, b)]);
            }
        }
        if self.knockout != Knockout::C7 {
            let c256 = {
                let mut e = AB::Expr::ONE;
                for _ in 0..8 {
                    e *= AB::Expr::TWO;
                }
                e
            };
            let four = AB::Expr::TWO * AB::Expr::TWO;
            let mut carry_in = AB::Expr::ZERO;
            for j in 0..LIMBS {
                let carry_out = local[carry_col(j, 0)]
                    + local[carry_col(j, 1)] * AB::Expr::TWO
                    + local[carry_col(j, 2)] * four.clone()
                    - AB::Expr::TWO;
                let acc: AB::Expr = local[S_ACC + j].into();
                let mint: AB::Expr = pis[PI_MINT + j].into();
                builder.assert_zero(
                    last.clone() * (acc + mint + carry_in - carry_out.clone() * c256.clone()),
                );
                carry_in = carry_out;
            }
            builder.assert_zero(last * carry_in);
        }

        // Public bindings: nullifiers (C2), output commitments (C5), anchor
        // root for non-dummy inputs (C1).
        if self.knockout != Knockout::C2 {
            for (sel, base) in [(Q_NF0, pi_nf(0)), (Q_NF1, pi_nf(1))] {
                for j in 0..DIGEST {
                    let o: AB::Expr = local[out + j].into();
                    let p: AB::Expr = pis[base + j].into();
                    builder.assert_zero(q[sel] * (o - p));
                }
            }
        }
        if self.knockout != Knockout::C5 {
            for (sel, base) in [(Q_CM0, pi_cm(0)), (Q_CM1, pi_cm(1))] {
                for j in 0..DIGEST {
                    let o: AB::Expr = local[out + j].into();
                    let p: AB::Expr = pis[base + j].into();
                    builder.assert_zero(q[sel] * (o - p));
                }
            }
        }
        if self.knockout != Knockout::C1 {
            let real: AB::Expr = AB::Expr::ONE - local[S_DUMMY].into();
            for j in 0..DIGEST {
                let o: AB::Expr = local[out + j].into();
                let p: AB::Expr = pis[PI_ROOT + j].into();
                builder.assert_zero(q[Q_ROOT] * real.clone() * (o - p));
            }
        }
    }
}

/// Prove a full spend in the tall layout. Returns config, proof, preprocessed
/// verifier key, and the public values.
pub fn prove_tall_spend(
    air: &TallSpendAir<Val>,
    nk: [Val; RATE],
    inputs: &[InputNote; N_IN],
    outputs: &[OutputNote; N_OUT],
    mint: u64,
) -> (
    Config,
    Proof<Config>,
    PreprocessedVerifierKey<Config>,
    SpendPublic,
) {
    let config = make_config(FriProfile::COMPACT);
    let degree_bits = HEIGHT.trailing_zeros() as usize;
    let (pd, vk) =
        setup_preprocessed(&config, air, degree_bits).expect("AIR has preprocessed columns");
    let (trace, public) = air.generate_trace(nk, inputs, outputs, mint);
    let pis = public.to_vec();
    let proof = prove_with_preprocessed(&config, air, trace, &pis, Some(&pd));
    (config, proof, vk, public)
}

/// Verify a tall-spend proof against its public values.
pub fn verify_tall_spend(
    config: &Config,
    air: &TallSpendAir<Val>,
    proof: &Proof<Config>,
    vk: &PreprocessedVerifierKey<Config>,
    public: &SpendPublic,
) -> Result<(), String> {
    verify_with_preprocessed(config, air, proof, &public.to_vec(), Some(vk))
        .map_err(|e| format!("{e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spend::PathStep;
    use rand::distr::StandardUniform;
    use rand::rngs::SmallRng;
    use rand::{RngExt, SeedableRng};

    fn digest(rng: &mut SmallRng) -> [Val; DIGEST] {
        core::array::from_fn(|_| rng.sample(StandardUniform))
    }

    /// Balanced 2-real-input transfer, adjacent leaves of one tree (mirrors
    /// the wide circuit's test builder).
    fn build(
        seed: u64,
        vin: [u64; 2],
        vout: [u64; 2],
    ) -> (
        TallSpendAir<Val>,
        [Val; RATE],
        [InputNote; N_IN],
        [OutputNote; N_OUT],
    ) {
        let air = TallSpendAir::new_seeded();
        let mut rng = SmallRng::seed_from_u64(seed);
        let nk = digest(&mut rng);
        let tag = unknown_poseidon::sponge(&[nk]);
        let rho0 = digest(&mut rng);
        let rho1 = digest(&mut rng);
        let rs0 = digest(&mut rng);
        let rs1 = digest(&mut rng);
        let commit = |v: u64, rho, rs| {
            unknown_poseidon::sponge(&[unknown_poseidon::value_limbs(v), tag, rho, rs])
        };
        let cm0 = commit(vin[0], rho0, rs0);
        let cm1 = commit(vin[1], rho1, rs1);
        let shared: Vec<PathStep> = (1..DEPTH)
            .map(|_| (digest(&mut rng), rng.sample::<bool, _>(StandardUniform)))
            .collect();
        let mut p0 = vec![(cm1, false)];
        p0.extend(shared.iter().cloned());
        let mut p1 = vec![(cm0, true)];
        p1.extend(shared.iter().cloned());
        let inputs = [
            InputNote {
                value: vin[0],
                addr_tag: tag,
                rho: rho0,
                rseed: rs0,
                path: p0,
                dummy: false,
            },
            InputNote {
                value: vin[1],
                addr_tag: tag,
                rho: rho1,
                rseed: rs1,
                path: p1,
                dummy: false,
            },
        ];
        let outputs = [
            OutputNote {
                value: vout[0],
                addr_tag: digest(&mut rng),
                rho: digest(&mut rng),
                rseed: digest(&mut rng),
            },
            OutputNote {
                value: vout[1],
                addr_tag: digest(&mut rng),
                rho: digest(&mut rng),
                rseed: digest(&mut rng),
            },
        ];
        (air, nk, inputs, outputs)
    }

    #[test]
    fn tall_spend_proves_and_verifies() {
        let (air, nk, inputs, outputs) = build(1, [600, 400], [700, 300]);
        let (config, proof, vk, public) = prove_tall_spend(&air, nk, &inputs, &outputs, 0);
        verify_tall_spend(&config, &air, &proof, &vk, &public).expect("tall spend verifies");
    }

    #[test]
    fn tall_spend_matches_wide_public_values() {
        // Same witness ⇒ identical public values as the wide circuit (they
        // share the pipeline hash), so the tall circuit is a drop-in.
        let (air, nk, inputs, outputs) = build(2, [600, 400], [700, 300]);
        let wide = crate::spend::SpendAir::new_seeded();
        let (_, wide_public) = wide.generate_trace(nk, &inputs, &outputs, 0);
        let (_, tall_public) = air.generate_trace(nk, &inputs, &outputs, 0);
        assert_eq!(tall_public.to_vec(), wide_public.to_vec());
    }

    #[test]
    fn mint_coinbase_proves_and_verifies() {
        // Two dummies fund an output from the public mint.
        let air = TallSpendAir::new_seeded();
        let mut rng = SmallRng::seed_from_u64(3);
        let nk = digest(&mut rng);
        let tag = unknown_poseidon::sponge(&[nk]);
        let dpath = |rng: &mut SmallRng| -> Vec<PathStep> {
            (0..DEPTH).map(|_| (digest(rng), false)).collect()
        };
        let inputs = [
            InputNote {
                value: 0,
                addr_tag: tag,
                rho: digest(&mut rng),
                rseed: digest(&mut rng),
                path: dpath(&mut rng),
                dummy: true,
            },
            InputNote {
                value: 0,
                addr_tag: tag,
                rho: digest(&mut rng),
                rseed: digest(&mut rng),
                path: dpath(&mut rng),
                dummy: true,
            },
        ];
        let outputs = [
            OutputNote {
                value: 1000,
                addr_tag: digest(&mut rng),
                rho: digest(&mut rng),
                rseed: digest(&mut rng),
            },
            OutputNote {
                value: 0,
                addr_tag: digest(&mut rng),
                rho: digest(&mut rng),
                rseed: digest(&mut rng),
            },
        ];
        let (config, proof, vk, public) = prove_tall_spend(&air, nk, &inputs, &outputs, 1000);
        verify_tall_spend(&config, &air, &proof, &vk, &public).expect("mint verifies");
    }

    #[test]
    fn tampered_publics_are_rejected() {
        let (air, nk, inputs, outputs) = build(4, [600, 400], [700, 300]);
        let (config, proof, vk, public) = prove_tall_spend(&air, nk, &inputs, &outputs, 0);
        for f in [
            |p: &mut SpendPublic| p.root[0] += Val::ONE,
            |p: &mut SpendPublic| p.nullifiers[0][0] += Val::ONE,
            |p: &mut SpendPublic| p.nullifiers[1][0] += Val::ONE,
            |p: &mut SpendPublic| p.out_cms[0][0] += Val::ONE,
            |p: &mut SpendPublic| p.out_cms[1][0] += Val::ONE,
            |p: &mut SpendPublic| p.mint += 1,
        ] {
            let mut bad = public.clone();
            f(&mut bad);
            assert!(
                verify_tall_spend(&config, &air, &proof, &vk, &bad).is_err(),
                "tampered public value accepted"
            );
        }
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "constraints")]
    fn inflation_is_rejected() {
        // 600 + 400 != 800 + 300 — no valid carry assignment exists.
        let (air, nk, inputs, outputs) = build(5, [600, 400], [800, 300]);
        let _ = prove_tall_spend(&air, nk, &inputs, &outputs, 0);
    }

    /// The KPI test: the full tall spend proof must be under the 250 KB
    /// Gate-A budget (the wide layout was 5.4 MB).
    #[test]
    fn tall_spend_proof_meets_gate_a_kpi() {
        let (air, nk, inputs, outputs) = build(6, [600, 400], [700, 300]);
        let (_c, proof, _vk, _p) = prove_tall_spend(&air, nk, &inputs, &outputs, 0);
        let size = postcard::to_allocvec(&proof).unwrap().len();
        println!("tall fused spend proof: {size} bytes");
        assert!(
            size < 250 * 1024,
            "tall spend proof ({size} B) exceeds the 250 KB Gate-A KPI"
        );
    }
}
