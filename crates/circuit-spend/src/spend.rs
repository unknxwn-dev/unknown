//! WP6b — the full 2-in / 2-out spend statement (C1–C7) in one STARK.
//!
//! Composes the gadgets into the complete shielded-transfer statement:
//! - **C5** each input/output commitment `cm = H(value ‖ addr_tag ‖ rho)`;
//! - **C1** each *real* input commitment is a depth-32 Merkle leaf to the
//!   public anchor root (bypassed for dummies, **C4**);
//! - **C2** each input nullifier `nf = H(nk ‖ rho)`, bound to a public value;
//! - **C3** ownership: every input's `addr_tag` is `Poseidon2(nk)` for the
//!   spender's nullifier key `nk` (matching `unknown_keys`), so the address
//!   commits to `nk` without revealing it;
//! - **C4** a dummy input carries zero value and skips membership;
//! - **C6** every value `< 2^62` (8 byte-limbs, bit-decomposed);
//! - **C7** balance `Σ v_in + mint = Σ v_out` over the byte-limbs, with the
//!   public mint amount.
//!
//! Values are 8 byte-limbs; the *same* columns feed both the commitment sponge
//! (block 0) and the balance/range arithmetic, so there is nothing to keep in
//! sync. The two output commitments and the two nullifiers are bound to public
//! values; the anchor root and mint are public; everything else is witness.
//!
//! Layout is single-row (replicated to the COMPACT-SHORT minimum height): two
//! input blocks (commitment + nullifier sponges + Merkle path), two output
//! commitment sponges, then Merkle siblings/dirs, value range bits, balance
//! carry bits, and dummy flags.
//!
//! Not yet wired to the frozen `unknown_interfaces::SpendVerifier`: that trait
//! speaks 32-byte digests and a `u64` mint, whereas this circuit speaks
//! Poseidon2 field-element digests (decision D3). Bridging them is the
//! pipeline's BLAKE3→Poseidon2 migration, tracked separately.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{prove, verify, Proof};
use unknown_interfaces::TREE_DEPTH;

use crate::field::{make_config, Config, FriProfile, Val};
use crate::hash::{CAP, DIGEST, RATE};
use crate::perm::{eval_perm_body, input_off, output_off, Poseidon2PermAir, WIDTH, WIDTH_COLS};

/// Commitment preimage blocks: value ‖ addr_tag ‖ rho ‖ rseed (matches
/// `unknown_notes::Note::commitment`).
pub const CM_BLOCKS: usize = 4;
/// Nullifier preimage blocks: nk ‖ rho.
pub const NF_BLOCKS: usize = 2;
/// Merkle depth.
pub const DEPTH: usize = TREE_DEPTH;
/// Uniform transfer arity (decision D9).
pub const N_IN: usize = 2;
pub const N_OUT: usize = 2;
/// Byte-limbs per value, bits per limb.
const LIMBS: usize = 8;
const BITS: usize = 8;
/// 16-bit limbs of the 32-byte tx binding digest carried as public values.
/// 16-bit chunks are always < BabyBear's modulus, so arbitrary digest bytes
/// (BLAKE3 output) embed losslessly.
pub const BINDING_LIMBS: usize = 16;
/// Values that are range-checked in-circuit (the witness in/out amounts).
const N_VALUES: usize = N_IN + N_OUT;
/// Replicated rows (single-row computation; COMPACT-SHORT minimum height).
pub const ROWS: usize = 16;

// ----- column layout -------------------------------------------------------

/// Address-tag preimage blocks: nk (so addr_tag = Poseidon2(nk), C3).
const TAG_BLOCKS: usize = 1;
const PERMS_PER_IN: usize = CM_BLOCKS + NF_BLOCKS + TAG_BLOCKS + DEPTH;
const IN_COLS: usize = PERMS_PER_IN * WIDTH_COLS;
const OUT_COLS: usize = CM_BLOCKS * WIDTH_COLS;
const PERMS_END: usize = N_IN * IN_COLS + N_OUT * OUT_COLS;

const MERKLE_EX: usize = PERMS_END; // sib/dir per input
const BITS_BASE: usize = MERKLE_EX + N_IN * DEPTH * (DIGEST + 1);
const CARRY_BASE: usize = BITS_BASE + N_VALUES * LIMBS * BITS;
const DUMMY_BASE: usize = CARRY_BASE + LIMBS * 3;
/// Total trace width.
pub const TOTAL_COLS: usize = DUMMY_BASE + N_IN;

const fn in_base(i: usize) -> usize {
    i * IN_COLS
}
const fn out_base(j: usize) -> usize {
    N_IN * IN_COLS + j * OUT_COLS
}
const fn in_cm_block(i: usize, b: usize) -> usize {
    in_base(i) + b * WIDTH_COLS
}
const fn in_nf_block(i: usize, b: usize) -> usize {
    in_base(i) + (CM_BLOCKS + b) * WIDTH_COLS
}
/// The single address-tag sponge block for input `i` (hashes nk).
const fn in_tag_block(i: usize) -> usize {
    in_base(i) + (CM_BLOCKS + NF_BLOCKS) * WIDTH_COLS
}
const fn in_tag_out(i: usize) -> usize {
    in_tag_block(i) + output_off()
}
const fn in_merkle(i: usize, l: usize) -> usize {
    in_base(i) + (CM_BLOCKS + NF_BLOCKS + TAG_BLOCKS + l) * WIDTH_COLS
}
const fn in_cm_out(i: usize) -> usize {
    in_cm_block(i, CM_BLOCKS - 1) + output_off()
}
const fn in_nf_out(i: usize) -> usize {
    in_nf_block(i, NF_BLOCKS - 1) + output_off()
}
const fn in_root(i: usize) -> usize {
    in_merkle(i, DEPTH - 1) + output_off()
}
const fn out_cm_block(j: usize, b: usize) -> usize {
    out_base(j) + b * WIDTH_COLS
}
const fn out_cm_out(j: usize) -> usize {
    out_cm_block(j, CM_BLOCKS - 1) + output_off()
}
const fn sib_off(i: usize, l: usize) -> usize {
    MERKLE_EX + (i * DEPTH + l) * (DIGEST + 1)
}
const fn dir_off(i: usize, l: usize) -> usize {
    sib_off(i, l) + DIGEST
}
const fn val_bit(v: usize, j: usize, k: usize) -> usize {
    BITS_BASE + (v * LIMBS + j) * BITS + k
}
const fn carry_bit(j: usize, b: usize) -> usize {
    CARRY_BASE + j * 3 + b
}
const fn dummy_col(i: usize) -> usize {
    DUMMY_BASE + i
}

/// Value-byte column `j` of value `v` (0,1 = inputs; 2,3 = outputs). These are
/// the commitment sponge's block-0 rate inputs.
const fn val_byte(v: usize, j: usize) -> usize {
    let cm0 = if v < N_IN {
        in_cm_block(v, 0)
    } else {
        out_cm_block(v - N_IN, 0)
    };
    cm0 + input_off() + j
}

/// One Merkle path step (sibling digest, direction bit).
pub type PathStep = ([Val; DIGEST], bool);

/// Witness for one input note. For an honestly-owned note
/// `addr_tag == Poseidon2(nk)`.
#[derive(Clone)]
pub struct InputNote {
    pub value: u64,
    pub addr_tag: [Val; RATE],
    pub rho: [Val; RATE],
    pub rseed: [Val; RATE],
    pub path: Vec<PathStep>,
    pub dummy: bool,
}

/// Which constraint family to disable, for the WP6d knockout/mutation harness.
/// `None` is the real circuit; the others drop exactly one family so a test can
/// confirm that family (and only it) catches a corresponding fault.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Knockout {
    #[default]
    None,
    C1,
    C2,
    C3,
    C4,
    C5,
    C6,
    C7,
}

/// Witness for one output note.
#[derive(Clone)]
pub struct OutputNote {
    pub value: u64,
    pub addr_tag: [Val; RATE],
    pub rho: [Val; RATE],
    pub rseed: [Val; RATE],
}

/// Public outputs of proving: anchor root, the two nullifiers, the two output
/// commitments, the mint amount (as byte-limbs), and the tx binding digest
/// (as 16-bit limbs).
///
/// No AIR constraint reads the binding limbs; they bind the proof through the
/// Fiat–Shamir transcript alone. `p3_uni_stark`'s prover and verifier both
/// absorb the full public-values slice into the challenger before sampling
/// any challenge, so a proof generated for one binding digest fails
/// verification under any other. This is what authenticates the tx fields
/// outside the circuit's digests — notably `enc_outputs` and `anchor.height`
/// (security review F-1).
#[derive(Clone, Debug)]
pub struct SpendPublic {
    pub root: [Val; DIGEST],
    pub nullifiers: [[Val; DIGEST]; N_IN],
    pub out_cms: [[Val; DIGEST]; N_OUT],
    pub mint: u64,
    pub binding: [Val; BINDING_LIMBS],
}

/// Embed a 32-byte binding digest as public-value limbs (16-bit LE chunks).
pub fn binding_limbs(digest: [u8; 32]) -> [Val; BINDING_LIMBS] {
    use p3_field::integers::QuotientMap;
    core::array::from_fn(|i| {
        let x = u16::from_le_bytes(digest[i * 2..i * 2 + 2].try_into().unwrap());
        Val::from_int(x as u32)
    })
}

impl SpendPublic {
    /// Flatten to the public-values vector the prover/verifier use.
    pub fn to_vec(&self) -> Vec<Val> {
        let mut v = Vec::with_capacity(8 * (1 + N_IN + N_OUT) + LIMBS + BINDING_LIMBS);
        v.extend_from_slice(&self.root);
        for nf in &self.nullifiers {
            v.extend_from_slice(nf);
        }
        for cm in &self.out_cms {
            v.extend_from_slice(cm);
        }
        for j in 0..LIMBS {
            v.push(byte_to_field(byte(self.mint, j)));
        }
        v.extend_from_slice(&self.binding);
        v
    }
}

// public-value offsets within SpendPublic::to_vec()
const PI_ROOT: usize = 0;
const fn pi_nf(i: usize) -> usize {
    DIGEST + i * DIGEST
}
const fn pi_cm(j: usize) -> usize {
    DIGEST + N_IN * DIGEST + j * DIGEST
}
const PI_MINT: usize = DIGEST + (N_IN + N_OUT) * DIGEST;

fn byte(v: u64, j: usize) -> u64 {
    (v >> (8 * j)) & 0xff
}

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

/// The full spend AIR.
#[derive(Clone)]
pub struct SpendAir<F> {
    perm: Poseidon2PermAir<F>,
    /// Constraint family to disable (knockout harness); `None` in production.
    pub knockout: Knockout,
}

impl SpendAir<Val> {
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

    fn join(left: [Val; DIGEST], right: [Val; DIGEST]) -> [Val; WIDTH] {
        let mut out = [Val::ZERO; WIDTH];
        out[..DIGEST].copy_from_slice(&left);
        out[DIGEST..].copy_from_slice(&right);
        out
    }

    fn value_block(value: u64) -> [Val; RATE] {
        core::array::from_fn(|j| byte_to_field(byte(value, j)))
    }

    /// Host: note commitment `H(value ‖ addr_tag ‖ rho ‖ rseed)`.
    pub fn commit(
        &self,
        value: u64,
        addr_tag: [Val; RATE],
        rho: [Val; RATE],
        rseed: [Val; RATE],
    ) -> [Val; DIGEST] {
        let blocks = [Self::value_block(value), addr_tag, rho, rseed];
        let mut state = [Val::ZERO; WIDTH];
        for block in &blocks {
            state[0..RATE].copy_from_slice(block);
            state = self.perm.permute(state);
        }
        state[0..DIGEST].try_into().unwrap()
    }

    /// Host: address tag `Poseidon2(nk)` (1-block sponge) — equals
    /// `unknown_keys::SpendingKey::addr_tag` for the same `nk`.
    pub fn tag(&self, nk: [Val; RATE]) -> [Val; DIGEST] {
        let mut state = [Val::ZERO; WIDTH];
        state[0..RATE].copy_from_slice(&nk);
        let o = self.perm.permute(state);
        o[0..DIGEST].try_into().unwrap()
    }

    /// Host: 2-to-1 Merkle compression.
    pub fn compress(&self, a: [Val; DIGEST], b: [Val; DIGEST]) -> [Val; DIGEST] {
        let out = self.perm.permute(Self::join(a, b));
        out[0..DIGEST].try_into().unwrap()
    }

    fn fill_sponge(&self, blocks: &[[Val; RATE]], dst: &mut [Val], base: usize) -> [Val; DIGEST] {
        let mut cap = [Val::ZERO; CAP];
        let mut digest = [Val::ZERO; DIGEST];
        for (b, block) in blocks.iter().enumerate() {
            let off = base + b * WIDTH_COLS;
            let mut input = [Val::ZERO; WIDTH];
            input[0..RATE].copy_from_slice(block);
            input[RATE..WIDTH].copy_from_slice(&cap);
            self.perm
                .fill_perm_row(input, &mut dst[off..off + WIDTH_COLS]);
            let out = off + output_off();
            cap = dst[out + RATE..out + WIDTH].try_into().unwrap();
            digest = dst[out..out + DIGEST].try_into().unwrap();
        }
        digest
    }

    fn fill_merkle(
        &self,
        i: usize,
        cm: [Val; DIGEST],
        path: &[PathStep],
        row: &mut [Val],
    ) -> [Val; DIGEST] {
        let mut cur = cm;
        for (l, &(sib, dir)) in path.iter().enumerate() {
            let pbase = in_merkle(i, l);
            let input = if dir {
                Self::join(sib, cur)
            } else {
                Self::join(cur, sib)
            };
            self.perm
                .fill_perm_row(input, &mut row[pbase..pbase + WIDTH_COLS]);
            row[sib_off(i, l)..sib_off(i, l) + DIGEST].copy_from_slice(&sib);
            row[dir_off(i, l)] = Val::from_bool(dir);
            let out = pbase + output_off();
            cur = row[out..out + DIGEST].try_into().unwrap();
        }
        cur
    }

    /// Build the trace and the public values. The caller must supply a balanced,
    /// in-range transfer with a shared spender key `nk`.
    pub fn generate_trace(
        &self,
        nk: [Val; RATE],
        inputs: &[InputNote; N_IN],
        outputs: &[OutputNote; N_OUT],
        mint: u64,
    ) -> (RowMajorMatrix<Val>, SpendPublic) {
        let mut row = vec![Val::ZERO; TOTAL_COLS];
        let mut nullifiers = [[Val::ZERO; DIGEST]; N_IN];
        let mut anchor = [Val::ZERO; DIGEST];

        for (i, note) in inputs.iter().enumerate() {
            let value = Self::value_block(note.value);
            // cm = H(value ‖ addr_tag ‖ rho ‖ rseed); addr_tag = Poseidon2(nk).
            let cm = self.fill_sponge(
                &[value, note.addr_tag, note.rho, note.rseed],
                &mut row,
                in_base(i),
            );
            // nf = H(nk ‖ rho)
            let nf = self.fill_sponge(&[nk, note.rho], &mut row, in_nf_block(i, 0));
            nullifiers[i] = nf;
            // addr_tag = H(nk) (C3): fill the tag sponge; the digest is
            // recomputed/bound in-circuit, so the return value is unused here.
            let _ = self.fill_sponge(&[nk], &mut row, in_tag_block(i));
            let root = self.fill_merkle(i, cm, &note.path, &mut row);
            if !note.dummy {
                anchor = root; // all real inputs share the anchor
            }
            row[dummy_col(i)] = Val::from_bool(note.dummy);
        }

        let mut out_cms = [[Val::ZERO; DIGEST]; N_OUT];
        for (j, note) in outputs.iter().enumerate() {
            let value = Self::value_block(note.value);
            out_cms[j] = self.fill_sponge(
                &[value, note.addr_tag, note.rho, note.rseed],
                &mut row,
                out_base(j),
            );
        }

        // value range bits (inputs then outputs) + balance carry bits.
        let amounts = [
            inputs[0].value,
            inputs[1].value,
            outputs[0].value,
            outputs[1].value,
        ];
        for (v, &amt) in amounts.iter().enumerate() {
            for j in 0..LIMBS {
                let b = byte(amt, j);
                for k in 0..BITS {
                    row[val_bit(v, j, k)] = Val::from_bool((b >> k) & 1 == 1);
                }
            }
        }
        let mut carry: i64 = 0;
        for j in 0..LIMBS {
            let in_sum = byte(inputs[0].value, j) as i64
                + byte(inputs[1].value, j) as i64
                + byte(mint, j) as i64;
            let out_sum = byte(outputs[0].value, j) as i64 + byte(outputs[1].value, j) as i64;
            let nc = (in_sum - out_sum + carry).div_euclid(256);
            let off = nc + 2;
            row[carry_bit(j, 0)] = Val::from_bool(off & 1 == 1);
            row[carry_bit(j, 1)] = Val::from_bool((off >> 1) & 1 == 1);
            row[carry_bit(j, 2)] = Val::from_bool((off >> 2) & 1 == 1);
            carry = nc;
        }

        let public = SpendPublic {
            root: anchor,
            nullifiers,
            out_cms,
            mint,
            binding: [Val::ZERO; BINDING_LIMBS],
        };

        let mut values = Vec::with_capacity(TOTAL_COLS * ROWS);
        for _ in 0..ROWS {
            values.extend_from_slice(&row);
        }
        (RowMajorMatrix::new(values, TOTAL_COLS), public)
    }
}

impl<F: PrimeCharacteristicRing + Sync> BaseAir<F> for SpendAir<F> {
    fn width(&self) -> usize {
        TOTAL_COLS
    }
    fn num_public_values(&self) -> usize {
        DIGEST * (1 + N_IN + N_OUT) + LIMBS + BINDING_LIMBS
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }
}

fn eval_sponge<AB: AirBuilder>(
    perm: &Poseidon2PermAir<AB::F>,
    builder: &mut AB,
    local: &[AB::Var],
    base: usize,
    blocks: usize,
) {
    for b in 0..blocks {
        let off = base + b * WIDTH_COLS;
        for j in 0..CAP {
            let cap_in = off + input_off() + RATE + j;
            if b == 0 {
                builder.assert_zero(local[cap_in]);
            } else {
                let prev_out = (off - WIDTH_COLS) + output_off() + RATE + j;
                builder.assert_eq(local[cap_in], local[prev_out]);
            }
        }
        eval_perm_body(perm, builder, local, off);
    }
}

fn pow2<AB: AirBuilder>(k: usize) -> AB::Expr {
    let mut e = AB::Expr::ONE;
    for _ in 0..k {
        e *= AB::Expr::TWO;
    }
    e
}

/// Reconstruct value `v`'s byte-limb `j` from its bit columns.
fn limb_from_bits<AB: AirBuilder>(local: &[AB::Var], v: usize, j: usize) -> AB::Expr {
    let mut acc = AB::Expr::ZERO;
    let mut coeff = AB::Expr::ONE;
    for k in 0..BITS {
        acc += local[val_bit(v, j, k)] * coeff.clone();
        coeff *= AB::Expr::TWO;
    }
    acc
}

impl<AB: AirBuilder> Air<AB> for SpendAir<AB::F> {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let pis: Vec<AB::PublicVar> = builder.public_values().to_vec();

        // ---- inputs: commitment, nullifier, ownership, membership ----
        for i in 0..N_IN {
            eval_sponge(&self.perm, builder, local, in_base(i), CM_BLOCKS);
            eval_sponge(&self.perm, builder, local, in_nf_block(i, 0), NF_BLOCKS);
            // Tag sponge: addr_tag = Poseidon2(nk).
            eval_sponge(&self.perm, builder, local, in_tag_block(i), TAG_BLOCKS);

            let addr_tag = in_cm_block(i, 1) + input_off();
            let nk = in_nf_block(i, 0) + input_off();
            let cm_rho = in_cm_block(i, 2) + input_off();
            let nf_rho = in_nf_block(i, 1) + input_off();
            let tag_in = in_tag_block(i) + input_off();
            for j in 0..RATE {
                // The tag sponge hashes the same nk the nullifier uses.
                builder.assert_eq(local[tag_in + j], local[nk + j]);
                // rho is shared between the commitment and nullifier.
                builder.assert_eq(local[cm_rho + j], local[nf_rho + j]);
            }
            // C3 ownership: the note's addr_tag is Poseidon2(nk).
            if self.knockout != Knockout::C3 {
                for j in 0..DIGEST {
                    builder.assert_eq(local[addr_tag + j], local[in_tag_out(i) + j]);
                }
            }
            // For input i > 0 the keys must match input 0's (one spender).
            if i > 0 {
                let nk0 = in_nf_block(0, 0) + input_off();
                for j in 0..RATE {
                    builder.assert_eq(local[nk + j], local[nk0 + j]);
                }
            }

            // C2 nullifier bound to public.
            if self.knockout != Knockout::C2 {
                for j in 0..DIGEST {
                    builder.assert_eq(local[in_nf_out(i) + j], pis[pi_nf(i) + j]);
                }
            }

            // C4 dummy flag boolean; a dummy carries no value.
            let d = local[dummy_col(i)];
            builder.assert_bool(d);
            if self.knockout != Knockout::C4 {
                for j in 0..LIMBS {
                    builder.assert_zero(d * limb_from_bits::<AB>(local, i, j));
                }
            }

            // C1 membership: Merkle path from cm; root bound to anchor unless
            // the input is a dummy.
            for l in 0..DEPTH {
                let pbase = in_merkle(i, l);
                builder.assert_bool(local[dir_off(i, l)]);
                let cur_src = if l == 0 {
                    in_cm_out(i)
                } else {
                    in_merkle(i, l - 1) + output_off()
                };
                for j in 0..DIGEST {
                    let cur = local[cur_src + j];
                    let sib = local[sib_off(i, l) + j];
                    let dir: AB::Expr = local[dir_off(i, l)].into();
                    let left = cur * (AB::Expr::ONE - dir.clone()) + sib * dir.clone();
                    let right = sib * (AB::Expr::ONE - dir.clone()) + cur * dir;
                    builder.assert_eq(local[pbase + input_off() + j], left);
                    builder.assert_eq(local[pbase + input_off() + DIGEST + j], right);
                }
                eval_perm_body(&self.perm, builder, local, pbase);
            }
            // C1 root binding (skipped for dummies).
            if self.knockout != Knockout::C1 {
                let real: AB::Expr = AB::Expr::ONE - local[dummy_col(i)].into();
                for j in 0..DIGEST {
                    let diff: AB::Expr = local[in_root(i) + j].into() - pis[PI_ROOT + j].into();
                    builder.assert_zero(real.clone() * diff);
                }
            }
        }

        // ---- outputs: commitment bound to public (C5) ----
        for j in 0..N_OUT {
            eval_sponge(&self.perm, builder, local, out_base(j), CM_BLOCKS);
            if self.knockout != Knockout::C5 {
                for k in 0..DIGEST {
                    builder.assert_eq(local[out_cm_out(j) + k], pis[pi_cm(j) + k]);
                }
            }
        }

        // ---- C6 range: each value byte is a bit-decomposed limb < 256, and
        // the value is < 2^62 (top two bits of the high limb are zero). The
        // commitment sponge's value block must equal the reconstructed limbs.
        if self.knockout != Knockout::C6 {
            for v in 0..N_VALUES {
                for j in 0..LIMBS {
                    for k in 0..BITS {
                        builder.assert_bool(local[val_bit(v, j, k)]);
                    }
                    builder.assert_eq(local[val_byte(v, j)], limb_from_bits::<AB>(local, v, j));
                }
                builder.assert_zero(local[val_bit(v, LIMBS - 1, 6)]);
                builder.assert_zero(local[val_bit(v, LIMBS - 1, 7)]);
            }
        }

        // ---- C7 balance: Σ v_in + mint = Σ v_out via signed byte carries ----
        if self.knockout != Knockout::C7 {
            let c256 = pow2::<AB>(8);
            let four = pow2::<AB>(2);
            let mut carry_in = AB::Expr::ZERO;
            for j in 0..LIMBS {
                let in_sum = limb_from_bits::<AB>(local, 0, j)
                    + limb_from_bits::<AB>(local, 1, j)
                    + pis[PI_MINT + j].into();
                let out_sum = limb_from_bits::<AB>(local, 2, j) + limb_from_bits::<AB>(local, 3, j);
                let carry_out = local[carry_bit(j, 0)]
                    + local[carry_bit(j, 1)] * AB::Expr::TWO
                    + local[carry_bit(j, 2)] * four.clone()
                    - AB::Expr::TWO;
                builder.assert_eq(
                    in_sum + carry_in.clone(),
                    out_sum + carry_out.clone() * c256.clone(),
                );
                carry_in = carry_out;
            }
            builder.assert_zero(carry_in);
        }

        // carry bits boolean.
        for j in 0..LIMBS {
            for b in 0..3 {
                builder.assert_bool(local[carry_bit(j, b)]);
            }
        }
    }
}

/// Prove a full spend. Returns config, proof, and the public values.
/// `binding` is the tx binding digest, transcript-bound (see [`SpendPublic`]).
pub fn prove_spend(
    air: &SpendAir<Val>,
    nk: [Val; RATE],
    inputs: &[InputNote; N_IN],
    outputs: &[OutputNote; N_OUT],
    mint: u64,
    binding: [u8; 32],
) -> (Config, Proof<Config>, SpendPublic) {
    let config = make_config(FriProfile::COMPACT_SHORT);
    let (trace, mut public) = air.generate_trace(nk, inputs, outputs, mint);
    public.binding = binding_limbs(binding);
    let pis = public.to_vec();
    let proof = prove(&config, air, trace, &pis);
    (config, proof, public)
}

/// Verify a full-spend proof against its public values.
pub fn verify_spend(
    config: &Config,
    air: &SpendAir<Val>,
    proof: &Proof<Config>,
    public: &SpendPublic,
) -> Result<(), String> {
    verify(config, air, proof, &public.to_vec()).map_err(|e| format!("{e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::distr::StandardUniform;
    use rand::rngs::SmallRng;
    use rand::{RngExt, SeedableRng};

    fn digest(rng: &mut SmallRng) -> [Val; DIGEST] {
        core::array::from_fn(|_| rng.sample(StandardUniform))
    }

    /// Build a balanced 2-real-input transfer whose two input commitments are
    /// adjacent leaves of the *same* tree (so both Merkle paths reach one
    /// anchor root, as a real spend requires).
    fn build(
        seed: u64,
        vin: [u64; 2],
        vout: [u64; 2],
    ) -> (
        SpendAir<Val>,
        [Val; RATE],
        [InputNote; N_IN],
        [OutputNote; N_OUT],
    ) {
        let air = SpendAir::new_seeded();
        let mut rng = SmallRng::seed_from_u64(seed);
        let nk = digest(&mut rng);
        let rho0 = digest(&mut rng);
        let rho1 = digest(&mut rng);
        let rs0 = digest(&mut rng);
        let rs1 = digest(&mut rng);

        // addr_tag = Poseidon2(nk) is the recipient tag bound into the note.
        let tag = air.tag(nk);
        let cm0 = air.commit(vin[0], tag, rho0, rs0);
        let cm1 = air.commit(vin[1], tag, rho1, rs1);

        // Level 0: the inputs are each other's siblings (leaf0 left, leaf1
        // right); levels 1.. share the same siblings, so both reach one root.
        let shared: Vec<PathStep> = (1..DEPTH)
            .map(|_| (digest(&mut rng), rng.sample::<bool, _>(StandardUniform)))
            .collect();
        let mut path0 = vec![(cm1, false)];
        path0.extend(shared.iter().cloned());
        let mut path1 = vec![(cm0, true)];
        path1.extend(shared.iter().cloned());

        let inputs = [
            InputNote {
                value: vin[0],
                addr_tag: tag,
                rho: rho0,
                rseed: rs0,
                path: path0,
                dummy: false,
            },
            InputNote {
                value: vin[1],
                addr_tag: tag,
                rho: rho1,
                rseed: rs1,
                path: path1,
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
    fn full_spend_proves_and_verifies() {
        let (air, nk, inputs, outputs) = build(1, [600, 400], [700, 300]);
        let (config, proof, public) = prove_spend(&air, nk, &inputs, &outputs, 0, [9u8; 32]);
        verify_spend(&config, &air, &proof, &public).expect("spend verifies");
    }

    #[test]
    fn mint_coinbase_proves_and_verifies() {
        // Two dummy inputs, mint funds an output: 0 + 0 + mint(1000) = 1000 + 0.
        // Dummies bypass membership, so their paths are arbitrary.
        let air = SpendAir::new_seeded();
        let mut rng = SmallRng::seed_from_u64(2);
        let nk = digest(&mut rng);
        let dpath = |rng: &mut SmallRng| -> Vec<PathStep> {
            (0..DEPTH).map(|_| (digest(rng), false)).collect()
        };
        let tag = air.tag(nk);
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
        let (config, proof, public) = prove_spend(&air, nk, &inputs, &outputs, 1000, [9u8; 32]);
        verify_spend(&config, &air, &proof, &public).expect("mint verifies");
    }

    #[test]
    fn wrong_root_is_rejected() {
        let (air, nk, inputs, outputs) = build(3, [600, 400], [700, 300]);
        let (config, proof, mut public) = prove_spend(&air, nk, &inputs, &outputs, 0, [9u8; 32]);
        public.root[0] += Val::ONE;
        assert!(verify_spend(&config, &air, &proof, &public).is_err());
    }

    #[test]
    fn wrong_nullifier_is_rejected() {
        let (air, nk, inputs, outputs) = build(4, [600, 400], [700, 300]);
        let (config, proof, mut public) = prove_spend(&air, nk, &inputs, &outputs, 0, [9u8; 32]);
        public.nullifiers[1][0] += Val::ONE;
        assert!(verify_spend(&config, &air, &proof, &public).is_err());
    }

    #[test]
    fn wrong_output_commitment_is_rejected() {
        let (air, nk, inputs, outputs) = build(5, [600, 400], [700, 300]);
        let (config, proof, mut public) = prove_spend(&air, nk, &inputs, &outputs, 0, [9u8; 32]);
        public.out_cms[0][0] += Val::ONE;
        assert!(verify_spend(&config, &air, &proof, &public).is_err());
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "constraints")]
    fn inflation_is_rejected() {
        // Consistent paths, but outputs exceed inputs + mint: 600+400 != 800+300.
        let (air, nk, inputs, outputs) = build(6, [600, 400], [800, 300]);
        let _ = prove_spend(&air, nk, &inputs, &outputs, 0, [9u8; 32]);
    }
}
