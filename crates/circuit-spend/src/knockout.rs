//! WP6d — knockout / mutation harness for the spend circuits.
//!
//! The anti-counterfeiting tripwire (feasibility §10 risk 5): for each spend
//! constraint family C1–C7 we construct a witness that violates *only* that
//! family, then assert that
//!  (a) the full circuit **rejects** it (the family is load-bearing), and
//!  (b) the circuit with exactly that family disabled **accepts** it (so the
//!      fault is specific — the test really exercises C_i and nothing else).
//!
//! The same fault matrix runs against both the wide [`SpendAir`] and the tall
//! [`TallSpendAir`] — the two must enforce the *same statement*, so a family
//! silently unenforced in either layout fails here.
//!
//! Constraint evaluation uses Plonky3's `check_constraints` directly (no FRI),
//! so the whole matrix of faults runs fast.

#![cfg(test)]

use p3_air::check_constraints;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use rand::distr::StandardUniform;
use rand::rngs::SmallRng;
use rand::{RngExt, SeedableRng};

use crate::field::Val;
use crate::hash::{DIGEST, RATE};
use crate::spend::{InputNote, Knockout, OutputNote, SpendAir, SpendPublic, DEPTH, N_IN, N_OUT};
use crate::tall_spend::TallSpendAir;

fn digest(rng: &mut SmallRng) -> [Val; DIGEST] {
    core::array::from_fn(|_| rng.sample(StandardUniform))
}

/// A complete spend witness (the inputs to either circuit's trace generator).
struct Witness {
    nk: [Val; RATE],
    inputs: [InputNote; N_IN],
    outputs: [OutputNote; N_OUT],
    mint: u64,
}

/// Does the trace satisfy the AIR's constraints? (Silences the panic hook so a
/// caught violation doesn't spam the test log.)
fn holds<A>(air: &A, trace: &RowMajorMatrix<Val>, pis: &[Val]) -> bool
where
    A: for<'a> p3_air::Air<p3_air::DebugConstraintBuilder<'a, Val>>,
{
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        check_constraints(air, trace, pis);
    }));
    std::panic::set_hook(prev);
    r.is_ok()
}

/// Build a balanced 2-real-input transfer whose commitments are adjacent leaves
/// of one tree. `addr0_bad` makes input 0's `addr_tag != Poseidon2(nk)` (a C3
/// fault). Host hashing goes through `unknown_poseidon` (shared by both AIRs).
fn two_real(
    rng: &mut SmallRng,
    vin: [u64; 2],
    vout: [u64; 2],
    mint: u64,
    addr0_bad: bool,
) -> Witness {
    let nk = digest(rng);
    let honest_tag = unknown_poseidon::sponge(&[nk]);
    let addr0 = if addr0_bad {
        // addr_tag != Poseidon2(nk): violates only C3.
        let mut a = honest_tag;
        a[0] += Val::ONE;
        a
    } else {
        honest_tag
    };
    let rho0 = digest(rng);
    let rho1 = digest(rng);
    let rs0 = digest(rng);
    let rs1 = digest(rng);
    let commit = |v: u64, tag, rho, rs| {
        unknown_poseidon::sponge(&[unknown_poseidon::value_limbs(v), tag, rho, rs])
    };
    let cm0 = commit(vin[0], addr0, rho0, rs0);
    let cm1 = commit(vin[1], honest_tag, rho1, rs1);
    let shared: Vec<_> = (1..DEPTH)
        .map(|_| (digest(rng), rng.sample::<bool, _>(StandardUniform)))
        .collect();
    let mut path0 = vec![(cm1, false)];
    path0.extend(shared.iter().cloned());
    let mut path1 = vec![(cm0, true)];
    path1.extend(shared.iter().cloned());

    Witness {
        nk,
        inputs: [
            InputNote {
                value: vin[0],
                addr_tag: addr0,
                rho: rho0,
                rseed: rs0,
                path: path0,
                dummy: false,
            },
            InputNote {
                value: vin[1],
                addr_tag: honest_tag,
                rho: rho1,
                rseed: rs1,
                path: path1,
                dummy: false,
            },
        ],
        outputs: [
            OutputNote {
                value: vout[0],
                addr_tag: digest(rng),
                rho: digest(rng),
                rseed: digest(rng),
            },
            OutputNote {
                value: vout[1],
                addr_tag: digest(rng),
                rho: digest(rng),
                rseed: digest(rng),
            },
        ],
        mint,
    }
}

/// Input 0 is a dummy carrying a non-zero value (a C4 fault); input 1 is real.
/// Balanced: 5 (dummy) + 395 (real) = 200 + 200.
fn dummy_with_value(rng: &mut SmallRng) -> Witness {
    let nk = digest(rng);
    let tag = unknown_poseidon::sponge(&[nk]);
    let path0: Vec<_> = (0..DEPTH).map(|_| (digest(rng), false)).collect();
    let path1: Vec<_> = (0..DEPTH)
        .map(|_| (digest(rng), rng.sample::<bool, _>(StandardUniform)))
        .collect();
    Witness {
        nk,
        inputs: [
            InputNote {
                value: 5,
                addr_tag: tag,
                rho: digest(rng),
                rseed: digest(rng),
                path: path0,
                dummy: true,
            },
            InputNote {
                value: 395,
                addr_tag: tag,
                rho: digest(rng),
                rseed: digest(rng),
                path: path1,
                dummy: false,
            },
        ],
        outputs: [
            OutputNote {
                value: 200,
                addr_tag: digest(rng),
                rho: digest(rng),
                rseed: digest(rng),
            },
            OutputNote {
                value: 200,
                addr_tag: digest(rng),
                rho: digest(rng),
                rseed: digest(rng),
            },
        ],
        mint: 0,
    }
}

/// Build the (witness, public-value mutation) for a given knockout family.
fn fault(family: Knockout, seed: u64) -> (Witness, fn(&mut SpendPublic)) {
    let mut rng = SmallRng::seed_from_u64(seed);
    let nop: fn(&mut SpendPublic) = |_| {};
    match family {
        Knockout::C1 => {
            // Valid spend, then claim a wrong anchor root.
            let w = two_real(&mut rng, [600, 400], [700, 300], 0, false);
            (w, |p| p.root[0] += Val::ONE)
        }
        Knockout::C2 => {
            let w = two_real(&mut rng, [600, 400], [700, 300], 0, false);
            (w, |p| p.nullifiers[0][0] += Val::ONE)
        }
        Knockout::C3 => {
            // addr_tag != Poseidon2(nk) on input 0.
            let w = two_real(&mut rng, [600, 400], [700, 300], 0, true);
            (w, nop)
        }
        Knockout::C4 => (dummy_with_value(&mut rng), nop),
        Knockout::C5 => {
            let w = two_real(&mut rng, [600, 400], [700, 300], 0, false);
            (w, |p| p.out_cms[0][0] += Val::ONE)
        }
        Knockout::C6 => {
            // A value == 2^62 (not < 2^62), kept balanced.
            let big = 1u64 << 62;
            let w = two_real(&mut rng, [big, 0], [big, 0], 0, false);
            (w, nop)
        }
        Knockout::C7 => {
            // Outputs exceed inputs + mint.
            let w = two_real(&mut rng, [600, 400], [800, 300], 0, false);
            (w, nop)
        }
        Knockout::None => unreachable!(),
    }
}

const FAMILIES: [Knockout; 7] = [
    Knockout::C1,
    Knockout::C2,
    Knockout::C3,
    Knockout::C4,
    Knockout::C5,
    Knockout::C6,
    Knockout::C7,
];

#[test]
fn each_constraint_family_is_load_bearing_wide() {
    let air = SpendAir::new_seeded();
    for (i, &fam) in FAMILIES.iter().enumerate() {
        let (w, mutate) = fault(fam, 100 + i as u64);
        let (trace, mut public) = air.generate_trace(w.nk, &w.inputs, &w.outputs, w.mint);
        mutate(&mut public);
        let pis = public.to_vec();

        // (a) The full circuit must catch the fault.
        assert!(
            !holds(&air, &trace, &pis),
            "{fam:?}: wide circuit accepted a witness that violates {fam:?}"
        );
        // (b) Disabling exactly that family must make the same witness valid.
        let masked = air.with_knockout(fam);
        assert!(
            holds(&masked, &trace, &pis),
            "{fam:?}: knocking out {fam:?} did not make the faulty witness valid \
             in the wide circuit (the fault is not isolated to {fam:?})"
        );
    }
}

#[test]
fn each_constraint_family_is_load_bearing_tall() {
    let air = TallSpendAir::new_seeded();
    for (i, &fam) in FAMILIES.iter().enumerate() {
        let (w, mutate) = fault(fam, 100 + i as u64);
        let (trace, mut public) = air.generate_trace(w.nk, &w.inputs, &w.outputs, w.mint);
        mutate(&mut public);
        let pis = public.to_vec();

        assert!(
            !holds(&air, &trace, &pis),
            "{fam:?}: tall circuit accepted a witness that violates {fam:?}"
        );
        let masked = air.with_knockout(fam);
        assert!(
            holds(&masked, &trace, &pis),
            "{fam:?}: knocking out {fam:?} did not make the faulty witness valid \
             in the tall circuit (the fault is not isolated to {fam:?})"
        );
    }
}

/// Sanity: a fully valid witness passes both circuits' constraint checks.
#[test]
fn valid_witness_holds() {
    let mut rng = SmallRng::seed_from_u64(7);
    let w = two_real(&mut rng, [600, 400], [700, 300], 0, false);

    let wide = SpendAir::new_seeded();
    let (trace, public) = wide.generate_trace(w.nk, &w.inputs, &w.outputs, w.mint);
    assert!(holds(&wide, &trace, &public.to_vec()));

    let tall = TallSpendAir::new_seeded();
    let (trace, public) = tall.generate_trace(w.nk, &w.inputs, &w.outputs, w.mint);
    assert!(holds(&tall, &trace, &public.to_vec()));
}
