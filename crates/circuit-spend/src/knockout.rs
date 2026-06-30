//! WP6d — knockout / mutation harness for the spend circuit.
//!
//! The anti-counterfeiting tripwire (feasibility §10 risk 5): for each spend
//! constraint family C1–C7 we construct a witness that violates *only* that
//! family, then assert that
//!  (a) the full circuit **rejects** it (the family is load-bearing), and
//!  (b) the circuit with exactly that family disabled **accepts** it (so the
//!      fault is specific — the test really exercises C_i and nothing else).
//!
//! Constraint evaluation uses Plonky3's `check_constraints` directly (no FRI),
//! so the whole matrix of faults runs fast. If any family were silently
//! unenforced, (a) would fail here.

#![cfg(test)]

use p3_air::check_constraints;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use rand::distr::StandardUniform;
use rand::rngs::SmallRng;
use rand::{RngExt, SeedableRng};

use crate::field::Val;
use crate::hash::DIGEST;
use crate::spend::{InputNote, Knockout, OutputNote, SpendAir, SpendPublic, DEPTH};

fn digest(rng: &mut SmallRng) -> [Val; DIGEST] {
    core::array::from_fn(|_| rng.sample(StandardUniform))
}

/// Does the trace satisfy the AIR's constraints? (Silences the panic hook so a
/// caught violation doesn't spam the test log.)
fn holds(air: &SpendAir<Val>, trace: &RowMajorMatrix<Val>, pis: &[Val]) -> bool {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        check_constraints(air, trace, pis);
    }));
    std::panic::set_hook(prev);
    r.is_ok()
}

/// Build a balanced 2-real-input transfer whose commitments are adjacent leaves
/// of one tree. `addr0_bad` makes input 0's `addr_tag != nk` (a C3 fault).
fn two_real(
    air: &SpendAir<Val>,
    rng: &mut SmallRng,
    vin: [u64; 2],
    vout: [u64; 2],
    mint: u64,
    addr0_bad: bool,
) -> (RowMajorMatrix<Val>, SpendPublic) {
    let nk = digest(rng);
    let honest_tag = air.tag(nk);
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
    let cm0 = air.commit(vin[0], addr0, rho0, rs0);
    let cm1 = air.commit(vin[1], honest_tag, rho1, rs1);
    let shared: Vec<_> = (1..DEPTH)
        .map(|_| (digest(rng), rng.sample::<bool, _>(StandardUniform)))
        .collect();
    let mut path0 = vec![(cm1, false)];
    path0.extend(shared.iter().cloned());
    let mut path1 = vec![(cm0, true)];
    path1.extend(shared.iter().cloned());

    let inputs = [
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
    ];
    let outputs = [
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
    ];
    air.generate_trace(nk, &inputs, &outputs, mint)
}

/// Input 0 is a dummy carrying a non-zero value (a C4 fault); input 1 is real.
/// Balanced: 5 (dummy) + 395 (real) = 200 + 200.
fn dummy_with_value(air: &SpendAir<Val>, rng: &mut SmallRng) -> (RowMajorMatrix<Val>, SpendPublic) {
    let nk = digest(rng);
    let tag = air.tag(nk);
    let path0: Vec<_> = (0..DEPTH).map(|_| (digest(rng), false)).collect();
    let path1: Vec<_> = (0..DEPTH)
        .map(|_| (digest(rng), rng.sample::<bool, _>(StandardUniform)))
        .collect();
    let inputs = [
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
    ];
    let outputs = [
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
    ];
    air.generate_trace(nk, &inputs, &outputs, 0)
}

/// Build the (faulty trace, public values) for a given knockout family.
fn fault(air: &SpendAir<Val>, family: Knockout, seed: u64) -> (RowMajorMatrix<Val>, Vec<Val>) {
    let mut rng = SmallRng::seed_from_u64(seed);
    match family {
        Knockout::C1 => {
            // Valid spend, then claim a wrong anchor root.
            let (trace, mut public) = two_real(air, &mut rng, [600, 400], [700, 300], 0, false);
            public.root[0] += Val::ONE;
            (trace, public.to_vec())
        }
        Knockout::C2 => {
            let (trace, mut public) = two_real(air, &mut rng, [600, 400], [700, 300], 0, false);
            public.nullifiers[0][0] += Val::ONE;
            (trace, public.to_vec())
        }
        Knockout::C3 => {
            // addr_tag != nk on input 0.
            let (trace, public) = two_real(air, &mut rng, [600, 400], [700, 300], 0, true);
            (trace, public.to_vec())
        }
        Knockout::C4 => {
            let (trace, public) = dummy_with_value(air, &mut rng);
            (trace, public.to_vec())
        }
        Knockout::C5 => {
            let (trace, mut public) = two_real(air, &mut rng, [600, 400], [700, 300], 0, false);
            public.out_cms[0][0] += Val::ONE;
            (trace, public.to_vec())
        }
        Knockout::C6 => {
            // A value == 2^62 (not < 2^62), kept balanced.
            let big = 1u64 << 62;
            let (trace, public) = two_real(air, &mut rng, [big, 0], [big, 0], 0, false);
            (trace, public.to_vec())
        }
        Knockout::C7 => {
            // Outputs exceed inputs + mint.
            let (trace, public) = two_real(air, &mut rng, [600, 400], [800, 300], 0, false);
            (trace, public.to_vec())
        }
        Knockout::None => unreachable!(),
    }
}

#[test]
fn each_constraint_family_is_load_bearing() {
    let air = SpendAir::new_seeded();
    let families = [
        Knockout::C1,
        Knockout::C2,
        Knockout::C3,
        Knockout::C4,
        Knockout::C5,
        Knockout::C6,
        Knockout::C7,
    ];
    for (i, &fam) in families.iter().enumerate() {
        let (trace, pis) = fault(&air, fam, 100 + i as u64);

        // (a) The full circuit must catch the fault.
        assert!(
            !holds(&air, &trace, &pis),
            "{fam:?}: full circuit accepted a witness that violates {fam:?}"
        );

        // (b) Disabling exactly that family must make the same witness valid,
        // proving the fault is specific to {fam:?}.
        let masked = air.with_knockout(fam);
        assert!(
            holds(&masked, &trace, &pis),
            "{fam:?}: knocking out {fam:?} did not make the faulty witness valid \
             (the fault is not isolated to {fam:?})"
        );
    }
}

/// Sanity: a fully valid witness passes the full circuit's constraint check.
#[test]
fn valid_witness_holds() {
    let air = SpendAir::new_seeded();
    let mut rng = SmallRng::seed_from_u64(7);
    let (trace, public) = two_real(&air, &mut rng, [600, 400], [700, 300], 0, false);
    assert!(holds(&air, &trace, &public.to_vec()));
}
