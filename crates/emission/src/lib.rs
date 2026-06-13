//! Issuance schedule and reward distribution (WP15, specs/emission.md).
//!
//! Per-checkpoint emission decays smoothly from `e0` to a perpetual tail
//! `e_tail` with half-life `half_life` checkpoints:
//!
//! ```text
//! E(h) = e_tail + (e0 - e_tail) * 2^(-h/half_life)
//! ```
//!
//! Computed in fixed point with NO floating point (consensus determinism,
//! engineering plan §6 rule 8). Within each half-life the curve is linearly
//! interpolated between successive halvings: smooth, monotonic, cliff-free,
//! and exactly reproducible on every node.
//!
//! The inclusion bonus (specs/emission.md §4) is structurally absent: β = 0
//! at genesis, so total emission is a pure function of height and the split
//! depends only on validator weight, never on transaction count.

const SCALE: u128 = 1 << 32;

#[derive(Clone, Copy, Debug)]
pub struct EmissionParams {
    pub e0: u64,
    pub e_tail: u64,
    pub half_life: u64,
}

impl EmissionParams {
    pub const fn new(e0: u64, e_tail: u64, half_life: u64) -> Self {
        assert!(half_life > 0, "half_life must be positive");
        Self {
            e0,
            e_tail,
            half_life,
        }
    }

    /// Fixed-point 2^(-h/half_life) scaled by SCALE, in [0, SCALE].
    fn decay_factor(&self, height: u64) -> u128 {
        let q = height / self.half_life; // whole halvings
        let r = height % self.half_life; // remainder within the period
        if q >= 64 {
            return 0;
        }
        let halvings = SCALE >> q; // 2^(-q) in fixed point
                                   // Linear interpolation toward the next halving: factor goes from
                                   // 2^(-q) at r=0 down to 2^(-(q+1)) at r=half_life.
        let drop = (halvings * r as u128) / (2 * self.half_life as u128);
        halvings - drop
    }

    /// Total emission minted at checkpoint `height`.
    pub fn emission_at(&self, height: u64) -> u64 {
        let span = (self.e0 - self.e_tail) as u128;
        let decayed = (span * self.decay_factor(height)) / SCALE;
        self.e_tail + decayed as u64
    }
}

/// One validator's reward at a checkpoint.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RewardShare {
    pub validator_index: u32,
    pub amount: u64,
}

/// Split `total` among validators in proportion to integer weights
/// (stake × participation). Deterministic: the rounding remainder goes to
/// the lowest-index validators so every node computes the same descriptor
/// and the shares sum exactly to `total`.
pub fn distribute(total: u64, weights: &[u64]) -> Vec<RewardShare> {
    let weight_sum: u128 = weights.iter().map(|&w| w as u128).sum();
    if weight_sum == 0 || weights.is_empty() {
        return Vec::new();
    }
    let mut shares = Vec::with_capacity(weights.len());
    let mut distributed: u64 = 0;
    for (i, &w) in weights.iter().enumerate() {
        let amount = ((total as u128 * w as u128) / weight_sum) as u64;
        distributed += amount;
        shares.push(RewardShare {
            validator_index: i as u32,
            amount,
        });
    }
    // Hand the remainder out one unit at a time, lowest index first.
    let mut remainder = total - distributed;
    let mut i = 0;
    while remainder > 0 {
        shares[i].amount += 1;
        remainder -= 1;
        i = (i + 1) % shares.len();
    }
    shares
}

/// Reward descriptor for a checkpoint: the public, auditable issuance event.
#[derive(Clone, Debug)]
pub struct RewardDescriptor {
    pub height: u64,
    pub total: u64,
    pub shares: Vec<RewardShare>,
}

pub fn reward_descriptor(
    params: &EmissionParams,
    height: u64,
    validator_weights: &[u64],
) -> RewardDescriptor {
    let total = params.emission_at(height);
    let shares = distribute(total, validator_weights);
    RewardDescriptor {
        height,
        total,
        shares,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: EmissionParams = EmissionParams::new(1_000_000, 10_000, 100);

    #[test]
    fn starts_at_e0_and_decays_to_tail() {
        assert_eq!(P.emission_at(0), 1_000_000);
        // One half-life in, roughly halfway between e0 and tail above tail.
        let mid = P.emission_at(100);
        let expected = 10_000 + (1_000_000 - 10_000) / 2;
        assert!((mid as i64 - expected as i64).abs() < 5_000);
        // Far future approaches the tail floor, never below.
        assert!(P.emission_at(10_000) >= P.e_tail);
        assert!(P.emission_at(10_000) < 12_000);
    }

    #[test]
    fn monotonic_non_increasing() {
        let mut prev = u64::MAX;
        for h in 0..2000 {
            let e = P.emission_at(h);
            assert!(
                e <= prev,
                "emission must never increase: h={h} e={e} prev={prev}"
            );
            assert!(e >= P.e_tail, "emission must never fall below tail");
            prev = e;
        }
    }

    #[test]
    fn distribute_sums_exactly() {
        for total in [0u64, 1, 7, 1_000_000, 999_999] {
            for weights in [vec![1u64, 1, 1], vec![10, 1], vec![3, 5, 7, 11], vec![1]] {
                let shares = distribute(total, &weights);
                let sum: u64 = shares.iter().map(|s| s.amount).sum();
                assert_eq!(sum, total, "total={total} weights={weights:?}");
            }
        }
    }

    #[test]
    fn equal_weights_equal_shares_modulo_remainder() {
        let shares = distribute(100, &[1, 1, 1, 1]);
        assert_eq!(shares.iter().map(|s| s.amount).sum::<u64>(), 100);
        for s in &shares {
            assert!(s.amount == 25);
        }
    }

    #[test]
    fn descriptor_is_auditable() {
        let d = reward_descriptor(&P, 50, &[2, 1]);
        assert_eq!(d.total, P.emission_at(50));
        assert_eq!(d.shares.iter().map(|s| s.amount).sum::<u64>(), d.total);
    }
}
