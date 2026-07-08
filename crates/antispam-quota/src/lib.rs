//! RLN-style anonymous rate-limiting quota lane (WP16b).
//!
//! The primary feeless anti-spam mechanism (specs/emission.md §7.2, feasibility
//! §7). A user locks stake into a *quota note* granting `quota(stake)` message
//! slots per epoch. Each transaction carries a Rate-Limiting Nullifier proof:
//!
//!   * a per-slot **rate nullifier** `PRF(quota_key, epoch, k)`, `k < quota` —
//!     revealing the same (epoch, k) twice is detectable, and
//!   * a **Shamir share** `(x, y)` on the line `y = a0 + a1·x` where
//!     `a0` is the user's secret and `a1 = H(quota_key, epoch)`, evaluated at
//!     `x = H(message)`.
//!
//! Using one slot for two different messages yields two points on that line,
//! which recover `a0` — the secret — enabling **anonymous slashing** without
//! ever learning the honest user's identity. In production a zero-knowledge
//! proof attests that the nullifier and share are correctly derived from a
//! quota note in the pool with sufficient stake; this crate implements the
//! field/PRF core and the registry that rate-limits and slashes. It is
//! hash/field-based and post-quantum-friendly, and reuses the same note
//! machinery as the value pool.

use unknown_primitives::hash_parts;

/// Prime field GF(2^61 − 1) — a Mersenne prime. Products of two reduced
/// elements fit in u128, so reduction is a single `%`.
pub mod field {
    pub const P: u64 = (1 << 61) - 1;

    pub fn reduce(x: u128) -> u64 {
        (x % P as u128) as u64
    }
    pub fn add(a: u64, b: u64) -> u64 {
        ((a as u128 + b as u128) % P as u128) as u64
    }
    pub fn sub(a: u64, b: u64) -> u64 {
        ((a as u128 + P as u128 - b as u128) % P as u128) as u64
    }
    pub fn mul(a: u64, b: u64) -> u64 {
        reduce(a as u128 * b as u128)
    }
    pub fn pow(mut base: u64, mut exp: u64) -> u64 {
        let mut acc = 1u64;
        base %= P;
        while exp > 0 {
            if exp & 1 == 1 {
                acc = mul(acc, base);
            }
            base = mul(base, base);
            exp >>= 1;
        }
        acc
    }
    /// Multiplicative inverse via Fermat's little theorem.
    pub fn inv(a: u64) -> u64 {
        pow(a, P - 2)
    }
}

fn field_from(context: &str, parts: &[&[u8]]) -> u64 {
    let h = hash_parts(context, parts);
    field::reduce(u64::from_le_bytes(h[..8].try_into().unwrap()) as u128)
}

/// A quota note: locked stake plus a secret key. Its commitment enters the
/// parallel quota pool (mirrors `unknown_notes::Note`).
#[derive(Clone, Copy, Debug)]
pub struct QuotaNote {
    pub stake: u64,
    pub quota_key: [u8; 32],
}

/// Slots per epoch granted by a given stake. Linear with a floor of 1 so any
/// staker gets at least one slot; tune the divisor with the economics sim.
pub const STAKE_PER_SLOT: u64 = 1_000;

impl QuotaNote {
    pub fn quota(&self) -> u64 {
        (self.stake / STAKE_PER_SLOT).max(1)
    }

    pub fn commitment(&self) -> [u8; 32] {
        hash_parts(
            "unknown.v0.quota.cm",
            &[&self.stake.to_le_bytes(), &self.quota_key],
        )
    }

    /// Secret `a0` (the constant term of the RLN line) — recovered on misuse.
    fn secret(&self) -> u64 {
        field_from("unknown.v0.quota.a0", &[&self.quota_key])
    }

    /// Line slope `a1 = H(quota_key, epoch)`.
    fn slope(&self, epoch: u64) -> u64 {
        field_from(
            "unknown.v0.quota.a1",
            &[&self.quota_key, &epoch.to_le_bytes()],
        )
    }

    /// Rate nullifier for slot `k` in `epoch`.
    pub fn rate_nullifier(&self, epoch: u64, k: u64) -> [u8; 32] {
        hash_parts(
            "unknown.v0.quota.rn",
            &[&self.quota_key, &epoch.to_le_bytes(), &k.to_le_bytes()],
        )
    }

    /// Produce a rate proof binding this slot to `message`.
    pub fn signal(&self, epoch: u64, k: u64, message: &[u8]) -> Result<RateProof, QuotaError> {
        if k >= self.quota() {
            return Err(QuotaError::QuotaExceeded {
                k,
                quota: self.quota(),
            });
        }
        let x = message_x(message);
        let y = field::add(self.secret(), field::mul(self.slope(epoch), x));
        Ok(RateProof {
            epoch,
            rate_nullifier: self.rate_nullifier(epoch, k),
            x,
            y,
        })
    }
}

/// The Shamir x-coordinate a rate proof must use for a given message (the tx
/// binding digest). A verifier recomputes this to bind the share to the tx.
pub fn message_x(message: &[u8]) -> u64 {
    field_from("unknown.v0.quota.x", &[message])
}

/// Serialized length of a [`RateProof`] on the wire.
pub const RATE_PROOF_LEN: usize = 8 + 32 + 8 + 8; // 56

/// The per-transaction anti-spam artifact for the quota lane.
///
/// NOTE: the quota note's commitment is deliberately NOT carried here. Putting
/// it on the wire would link every transaction from the same staker within an
/// epoch. In production a zero-knowledge proof attests that `rate_nullifier`
/// derives from *some* sufficiently-staked quota note in the pool without
/// revealing which — preserving unlinkability. The rate nullifier changes each
/// epoch and per slot, so it leaks only the slot count, never identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RateProof {
    pub epoch: u64,
    pub rate_nullifier: [u8; 32],
    pub x: u64,
    pub y: u64,
}

impl RateProof {
    pub fn to_bytes(&self) -> [u8; RATE_PROOF_LEN] {
        let mut b = [0u8; RATE_PROOF_LEN];
        b[0..8].copy_from_slice(&self.epoch.to_le_bytes());
        b[8..40].copy_from_slice(&self.rate_nullifier);
        b[40..48].copy_from_slice(&self.x.to_le_bytes());
        b[48..56].copy_from_slice(&self.y.to_le_bytes());
        b
    }

    pub fn from_bytes(b: &[u8; RATE_PROOF_LEN]) -> Self {
        Self {
            epoch: u64::from_le_bytes(b[0..8].try_into().unwrap()),
            rate_nullifier: b[8..40].try_into().unwrap(),
            x: u64::from_le_bytes(b[40..48].try_into().unwrap()),
            y: u64::from_le_bytes(b[48..56].try_into().unwrap()),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum QuotaError {
    #[allow(dead_code)]
    QuotaExceeded { k: u64, quota: u64 },
}

#[derive(Debug, PartialEq, Eq)]
pub enum Admit {
    /// Fresh slot — transaction admitted.
    Ok,
    /// This exact (epoch, slot) was already used for the *same* message; a
    /// benign duplicate (e.g., rebroadcast). Rejected, no slash.
    Duplicate,
    /// The slot was reused for a *different* message: the secret is recovered
    /// and returned so the staker can be slashed.
    Slash { recovered_secret: u64 },
}

/// Registry of used slots for an epoch window; rate-limits and detects reuse.
#[derive(Default)]
pub struct QuotaRegistry {
    // (epoch, rate_nullifier) -> the (x, y) share first seen for that slot.
    seen: std::collections::HashMap<(u64, [u8; 32]), (u64, u64)>,
}

impl QuotaRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit a rate proof. First use of a slot is Ok; reuse with the same
    /// message is a Duplicate; reuse with a different message recovers the
    /// secret (Slash) via Lagrange interpolation of the two shares.
    pub fn admit(&mut self, proof: &RateProof) -> Admit {
        let key = (proof.epoch, proof.rate_nullifier);
        match self.seen.get(&key) {
            None => {
                self.seen.insert(key, (proof.x, proof.y));
                Admit::Ok
            }
            Some(&(x0, y0)) => {
                if x0 == proof.x {
                    return Admit::Duplicate;
                }
                // Two points on y = a0 + a1·x  =>  a1 = (y1-y0)/(x1-x0), a0 = y0 - a1·x0.
                let dx = field::sub(proof.x, x0);
                let dy = field::sub(proof.y, y0);
                let a1 = field::mul(dy, field::inv(dx));
                let a0 = field::sub(y0, field::mul(a1, x0));
                Admit::Slash {
                    recovered_secret: a0,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(stake: u64) -> QuotaNote {
        QuotaNote {
            stake,
            quota_key: [42u8; 32],
        }
    }

    #[test]
    fn quota_scales_with_stake_and_floors_at_one() {
        assert_eq!(note(0).quota(), 1);
        assert_eq!(note(500).quota(), 1);
        assert_eq!(note(10_000).quota(), 10);
    }

    #[test]
    fn honest_usage_within_quota_is_admitted() {
        let n = note(3_000); // quota = 3
        let mut reg = QuotaRegistry::new();
        for k in 0..3 {
            let p = n.signal(7, k, format!("tx-{k}").as_bytes()).unwrap();
            assert_eq!(reg.admit(&p), Admit::Ok);
        }
        // The 4th slot is out of quota.
        assert!(matches!(
            n.signal(7, 3, b"tx-3"),
            Err(QuotaError::QuotaExceeded { .. })
        ));
    }

    #[test]
    fn same_slot_same_message_is_a_benign_duplicate() {
        let n = note(5_000);
        let mut reg = QuotaRegistry::new();
        let p = n.signal(1, 0, b"hello").unwrap();
        assert_eq!(reg.admit(&p), Admit::Ok);
        assert_eq!(reg.admit(&p), Admit::Duplicate);
    }

    #[test]
    fn slot_reuse_for_two_messages_recovers_the_secret() {
        let n = note(5_000);
        let mut reg = QuotaRegistry::new();
        // Double-signal: same epoch, same slot k=0, two different messages.
        let p1 = n.signal(9, 0, b"pay alice").unwrap();
        let p2 = n.signal(9, 0, b"pay bob").unwrap();
        assert_eq!(reg.admit(&p1), Admit::Ok);
        match reg.admit(&p2) {
            Admit::Slash { recovered_secret } => {
                assert_eq!(
                    recovered_secret,
                    n.secret(),
                    "must recover the staker's secret"
                );
            }
            other => panic!("expected slash, got {other:?}"),
        }
    }

    #[test]
    fn different_epochs_reset_quota_and_dont_collide() {
        let n = note(1_000); // quota = 1
        let mut reg = QuotaRegistry::new();
        assert_eq!(reg.admit(&n.signal(1, 0, b"m").unwrap()), Admit::Ok);
        // Same slot index but a new epoch is a distinct nullifier: allowed.
        assert_eq!(reg.admit(&n.signal(2, 0, b"m").unwrap()), Admit::Ok);
    }

    #[test]
    fn distinct_stakers_do_not_interfere() {
        let a = QuotaNote {
            stake: 2_000,
            quota_key: [1u8; 32],
        };
        let b = QuotaNote {
            stake: 2_000,
            quota_key: [2u8; 32],
        };
        let mut reg = QuotaRegistry::new();
        assert_eq!(reg.admit(&a.signal(5, 0, b"x").unwrap()), Admit::Ok);
        // b's slot-0 nullifier differs from a's, so no false collision.
        assert_eq!(reg.admit(&b.signal(5, 0, b"y").unwrap()), Admit::Ok);
    }

    #[test]
    fn field_inverse_is_correct() {
        for a in [1u64, 2, 3, 1234567, field::P - 1] {
            assert_eq!(field::mul(a, field::inv(a)), 1);
        }
    }
}
