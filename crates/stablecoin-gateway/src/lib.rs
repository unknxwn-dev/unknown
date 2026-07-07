//! Bank-facing stablecoin gateway core.
//!
//! This crate is the first implementation slice behind
//! `docs/stablecoin-bank-api-openapi.yaml`: typed assets and amounts, strict
//! resource state machines, and the two replaceable integration traits:
//! [`SettlementLedger`] for the chain side and [`BankConnector`] for the fiat
//! side. HTTP handlers, persistence, KYC providers, and real bank rails sit
//! above these interfaces.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use unknown_primitives::{ds, hash_parts};

/// Sandbox defaults from the G1/G2 OpenAPI contract.
pub const SANDBOX_ASSETS: [AssetId; 5] = [
    AssetId::new(*b"USD"),
    AssetId::new(*b"EUR"),
    AssetId::new(*b"GBP"),
    AssetId::new(*b"NGN"),
    AssetId::new(*b"JPY"),
];

/// Stablecoin asset id (`coinUSD`, `coinEUR`, ...).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct AssetId {
    currency: [u8; 3],
}

impl AssetId {
    pub const fn new(currency: [u8; 3]) -> Self {
        Self { currency }
    }

    pub fn currency(self) -> [u8; 3] {
        self.currency
    }

    pub fn api_id(self) -> String {
        format!(
            "coin{}{}{}",
            self.currency[0] as char, self.currency[1] as char, self.currency[2] as char
        )
    }
}

impl fmt::Display for AssetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.api_id())
    }
}

impl FromStr for AssetId {
    type Err = AssetParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.as_bytes();
        if bytes.len() != 7 || &bytes[..4] != b"coin" {
            return Err(AssetParseError);
        }
        let mut cur = [0u8; 3];
        cur.copy_from_slice(&bytes[4..]);
        if !cur.iter().all(u8::is_ascii_uppercase) {
            return Err(AssetParseError);
        }
        Ok(Self { currency: cur })
    }
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
#[error("asset id must look like coinUSD")]
pub struct AssetParseError;

/// Integer minor units. Never floating point.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct Amount(u128);

impl Amount {
    pub const ZERO: Self = Self(0);

    pub const fn new(raw: u128) -> Self {
        Self(raw)
    }

    pub fn raw(self) -> u128 {
        self.0
    }

    pub fn checked_add(self, other: Self) -> Option<Self> {
        self.0.checked_add(other.0).map(Self)
    }

    pub fn checked_sub(self, other: Self) -> Option<Self> {
        self.0.checked_sub(other.0).map(Self)
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Amount {
    type Err = AmountParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() || s.len() > 39 {
            return Err(AmountParseError);
        }
        if s.len() > 1 && s.starts_with('0') {
            return Err(AmountParseError);
        }
        let raw = s.parse::<u128>().map_err(|_| AmountParseError)?;
        Ok(Self(raw))
    }
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
#[error("amount must be a canonical unsigned integer minor-unit string")]
pub struct AmountParseError;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct CustomerId(pub [u8; 32]);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct AccountId(pub [u8; 32]);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct DepositId(pub [u8; 32]);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct TransferId(pub [u8; 32]);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct RedemptionId(pub [u8; 32]);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DepositState {
    Expected,
    Detected,
    Settled,
    Minting,
    Minted,
    Cancelled,
    Failed,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TransferState {
    Accepted,
    ComplianceCheck,
    Proving,
    Submitted,
    Confirmed,
    Failed,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RedemptionState {
    Accepted,
    ComplianceCheck,
    AwaitingBurn,
    Burning,
    Burned,
    PayoutPending,
    PayoutSent,
    PayoutFailed,
    Failed,
}

/// Validate a state transition for a resource with a closed lifecycle.
pub trait StateMachine: Copy + Eq {
    fn can_transition(self, next: Self) -> bool;
}

impl StateMachine for DepositState {
    fn can_transition(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Expected, Self::Detected | Self::Cancelled | Self::Failed)
                | (Self::Detected, Self::Settled | Self::Failed)
                | (Self::Settled, Self::Minting | Self::Failed)
                | (Self::Minting, Self::Minted | Self::Failed)
        )
    }
}

impl StateMachine for TransferState {
    fn can_transition(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Accepted, Self::ComplianceCheck | Self::Failed)
                | (Self::ComplianceCheck, Self::Proving | Self::Failed)
                | (Self::Proving, Self::Submitted | Self::Failed)
                | (Self::Submitted, Self::Confirmed | Self::Failed)
        )
    }
}

impl StateMachine for RedemptionState {
    fn can_transition(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Accepted, Self::ComplianceCheck | Self::Failed)
                | (Self::ComplianceCheck, Self::AwaitingBurn | Self::Failed)
                | (Self::AwaitingBurn, Self::Burning | Self::Failed)
                | (Self::Burning, Self::Burned | Self::Failed)
                | (Self::Burned, Self::PayoutPending | Self::Failed)
                | (Self::PayoutPending, Self::PayoutSent | Self::PayoutFailed)
                | (Self::PayoutFailed, Self::PayoutPending | Self::Failed)
        )
    }
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
#[error("illegal state transition")]
pub struct StateTransitionError;

pub fn transition<S: StateMachine>(current: S, next: S) -> Result<S, StateTransitionError> {
    if current.can_transition(next) {
        Ok(next)
    } else {
        Err(StateTransitionError)
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LedgerTxRef {
    pub tx_id: String,
    pub confirmed: bool,
    pub insecure_dev_ledger: bool,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BankEventRef {
    pub event_id: String,
    pub connector: &'static str,
    pub settled: bool,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ReserveInstructions {
    pub reference_code: String,
    pub currency: [u8; 3],
    pub account_hint: String,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PayoutAccount {
    pub currency: [u8; 3],
    pub account_ref: String,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Deposit {
    pub id: DepositId,
    pub customer_id: CustomerId,
    pub account_id: AccountId,
    pub asset_id: AssetId,
    pub amount: Amount,
    pub state: DepositState,
    pub reserve_instructions: ReserveInstructions,
    pub bank_event: Option<BankEventRef>,
    pub ledger_tx: Option<LedgerTxRef>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Transfer {
    pub id: TransferId,
    pub from_account_id: AccountId,
    pub to_account_id: AccountId,
    pub asset_id: AssetId,
    pub amount: Amount,
    pub state: TransferState,
    pub ledger_tx: Option<LedgerTxRef>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Redemption {
    pub id: RedemptionId,
    pub customer_id: CustomerId,
    pub account_id: AccountId,
    pub asset_id: AssetId,
    pub amount: Amount,
    pub state: RedemptionState,
    pub payout_account: PayoutAccount,
    pub bank_event: Option<BankEventRef>,
    pub ledger_tx: Option<LedgerTxRef>,
}

/// Chain-side adapter. Implementations may point at the current devnet, a stub,
/// a proven base chain, or the audited L1 later.
pub trait SettlementLedger {
    fn mint(
        &mut self,
        idempotency_key: &str,
        asset: AssetId,
        to_account: &AccountId,
        amount: Amount,
    ) -> Result<LedgerTxRef, LedgerError>;

    fn transfer(
        &mut self,
        idempotency_key: &str,
        asset: AssetId,
        from_account: &AccountId,
        to_account: &AccountId,
        amount: Amount,
    ) -> Result<LedgerTxRef, LedgerError>;

    fn burn(
        &mut self,
        idempotency_key: &str,
        asset: AssetId,
        from_account: &AccountId,
        amount: Amount,
    ) -> Result<LedgerTxRef, LedgerError>;

    fn circulating_supply(&self, asset: AssetId) -> Result<Amount, LedgerError>;
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum LedgerError {
    #[error("ledger rejected operation: {0}")]
    Rejected(&'static str),
    #[error("asset is not supported by this ledger")]
    UnsupportedAsset,
    #[error("ledger operation would overflow or underflow")]
    Balance,
}

/// Fiat-side adapter. One implementation per rail/bank connector.
pub trait BankConnector {
    fn reserve_instructions(
        &mut self,
        idempotency_key: &str,
        asset: AssetId,
        amount: Amount,
    ) -> Result<ReserveInstructions, BankError>;

    fn verify_settlement(
        &mut self,
        reference_code: &str,
    ) -> Result<Option<BankEventRef>, BankError>;

    fn initiate_payout(
        &mut self,
        idempotency_key: &str,
        asset: AssetId,
        amount: Amount,
        destination: &PayoutAccount,
    ) -> Result<BankEventRef, BankError>;

    fn reserve_balance(&self, asset: AssetId) -> Result<Amount, BankError>;
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum BankError {
    #[error("bank connector does not support this asset")]
    UnsupportedAsset,
    #[error("bank connector cannot find the requested reference")]
    UnknownReference,
    #[error("bank connector operation would overflow or underflow")]
    Balance,
}

/// Deterministic simulated bank for G1/G2 sandbox demos.
#[derive(Default)]
pub struct SimulatedBankConnector {
    reserves: BTreeMap<AssetId, Amount>,
    expected: BTreeMap<String, (AssetId, Amount)>,
}

impl SimulatedBankConnector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sandbox faucet: mark a deposit reference as settled and credit reserves.
    pub fn settle_reference(&mut self, reference_code: &str) -> Result<BankEventRef, BankError> {
        let (asset, amount) = self
            .expected
            .get(reference_code)
            .copied()
            .ok_or(BankError::UnknownReference)?;
        let current = self.reserves.get(&asset).copied().unwrap_or_default();
        let next = current.checked_add(amount).ok_or(BankError::Balance)?;
        self.reserves.insert(asset, next);
        Ok(BankEventRef {
            event_id: deterministic_id("bank.settle", reference_code),
            connector: "simulated",
            settled: true,
        })
    }
}

impl BankConnector for SimulatedBankConnector {
    fn reserve_instructions(
        &mut self,
        idempotency_key: &str,
        asset: AssetId,
        amount: Amount,
    ) -> Result<ReserveInstructions, BankError> {
        let reference_code = deterministic_id("bank.reference", idempotency_key);
        self.expected.insert(reference_code.clone(), (asset, amount));
        Ok(ReserveInstructions {
            reference_code,
            currency: asset.currency(),
            account_hint: format!("SIM-RESERVE-{asset}"),
        })
    }

    fn verify_settlement(
        &mut self,
        reference_code: &str,
    ) -> Result<Option<BankEventRef>, BankError> {
        if !self.expected.contains_key(reference_code) {
            return Err(BankError::UnknownReference);
        }
        Ok(None)
    }

    fn initiate_payout(
        &mut self,
        idempotency_key: &str,
        asset: AssetId,
        amount: Amount,
        destination: &PayoutAccount,
    ) -> Result<BankEventRef, BankError> {
        if destination.currency != asset.currency() {
            return Err(BankError::UnsupportedAsset);
        }
        let current = self.reserves.get(&asset).copied().unwrap_or_default();
        let next = current.checked_sub(amount).ok_or(BankError::Balance)?;
        self.reserves.insert(asset, next);
        Ok(BankEventRef {
            event_id: deterministic_id("bank.payout", idempotency_key),
            connector: "simulated",
            settled: true,
        })
    }

    fn reserve_balance(&self, asset: AssetId) -> Result<Amount, BankError> {
        Ok(self.reserves.get(&asset).copied().unwrap_or_default())
    }
}

fn deterministic_id(domain: &str, key: &str) -> String {
    let digest = hash_parts(ds::TX_BINDING, &[domain.as_bytes(), key.as_bytes()]);
    hex32(&digest[..16])
}

fn hex32(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_ids_parse_and_format() {
        let usd: AssetId = "coinUSD".parse().unwrap();
        assert_eq!(usd.to_string(), "coinUSD");
        assert!("USD".parse::<AssetId>().is_err());
        assert!("coinusd".parse::<AssetId>().is_err());
    }

    #[test]
    fn amounts_are_canonical_integer_strings() {
        assert_eq!("0".parse::<Amount>().unwrap().raw(), 0);
        assert_eq!("10000".parse::<Amount>().unwrap().raw(), 10_000);
        assert!("01".parse::<Amount>().is_err());
        assert!("1.0".parse::<Amount>().is_err());
        assert!("-1".parse::<Amount>().is_err());
    }

    #[test]
    fn state_machines_reject_skips() {
        assert!(transition(DepositState::Expected, DepositState::Detected).is_ok());
        assert!(transition(DepositState::Expected, DepositState::Minted).is_err());
        assert!(transition(TransferState::Submitted, TransferState::Confirmed).is_ok());
        assert!(transition(RedemptionState::Burned, RedemptionState::PayoutSent).is_err());
    }

    #[test]
    fn simulated_bank_settles_and_pays_out() {
        let mut bank = SimulatedBankConnector::new();
        let usd: AssetId = "coinUSD".parse().unwrap();
        let amount = Amount::new(10_000);
        let instructions = bank
            .reserve_instructions("deposit-1", usd, amount)
            .expect("instructions");
        assert_eq!(bank.reserve_balance(usd).unwrap(), Amount::ZERO);
        let event = bank
            .settle_reference(&instructions.reference_code)
            .expect("settlement");
        assert!(event.settled);
        assert_eq!(bank.reserve_balance(usd).unwrap(), amount);

        let payout = PayoutAccount {
            currency: *b"USD",
            account_ref: "sandbox:customer".into(),
        };
        let sent = bank
            .initiate_payout("redeem-1", usd, Amount::new(4_000), &payout)
            .expect("payout");
        assert!(sent.settled);
        assert_eq!(bank.reserve_balance(usd).unwrap(), Amount::new(6_000));
    }
}
