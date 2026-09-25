#![no_std]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

//! Invoice Token — tokenizes accounts-receivable invoices.
//! Each token unit represents 1 USD (7-decimal precision) of invoice face value.
//! Supports multiple invoices within a single deployed contract, each indexed
//! by its invoice_id.
//!
//! ## Lifecycle state machine
//! ```text
//! Created ──issue()──► Issued ──partial_settle()──► PartiallySettled ──settle()──► FullySettled
//!                         │                                │                             │
//!                         │                         transfer() OK                        │
//!                         └──────────────────settle()────────────────────────────────────┘
//!                                                                              redeem()/supply→0
//!                                                                           ► Redeemed
//! ```
//! Every transition is recorded in a per-invoice journal for audit purposes.

#[cfg(test)]
mod test;

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, symbol_short, Address,
    Env, String, Vec,
};
use token_helpers as th;

// ── Errors ────────────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum InvoiceError {
    AlreadyInitialized = 1,
    AlreadySettled = 2,
    NotSettled = 3,
    InsufficientBalance = 4,
    NegativeAmount = 5,
    InsufficientAllowance = 6,
    AllowanceExpired = 7,
    KycNotApproved = 8,
    CompliancePaused = 9,
    Blocklisted = 10,
    TransferBlocked = 11,
    PastDueDate = 12,
    InvoiceNotFound = 13,
    InvoiceAlreadyExists = 14,
    InvalidWebhook = 15,
    /// Attempted a lifecycle transition that is not permitted from the current state.
    InvalidLifecycleTransition = 16,
    /// Settlement amount or redemption amount exceeds the permitted ceiling.
    OverSettlement = 17,
    /// Settlement amount is below the required minimum (e.g. zero).
    UnderSettlement = 18,
    /// Settlement or redemption is blocked because the lifecycle is paused.
    LifecyclePaused = 19,
    /// Metadata field contains an invalid value (e.g. malformed ISIN or currency code).
    InvalidMetadata = 20,
}

// ── Lifecycle state machine ───────────────────────────────────────────────────

/// Formal lifecycle state of one invoice.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvoiceStatus {
    /// Invoice registered; no tokens minted yet.
    Created = 0,
    /// At least one token minted; settlement not yet initiated.
    Issued = 1,
    /// Partial payment recorded; redemption is proportional to the settlement ratio.
    /// Secondary-market transfers are still permitted in this state.
    PartiallySettled = 2,
    /// Full face-value payment recorded; holders may redeem their entire balance.
    FullySettled = 3,
    /// All tokens have been redeemed/burned post-settlement; supply is zero.
    Redeemed = 4,
}

/// One recorded entry in the per-invoice transition journal.
#[contracttype]
#[derive(Clone, Debug)]
pub struct JournalEntry {
    pub from_status: InvoiceStatus,
    pub to_status: InvoiceStatus,
    pub ledger: u32,
    pub timestamp: u64,
}

/// Result entry for batch_settle — one per invoice processed.
#[contracttype]
#[derive(Clone)]
pub struct BatchSettleResult {
    pub invoice_id: String,
    /// None on success; Some(InvoiceError code) on failure.
    pub error: Option<u32>,
}

// ── Storage keys ──────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    InvoiceMeta(String),
    Balance(Address, String),
    Allowance(Address, Address, String),
    TotalSupply(String),
    /// Replaces the old Settled(String) bool; read via `read_status`.
    InvoiceStatus(String),
    SettlementAmount(String),
    /// Append-only transition journal for a single invoice.
    Journal(String),
    InvoicesList,
    HolderList,
    /// When true, settle() and redeem() are blocked for all invoices.
    LifecyclePaused,
    /// Contract-level fee recipient role address (instance storage).
    FeeRecipientRole,
    /// When true, skip the per-transfer compliance check for the fee recipient (instance storage).
    FeeRecipientExempt,
    /// Locked-in redemption entitlement for a holder who transferred during PartiallySettled.
    /// Stores the remaining entitlement cap (i128, persistent).
    SettledEntitlement(String, Address),
    /// Accumulated unredeeemed settlement for an invoice (persistent, i128).
    /// Initialized to settlement_amount; decremented by each successful redeem().
    RedemptionDust(String),
}

// ── Supporting types ──────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
pub struct AllowanceValue {
    pub amount: i128,
    pub expiration_ledger: u32,
}

#[contracttype]
#[derive(Clone)]
pub struct InvoiceMeta {
    pub invoice_id: String,
    pub issuer: String,
    pub debtor: String,
    pub face_value_usd: i128,   // in stroops (7 decimals)
    pub discount_rate_bps: u32, // basis points
    pub due_date: u64,          // Unix timestamp
    pub currency: String,
    pub ipfs_doc_hash: String,
    pub transfer_fee_bps: u32,
    pub fee_recipient: Option<Address>,
    /// Optional webhook URL. If non-empty, must start with "https://".
    pub notification_webhook: String,
}

// ── TTL constants ─────────────────────────────────────────────────────────────

const DAY_IN_LEDGERS: u32 = 17280;
const BUMP: u32 = 90 * DAY_IN_LEDGERS;
const THRESHOLD: u32 = BUMP - DAY_IN_LEDGERS;

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct InvoiceToken;

#[contractimpl]
impl InvoiceToken {
    /// Constructor — sets admin/kyc/compliance and creates the first invoice atomically.
    pub fn __constructor(
        env: Env,
        admin: Address,
        kyc_registry: Address,
        compliance_engine: Address,
        meta: InvoiceMeta,
    ) {
        th::write_admin(&env, &admin);
        th::write_kyc_registry(&env, &kyc_registry);
        th::write_compliance_engine(&env, &compliance_engine);
        Self::do_create_invoice(&env, meta);
    }

    /// Legacy entry point — always panics.
    #[allow(clippy::too_many_arguments)]
    pub fn initialize(
        env: Env,
        _admin: Address,
        _kyc_registry: Address,
        _compliance_engine: Address,
        _meta: InvoiceMeta,
    ) {
        panic_with_error!(env, InvoiceError::AlreadyInitialized);
    }

    // ── Admin ─────────────────────────────────────────────────────────────────

    pub fn update_kyc_registry(env: Env, new_registry: Address) {
        th::update_kyc_registry(&env, new_registry);
    }

    pub fn update_compliance_engine(env: Env, new_engine: Address) {
        th::update_compliance_engine(&env, new_engine);
    }

    pub fn propose_admin(env: Env, new_admin: Address) {
        th::propose_admin(&env, new_admin);
    }

    pub fn accept_admin(env: Env) {
        th::accept_admin(&env);
    }

    // ── Fee recipient role ────────────────────────────────────────────────────

    /// Set the contract-level fee recipient role. Admin-only.
    /// Validates that `addr` is KYC-approved and not compliance-blocklisted
    /// at the time of assignment.
    pub fn set_fee_recipient(env: Env, addr: Address) {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        th::require_admin(&env);
        if th::get_kyc_state_of(&env, &addr) != th::KycState::Approved {
            panic_with_error!(env, InvoiceError::KycNotApproved);
        }
        // Verify the address passes a self-to-self compliance check (catches blocklist/pause).
        match th::evaluate_transfer_compliance(&env, &addr, &addr, 0) {
            th::TransferDecision::Allow => {}
            th::TransferDecision::Deny(ref reason) => {
                if th::is_kyc_deny_reason(reason) {
                    panic_with_error!(env, InvoiceError::KycNotApproved);
                } else {
                    panic_with_error!(env, InvoiceError::TransferBlocked);
                }
            }
        }
        env.storage()
            .instance()
            .set(&DataKey::FeeRecipientRole, &addr);
        env.events().publish((symbol_short!("fee_role"),), addr);
    }

    /// Set or clear the fee recipient exempt flag. When true, per-transfer compliance
    /// checks for the fee recipient are skipped and a `fee_skip` event is emitted.
    /// Admin-only.
    pub fn set_fee_recipient_exempt(env: Env, exempt: bool) {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        th::require_admin(&env);
        env.storage()
            .instance()
            .set(&DataKey::FeeRecipientExempt, &exempt);
        env.events().publish((symbol_short!("fee_xmpt"),), exempt);
    }

    /// Returns the contract-level fee recipient role address, if set.
    pub fn get_fee_recipient_role(env: Env) -> Option<Address> {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        env.storage().instance().get(&DataKey::FeeRecipientRole)
    }

    /// Returns whether the fee recipient compliance check is currently exempt.
    pub fn is_fee_recipient_exempt(env: Env) -> bool {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        env.storage()
            .instance()
            .get(&DataKey::FeeRecipientExempt)
            .unwrap_or(false)
    }

    // ── Lifecycle pause ───────────────────────────────────────────────────────

    /// Pause settlement and redemption for all invoices in this contract.
    /// Ordinary transfers (while in `Issued` or `PartiallySettled` state) are unaffected.
    /// Admin-only.
    pub fn pause_lifecycle(env: Env) {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        th::require_admin(&env);
        env.storage()
            .instance()
            .set(&DataKey::LifecyclePaused, &true);
        env.events().publish((symbol_short!("lc_pause"),), ());
    }

    /// Resume settlement and redemption.
    /// Admin-only.
    pub fn unpause_lifecycle(env: Env) {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        th::require_admin(&env);
        env.storage()
            .instance()
            .set(&DataKey::LifecyclePaused, &false);
        env.events().publish((symbol_short!("lc_unpse"),), ());
    }

    /// Returns true when settlement and redemption are currently paused.
    pub fn lifecycle_paused(env: Env) -> bool {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        env.storage()
            .instance()
            .get(&DataKey::LifecyclePaused)
            .unwrap_or(false)
    }

    // ── Invoice management ────────────────────────────────────────────────────

    /// Create a new invoice. Admin-only.
    pub fn create_invoice(env: Env, meta: InvoiceMeta) {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        th::require_admin(&env);
        Self::do_create_invoice(&env, meta);
    }

    /// List invoice IDs with pagination (zero-based offset, capped at 50).
    pub fn list_invoices(env: Env, start: u32, limit: u32) -> Vec<String> {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        let list: Vec<String> = env
            .storage()
            .instance()
            .get(&DataKey::InvoicesList)
            .unwrap_or_else(|| Vec::new(&env));
        let total = list.len();
        let cap: u32 = 50;
        let effective_limit = if limit > cap { cap } else { limit };
        let mut result: Vec<String> = Vec::new(&env);
        if start >= total {
            return result;
        }
        let end = (start + effective_limit).min(total);
        for i in start..end {
            result.push_back(list.get(i).expect("index in bounds"));
        }
        result
    }

    // ── Metadata ─────────────────────────────────────────────────────────────

    pub fn get_meta(env: Env, invoice_id: String) -> InvoiceMeta {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        env.storage()
            .persistent()
            .get(&DataKey::InvoiceMeta(invoice_id))
            .expect("invoice not found")
    }

    /// Replace stored invoice metadata. Admin-only; rejected if already settled.
    pub fn update_meta(env: Env, invoice_id: String, new_meta: InvoiceMeta) {
        th::require_admin(&env);
        Self::validate_webhook(&env, &new_meta.notification_webhook);
        Self::validate_invoice_meta(&env, &new_meta);
        let status = Self::read_status(&env, &invoice_id);
        if !matches!(status, InvoiceStatus::Created | InvoiceStatus::Issued) {
            panic_with_error!(env, InvoiceError::AlreadySettled);
        }
        env.storage()
            .persistent()
            .set(&DataKey::InvoiceMeta(invoice_id), &new_meta);
        env.events().publish((symbol_short!("upd_meta"),), ());
    }

    pub fn name(env: Env) -> String {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        String::from_str(&env, "Veritoken Invoice")
    }
    pub fn symbol(env: Env) -> String {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        String::from_str(&env, "VTINV")
    }
    pub fn decimals(env: Env) -> u32 {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        7
    }

    // ── Status & journal queries ──────────────────────────────────────────────

    /// Returns the current lifecycle status of an invoice.
    pub fn invoice_status(env: Env, invoice_id: String) -> InvoiceStatus {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        Self::read_status(&env, &invoice_id)
    }

    /// Returns the full audit journal for an invoice (all recorded transitions).
    pub fn get_journal(env: Env, invoice_id: String) -> Vec<JournalEntry> {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        Self::read_journal(&env, &invoice_id)
    }

    // ── Lifecycle ────────────────────────────────────────────────────────────

    /// Mint tokens for a specific invoice. Admin-only.
    pub fn issue(env: Env, invoice_id: String, to: Address, amount: i128) {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        th::require_admin(&env);
        if th::get_kyc_state_of(&env, &to) != th::KycState::Approved {
            panic_with_error!(env, InvoiceError::KycNotApproved);
        }

        let status = Self::read_status(&env, &invoice_id);
        match status {
            InvoiceStatus::Created => {
                Self::transition_status(
                    &env,
                    &invoice_id,
                    InvoiceStatus::Created,
                    InvoiceStatus::Issued,
                );
            }
            InvoiceStatus::Issued => {}
            _ => panic_with_error!(env, InvoiceError::AlreadySettled),
        }

        let meta: InvoiceMeta = env
            .storage()
            .persistent()
            .get(&DataKey::InvoiceMeta(invoice_id.clone()))
            .expect("invoice must exist");
        let supply: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::TotalSupply(invoice_id.clone()))
            .unwrap_or(0);
        if supply + amount > meta.face_value_usd {
            panic_with_error!(env, InvoiceError::OverSettlement);
        }

        let bal = Self::read_balance(&env, to.clone(), invoice_id.clone());
        env.storage().persistent().set(
            &DataKey::Balance(to.clone(), invoice_id.clone()),
            &(bal + amount),
        );
        env.storage().persistent().extend_ttl(
            &DataKey::Balance(to.clone(), invoice_id.clone()),
            THRESHOLD,
            BUMP,
        );
        th::do_register_holder(&env, &to);
        env.storage().persistent().set(
            &DataKey::TotalSupply(invoice_id.clone()),
            &(supply + amount),
        );
        env.storage().persistent().extend_ttl(
            &DataKey::TotalSupply(invoice_id.clone()),
            THRESHOLD,
            BUMP,
        );
        env.events().publish(
            (symbol_short!("issued"), to),
            (invoice_id, amount, meta.notification_webhook),
        );
    }

    /// Mark an invoice as fully settled (settlement_amount = face_value_usd).
    pub fn settle(env: Env, invoice_id: String) {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        th::require_admin(&env);
        Self::require_lifecycle_active(&env);

        let meta: InvoiceMeta = env
            .storage()
            .persistent()
            .get(&DataKey::InvoiceMeta(invoice_id.clone()))
            .expect("invoice must exist");

        let from_status = Self::read_status(&env, &invoice_id);
        if matches!(
            from_status,
            InvoiceStatus::FullySettled | InvoiceStatus::Redeemed
        ) {
            panic_with_error!(env, InvoiceError::AlreadySettled);
        }

        Self::transition_status(&env, &invoice_id, from_status, InvoiceStatus::FullySettled);

        env.storage().persistent().set(
            &DataKey::SettlementAmount(invoice_id.clone()),
            &meta.face_value_usd,
        );
        env.storage().persistent().extend_ttl(
            &DataKey::SettlementAmount(invoice_id.clone()),
            THRESHOLD,
            BUMP,
        );

        // Initialize redemption dust accumulator.
        env.storage().persistent().set(
            &DataKey::RedemptionDust(invoice_id.clone()),
            &meta.face_value_usd,
        );
        env.storage().persistent().extend_ttl(
            &DataKey::RedemptionDust(invoice_id.clone()),
            THRESHOLD,
            BUMP,
        );

        env.events().publish(
            (symbol_short!("settled"),),
            (invoice_id, meta.notification_webhook),
        );
    }

    /// Mark an invoice as partially settled with a specific payment amount.
    pub fn partial_settle(env: Env, invoice_id: String, settlement_amount: i128) {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        th::require_admin(&env);
        Self::require_lifecycle_active(&env);

        if settlement_amount <= 0 {
            panic_with_error!(env, InvoiceError::UnderSettlement);
        }
        let meta: InvoiceMeta = env
            .storage()
            .persistent()
            .get(&DataKey::InvoiceMeta(invoice_id.clone()))
            .expect("invoice must exist");
        if settlement_amount > meta.face_value_usd {
            panic_with_error!(env, InvoiceError::OverSettlement);
        }

        let from_status = Self::read_status(&env, &invoice_id);
        match from_status {
            InvoiceStatus::Created | InvoiceStatus::Issued => {}
            _ => panic_with_error!(env, InvoiceError::AlreadySettled),
        }

        let to_status = if settlement_amount == meta.face_value_usd {
            InvoiceStatus::FullySettled
        } else {
            InvoiceStatus::PartiallySettled
        };
        Self::transition_status(&env, &invoice_id, from_status, to_status);

        env.storage().persistent().set(
            &DataKey::SettlementAmount(invoice_id.clone()),
            &settlement_amount,
        );
        env.storage().persistent().extend_ttl(
            &DataKey::SettlementAmount(invoice_id.clone()),
            THRESHOLD,
            BUMP,
        );

        // Initialize redemption dust accumulator.
        env.storage().persistent().set(
            &DataKey::RedemptionDust(invoice_id.clone()),
            &settlement_amount,
        );
        env.storage().persistent().extend_ttl(
            &DataKey::RedemptionDust(invoice_id.clone()),
            THRESHOLD,
            BUMP,
        );

        env.events().publish(
            (symbol_short!("p_settld"),),
            (invoice_id, settlement_amount),
        );
    }

    pub fn settlement_amount(env: Env, invoice_id: String) -> i128 {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        env.storage()
            .persistent()
            .get(&DataKey::SettlementAmount(invoice_id))
            .unwrap_or(0)
    }

    /// Returns the remaining unredeemed settlement amount (dust) for an invoice.
    /// Admin-only.
    pub fn collect_redemption_dust(env: Env, invoice_id: String) -> i128 {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        th::require_admin(&env);
        env.storage()
            .persistent()
            .get(&DataKey::RedemptionDust(invoice_id))
            .unwrap_or(0)
    }

    /// Batch-settle up to 10 invoices in a single admin call.
    /// Each `(invoice_id, amount)` pair runs the partial_settle state machine.
    /// Failures are recorded in the result map; processing continues on error.
    pub fn batch_settle(env: Env, settlements: Vec<(String, i128)>) -> Vec<BatchSettleResult> {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        th::require_admin(&env);

        let total = settlements.len();
        let cap: u32 = 10;
        let effective = if total > cap { cap } else { total };

        let mut results: Vec<BatchSettleResult> = Vec::new(&env);
        for i in 0..effective {
            let (invoice_id, amount) = settlements.get(i).expect("index in bounds");
            let error = Self::try_do_partial_settle(&env, &invoice_id, amount);
            results.push_back(BatchSettleResult { invoice_id, error });
        }
        results
    }

    /// Redeem (burn) tokens after settlement.
    pub fn redeem(env: Env, invoice_id: String, from: Address, amount: i128) {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        from.require_auth();
        Self::require_lifecycle_active(&env);

        let status = Self::read_status(&env, &invoice_id);
        if !matches!(
            status,
            InvoiceStatus::PartiallySettled | InvoiceStatus::FullySettled
        ) {
            panic_with_error!(env, InvoiceError::NotSettled);
        }

        match th::evaluate_transfer_compliance(&env, &from, &from, amount) {
            th::TransferDecision::Allow => {}
            th::TransferDecision::Deny(ref reason) => {
                if th::is_kyc_deny_reason(reason) {
                    panic_with_error!(env, InvoiceError::KycNotApproved);
                } else {
                    panic_with_error!(env, InvoiceError::TransferBlocked);
                }
            }
        }

        let bal = Self::read_balance(&env, from.clone(), invoice_id.clone());
        if bal < amount {
            panic_with_error!(env, InvoiceError::InsufficientBalance);
        }

        let settlement: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::SettlementAmount(invoice_id.clone()))
            .unwrap_or(0);
        let total_supply: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::TotalSupply(invoice_id.clone()))
            .unwrap_or(0);

        // Compute max_redeemable: use SettledEntitlement if set (PartiallySettled transfer path),
        // otherwise use u128 arithmetic to avoid truncation-to-zero for small balances.
        let ent_key = DataKey::SettledEntitlement(invoice_id.clone(), from.clone());
        let has_entitlement = env.storage().persistent().has(&ent_key);
        let max_redeemable: i128 = if has_entitlement {
            let stored: i128 = env.storage().persistent().get(&ent_key).unwrap_or(0);
            stored.min(bal)
        } else if settlement > 0 && total_supply > 0 {
            (bal as u128)
                .checked_mul(settlement as u128)
                .and_then(|x| x.checked_div(total_supply as u128))
                .and_then(|x| i128::try_from(x).ok())
                .unwrap_or(0)
        } else {
            0
        };

        if amount > max_redeemable {
            panic_with_error!(env, InvoiceError::OverSettlement);
        }

        let new_bal = bal - amount;
        env.storage().persistent().set(
            &DataKey::Balance(from.clone(), invoice_id.clone()),
            &new_bal,
        );
        let new_supply = total_supply - amount;
        env.storage()
            .persistent()
            .set(&DataKey::TotalSupply(invoice_id.clone()), &new_supply);
        env.storage().persistent().extend_ttl(
            &DataKey::TotalSupply(invoice_id.clone()),
            THRESHOLD,
            BUMP,
        );

        // Decrement SettledEntitlement by amount redeemed.
        if has_entitlement {
            let stored: i128 = env.storage().persistent().get(&ent_key).unwrap_or(0);
            let remaining = stored.saturating_sub(amount);
            if remaining == 0 {
                env.storage().persistent().remove(&ent_key);
            } else {
                env.storage().persistent().set(&ent_key, &remaining);
                env.storage()
                    .persistent()
                    .extend_ttl(&ent_key, THRESHOLD, BUMP);
            }
        }

        // Decrement dust accumulator.
        let dust_key = DataKey::RedemptionDust(invoice_id.clone());
        if let Some(dust) = env.storage().persistent().get::<DataKey, i128>(&dust_key) {
            let new_dust = dust.saturating_sub(amount);
            env.storage().persistent().set(&dust_key, &new_dust);
            env.storage()
                .persistent()
                .extend_ttl(&dust_key, THRESHOLD, BUMP);
        }

        if new_supply == 0 {
            Self::transition_status(&env, &invoice_id, status, InvoiceStatus::Redeemed);
        }

        env.events()
            .publish((symbol_short!("redeemed"), from), (invoice_id, amount));
    }

    /// SEP-41-style burn.
    pub fn burn(env: Env, invoice_id: String, from: Address, amount: i128) {
        from.require_auth();
        match th::evaluate_transfer_compliance(&env, &from, &from, amount) {
            th::TransferDecision::Allow => {}
            th::TransferDecision::Deny(ref reason) => {
                if th::is_kyc_deny_reason(reason) {
                    panic_with_error!(env, InvoiceError::KycNotApproved);
                } else {
                    panic_with_error!(env, InvoiceError::TransferBlocked);
                }
            }
        }

        let bal = Self::read_balance(&env, from.clone(), invoice_id.clone());
        if bal < amount {
            panic_with_error!(env, InvoiceError::InsufficientBalance);
        }
        env.storage().persistent().set(
            &DataKey::Balance(from.clone(), invoice_id.clone()),
            &(bal - amount),
        );
        let supply: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::TotalSupply(invoice_id.clone()))
            .unwrap_or(0);
        let new_supply = supply - amount;
        env.storage()
            .persistent()
            .set(&DataKey::TotalSupply(invoice_id.clone()), &new_supply);
        env.storage().persistent().extend_ttl(
            &DataKey::TotalSupply(invoice_id.clone()),
            THRESHOLD,
            BUMP,
        );

        if new_supply == 0 {
            let status = Self::read_status(&env, &invoice_id);
            if matches!(
                status,
                InvoiceStatus::PartiallySettled | InvoiceStatus::FullySettled
            ) {
                Self::transition_status(&env, &invoice_id, status, InvoiceStatus::Redeemed);
            }
        }

        env.events()
            .publish((symbol_short!("burn"), from), (invoice_id, amount));
    }

    /// SEP-41-style burn_from.
    pub fn burn_from(env: Env, spender: Address, invoice_id: String, from: Address, amount: i128) {
        spender.require_auth();
        match th::evaluate_transfer_compliance(&env, &from, &from, amount) {
            th::TransferDecision::Allow => {}
            th::TransferDecision::Deny(ref reason) => {
                if th::is_kyc_deny_reason(reason) {
                    panic_with_error!(env, InvoiceError::KycNotApproved);
                } else {
                    panic_with_error!(env, InvoiceError::TransferBlocked);
                }
            }
        }

        let allowance =
            Self::read_allowance(&env, from.clone(), spender.clone(), invoice_id.clone());
        if allowance.amount < amount {
            panic_with_error!(env, InvoiceError::InsufficientAllowance);
        }
        if allowance.expiration_ledger < env.ledger().sequence() {
            panic_with_error!(env, InvoiceError::AllowanceExpired);
        }
        env.storage().persistent().set(
            &DataKey::Allowance(from.clone(), spender.clone(), invoice_id.clone()),
            &AllowanceValue {
                amount: allowance.amount - amount,
                expiration_ledger: allowance.expiration_ledger,
            },
        );

        let bal = Self::read_balance(&env, from.clone(), invoice_id.clone());
        if bal < amount {
            panic_with_error!(env, InvoiceError::InsufficientBalance);
        }
        env.storage().persistent().set(
            &DataKey::Balance(from.clone(), invoice_id.clone()),
            &(bal - amount),
        );
        let supply: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::TotalSupply(invoice_id.clone()))
            .unwrap_or(0);
        let new_supply = supply - amount;
        env.storage()
            .persistent()
            .set(&DataKey::TotalSupply(invoice_id.clone()), &new_supply);
        env.storage().persistent().extend_ttl(
            &DataKey::TotalSupply(invoice_id.clone()),
            THRESHOLD,
            BUMP,
        );

        if new_supply == 0 {
            let status = Self::read_status(&env, &invoice_id);
            if matches!(
                status,
                InvoiceStatus::PartiallySettled | InvoiceStatus::FullySettled
            ) {
                Self::transition_status(&env, &invoice_id, status, InvoiceStatus::Redeemed);
            }
        }

        env.events()
            .publish((symbol_short!("burn"), from), (invoice_id, amount));
    }

    pub fn balance(env: Env, id: Address, invoice_id: String) -> i128 {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        Self::read_balance(&env, id, invoice_id)
    }

    /// Transfer tokens between holders.
    /// Blocked in FullySettled and Redeemed states; allowed in Issued and PartiallySettled.
    /// When in PartiallySettled, the sender's redemption entitlement is snapshotted
    /// to prevent over-redemption after the transfer.
    pub fn transfer(env: Env, invoice_id: String, from: Address, to: Address, amount: i128) {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        from.require_auth();

        let status = Self::read_status(&env, &invoice_id);
        match status {
            InvoiceStatus::Issued | InvoiceStatus::PartiallySettled => {}
            InvoiceStatus::FullySettled | InvoiceStatus::Redeemed => {
                panic_with_error!(env, InvoiceError::AlreadySettled)
            }
            InvoiceStatus::Created => {
                panic_with_error!(env, InvoiceError::InvalidLifecycleTransition)
            }
        }

        let meta: InvoiceMeta = env
            .storage()
            .persistent()
            .get(&DataKey::InvoiceMeta(invoice_id.clone()))
            .expect("invoice not found");
        if env.ledger().timestamp() > meta.due_date {
            panic_with_error!(env, InvoiceError::PastDueDate);
        }
        if amount < 0 {
            panic_with_error!(env, InvoiceError::NegativeAmount);
        }
        match th::evaluate_transfer_compliance(&env, &from, &to, amount) {
            th::TransferDecision::Allow => {}
            th::TransferDecision::Deny(ref reason) => {
                if th::is_kyc_deny_reason(reason) {
                    panic_with_error!(env, InvoiceError::KycNotApproved);
                } else {
                    panic_with_error!(env, InvoiceError::TransferBlocked);
                }
            }
        }

        // ── Fee deduction ────────────────────────────────────────────────
        // Compute fee: floor(amount * transfer_fee_bps / 10_000).
        // Only collected when BOTH fee_bps > 0 AND a fee_recipient is set.
        let fee = if meta.transfer_fee_bps > 0 {
            if meta.fee_recipient.is_some() {
                amount * meta.transfer_fee_bps as i128 / 10_000
            } else {
                0
            }
        } else {
            0
        };
        let net_amount = amount - fee;

        // ── PartiallySettled entitlement snapshot ────────────────────────
        // Record the sender's redemption cap before balances change.
        if status == InvoiceStatus::PartiallySettled {
            let settlement: i128 = env
                .storage()
                .persistent()
                .get(&DataKey::SettlementAmount(invoice_id.clone()))
                .unwrap_or(0);
            let total_supply: i128 = env
                .storage()
                .persistent()
                .get(&DataKey::TotalSupply(invoice_id.clone()))
                .unwrap_or(0);
            let from_bal_now = Self::read_balance(&env, from.clone(), invoice_id.clone());
            if total_supply > 0 && settlement > 0 {
                let computed = (from_bal_now as u128)
                    .checked_mul(settlement as u128)
                    .and_then(|x| x.checked_div(total_supply as u128))
                    .unwrap_or(0) as i128;
                let ent_key = DataKey::SettledEntitlement(invoice_id.clone(), from.clone());
                let existing: Option<i128> = env.storage().persistent().get(&ent_key);
                // Take the minimum to prevent entitlement from growing on repeated transfers.
                let to_store = match existing {
                    None => computed,
                    Some(e) => e.min(computed),
                };
                env.storage().persistent().set(&ent_key, &to_store);
                env.storage()
                    .persistent()
                    .extend_ttl(&ent_key, THRESHOLD, BUMP);
            }
        }

        let from_bal = Self::read_balance(&env, from.clone(), invoice_id.clone());
        if from_bal < amount {
            panic_with_error!(env, InvoiceError::InsufficientBalance);
        }
        env.storage().persistent().set(
            &DataKey::Balance(from.clone(), invoice_id.clone()),
            &(from_bal - amount),
        );
        env.storage().persistent().extend_ttl(
            &DataKey::Balance(from.clone(), invoice_id.clone()),
            THRESHOLD,
            BUMP,
        );
        let to_bal = Self::read_balance(&env, to.clone(), invoice_id.clone());
        env.storage().persistent().set(
            &DataKey::Balance(to.clone(), invoice_id.clone()),
            &(to_bal + net_amount),
        );
        env.storage().persistent().extend_ttl(
            &DataKey::Balance(to.clone(), invoice_id.clone()),
            THRESHOLD,
            BUMP,
        );
        if fee > 0 {
            if let Some(ref recipient) = meta.fee_recipient {
                // Compliance check for the fee recipient unless exempt.
                let exempt: bool = env
                    .storage()
                    .instance()
                    .get(&DataKey::FeeRecipientExempt)
                    .unwrap_or(false);
                if exempt {
                    env.events()
                        .publish((symbol_short!("fee_skip"),), recipient.clone());
                } else {
                    match th::evaluate_transfer_compliance(&env, &from, recipient, fee) {
                        th::TransferDecision::Allow => {}
                        th::TransferDecision::Deny(ref reason) => {
                            if th::is_kyc_deny_reason(reason) {
                                panic_with_error!(env, InvoiceError::KycNotApproved);
                            } else {
                                panic_with_error!(env, InvoiceError::TransferBlocked);
                            }
                        }
                    }
                }
                let rec_bal = Self::read_balance(&env, recipient.clone(), invoice_id.clone());
                env.storage().persistent().set(
                    &DataKey::Balance(recipient.clone(), invoice_id.clone()),
                    &(rec_bal + fee),
                );
                env.storage().persistent().extend_ttl(
                    &DataKey::Balance(recipient.clone(), invoice_id.clone()),
                    THRESHOLD,
                    BUMP,
                );
                th::do_register_holder(&env, recipient);
            }
        }
        th::do_register_holder(&env, &to);
        env.events()
            .publish((symbol_short!("transfer"), from, to), (invoice_id, amount));
    }

    /// Delegated transfer.
    /// Blocked in FullySettled and Redeemed states; allowed in Issued and PartiallySettled.
    pub fn transfer_from(
        env: Env,
        spender: Address,
        invoice_id: String,
        from: Address,
        to: Address,
        amount: i128,
    ) {
        spender.require_auth();

        let status = Self::read_status(&env, &invoice_id);
        match status {
            InvoiceStatus::Issued | InvoiceStatus::PartiallySettled => {}
            InvoiceStatus::FullySettled | InvoiceStatus::Redeemed => {
                panic_with_error!(env, InvoiceError::AlreadySettled)
            }
            InvoiceStatus::Created => {
                panic_with_error!(env, InvoiceError::InvalidLifecycleTransition)
            }
        }

        let meta: InvoiceMeta = env
            .storage()
            .persistent()
            .get(&DataKey::InvoiceMeta(invoice_id.clone()))
            .expect("invoice not found");
        if env.ledger().timestamp() > meta.due_date {
            panic_with_error!(env, InvoiceError::PastDueDate);
        }
        if amount < 0 {
            panic_with_error!(env, InvoiceError::NegativeAmount);
        }
        match th::evaluate_transfer_compliance(&env, &from, &to, amount) {
            th::TransferDecision::Allow => {}
            th::TransferDecision::Deny(ref reason) => {
                if th::is_kyc_deny_reason(reason) {
                    panic_with_error!(env, InvoiceError::KycNotApproved);
                } else {
                    panic_with_error!(env, InvoiceError::TransferBlocked);
                }
            }
        }

        let allowance =
            Self::read_allowance(&env, from.clone(), spender.clone(), invoice_id.clone());
        if allowance.expiration_ledger < env.ledger().sequence() {
            panic_with_error!(env, InvoiceError::AllowanceExpired);
        }
        if allowance.amount < amount {
            panic_with_error!(env, InvoiceError::InsufficientAllowance);
        }
        env.storage().persistent().set(
            &DataKey::Allowance(from.clone(), spender.clone(), invoice_id.clone()),
            &AllowanceValue {
                amount: allowance.amount - amount,
                expiration_ledger: allowance.expiration_ledger,
            },
        );

        // ── PartiallySettled entitlement snapshot ────────────────────────
        if status == InvoiceStatus::PartiallySettled {
            let settlement: i128 = env
                .storage()
                .persistent()
                .get(&DataKey::SettlementAmount(invoice_id.clone()))
                .unwrap_or(0);
            let total_supply: i128 = env
                .storage()
                .persistent()
                .get(&DataKey::TotalSupply(invoice_id.clone()))
                .unwrap_or(0);
            let from_bal_now = Self::read_balance(&env, from.clone(), invoice_id.clone());
            if total_supply > 0 && settlement > 0 {
                let computed = (from_bal_now as u128)
                    .checked_mul(settlement as u128)
                    .and_then(|x| x.checked_div(total_supply as u128))
                    .unwrap_or(0) as i128;
                let ent_key = DataKey::SettledEntitlement(invoice_id.clone(), from.clone());
                let existing: Option<i128> = env.storage().persistent().get(&ent_key);
                let to_store = match existing {
                    None => computed,
                    Some(e) => e.min(computed),
                };
                env.storage().persistent().set(&ent_key, &to_store);
                env.storage()
                    .persistent()
                    .extend_ttl(&ent_key, THRESHOLD, BUMP);
            }
        }

        // ── Fee deduction ────────────────────────────────────────────────
        let fee = if meta.transfer_fee_bps > 0 {
            if meta.fee_recipient.is_some() {
                amount * meta.transfer_fee_bps as i128 / 10_000
            } else {
                0
            }
        } else {
            0
        };
        let net_amount = amount - fee;

        let from_bal = Self::read_balance(&env, from.clone(), invoice_id.clone());
        if from_bal < amount {
            panic_with_error!(env, InvoiceError::InsufficientBalance);
        }
        env.storage().persistent().set(
            &DataKey::Balance(from.clone(), invoice_id.clone()),
            &(from_bal - amount),
        );
        env.storage().persistent().extend_ttl(
            &DataKey::Balance(from.clone(), invoice_id.clone()),
            THRESHOLD,
            BUMP,
        );
        let to_bal = Self::read_balance(&env, to.clone(), invoice_id.clone());
        env.storage().persistent().set(
            &DataKey::Balance(to.clone(), invoice_id.clone()),
            &(to_bal + net_amount),
        );
        env.storage().persistent().extend_ttl(
            &DataKey::Balance(to.clone(), invoice_id.clone()),
            THRESHOLD,
            BUMP,
        );
        if fee > 0 {
            if let Some(ref recipient) = meta.fee_recipient {
                // Compliance check for the fee recipient unless exempt.
                let exempt: bool = env
                    .storage()
                    .instance()
                    .get(&DataKey::FeeRecipientExempt)
                    .unwrap_or(false);
                if exempt {
                    env.events()
                        .publish((symbol_short!("fee_skip"),), recipient.clone());
                } else {
                    match th::evaluate_transfer_compliance(&env, &from, recipient, fee) {
                        th::TransferDecision::Allow => {}
                        th::TransferDecision::Deny(ref reason) => {
                            if th::is_kyc_deny_reason(reason) {
                                panic_with_error!(env, InvoiceError::KycNotApproved);
                            } else {
                                panic_with_error!(env, InvoiceError::TransferBlocked);
                            }
                        }
                    }
                }
                let rec_bal = Self::read_balance(&env, recipient.clone(), invoice_id.clone());
                env.storage().persistent().set(
                    &DataKey::Balance(recipient.clone(), invoice_id.clone()),
                    &(rec_bal + fee),
                );
                env.storage().persistent().extend_ttl(
                    &DataKey::Balance(recipient.clone(), invoice_id.clone()),
                    THRESHOLD,
                    BUMP,
                );
                th::do_register_holder(&env, recipient);
            }
        }
        th::do_register_holder(&env, &to);
        env.events()
            .publish((symbol_short!("transfer"), from, to), (invoice_id, amount));
    }

    pub fn approve(
        env: Env,
        from: Address,
        spender: Address,
        invoice_id: String,
        amount: i128,
        expiration_ledger: u32,
    ) {
        from.require_auth();
        if amount < 0 {
            panic_with_error!(env, InvoiceError::NegativeAmount);
        }
        env.storage().persistent().set(
            &DataKey::Allowance(from.clone(), spender.clone(), invoice_id.clone()),
            &AllowanceValue {
                amount,
                expiration_ledger,
            },
        );
        env.storage().persistent().extend_ttl(
            &DataKey::Allowance(from.clone(), spender.clone(), invoice_id.clone()),
            THRESHOLD,
            BUMP,
        );
        env.events().publish(
            (symbol_short!("approve"), from, spender),
            (invoice_id, amount, expiration_ledger),
        );
    }

    pub fn allowance(env: Env, from: Address, spender: Address, invoice_id: String) -> i128 {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        let allowance = Self::read_allowance(&env, from, spender, invoice_id);
        if allowance.expiration_ledger < env.ledger().sequence() {
            0
        } else {
            allowance.amount
        }
    }

    pub fn total_supply(env: Env, invoice_id: String) -> i128 {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        env.storage()
            .persistent()
            .get(&DataKey::TotalSupply(invoice_id))
            .unwrap_or(0)
    }

    /// Returns true if the invoice is in any post-issuance settled state.
    pub fn is_settled(env: Env, invoice_id: String) -> bool {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        matches!(
            Self::read_status(&env, &invoice_id),
            InvoiceStatus::PartiallySettled | InvoiceStatus::FullySettled | InvoiceStatus::Redeemed
        )
    }

    pub fn version(env: Env) -> String {
        String::from_str(&env, env!("CARGO_PKG_VERSION"))
    }

    /// Discounted present value in stroops.
    pub fn present_value(env: Env, invoice_id: String) -> i128 {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        let meta: InvoiceMeta = env
            .storage()
            .persistent()
            .get(&DataKey::InvoiceMeta(invoice_id))
            .expect("invoice not found");
        let now = env.ledger().timestamp();
        let days_to_maturity = (meta.due_date.saturating_sub(now) / 86400) as i128;
        let pv = meta.face_value_usd
            - (meta.face_value_usd * meta.discount_rate_bps as i128 * days_to_maturity)
                / (365 * 10_000);
        pv.max(0)
    }

    // ── Internals ─────────────────────────────────────────────────────────────

    fn read_status(env: &Env, invoice_id: &String) -> InvoiceStatus {
        env.storage()
            .persistent()
            .get(&DataKey::InvoiceStatus(invoice_id.clone()))
            .unwrap_or(InvoiceStatus::Created)
    }

    fn read_journal(env: &Env, invoice_id: &String) -> Vec<JournalEntry> {
        env.storage()
            .persistent()
            .get(&DataKey::Journal(invoice_id.clone()))
            .unwrap_or_else(|| Vec::new(env))
    }

    /// Atomically records a journal entry and writes the new status.
    fn transition_status(env: &Env, invoice_id: &String, from: InvoiceStatus, to: InvoiceStatus) {
        let entry = JournalEntry {
            from_status: from,
            to_status: to,
            ledger: env.ledger().sequence(),
            timestamp: env.ledger().timestamp(),
        };
        let mut journal = Self::read_journal(env, invoice_id);
        journal.push_back(entry);
        env.storage()
            .persistent()
            .set(&DataKey::Journal(invoice_id.clone()), &journal);
        env.storage().persistent().extend_ttl(
            &DataKey::Journal(invoice_id.clone()),
            THRESHOLD,
            BUMP,
        );
        env.storage()
            .persistent()
            .set(&DataKey::InvoiceStatus(invoice_id.clone()), &to);
        env.storage().persistent().extend_ttl(
            &DataKey::InvoiceStatus(invoice_id.clone()),
            THRESHOLD,
            BUMP,
        );
    }

    fn validate_webhook(env: &Env, webhook: &String) {
        if webhook.is_empty() {
            return;
        }
        let len = webhook.len() as usize;
        if !(8..=256).contains(&len) {
            panic_with_error!(env, InvoiceError::InvalidWebhook);
        }
        let mut buf = [0u8; 256];
        webhook.copy_into_slice(&mut buf[..len]);
        if &buf[..8] != b"https://" {
            panic_with_error!(env, InvoiceError::InvalidWebhook);
        }
    }

    /// Validates normalizable metadata fields on an InvoiceMeta record.
    fn validate_invoice_meta(env: &Env, meta: &InvoiceMeta) {
        if !th::is_valid_currency(&meta.currency) {
            panic_with_error!(env, InvoiceError::InvalidMetadata);
        }
        if meta.face_value_usd <= 0 {
            panic_with_error!(env, InvoiceError::InvalidMetadata);
        }
        if !th::is_valid_ipfs_hash(&meta.ipfs_doc_hash) {
            panic_with_error!(env, InvoiceError::InvalidMetadata);
        }
        // Fee is amount * bps / 10_000; above 100% the net transfer goes negative.
        if meta.transfer_fee_bps > 10_000 {
            panic_with_error!(env, InvoiceError::InvalidMetadata);
        }
    }

    fn do_create_invoice(env: &Env, meta: InvoiceMeta) {
        Self::validate_webhook(env, &meta.notification_webhook);
        Self::validate_invoice_meta(env, &meta);
        let invoice_id = meta.invoice_id.clone();
        if env
            .storage()
            .persistent()
            .has(&DataKey::InvoiceMeta(invoice_id.clone()))
        {
            panic_with_error!(env, InvoiceError::InvoiceAlreadyExists);
        }
        env.storage()
            .persistent()
            .set(&DataKey::InvoiceMeta(invoice_id.clone()), &meta);
        env.storage().persistent().extend_ttl(
            &DataKey::InvoiceMeta(invoice_id.clone()),
            THRESHOLD,
            BUMP,
        );
        env.storage()
            .persistent()
            .set(&DataKey::TotalSupply(invoice_id.clone()), &0i128);
        env.storage().persistent().extend_ttl(
            &DataKey::TotalSupply(invoice_id.clone()),
            THRESHOLD,
            BUMP,
        );
        env.storage().persistent().set(
            &DataKey::InvoiceStatus(invoice_id.clone()),
            &InvoiceStatus::Created,
        );
        env.storage().persistent().extend_ttl(
            &DataKey::InvoiceStatus(invoice_id.clone()),
            THRESHOLD,
            BUMP,
        );
        env.storage().persistent().set(
            &DataKey::Journal(invoice_id.clone()),
            &Vec::<JournalEntry>::new(env),
        );
        env.storage().persistent().extend_ttl(
            &DataKey::Journal(invoice_id.clone()),
            THRESHOLD,
            BUMP,
        );

        let mut list: Vec<String> = env
            .storage()
            .instance()
            .get(&DataKey::InvoicesList)
            .unwrap_or_else(|| Vec::new(env));
        list.push_back(invoice_id.clone());
        env.storage().instance().set(&DataKey::InvoicesList, &list);
        env.events()
            .publish((symbol_short!("inv_crt"),), invoice_id);
    }

    fn require_lifecycle_active(env: &Env) {
        let paused: bool = env
            .storage()
            .instance()
            .get(&DataKey::LifecyclePaused)
            .unwrap_or(false);
        if paused {
            panic_with_error!(env, InvoiceError::LifecyclePaused);
        }
    }

    fn read_balance(env: &Env, addr: Address, invoice_id: String) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(addr, invoice_id))
            .unwrap_or(0)
    }

    fn read_allowance(
        env: &Env,
        from: Address,
        spender: Address,
        invoice_id: String,
    ) -> AllowanceValue {
        env.storage()
            .persistent()
            .get(&DataKey::Allowance(from, spender, invoice_id))
            .unwrap_or(AllowanceValue {
                amount: 0,
                expiration_ledger: 0,
            })
    }

    /// Non-panicking settlement helper used by `batch_settle`.
    /// Returns None on success, Some(InvoiceError code) on failure.
    fn try_do_partial_settle(
        env: &Env,
        invoice_id: &String,
        settlement_amount: i128,
    ) -> Option<u32> {
        let paused: bool = env
            .storage()
            .instance()
            .get(&DataKey::LifecyclePaused)
            .unwrap_or(false);
        if paused {
            return Some(InvoiceError::LifecyclePaused as u32);
        }
        if settlement_amount <= 0 {
            return Some(InvoiceError::UnderSettlement as u32);
        }
        let meta: Option<InvoiceMeta> = env
            .storage()
            .persistent()
            .get(&DataKey::InvoiceMeta(invoice_id.clone()));
        let meta = match meta {
            None => return Some(InvoiceError::InvoiceNotFound as u32),
            Some(m) => m,
        };
        if settlement_amount > meta.face_value_usd {
            return Some(InvoiceError::OverSettlement as u32);
        }
        let from_status = Self::read_status(env, invoice_id);
        match from_status {
            InvoiceStatus::Created | InvoiceStatus::Issued => {}
            _ => return Some(InvoiceError::AlreadySettled as u32),
        }
        let to_status = if settlement_amount == meta.face_value_usd {
            InvoiceStatus::FullySettled
        } else {
            InvoiceStatus::PartiallySettled
        };
        Self::transition_status(env, invoice_id, from_status, to_status);
        env.storage().persistent().set(
            &DataKey::SettlementAmount(invoice_id.clone()),
            &settlement_amount,
        );
        env.storage().persistent().extend_ttl(
            &DataKey::SettlementAmount(invoice_id.clone()),
            THRESHOLD,
            BUMP,
        );
        env.storage().persistent().set(
            &DataKey::RedemptionDust(invoice_id.clone()),
            &settlement_amount,
        );
        env.storage().persistent().extend_ttl(
            &DataKey::RedemptionDust(invoice_id.clone()),
            THRESHOLD,
            BUMP,
        );
        env.events().publish(
            (symbol_short!("p_settld"),),
            (invoice_id.clone(), settlement_amount),
        );
        None
    }
}
