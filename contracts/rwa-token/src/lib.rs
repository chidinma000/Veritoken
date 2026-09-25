#![no_std]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![allow(clippy::too_many_arguments)]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, symbol_short, Address,
    Env, String, Symbol, Vec,
};

mod admin;
mod allowance;
mod balance;
mod compliance;
mod events;
mod kyc;
mod metadata;
mod roles;
mod storage_types;
mod versioning;

// Re-export public KYC sync types so the generated client surfaces them.
pub use kyc::{KycStatusMirror, KycSyncStatus};

#[cfg(test)]
mod test;

#[cfg(test)]
mod sep41_compliance;

// ── Errors ────────────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum RwaError {
    AlreadyInitialized = 1,
    KycNotApproved = 2,
    TransferBlocked = 3,
    InsufficientBalance = 4,
    AllowanceExpired = 5,
    InsufficientAllowance = 6,
    AccountFrozen = 7,
    /// Transfer amount is zero or negative.
    NegativeAmount = 8,
    /// Batch recipient list exceeds the maximum of 10 entries.
    BatchTooLarge = 9,
    /// Recovery config has not been set by the admin.
    RecoveryNotConfigured = 10,
    /// Caller is not in the recovery members list.
    NotRecoveryMember = 11,
    /// A recovery proposal is already in progress.
    RecoveryAlreadyActive = 12,
    /// This address has already approved the active recovery proposal.
    AlreadyApproved = 13,
    /// No active recovery proposal exists.
    NoActiveRecovery = 14,
    /// Threshold must be ≥ 1 and ≤ len(members).
    InvalidRecoveryConfig = 15,
    /// Mint would exceed the configured max supply cap.
    ExceedsMaxSupply = 16,
    /// Nonce-protected admin operation was submitted out of order.
    InvalidNonce = 17,
    /// The linked compliance engine trapped or could not be reached.
    ComplianceEngineUnavailable = 18,
    /// The linked KYC registry trapped or could not be reached.
    KycRegistryUnavailable = 19,
    /// Caller is neither the admin nor the holder of the required role.
    UnauthorizedRole = 20,
    /// The sum of batch entries cannot be represented as an `i128`.
    BatchAmountOverflow = 21,
    /// The complete transfer plan would exceed the configured holder cap.
    HolderLimitExceeded = 22,
    /// A migration was attempted with the same version that is already stored.
    MigrationVersionConflict = 23,
    /// A numeric schema migration must increment the version by exactly one.
    MigrationVersionNotSequential = 24,
    /// The active recovery proposal has passed its expiry ledger.
    RecoveryExpired = 25,
    /// Not enough guardian approvals to execute recovery.
    InsufficientApprovals = 26,
    /// The proposer may not also approve their own recovery proposal.
    ProposerCannotApprove = 27,
    /// Execute attempted before the inter-recovery cooldown has elapsed.
    RecoveryCooldown = 28,
    /// An admin-gated call was made before the contract's admin was set.
    NotInitialized = 29,
    /// Constructor was called with an unrecognized `asset_type` string.
    InvalidAssetType = 30,
    /// batch_transfer was called with an empty recipients vector.
    EmptyBatch = 31,
    /// accept_admin was called when no pending admin transfer is in progress.
    NoPendingAdmin = 32,
    /// propose_admin was called with the current admin as successor.
    AlreadyAdmin = 33,
}

// ── Public types ──────────────────────────────────────────────────────────────

/// On-chain record of a single admin-initiated migration.
#[contracttype]
#[derive(Clone)]
pub struct MigrationRecord {
    pub from_version: String,
    pub to_version: String,
    pub timestamp: u64,
    pub description: String,
}

/// On-chain record of a single numeric schema version migration.
#[contracttype]
#[derive(Clone)]
pub struct SchemaVersionRecord {
    pub from_version: u32,
    pub to_version: u32,
    pub timestamp: u64,
    pub description: String,
}

/// Snapshot of an in-progress recovery proposal.
#[contracttype]
#[derive(Clone)]
pub struct RecoveryProposal {
    pub proposed_admin: Address,
    pub proposer: Address,
    pub approvals: Vec<Address>,
    pub expiry_ledger: u64,
}

/// Stored recovery configuration (threshold, cooldown, last-execution ledger).
/// The guardian member list is stored separately under DataKey::RecoveryMembers.
#[contracttype]
#[derive(Clone)]
pub struct RecoveryConfig {
    pub threshold: u32,
    pub cooldown_ledgers: u32,
    pub last_executed_ledger: u64,
}

pub const META_LEGAL_ENTITY: &str = "legal_ent";
pub const META_GOVERNING_LAW: &str = "gov_law";
pub const META_ISIN: &str = "isin";
pub const META_PROSPECTUS_HASH: &str = "pros_hash";

#[contracttype]
#[derive(Clone)]
pub struct ComplianceMetadata {
    pub legal_entity: Option<String>,
    pub governing_law: Option<String>,
    pub isin: Option<String>,
    pub prospectus_hash: Option<String>,
}

#[contracttype]
#[derive(Clone)]
pub struct RecipientEntry {
    pub to: Address,
    pub amount: i128,
}

/// Fully validated, immutable execution data for one or more transfer legs.
///
/// Every transfer entry point builds this plan before mutating balances,
/// allowances, holder registration, or events.
struct TransferPlan {
    total_amount: i128,
    sender_balance_after: i128,
}

// ── Contract ──────────────────────────────────────────────────────────────────
//
// # Transfer safety invariant (reentrancy guard)
//
// Every transfer entry point (`transfer`, `transfer_from`, `batch_transfer`,
// `batch_transfer_from`) wraps its execution in `enter_transfer_guard` /
// `exit_transfer_guard`. The guard stores a boolean flag in instance storage
// (`DataKey::TransferLock`) and panics if a nested entry is attempted while
// the flag is set.
//
// In Soroban's single-threaded WASM execution model, true reentrancy within
// a single invocation is not possible. This guard exists to make the
// check-effects-interactions ordering *explicit and enforceable* as an
// on-chain invariant, so that future cross-contract extensions that might
// invoke this contract during a transfer are caught at the border rather
// than silently corrupting state.
//
// Sequence every transfer entry point must follow:
//   1. `enter_transfer_guard` — fail fast if already locked.
//   2. Auth check (require_auth).
//   3. **Validation pass** — all checks (frozen, KYC, compliance, balances).
//      No state is mutated during this phase.
//   4. **Mutation pass** — balance updates, holder registration changes.
//   5. Event emission.
//   6. `exit_transfer_guard` — clear the lock.

#[contract]
pub struct RwaToken;

#[allow(clippy::too_many_arguments)]
#[contractimpl]
impl RwaToken {
    // ── Constructor ───────────────────────────────────────────────────────────

    /// Deploy-time constructor — eliminates the deploy→initialize front-running window.
    #[allow(clippy::too_many_arguments)]
    pub fn __constructor(
        env: Env,
        admin: Address,
        decimal: u32,
        name: String,
        symbol: String,
        asset_type: String,
        kyc_registry: Address,
        compliance_engine: Address,
        compliance_metadata: Option<ComplianceMetadata>,
        max_supply: i128,
    ) {
        if asset_type != String::from_str(&env, "invoice")
            && asset_type != String::from_str(&env, "property")
            && asset_type != String::from_str(&env, "carbon_credit")
        {
            panic_with_error!(env, RwaError::InvalidAssetType);
        }
        if max_supply < 0 {
            panic_with_error!(env, RwaError::NegativeAmount);
        }
        admin::write_admin(&env, &admin);
        metadata::write_metadata(&env, decimal, name, symbol);
        metadata::write_asset_type(&env, asset_type);
        kyc::write_kyc_registry(&env, &kyc_registry);
        compliance::write_compliance_engine(&env, &compliance_engine);
        balance::write_total_supply(&env, 0);
        balance::write_max_supply(&env, max_supply);
        versioning::write_initial_version(&env);
        if let Some(meta) = compliance_metadata {
            if let Some(v) = meta.legal_entity {
                compliance::write_metadata(&env, Symbol::new(&env, META_LEGAL_ENTITY), v);
            }
            if let Some(v) = meta.governing_law {
                compliance::write_metadata(&env, Symbol::new(&env, META_GOVERNING_LAW), v);
            }
            if let Some(v) = meta.isin {
                compliance::write_metadata(&env, Symbol::new(&env, META_ISIN), v);
            }
            if let Some(v) = meta.prospectus_hash {
                compliance::write_metadata(&env, Symbol::new(&env, META_PROSPECTUS_HASH), v);
            }
        }
    }

    /// Legacy entry point — always panics.
    #[allow(clippy::too_many_arguments)]
    pub fn initialize(
        env: Env,
        _admin: Address,
        _decimal: u32,
        _name: String,
        _symbol: String,
        _asset_type: String,
        _kyc_registry: Address,
        _compliance_engine: Address,
    ) {
        panic_with_error!(env, RwaError::AlreadyInitialized);
    }

    // ── Admin ─────────────────────────────────────────────────────────────────

    #[deprecated(since = "0.2.0", note = "Use propose_admin and accept_admin instead")]
    pub fn set_admin(env: Env, new_admin: Address) {
        let old_admin = admin::read_admin(&env);
        old_admin.require_auth();
        admin::write_admin(&env, &new_admin);
        events::emit_admin_set(&env, old_admin, new_admin, admin::read_admin_nonce(&env));
    }

    /// Step 1 of the two-step admin handover.
    ///
    /// `caller` must be the admin or the `"governance"` role holder.
    /// Requires the current admin nonce (#349) to prevent accidental replay.
    pub fn propose_admin(env: Env, caller: Address, new_admin: Address, nonce: u64) {
        roles::require_admin_or_role(&env, &caller, &Symbol::new(&env, roles::ROLE_GOVERNANCE));
        // Proposing the sitting admin as their own successor is a no-op that
        // still burns a nonce, writes storage, and emits a misleading
        // `adm_prop` event.  Reject it with a typed error instead.
        if new_admin == admin::read_admin(&env) {
            panic_with_error!(env, RwaError::AlreadyAdmin);
        }
        admin::consume_nonce(&env, nonce);
        if admin::read_pending_admin(&env).is_some() {
            events::emit_pending_admin_cleared(&env);
        }
        admin::write_pending_admin(&env, &new_admin);
        events::emit_admin_proposed(&env, new_admin, nonce);
    }

    /// Step 2 of the two-step admin handover — called by the proposed admin.
    pub fn accept_admin(env: Env) {
        let pending = admin::read_pending_admin(&env)
            .unwrap_or_else(|| panic_with_error!(env, RwaError::NoPendingAdmin));
        pending.require_auth();
        let old_admin = admin::read_admin(&env);
        admin::write_admin(&env, &pending);
        admin::remove_pending_admin(&env);
        events::emit_admin_set(&env, old_admin, pending, admin::read_admin_nonce(&env));
    }

    /// Updates the KYC registry address.
    /// `caller` must be the admin or the `"registry"` role holder.
    /// Nonce-protected (#349).
    pub fn update_kyc_registry(env: Env, caller: Address, new_registry: Address, nonce: u64) {
        roles::require_admin_or_role(&env, &caller, &Symbol::new(&env, roles::ROLE_REGISTRY));
        admin::consume_nonce(&env, nonce);
        kyc::write_kyc_registry(&env, &new_registry);
        events::emit_kyc_updated(&env, new_registry, nonce);
    }

    /// Updates the compliance engine address.
    /// `caller` must be the admin or the `"registry"` role holder.
    /// Nonce-protected (#349).
    pub fn update_compliance_engine(env: Env, caller: Address, new_engine: Address, nonce: u64) {
        roles::require_admin_or_role(&env, &caller, &Symbol::new(&env, roles::ROLE_REGISTRY));
        admin::consume_nonce(&env, nonce);
        compliance::write_compliance_engine(&env, &new_engine);
        events::emit_ce_updated(&env, new_engine, nonce);
    }

    // ── Granular roles (#347) ─────────────────────────────────────────────────

    /// Assigns `holder` to the given `role`.  Admin-only, nonce-protected.
    ///
    /// Role symbols: `"governance"`, `"compliance"`, `"liquidity"`, `"registry"`.
    pub fn assign_role(env: Env, role: Symbol, holder: Address, nonce: u64) {
        let current_admin = admin::read_admin(&env);
        current_admin.require_auth();
        admin::consume_nonce(&env, nonce);
        roles::write_role_holder(&env, &role, &holder);
        events::emit_role_assigned(&env, role, holder, nonce);
    }

    /// Removes the holder for the given `role`.  Admin-only, nonce-protected.
    pub fn revoke_role(env: Env, role: Symbol, nonce: u64) {
        let current_admin = admin::read_admin(&env);
        current_admin.require_auth();
        admin::consume_nonce(&env, nonce);
        roles::remove_role_holder(&env, &role);
        events::emit_role_revoked(&env, role, nonce);
    }

    /// Returns the address currently holding `role`, or `None` if unassigned.
    pub fn get_role_holder(env: Env, role: Symbol) -> Option<Address> {
        roles::read_role_holder(&env, &role)
    }

    // ── Freeze / Unfreeze ─────────────────────────────────────────────────────

    /// Freezes an account.  `caller` must be the admin or the `"compliance"` role holder.
    pub fn freeze(env: Env, caller: Address, addr: Address) {
        roles::require_admin_or_role(&env, &caller, &Symbol::new(&env, roles::ROLE_COMPLIANCE));
        compliance::set_frozen(&env, &addr, true);
        events::emit_freeze(&env, addr);
    }

    /// Unfreezes an account.  `caller` must be the admin or the `"compliance"` role holder.
    pub fn unfreeze(env: Env, caller: Address, addr: Address) {
        roles::require_admin_or_role(&env, &caller, &Symbol::new(&env, roles::ROLE_COMPLIANCE));
        compliance::set_frozen(&env, &addr, false);
        events::emit_unfreeze(&env, addr);
    }

    pub fn is_frozen(env: Env, addr: Address) -> bool {
        compliance::is_frozen(&env, &addr)
    }

    // ── SEP-41 Token Interface ────────────────────────────────────────────────

    pub fn allowance(env: Env, from: Address, spender: Address) -> i128 {
        // Instance TTL is extended by the first storage helper called in this function.
        allowance::read_allowance(&env, from, spender).amount
    }

    pub fn approve(
        env: Env,
        from: Address,
        spender: Address,
        amount: i128,
        expiration_ledger: u32,
    ) {
        from.require_auth();
        allowance::write_allowance(
            &env,
            from.clone(),
            spender.clone(),
            amount,
            expiration_ledger,
        );
        events::emit_approve(&env, from, spender, amount, expiration_ledger);
    }

    pub fn balance(env: Env, id: Address) -> i128 {
        // Instance TTL is extended by the first storage helper called in this function.
        balance::read_balance(&env, id)
    }

    /// Single transfer: validates sender + recipient against all invariants, then
    /// applies balance changes and holder registration/deregistration atomically.
    ///
    /// Sequence: guard → auth → validate_sender → validate_recipient →
    ///           apply_transfer_leg → unregister_holder (if drained) → emit → unlock.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        // Instance TTL is extended by the first storage helper called in this function.
        Self::enter_transfer_guard(&env);
        from.require_auth();
        let mut recipients = Vec::new(&env);
        recipients.push_back(RecipientEntry { to, amount });
        let plan = Self::prepare_transfer_plan(&env, &from, &recipients);
        Self::execute_transfer_plan(&env, &from, &recipients, &plan);
        Self::exit_transfer_guard(&env);
    }

    /// Delegated single transfer: identical invariants to `transfer`, plus allowance deduction.
    ///
    /// Sequence: guard → auth → validate_sender → validate_recipient →
    ///           spend_allowance → apply_transfer_leg → unregister → emit → unlock.
    pub fn transfer_from(env: Env, spender: Address, from: Address, to: Address, amount: i128) {
        Self::enter_transfer_guard(&env);
        spender.require_auth();
        let mut recipients = Vec::new(&env);
        recipients.push_back(RecipientEntry { to, amount });
        let plan = Self::prepare_transfer_plan(&env, &from, &recipients);
        // spender == from is allowed; the holder may approve themselves, though
        // transfer() is simpler. Behaves the same as a direct transfer with an
        // extra allowance step.
        allowance::spend_allowance(&env, from.clone(), spender, plan.total_amount);
        Self::execute_transfer_plan(&env, &from, &recipients, &plan);
        Self::exit_transfer_guard(&env);
    }

    pub fn burn(env: Env, from: Address, amount: i128) {
        // Instance TTL is extended by the first storage helper called in this function.
        from.require_auth();
        if amount <= 0 {
            panic_with_error!(env, RwaError::NegativeAmount);
        }
        if compliance::is_frozen(&env, &from) {
            panic_with_error!(env, RwaError::AccountFrozen);
        }
        kyc::require_kyc(&env, &from);
        let from_balance_before = balance::read_balance(&env, from.clone());
        balance::spend_balance(&env, from.clone(), amount);
        if from_balance_before == amount {
            compliance::unregister_holder(&env, &from);
        }
        let supply = balance::read_total_supply(&env);
        balance::write_total_supply(&env, supply - amount);
        events::emit_burn(&env, from, amount);
    }

    pub fn burn_from(env: Env, spender: Address, from: Address, amount: i128) {
        spender.require_auth();
        if amount <= 0 {
            panic_with_error!(env, RwaError::NegativeAmount);
        }
        if compliance::is_frozen(&env, &from) {
            panic_with_error!(env, RwaError::AccountFrozen);
        }
        kyc::require_kyc(&env, &from);
        let from_balance_before = balance::read_balance(&env, from.clone());
        allowance::spend_allowance(&env, from.clone(), spender, amount);
        balance::spend_balance(&env, from.clone(), amount);
        if from_balance_before == amount {
            compliance::unregister_holder(&env, &from);
        }
        let supply = balance::read_total_supply(&env);
        balance::write_total_supply(&env, supply - amount);
        events::emit_burn(&env, from, amount);
    }

    pub fn decimals(env: Env) -> u32 {
        metadata::read_decimal(&env)
    }

    pub fn name(env: Env) -> String {
        metadata::read_name(&env)
    }

    pub fn symbol(env: Env) -> String {
        metadata::read_symbol(&env)
    }

    pub fn total_supply(env: Env) -> i128 {
        balance::read_total_supply(&env)
    }

    /// Returns the configured maximum supply cap.
    /// `0` means unlimited — no cap is enforced.
    pub fn max_supply(env: Env) -> i128 {
        balance::read_max_supply(&env)
    }

    // ── Minting ───────────────────────────────────────────────────────────────

    /// Mints `amount` tokens to `to`.
    /// `caller` must be the admin or the `"liquidity"` role holder.
    pub fn mint(env: Env, caller: Address, to: Address, amount: i128) {
        // Instance TTL is extended by the first storage helper called in this function.
        roles::require_admin_or_role(&env, &caller, &Symbol::new(&env, roles::ROLE_LIQUIDITY));
        if amount <= 0 {
            panic_with_error!(env, RwaError::NegativeAmount);
        }
        let max_supply = balance::read_max_supply(&env);
        if max_supply > 0 {
            let current_supply = balance::read_total_supply(&env);
            if current_supply + amount > max_supply {
                panic_with_error!(env, RwaError::ExceedsMaxSupply);
            }
        }
        kyc::require_kyc(&env, &to);
        let previous_balance = balance::read_balance(&env, to.clone());
        if previous_balance == 0 {
            compliance::check_mint(&env, &to, amount);
        }
        balance::receive_balance(&env, to.clone(), amount);
        if previous_balance == 0 {
            compliance::register_holder(&env, &to);
        }
        let supply = balance::read_total_supply(&env);
        balance::write_total_supply(&env, supply + amount);
        events::emit_mint(&env, to, amount);
    }

    // ── Batch Transfer ────────────────────────────────────────────────────────

    /// Atomic batch transfer from `from` to up to 10 recipients.
    ///
    /// Invariants enforced before any state change:
    /// - Recipient list must not exceed 10 entries.
    /// - `from` must not be frozen and must have KYC approval.
    /// - Each entry amount must be positive.
    /// - Each recipient must not be frozen and must have KYC approval.
    /// - Each leg must pass the compliance engine's `can_transfer` check.
    /// - `from` must hold at least the sum of all entry amounts (total balance check).
    ///
    /// If any check fails, the entire batch is rejected with no state changes.
    pub fn batch_transfer(env: Env, from: Address, recipients: Vec<RecipientEntry>) {
        Self::enter_transfer_guard(&env);
        from.require_auth();
        let plan = Self::prepare_transfer_plan(&env, &from, &recipients);
        Self::execute_transfer_plan(&env, &from, &recipients, &plan);
        events::emit_batch_transfer_completed(&env, recipients.len() as u32);
        Self::exit_transfer_guard(&env);
    }

    /// Atomic delegated batch transfer: identical invariants to `batch_transfer`,
    /// plus a single upfront allowance deduction for the total transferred amount.
    pub fn batch_transfer_from(
        env: Env,
        spender: Address,
        from: Address,
        recipients: Vec<RecipientEntry>,
    ) {
        Self::enter_transfer_guard(&env);
        spender.require_auth();
        let plan = Self::prepare_transfer_plan(&env, &from, &recipients);
        allowance::spend_allowance(&env, from.clone(), spender, plan.total_amount);
        Self::execute_transfer_plan(&env, &from, &recipients, &plan);
        events::emit_batch_transfer_completed(&env, recipients.len() as u32);
        Self::exit_transfer_guard(&env);
    }

    // ── RWA Compliance Metadata ───────────────────────────────────────────────

    pub fn asset_type(env: Env) -> String {
        metadata::read_asset_type(&env)
    }

    pub fn kyc_registry(env: Env) -> Address {
        kyc::read_kyc_registry(&env)
    }

    pub fn compliance_engine(env: Env) -> Address {
        compliance::read_compliance_engine(&env)
    }

    /// Sets a compliance metadata field.  Nonce-protected (#349).
    /// `caller` must be the admin or the `"compliance"` role holder.
    pub fn set_compliance_metadata(
        env: Env,
        caller: Address,
        key: Symbol,
        value: String,
        nonce: u64,
    ) {
        roles::require_admin_or_role(&env, &caller, &Symbol::new(&env, roles::ROLE_COMPLIANCE));
        admin::consume_nonce(&env, nonce);
        compliance::write_metadata(&env, key, value);
    }

    pub fn get_compliance_metadata(env: Env, key: Symbol) -> String {
        compliance::read_metadata(&env, key)
    }

    pub fn get_all_compliance_metadata(env: Env) -> ComplianceMetadata {
        let read = |key: &str| {
            let v = compliance::read_metadata(&env, Symbol::new(&env, key));
            if v.is_empty() {
                None
            } else {
                Some(v)
            }
        };
        ComplianceMetadata {
            legal_entity: read(META_LEGAL_ENTITY),
            governing_law: read(META_GOVERNING_LAW),
            isin: read(META_ISIN),
            prospectus_hash: read(META_PROSPECTUS_HASH),
        }
    }

    pub fn version(env: Env) -> String {
        String::from_str(&env, env!("CARGO_PKG_VERSION"))
    }

    // ── Metadata export ───────────────────────────────────────────────────────

    /// Admin-only: store an optional URI pointing to an off-chain metadata
    /// document (e.g. `ipfs://Qm...` or `https://api.example.com/tokens/1`).
    /// Pass an empty string to clear the value.
    pub fn set_external_uri(env: Env, uri: String) {
        let admin = admin::read_admin(&env);
        admin.require_auth();
        if uri.is_empty() {
            env.storage()
                .instance()
                .remove(&storage_types::DataKey::ExternalUri);
            events::emit_external_uri_cleared(&env);
            return;
        }
        env.storage()
            .instance()
            .set(&storage_types::DataKey::ExternalUri, &uri);
        events::emit_external_uri(&env, uri);
    }

    /// Returns the optional external URI set by the admin (empty string if unset).
    pub fn get_external_uri(env: Env) -> String {
        env.storage()
            .instance()
            .get(&storage_types::DataKey::ExternalUri)
            .unwrap_or_else(|| String::from_str(&env, ""))
    }

    // ── KYC synchronization layer ─────────────────────────────────────────────

    /// Read-only: returns the live KYC status for `addr` as seen from this
    /// token contract.
    ///
    /// This is the primary synchronization read for frontends and external tools.
    /// It fetches the current record from the linked KYC registry (a cross-contract
    /// call) and evaluates whether the address is truly active right now —
    /// accounting for both status (Approved/Revoked/Rejected) and expiry.
    ///
    /// ## Behavior
    /// - `is_active = true`  only when `status == Approved` AND (expiry == 0 OR expiry >= now)
    /// - `is_active = false` when status is Revoked/Rejected/Pending, or when expired
    ///
    /// ## Frontend usage
    /// Poll this before showing transfer UI or after receiving a `kyc_stale` event:
    /// ```ts
    /// const status = await contracts.rwa.checkKycStatus(walletAddress);
    /// if (!status.is_active) showKycWarning(status);
    /// ```
    pub fn check_kyc_status(env: Env, addr: Address) -> kyc::KycSyncStatus {
        kyc::fetch_kyc_sync_status(&env, &addr)
    }

    /// Permissionless: verify `addr`'s live KYC state and emit a `kyc_stale`
    /// event when the approval is no longer active (expired or revoked).
    ///
    /// Anyone may call this.  It is the on-chain signal that frontends and
    /// automation scripts subscribe to for cache invalidation.
    ///
    /// ## Events emitted
    /// - `("kyc_stale", addr)` with data `(is_active: bool, expiry: u64)`
    ///   — always emitted, giving listeners both the current state and expiry.
    ///
    /// ## Automation pattern
    /// Schedule periodic `sync_kyc_status` calls (e.g. via a keeper bot) for
    /// all addresses that hold tokens.  Frontends subscribe to `kyc_stale` events
    /// on the token contract and re-check wallet KYC status when they appear.
    pub fn sync_kyc_status(env: Env, addr: Address) -> bool {
        let snap = kyc::fetch_kyc_sync_status(&env, &addr);
        // Always emit so listeners can refresh state; the bool payload
        // tells them whether they need to act.
        env.events().publish(
            (symbol_short!("kyc_stale"), addr),
            (snap.is_active, snap.expiry),
        );
        snap.is_active
    }

    /// Returns a canonical metadata export snapshot for external integrations.
    ///
    /// This is the primary integration point for blockchain explorers,
    /// dashboards, and metadata APIs. The returned struct contains:
    /// - Core token fields (name, symbol, decimals, asset type, supply)
    /// - Linked contract addresses (KYC registry, compliance engine)
    /// - All compliance metadata fields (legal entity, governing law, ISIN, prospectus hash)
    /// - An optional external URI for extended off-chain metadata
    ///
    /// ## Explorer integration
    ///
    /// Call this method read-only via simulateTransaction:
    ///   stellar contract invoke --network testnet --id <CONTRACT_ID> -- get_token_export
    ///
    /// ## JSON-LD metadata
    ///
    /// The returned struct serialises directly to XDR and can be decoded
    /// by any Stellar SDK. The SDK getTokenExport() helper re-encodes
    /// it as a JSON object ready for indexers.
    pub fn get_token_export(env: Env) -> storage_types::TokenExportMetadata {
        let read_compliance = |key: &str| {
            let v = compliance::read_metadata(&env, Symbol::new(&env, key));
            if v.is_empty() {
                None
            } else {
                Some(v)
            }
        };
        storage_types::TokenExportMetadata {
            name: metadata::read_name(&env),
            symbol: metadata::read_symbol(&env),
            decimals: metadata::read_decimal(&env),
            asset_type: metadata::read_asset_type(&env),
            total_supply: balance::read_total_supply(&env),
            max_supply: balance::read_max_supply(&env),
            contract_version: String::from_str(&env, env!("CARGO_PKG_VERSION")),
            kyc_registry: kyc::read_kyc_registry(&env),
            compliance_engine: compliance::read_compliance_engine(&env),
            legal_entity: read_compliance(META_LEGAL_ENTITY),
            governing_law: read_compliance(META_GOVERNING_LAW),
            isin: read_compliance(META_ISIN),
            prospectus_hash: read_compliance(META_PROSPECTUS_HASH),
            external_uri: env
                .storage()
                .instance()
                .get(&storage_types::DataKey::ExternalUri),
        }
    }

    /// Returns the on-chain stored version string, total migration count, and
    /// the ledger timestamp of the last migration (0 if none have run).
    pub fn contract_version_info(env: Env) -> (String, u32, u64) {
        let version = versioning::read_version(&env);
        let count = versioning::read_migration_count(&env);
        let last_ts: u64 = if count > 0 {
            versioning::get_migration_record(&env, count - 1)
                .map(|r| r.timestamp)
                .unwrap_or(0)
        } else {
            0
        };
        (version, count, last_ts)
    }

    /// Admin-only migration entry point. Records the version bump on-chain.
    /// Nonce-protected (#349) to prevent accidental re-submission.
    /// Panics with `MigrationVersionConflict` if `new_version` equals the
    /// currently stored semver (idempotency guard).
    pub fn migrate(env: Env, new_version: String, description: String, nonce: u64) {
        let current_admin = admin::read_admin(&env);
        current_admin.require_auth();
        admin::consume_nonce(&env, nonce);
        let current = versioning::read_version(&env);
        if new_version == current {
            panic_with_error!(env, RwaError::MigrationVersionConflict)
        }
        versioning::apply_migration(&env, new_version.clone(), description);
        env.events()
            .publish((symbol_short!("migrated"),), (new_version, nonce));
    }

    /// Returns the migration record at the given index, or panics if out of range.
    pub fn get_migration_record(env: Env, index: u32) -> MigrationRecord {
        versioning::get_migration_record(&env, index).expect("migration record not found")
    }

    /// Returns the current numeric schema version.
    ///
    /// Returns `0` for legacy deployments initialized before schema versioning
    /// was introduced.  New deployments start at `1` via `initialize`.
    pub fn schema_version(env: Env) -> u32 {
        versioning::read_schema_version(&env)
    }

    /// Admin-only numeric schema upgrade hook.
    /// Nonce-protected to prevent accidental re-submission.
    /// `to_version` must equal `current_schema_version + 1`.
    pub fn migrate_schema(env: Env, to_version: u32, description: String, nonce: u64) {
        let current_admin = admin::read_admin(&env);
        current_admin.require_auth();
        admin::consume_nonce(&env, nonce);

        let current = versioning::read_schema_version(&env);
        if to_version == current {
            panic_with_error!(env, RwaError::MigrationVersionConflict);
        }
        if to_version != current + 1 {
            panic_with_error!(env, RwaError::MigrationVersionNotSequential);
        }

        // ── Per-version migration hooks ────────────────────────────────────
        match to_version {
            1 => {
                // Bootstrap: v0 layout == v1 layout, no data transformation.
            }
            _ => {
                // Future versions: implement data migrations here.
            }
        }

        let count: u32 = env
            .storage()
            .instance()
            .get(&storage_types::DataKey::SchemaMigrationCount)
            .unwrap_or(0);
        let record = SchemaVersionRecord {
            from_version: current,
            to_version,
            timestamp: env.ledger().timestamp(),
            description,
        };
        env.storage()
            .instance()
            .set(&storage_types::DataKey::SchemaMigration(count), &record);
        env.storage()
            .instance()
            .set(&storage_types::DataKey::SchemaMigrationCount, &(count + 1));
        env.storage()
            .instance()
            .set(&storage_types::DataKey::SchemaVersion, &to_version);

        env.events()
            .publish((symbol_short!("migrated"),), (current, to_version));
    }

    /// Returns the schema migration record at `index`, or panics if out of range.
    pub fn get_schema_migration_record(env: Env, index: u32) -> SchemaVersionRecord {
        env.storage()
            .instance()
            .get(&storage_types::DataKey::SchemaMigration(index))
            .expect("schema migration record not found")
    }

    // ── Replay-protection nonce (#349) ────────────────────────────────────────

    /// Returns the current admin nonce.  Callers must pass this value to every
    /// nonce-protected admin operation.  It increments by 1 on each successful
    /// protected call, so repeated or out-of-order submissions are rejected.
    pub fn admin_nonce(env: Env) -> u64 {
        admin::read_admin_nonce(&env)
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Sets the reentrancy guard flag.  Panics if already set.
    fn enter_transfer_guard(env: &Env) {
        if env
            .storage()
            .instance()
            .get::<_, bool>(&storage_types::DataKey::TransferLock)
            .unwrap_or(false)
        {
            panic!("transfer reentrant");
        }
        env.storage()
            .instance()
            .set(&storage_types::DataKey::TransferLock, &true);
    }

    /// Clears the reentrancy guard flag.
    fn exit_transfer_guard(env: &Env) {
        env.storage()
            .instance()
            .remove(&storage_types::DataKey::TransferLock);
    }

    /// Validates the sending side of a transfer: frozen check + KYC.
    /// Called once per transfer (or once per batch, not per entry).
    fn validate_sender(env: &Env, from: &Address) {
        if compliance::is_frozen(env, from) {
            panic_with_error!(env, RwaError::AccountFrozen);
        }
        kyc::require_kyc(env, from);
    }

    /// Validates one recipient entry: positive amount, frozen check, KYC, and
    /// the compliance engine's `can_transfer` rule set.
    fn validate_recipient(env: &Env, from: &Address, to: &Address, amount: i128) {
        if amount <= 0 {
            panic_with_error!(env, RwaError::NegativeAmount);
        }
        if compliance::is_frozen(env, to) {
            panic_with_error!(env, RwaError::AccountFrozen);
        }
        kyc::require_kyc(env, to);
        compliance::check_transfer(env, from, to, amount);
    }

    /// Builds a complete transfer plan without mutating token, allowance,
    /// compliance, or event state.
    fn prepare_transfer_plan(
        env: &Env,
        from: &Address,
        recipients: &Vec<RecipientEntry>,
    ) -> TransferPlan {
        let len = recipients.len();
        if len == 0 {
            panic_with_error!(env, RwaError::EmptyBatch);
        }
        if len > 10 {
            panic_with_error!(env, RwaError::BatchTooLarge);
        }

        Self::validate_sender(env, from);

        let mut total_amount = 0i128;
        let mut self_transfer_amount = 0i128;
        let mut new_holders = Vec::<Address>::new(env);

        for i in 0..len {
            let entry = recipients.get(i).expect("recipient index out of bounds");
            Self::validate_recipient(env, from, &entry.to, entry.amount);

            total_amount = match total_amount.checked_add(entry.amount) {
                Some(total) => total,
                None => panic_with_error!(env, RwaError::BatchAmountOverflow),
            };

            if entry.to == from.clone() {
                self_transfer_amount = match self_transfer_amount.checked_add(entry.amount) {
                    Some(total) => total,
                    None => panic_with_error!(env, RwaError::BatchAmountOverflow),
                };
            } else if balance::read_balance(env, entry.to.clone()) == 0
                && !new_holders.contains(&entry.to)
            {
                new_holders.push_back(entry.to);
            }
        }

        let sender_balance_before = balance::read_balance(env, from.clone());
        if sender_balance_before < total_amount {
            panic_with_error!(env, RwaError::InsufficientBalance);
        }

        let net_outgoing = total_amount - self_transfer_amount;
        let sender_balance_after = sender_balance_before - net_outgoing;
        compliance::ensure_holder_capacity(
            env,
            new_holders.len(),
            sender_balance_before > 0 && sender_balance_after == 0,
        );

        TransferPlan {
            total_amount,
            sender_balance_after,
        }
    }

    /// Applies a previously validated plan. No validation is performed here,
    /// so all entry points have exactly the same mutation and event ordering.
    fn execute_transfer_plan(
        env: &Env,
        from: &Address,
        recipients: &Vec<RecipientEntry>,
        plan: &TransferPlan,
    ) {
        for i in 0..recipients.len() {
            let entry = recipients.get(i).expect("recipient index out of bounds");
            Self::apply_transfer_leg(env, from, &entry.to, entry.amount);
            events::emit_transfer(env, from.clone(), entry.to, entry.amount);
        }

        if plan.total_amount > 0 && plan.sender_balance_after == 0 {
            compliance::unregister_holder(env, from);
        }
    }

    /// Applies the balance mutations and recipient holder registration for one
    /// transfer leg. Does NOT handle sender deregistration — callers must do
    /// that after all legs are applied so batch semantics remain correct.
    fn apply_transfer_leg(env: &Env, from: &Address, to: &Address, amount: i128) {
        let to_balance_before = balance::read_balance(env, to.clone());
        balance::spend_balance(env, from.clone(), amount);
        balance::receive_balance(env, to.clone(), amount);
        if from != to && to_balance_before == 0 {
            compliance::register_holder(env, to);
        }
    }

    // ── Recovery storage helpers ──────────────────────────────────────────────

    fn read_recovery_config(env: &Env) -> RecoveryConfig {
        env.storage()
            .instance()
            .get(&storage_types::DataKey::RecoveryConfig)
            .unwrap_or_else(|| panic_with_error!(env, RwaError::RecoveryNotConfigured))
    }

    fn read_recovery_members(env: &Env) -> Vec<Address> {
        env.storage()
            .instance()
            .get(&storage_types::DataKey::RecoveryMembers)
            .unwrap_or_else(|| panic_with_error!(env, RwaError::RecoveryNotConfigured))
    }

    fn assert_recovery_member(env: &Env, addr: &Address, members: &Vec<Address>) {
        if !members.contains(addr) {
            panic_with_error!(env, RwaError::NotRecoveryMember);
        }
    }

    // ── Recovery entry points ─────────────────────────────────────────────────

    /// Configures the M-of-N guardian recovery system. Admin-only.
    ///
    /// Requires 2 ≤ threshold ≤ members.len() ≤ 10 and no duplicate members.
    /// Clears any active recovery proposal to prevent stale proposals from
    /// executing under a new configuration.
    pub fn configure_recovery(env: Env, threshold: u32, members: Vec<Address>, cooldown: u32) {
        let current_admin = admin::read_admin(&env);
        current_admin.require_auth();

        let n = members.len();
        if threshold < 2 || threshold > n || n > 10 {
            panic_with_error!(env, RwaError::InvalidRecoveryConfig);
        }
        // Duplicate guardians would inflate N and let one key count twice.
        for i in 0..n {
            let m = members.get_unchecked(i);
            if members.first_index_of(&m) != Some(i) {
                panic_with_error!(env, RwaError::InvalidRecoveryConfig);
            }
        }

        let last_executed_ledger: u64 = env
            .storage()
            .instance()
            .get::<_, RecoveryConfig>(&storage_types::DataKey::RecoveryConfig)
            .map(|c: RecoveryConfig| c.last_executed_ledger)
            .unwrap_or(0);

        let cfg = RecoveryConfig {
            threshold,
            cooldown_ledgers: cooldown,
            last_executed_ledger,
        };
        env.storage()
            .instance()
            .set(&storage_types::DataKey::RecoveryConfig, &cfg);
        env.storage()
            .instance()
            .set(&storage_types::DataKey::RecoveryMembers, &members);
        // Mirror threshold in the dedicated slot for direct-read consumers.
        env.storage()
            .instance()
            .set(&storage_types::DataKey::RecoveryThreshold, &threshold);
        env.storage()
            .instance()
            .remove(&storage_types::DataKey::ActiveRecovery);

        events::emit_recovery_configured(&env, threshold, n);
    }

    /// Opens a new recovery proposal, replacing any prior one. Guardian-only.
    ///
    /// The proposal expires after `cooldown_ledgers / 2` ledgers.
    pub fn propose_recovery(env: Env, caller: Address, proposed_admin: Address) {
        caller.require_auth();
        let cfg = Self::read_recovery_config(&env);
        let members = Self::read_recovery_members(&env);
        Self::assert_recovery_member(&env, &caller, &members);

        let expiry_ledger = env.ledger().sequence() as u64 + cfg.cooldown_ledgers as u64 / 2;
        let approvals: Vec<Address> = Vec::new(&env);
        let proposal = RecoveryProposal {
            proposed_admin: proposed_admin.clone(),
            proposer: caller,
            approvals,
            expiry_ledger,
        };
        env.storage()
            .instance()
            .set(&storage_types::DataKey::ActiveRecovery, &proposal);
        events::emit_recovery_proposed(&env, proposed_admin, expiry_ledger);
    }

    /// Records caller's approval on the active proposal. Guardian-only.
    ///
    /// Panics if:
    /// - caller is not a guardian
    /// - no proposal is active
    /// - proposal has expired
    /// - caller is the proposer (self-approval)
    /// - caller has already approved
    pub fn approve_recovery(env: Env, caller: Address) {
        caller.require_auth();
        let members = Self::read_recovery_members(&env);
        Self::assert_recovery_member(&env, &caller, &members);

        let proposal: RecoveryProposal = env
            .storage()
            .instance()
            .get(&storage_types::DataKey::ActiveRecovery)
            .unwrap_or_else(|| panic_with_error!(env, RwaError::NoActiveRecovery));

        if env.ledger().sequence() as u64 > proposal.expiry_ledger {
            panic_with_error!(env, RwaError::RecoveryExpired);
        }
        if caller == proposal.proposer {
            panic_with_error!(env, RwaError::ProposerCannotApprove);
        }
        if proposal.approvals.contains(&caller) {
            panic_with_error!(env, RwaError::AlreadyApproved);
        }

        let mut new_approvals = proposal.approvals.clone();
        new_approvals.push_back(caller.clone());
        let count = new_approvals.len();
        let updated = RecoveryProposal {
            proposed_admin: proposal.proposed_admin,
            proposer: proposal.proposer,
            approvals: new_approvals,
            expiry_ledger: proposal.expiry_ledger,
        };
        env.storage()
            .instance()
            .set(&storage_types::DataKey::ActiveRecovery, &updated);
        events::emit_recovery_approved(&env, caller, count);
    }

    /// Executes the approved recovery, replacing the admin. Any guardian can call.
    ///
    /// Requires:
    /// - approvals.len() ≥ threshold
    /// - proposal not expired
    /// - cooldown since last execution has elapsed
    ///
    /// On success: sets the new admin, bumps AdminNonce (invalidating prior
    /// nonce-protected ops), clears the proposal, and records the execution ledger.
    pub fn execute_recovery(env: Env, caller: Address) {
        caller.require_auth();
        let cfg = Self::read_recovery_config(&env);
        let members = Self::read_recovery_members(&env);
        Self::assert_recovery_member(&env, &caller, &members);

        let proposal: RecoveryProposal = env
            .storage()
            .instance()
            .get(&storage_types::DataKey::ActiveRecovery)
            .unwrap_or_else(|| panic_with_error!(env, RwaError::NoActiveRecovery));

        let seq = env.ledger().sequence() as u64;
        if seq > proposal.expiry_ledger {
            panic_with_error!(env, RwaError::RecoveryExpired);
        }
        if proposal.approvals.len() < cfg.threshold {
            panic_with_error!(env, RwaError::InsufficientApprovals);
        }
        if seq < cfg.last_executed_ledger + cfg.cooldown_ledgers as u64 {
            panic_with_error!(env, RwaError::RecoveryCooldown);
        }

        let old_admin = admin::read_admin(&env);
        let new_admin = proposal.proposed_admin.clone();
        admin::write_admin(&env, &new_admin);

        let nonce = admin::read_admin_nonce(&env);
        env.storage()
            .instance()
            .set(&storage_types::DataKey::AdminNonce, &(nonce + 1));

        env.storage()
            .instance()
            .remove(&storage_types::DataKey::ActiveRecovery);

        let updated_cfg = RecoveryConfig {
            threshold: cfg.threshold,
            cooldown_ledgers: cfg.cooldown_ledgers,
            last_executed_ledger: seq,
        };
        env.storage()
            .instance()
            .set(&storage_types::DataKey::RecoveryConfig, &updated_cfg);

        events::emit_recovery_executed(&env, old_admin, new_admin);
    }

    /// Cancels the active recovery proposal. Admin-only.
    pub fn cancel_recovery(env: Env) {
        let current_admin = admin::read_admin(&env);
        current_admin.require_auth();
        if !env
            .storage()
            .instance()
            .has(&storage_types::DataKey::ActiveRecovery)
        {
            panic_with_error!(env, RwaError::NoActiveRecovery);
        }
        env.storage()
            .instance()
            .remove(&storage_types::DataKey::ActiveRecovery);
        events::emit_recovery_cancelled(&env);
    }

    // ── Recovery read-only views ──────────────────────────────────────────────

    /// Returns the current recovery configuration, or panics if not configured.
    pub fn recovery_config(env: Env) -> RecoveryConfig {
        Self::read_recovery_config(&env)
    }

    /// Returns the guardian member list, or panics if recovery is not configured.
    pub fn recovery_members(env: Env) -> Vec<Address> {
        Self::read_recovery_members(&env)
    }

    /// Returns the active recovery proposal, or None if no proposal is open.
    pub fn active_recovery(env: Env) -> Option<RecoveryProposal> {
        env.storage()
            .instance()
            .get(&storage_types::DataKey::ActiveRecovery)
    }
}
