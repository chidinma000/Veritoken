/// Structured event emission for the RWA Token contract.
///
/// ## Event schema
///
/// Every event is published as `env.events().publish(topics, data)`.
/// Topics are `(Symbol, ...)` tuples; data carries the payload.
///
/// | Function              | Topics                          | Data                              |
/// |-----------------------|---------------------------------|-----------------------------------|
/// | emit_transfer         | ("transfer", from, to)          | (amount: i128, ts: u64)           |
/// | emit_mint             | ("mint", to)                    | (amount: i128, ts: u64)           |
/// | emit_burn             | ("burn", from)                  | (amount: i128, ts: u64)           |
/// | emit_approve          | ("approve", from, spender)      | (amount: i128, exp: u32)          |
/// | emit_freeze           | ("freeze", addr)                | ()                                |
/// | emit_unfreeze         | ("unfreeze", addr)              | ()                                |
/// | emit_admin_proposed   | ("adm_prp",)                    | (new_admin: Address, nonce: u64)  |
/// | emit_admin_set        | ("adm_set",)                    | (old: Address, new: Address, nonce: u64) |
/// | emit_pending_admin_cleared | ("adm_clr",)               | ()                                 |
/// | emit_kyc_updated      | ("kyc_upd",)                    | (new_registry: Address, nonce: u64) |
/// | emit_ce_updated       | ("ce_upd",)                     | (new_engine: Address, nonce: u64) |
/// | emit_role_assigned    | ("role_set",)                   | (role: Symbol, holder: Address, nonce: u64) |
/// | emit_role_revoked     | ("role_rev",)                   | (role: Symbol, nonce: u64)        |
///
/// All timestamps (`ts`) are Soroban ledger timestamps (Unix epoch, seconds).
/// All `nonce` values are the admin nonce consumed by that operation (#349).
///
/// ## Indexing with Stellar RPC
///
/// Use `getEvents` with a `ContractId` filter and topic filters:
/// ```json
/// { "type": "contract", "contractIds": ["<id>"],
///   "topics": [["AAAADwAAAAh0cmFuc2Zlcg=="]] }
/// ```
/// (The base64 value encodes the `Symbol` "transfer".)
///
/// Iterate returned events; each entry's `value.xdr` decodes to the data tuple.
use soroban_sdk::{symbol_short, Address, Env, String, Symbol};

pub fn emit_transfer(env: &Env, from: Address, to: Address, amount: i128) {
    env.events().publish(
        (symbol_short!("transfer"), from, to),
        (amount, env.ledger().timestamp()),
    );
}

pub fn emit_mint(env: &Env, to: Address, amount: i128) {
    env.events().publish(
        (symbol_short!("mint"), to),
        (amount, env.ledger().timestamp()),
    );
}

pub fn emit_burn(env: &Env, from: Address, amount: i128) {
    env.events().publish(
        (symbol_short!("burn"), from),
        (amount, env.ledger().timestamp()),
    );
}

pub fn emit_approve(
    env: &Env,
    from: Address,
    spender: Address,
    amount: i128,
    expiration_ledger: u32,
) {
    env.events().publish(
        (symbol_short!("approve"), from, spender),
        (amount, expiration_ledger),
    );
}

pub fn emit_freeze(env: &Env, addr: Address) {
    env.events().publish((symbol_short!("freeze"), addr), ());
}

pub fn emit_unfreeze(env: &Env, addr: Address) {
    env.events().publish((symbol_short!("unfreeze"), addr), ());
}

pub fn emit_admin_proposed(env: &Env, new_admin: Address, nonce: u64) {
    env.events()
        .publish((symbol_short!("adm_prp"),), (new_admin, nonce));
}

pub fn emit_admin_set(env: &Env, old_admin: Address, new_admin: Address, nonce: u64) {
    env.events()
        .publish((symbol_short!("adm_set"),), (old_admin, new_admin, nonce));
}

pub fn emit_pending_admin_cleared(env: &Env) {
    env.events().publish((symbol_short!("adm_clr"),), ());
}

pub fn emit_kyc_updated(env: &Env, new_registry: Address, nonce: u64) {
    env.events()
        .publish((symbol_short!("kyc_upd"),), (new_registry, nonce));
}

pub fn emit_ce_updated(env: &Env, new_engine: Address, nonce: u64) {
    env.events()
        .publish((symbol_short!("ce_upd"),), (new_engine, nonce));
}

pub fn emit_role_assigned(env: &Env, role: Symbol, holder: Address, nonce: u64) {
    env.events()
        .publish((symbol_short!("role_set"),), (role, holder, nonce));
}

pub fn emit_role_revoked(env: &Env, role: Symbol, nonce: u64) {
    env.events()
        .publish((symbol_short!("role_rev"),), (role, nonce));
}

pub fn emit_recovery_configured(env: &Env, threshold: u32, member_count: u32) {
    env.events()
        .publish((symbol_short!("rcv_cfg"),), (threshold, member_count));
}

pub fn emit_recovery_proposed(env: &Env, proposed_admin: Address, expiry_ledger: u64) {
    env.events()
        .publish((symbol_short!("rcv_prp"),), (proposed_admin, expiry_ledger));
}

pub fn emit_recovery_approved(env: &Env, approver: Address, approval_count: u32) {
    env.events()
        .publish((symbol_short!("rcv_apv"),), (approver, approval_count));
}

pub fn emit_recovery_executed(env: &Env, old_admin: Address, new_admin: Address) {
    env.events()
        .publish((symbol_short!("rcv_exe"),), (old_admin, new_admin));
}

pub fn emit_recovery_cancelled(env: &Env) {
    env.events().publish((symbol_short!("rcv_can"),), ());
}

pub fn emit_external_uri(env: &Env, uri: String) {
    env.events().publish((symbol_short!("ext_uri"),), uri);
}

pub fn emit_external_uri_cleared(env: &Env) {
    env.events()
        .publish((Symbol::new(env, "ext_uri_cleared"),), ());
}

pub fn emit_batch_transfer_completed(env: &Env, count: u32) {
    env.events()
        .publish((Symbol::new(env, "batch_xfer"),), count);
}
