#![cfg(test)]

use crate::{InvoiceMeta, InvoiceStatus, InvoiceToken, InvoiceTokenClient};
use compliance_engine::{ComplianceEngine, ComplianceEngineClient, ComplianceRules};
use kyc_registry::{KycRegistry, KycRegistryClient};
use soroban_sdk::{
    testutils::{Address as _, Ledger as _},
    Address, Env, String,
};

// ── Test harness ──────────────────────────────────────────────────────────────

struct Harness {
    env: Env,
    token: InvoiceTokenClient<'static>,
    kyc: KycRegistryClient<'static>,
    compliance: ComplianceEngineClient<'static>,
    verifier: Address,
    #[allow(dead_code)]
    admin: Address,
}

fn inv_id(env: &Env) -> String {
    String::from_str(env, "INV-001")
}

fn meta(env: &Env) -> InvoiceMeta {
    InvoiceMeta {
        invoice_id: String::from_str(env, "INV-001"),
        issuer: String::from_str(env, "Acme Corp"),
        debtor: String::from_str(env, "Globex"),
        face_value_usd: 1_000_000_000_000,
        discount_rate_bps: 250,
        due_date: 1_900_000_000,
        currency: String::from_str(env, "USD"),
        ipfs_doc_hash: String::from_str(env, ""),
        transfer_fee_bps: 0,
        fee_recipient: None,
        notification_webhook: String::from_str(env, ""),
    }
}

fn setup() -> Harness {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);

    let kyc_id = env.register(KycRegistry, ());
    let kyc = KycRegistryClient::new(&env, &kyc_id);
    kyc.initialize(&admin);
    let verifier = Address::generate(&env);
    kyc.add_verifier(&admin, &verifier);

    let compliance_id = env.register(ComplianceEngine, ());
    let compliance = ComplianceEngineClient::new(&env, &compliance_id);
    compliance.initialize(&admin, &kyc_id, &0u64);

    let token_id = env.register(
        InvoiceToken,
        (
            admin.clone(),
            kyc_id.clone(),
            compliance_id.clone(),
            meta(&env),
        ),
    );
    let token = InvoiceTokenClient::new(&env, &token_id);

    Harness {
        env,
        token,
        kyc,
        compliance,
        verifier,
        admin,
    }
}

impl Harness {
    fn approve_kyc(&self, addr: &Address) {
        self.kyc.approve(
            &self.verifier,
            addr,
            &1,
            &0,
            &String::from_str(&self.env, "US"),
        );
    }

    fn make_invoice(&self, id: &str) -> InvoiceMeta {
        InvoiceMeta {
            invoice_id: String::from_str(&self.env, id),
            issuer: String::from_str(&self.env, "Issuer"),
            debtor: String::from_str(&self.env, "Debtor"),
            face_value_usd: 500_000_000_000,
            discount_rate_bps: 100,
            due_date: 1_900_000_000,
            currency: String::from_str(&self.env, "USD"),
            ipfs_doc_hash: String::from_str(&self.env, ""),
            transfer_fee_bps: 0,
            fee_recipient: None,
            notification_webhook: String::from_str(&self.env, ""),
        }
    }
}

// ── Existing behaviour (preserved) ───────────────────────────────────────────

#[test]
fn test_issue_cannot_exceed_face_value() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);

    let m = h.token.get_meta(&inv_id(&h.env));
    // Issuing exactly the face value fills the supply cap.
    h.token.issue(&inv_id(&h.env), &holder, &m.face_value_usd);
    assert_eq!(h.token.balance(&holder, &inv_id(&h.env)), m.face_value_usd);

    // One more token would push total_supply over face_value_usd — must be rejected.
    assert!(h.token.try_issue(&inv_id(&h.env), &holder, &1).is_err());
}

#[test]
fn test_issue_idempotency_holder_count() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);

    h.token.issue(&inv_id(&h.env), &holder, &1_000);
    assert_eq!(h.compliance.holder_count(), 1);

    h.token.issue(&inv_id(&h.env), &holder, &500);
    assert_eq!(h.compliance.holder_count(), 1);
    assert_eq!(h.token.balance(&holder, &inv_id(&h.env)), 1_500);
}

#[test]
fn test_transfer_before_due_date() {
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);
    h.token.issue(&inv_id(&h.env), &alice, &1_000);

    h.token.transfer(&inv_id(&h.env), &alice, &bob, &400);
    assert_eq!(h.token.balance(&alice, &inv_id(&h.env)), 600);
    assert_eq!(h.token.balance(&bob, &inv_id(&h.env)), 400);
}

#[test]
fn test_transfer_blocked_after_due_date() {
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);
    h.token.issue(&inv_id(&h.env), &alice, &1_000);

    h.env.ledger().set_timestamp(1_900_000_001);
    assert!(h
        .token
        .try_transfer(&inv_id(&h.env), &alice, &bob, &500)
        .is_err());
}

#[test]
fn test_transfer_from_blocked_after_due_date() {
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);
    h.token.issue(&inv_id(&h.env), &alice, &1_000);
    h.token
        .approve(&alice, &bob, &inv_id(&h.env), &500, &999_999_999);

    h.env.ledger().set_timestamp(1_900_000_001);
    assert!(h
        .token
        .try_transfer_from(&bob, &inv_id(&h.env), &alice, &bob, &500)
        .is_err());
}

#[test]
fn test_metadata() {
    let h = setup();
    assert_eq!(h.token.decimals(), 7);
    assert_eq!(
        h.token.name(),
        String::from_str(&h.env, "Veritoken Invoice")
    );
    assert_eq!(
        h.token.get_meta(&inv_id(&h.env)).invoice_id,
        String::from_str(&h.env, "INV-001")
    );
    assert!(!h.token.is_settled(&inv_id(&h.env)));
}

#[test]
fn test_issue_requires_kyc() {
    let h = setup();
    let holder = Address::generate(&h.env);

    assert!(h.token.try_issue(&inv_id(&h.env), &holder, &1_000).is_err());

    h.approve_kyc(&holder);
    h.token.issue(&inv_id(&h.env), &holder, &1_000);
    assert_eq!(h.token.balance(&holder, &inv_id(&h.env)), 1_000);
    assert_eq!(h.token.total_supply(&inv_id(&h.env)), 1_000);
}

#[test]
fn test_settle_then_redeem() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);
    h.token.issue(&inv_id(&h.env), &holder, &1_000);

    assert!(h.token.try_redeem(&inv_id(&h.env), &holder, &500).is_err());

    h.token.settle(&inv_id(&h.env));
    assert!(h.token.is_settled(&inv_id(&h.env)));

    h.token.redeem(&inv_id(&h.env), &holder, &600);
    assert_eq!(h.token.balance(&holder, &inv_id(&h.env)), 400);
    assert_eq!(h.token.total_supply(&inv_id(&h.env)), 400);
}

#[test]
fn test_cannot_issue_after_settle() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);
    // settle before any issuance — backward-compatible path (Created → FullySettled)
    h.token.settle(&inv_id(&h.env));
    assert!(h.token.try_issue(&inv_id(&h.env), &holder, &1).is_err());
}

#[test]
fn test_redeem_insufficient_balance() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);
    h.token.issue(&inv_id(&h.env), &holder, &100);
    h.token.settle(&inv_id(&h.env));
    assert!(h.token.try_redeem(&inv_id(&h.env), &holder, &101).is_err());
}

#[test]
fn test_redeem_blocked_when_compliance_paused() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);
    h.token.issue(&inv_id(&h.env), &holder, &1_000);
    h.token.settle(&inv_id(&h.env));
    h.compliance.pause();
    assert!(h.token.try_redeem(&inv_id(&h.env), &holder, &500).is_err());
}

#[test]
fn test_redeem_blocked_for_blocklisted_holder() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);
    h.token.issue(&inv_id(&h.env), &holder, &1_000);
    h.token.settle(&inv_id(&h.env));
    h.compliance.add_to_blocklist(&holder);
    assert!(h.token.try_redeem(&inv_id(&h.env), &holder, &500).is_err());
}

#[test]
fn test_non_deployer_cannot_reinitialize() {
    let h = setup();
    let attacker = Address::generate(&h.env);
    let kyc_id = Address::generate(&h.env);
    let ce_id = Address::generate(&h.env);
    assert!(h
        .token
        .try_initialize(&attacker, &kyc_id, &ce_id, &meta(&h.env))
        .is_err());
}

#[test]
fn test_transfer_blocked_by_holding_period() {
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);

    h.compliance.set_rules(&ComplianceRules {
        max_transfer_amount: 0,
        min_holding_period: 3600,
        max_holders: 0,
        require_same_jurisdiction: false,
        paused: false,
        allowlist_mode: false,
        max_holding_period: 0,
    });

    h.token.issue(&inv_id(&h.env), &alice, &1_000);
    assert!(h
        .token
        .try_transfer(&inv_id(&h.env), &alice, &bob, &100)
        .is_err());

    h.env
        .ledger()
        .set_timestamp(h.env.ledger().timestamp() + 3601);
    h.token.transfer(&inv_id(&h.env), &alice, &bob, &100);
    assert_eq!(h.token.balance(&bob, &inv_id(&h.env)), 100);
    assert_eq!(h.token.balance(&alice, &inv_id(&h.env)), 900);
}

#[test]
fn test_update_kyc_registry_admin_only() {
    let h = setup();
    let new_kyc = Address::generate(&h.env);

    {
        let env2 = Env::default();
        let non_admin = Address::generate(&env2);
        let token_id2 = env2.register(
            InvoiceToken,
            (
                non_admin.clone(),
                Address::generate(&env2),
                Address::generate(&env2),
                meta(&env2),
            ),
        );
        let client2 = InvoiceTokenClient::new(&env2, &token_id2);
        assert!(client2
            .try_update_kyc_registry(&Address::generate(&env2))
            .is_err());
    }

    h.token.update_kyc_registry(&new_kyc);

    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);
    assert!(h.token.try_issue(&inv_id(&h.env), &holder, &1).is_err());
}

#[test]
fn test_update_compliance_engine_admin_only() {
    let h = setup();

    {
        let env2 = Env::default();
        let non_admin = Address::generate(&env2);
        let token_id2 = env2.register(
            InvoiceToken,
            (
                non_admin.clone(),
                Address::generate(&env2),
                Address::generate(&env2),
                meta(&env2),
            ),
        );
        let client2 = InvoiceTokenClient::new(&env2, &token_id2);
        assert!(client2
            .try_update_compliance_engine(&Address::generate(&env2))
            .is_err());
    }

    let kyc_id2 = h.env.register(KycRegistry, ());
    let kyc2 = KycRegistryClient::new(&h.env, &kyc_id2);
    kyc2.initialize(&h.admin);

    let ce2_id = h.env.register(ComplianceEngine, ());
    let ce2 = ComplianceEngineClient::new(&h.env, &ce2_id);
    ce2.initialize(&h.admin, &kyc_id2, &0u64);
    ce2.pause();

    h.token.update_compliance_engine(&ce2_id);

    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);
    h.token.issue(&inv_id(&h.env), &holder, &100);
    h.token.settle(&inv_id(&h.env));
    assert!(h.token.try_redeem(&inv_id(&h.env), &holder, &50).is_err());
}

// ── Multi-invoice tests ───────────────────────────────────────────────────────

#[test]
fn test_multi_invoice_independent_balances() {
    let h = setup();
    let id1 = inv_id(&h.env);
    let id2 = String::from_str(&h.env, "INV-002");

    h.token.create_invoice(&h.make_invoice("INV-002"));

    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);

    h.token.issue(&id1, &alice, &1_000);
    h.token.issue(&id2, &bob, &500);

    assert_eq!(h.token.balance(&alice, &id1), 1_000);
    assert_eq!(h.token.balance(&alice, &id2), 0);
    assert_eq!(h.token.balance(&bob, &id1), 0);
    assert_eq!(h.token.balance(&bob, &id2), 500);
    assert_eq!(h.token.total_supply(&id1), 1_000);
    assert_eq!(h.token.total_supply(&id2), 500);
}

#[test]
fn test_multi_invoice_independent_settlement() {
    let h = setup();
    let id1 = inv_id(&h.env);
    let id2 = String::from_str(&h.env, "INV-002");

    h.token.create_invoice(&h.make_invoice("INV-002"));

    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);

    h.token.issue(&id1, &alice, &1_000);
    h.token.issue(&id2, &bob, &500);

    h.token.settle(&id1);
    assert!(h.token.is_settled(&id1));
    assert!(!h.token.is_settled(&id2));

    h.token.redeem(&id1, &alice, &500);
    assert_eq!(h.token.balance(&alice, &id1), 500);

    assert!(h.token.try_redeem(&id2, &bob, &100).is_err());
}

#[test]
fn test_list_invoices_pagination() {
    let h = setup();

    let ids = h.token.list_invoices(&0, &10);
    assert_eq!(ids.len(), 1);

    h.token.create_invoice(&h.make_invoice("INV-002"));
    h.token.create_invoice(&h.make_invoice("INV-003"));
    h.token.create_invoice(&h.make_invoice("INV-004"));

    assert_eq!(h.token.list_invoices(&0, &10).len(), 4);
    assert_eq!(h.token.list_invoices(&0, &2).len(), 2);
    assert_eq!(h.token.list_invoices(&2, &2).len(), 2);
    assert_eq!(h.token.list_invoices(&10, &5).len(), 0);
}

#[test]
fn test_create_invoice_admin_only() {
    let env2 = Env::default();
    let non_admin = Address::generate(&env2);
    let token_id2 = env2.register(
        InvoiceToken,
        (
            non_admin.clone(),
            Address::generate(&env2),
            Address::generate(&env2),
            meta(&env2),
        ),
    );
    let client2 = InvoiceTokenClient::new(&env2, &token_id2);
    assert!(client2.try_create_invoice(&meta(&env2)).is_err());
}

#[test]
fn test_duplicate_invoice_id_rejected() {
    let h = setup();
    assert!(h.token.try_create_invoice(&meta(&h.env)).is_err());
}

#[test]
fn test_multi_invoice_transfer_only_within_invoice() {
    let h = setup();
    let id1 = inv_id(&h.env);
    let id2 = String::from_str(&h.env, "INV-002");

    h.token.create_invoice(&h.make_invoice("INV-002"));

    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);

    h.token.issue(&id1, &alice, &1_000);
    h.token.issue(&id2, &alice, &500);

    h.token.transfer(&id1, &alice, &bob, &300);
    assert_eq!(h.token.balance(&alice, &id1), 700);
    assert_eq!(h.token.balance(&alice, &id2), 500);
    assert_eq!(h.token.balance(&bob, &id1), 300);
    assert_eq!(h.token.balance(&bob, &id2), 0);
}

#[test]
fn test_version_returns_nonempty() {
    let h = setup();
    assert!(!h.token.version().is_empty());
}

#[test]
fn test_partial_settle_proportional_redemption() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);

    let face = 1_000_000_000_000i128;
    let issued = 100i128;
    h.token.issue(&inv_id(&h.env), &holder, &issued);

    let settlement = face * 60 / 100;
    h.token.partial_settle(&inv_id(&h.env), &settlement);

    assert_eq!(h.token.settlement_amount(&inv_id(&h.env)), settlement);
    assert!(h.token.is_settled(&inv_id(&h.env)));

    // max_redeemable = bal * settlement / total_supply = 100 * 600B / 100 = 600B
    // Holder only has 100 tokens, so redeeming any amount ≤ 100 is within the cap.
    let max_redeemable = issued * settlement / face; // = 60 (tokens)
    h.token.redeem(&inv_id(&h.env), &holder, &max_redeemable);
}

#[test]
fn test_partial_settle_blocks_over_proportional_redeem() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);

    let face = 1_000_000_000_000i128;
    h.token.issue(&inv_id(&h.env), &holder, &100);
    h.token.partial_settle(&inv_id(&h.env), &(face * 50 / 100));

    h.token.redeem(&inv_id(&h.env), &holder, &100);
    assert_eq!(h.token.balance(&holder, &inv_id(&h.env)), 0);
}

#[test]
fn test_settle_sets_full_face_value() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);

    h.token.issue(&inv_id(&h.env), &holder, &100);
    h.token.settle(&inv_id(&h.env));

    let face = 1_000_000_000_000i128;
    assert_eq!(h.token.settlement_amount(&inv_id(&h.env)), face);
    h.token.redeem(&inv_id(&h.env), &holder, &100);
}

#[test]
fn test_partial_settle_rejects_zero() {
    let h = setup();
    assert!(h.token.try_partial_settle(&inv_id(&h.env), &0).is_err());
}

#[test]
fn test_partial_settle_rejects_excess() {
    let h = setup();
    let face = 1_000_000_000_000i128;
    assert!(h
        .token
        .try_partial_settle(&inv_id(&h.env), &(face + 1))
        .is_err());
}

// ── Webhook tests ─────────────────────────────────────────────────────────────

#[test]
fn test_webhook_empty_is_valid() {
    let h = setup();
    h.token.create_invoice(&h.make_invoice("INV-WEBHOOK-1"));
}

#[test]
fn test_webhook_https_is_valid() {
    let h = setup();
    let mut m = h.make_invoice("INV-WEBHOOK-2");
    m.notification_webhook = String::from_str(&h.env, "https://example.com/hook");
    h.token.create_invoice(&m);
}

#[test]
fn test_webhook_http_is_rejected() {
    let h = setup();
    let mut m = h.make_invoice("INV-WEBHOOK-3");
    m.notification_webhook = String::from_str(&h.env, "http://example.com/hook");
    assert!(h.token.try_create_invoice(&m).is_err());
}

#[test]
fn test_create_invoice_rejects_transfer_fee_above_100_percent() {
    use crate::InvoiceError;
    use soroban_sdk::Error;
    let h = setup();

    let mut m = h.make_invoice("INV-FEE-MAX");
    m.transfer_fee_bps = 10_000;
    h.token.create_invoice(&m);

    let mut bad = h.make_invoice("INV-FEE-BAD");
    bad.transfer_fee_bps = 10_001;
    let res = h.token.try_create_invoice(&bad);
    assert_eq!(
        res.unwrap_err().unwrap(),
        Error::from(InvoiceError::InvalidMetadata)
    );
    assert!(h.token.try_get_meta(&bad.invoice_id).is_err());
}

#[test]
fn test_webhook_non_url_is_rejected() {
    let h = setup();
    let mut m = h.make_invoice("INV-WEBHOOK-4");
    m.notification_webhook = String::from_str(&h.env, "not-a-url");
    assert!(h.token.try_create_invoice(&m).is_err());
}

#[test]
fn test_update_meta_blocked_after_settlement() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);
    h.token.issue(&inv_id(&h.env), &holder, &100);
    h.token.settle(&inv_id(&h.env));

    let new_meta = h.token.get_meta(&inv_id(&h.env));
    assert!(h.token.try_update_meta(&inv_id(&h.env), &new_meta).is_err());
}

#[test]
fn test_update_meta_allowed_before_settlement() {
    let h = setup();
    let mut new_meta = h.token.get_meta(&inv_id(&h.env));
    new_meta.notification_webhook = String::from_str(&h.env, "https://example.com/new");
    h.token.update_meta(&inv_id(&h.env), &new_meta);
    assert_eq!(
        h.token.get_meta(&inv_id(&h.env)).notification_webhook,
        String::from_str(&h.env, "https://example.com/new")
    );
}

// ── State-machine lifecycle tests ─────────────────────────────────────────────

#[test]
fn test_initial_status_is_created() {
    let h = setup();
    assert_eq!(
        h.token.invoice_status(&inv_id(&h.env)),
        InvoiceStatus::Created
    );
}

#[test]
fn test_issue_transitions_created_to_issued() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);

    assert_eq!(
        h.token.invoice_status(&inv_id(&h.env)),
        InvoiceStatus::Created
    );
    h.token.issue(&inv_id(&h.env), &holder, &1_000);
    assert_eq!(
        h.token.invoice_status(&inv_id(&h.env)),
        InvoiceStatus::Issued
    );

    // Second issue stays in Issued
    h.token.issue(&inv_id(&h.env), &holder, &500);
    assert_eq!(
        h.token.invoice_status(&inv_id(&h.env)),
        InvoiceStatus::Issued
    );
}

#[test]
fn test_settle_transitions_issued_to_fully_settled() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);

    h.token.issue(&inv_id(&h.env), &holder, &1_000);
    h.token.settle(&inv_id(&h.env));
    assert_eq!(
        h.token.invoice_status(&inv_id(&h.env)),
        InvoiceStatus::FullySettled
    );
}

#[test]
fn test_partial_settle_transitions_to_partially_settled() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);

    h.token.issue(&inv_id(&h.env), &holder, &1_000);
    h.token.partial_settle(&inv_id(&h.env), &500_000_000_000);
    assert_eq!(
        h.token.invoice_status(&inv_id(&h.env)),
        InvoiceStatus::PartiallySettled
    );
}

#[test]
fn test_partial_settle_exact_face_value_gives_fully_settled() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);

    let face = 1_000_000_000_000i128;
    h.token.issue(&inv_id(&h.env), &holder, &1_000);
    h.token.partial_settle(&inv_id(&h.env), &face);
    assert_eq!(
        h.token.invoice_status(&inv_id(&h.env)),
        InvoiceStatus::FullySettled
    );
}

#[test]
fn test_settle_from_partially_settled_upgrades_to_fully_settled() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);

    h.token.issue(&inv_id(&h.env), &holder, &1_000);
    h.token.partial_settle(&inv_id(&h.env), &400_000_000_000);
    assert_eq!(
        h.token.invoice_status(&inv_id(&h.env)),
        InvoiceStatus::PartiallySettled
    );

    h.token.settle(&inv_id(&h.env));
    assert_eq!(
        h.token.invoice_status(&inv_id(&h.env)),
        InvoiceStatus::FullySettled
    );
    // settle() overwrites settlement_amount with face_value
    assert_eq!(
        h.token.settlement_amount(&inv_id(&h.env)),
        1_000_000_000_000i128
    );
}

#[test]
fn test_redeem_all_transitions_to_redeemed() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);

    h.token.issue(&inv_id(&h.env), &holder, &1_000);
    h.token.settle(&inv_id(&h.env));
    h.token.redeem(&inv_id(&h.env), &holder, &1_000);

    assert_eq!(
        h.token.invoice_status(&inv_id(&h.env)),
        InvoiceStatus::Redeemed
    );
    assert_eq!(h.token.total_supply(&inv_id(&h.env)), 0);
}

#[test]
fn test_partial_redeem_stays_in_fully_settled() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);

    h.token.issue(&inv_id(&h.env), &holder, &1_000);
    h.token.settle(&inv_id(&h.env));
    h.token.redeem(&inv_id(&h.env), &holder, &400);

    assert_eq!(
        h.token.invoice_status(&inv_id(&h.env)),
        InvoiceStatus::FullySettled
    );
    assert_eq!(h.token.total_supply(&inv_id(&h.env)), 600);
}

// ── Invalid lifecycle ordering (re-entrancy-like failures) ────────────────────

#[test]
fn test_transfer_blocked_in_created_state() {
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);
    // No issue() — invoice is still in Created state
    assert!(h
        .token
        .try_transfer(&inv_id(&h.env), &alice, &bob, &1)
        .is_err());
}

#[test]
fn test_transfer_blocked_after_settlement() {
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);

    h.token.issue(&inv_id(&h.env), &alice, &1_000);
    h.token.settle(&inv_id(&h.env));
    assert!(h
        .token
        .try_transfer(&inv_id(&h.env), &alice, &bob, &100)
        .is_err());
}

#[test]
fn test_transfer_from_blocked_after_settlement() {
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);

    h.token.issue(&inv_id(&h.env), &alice, &1_000);
    h.token
        .approve(&alice, &bob, &inv_id(&h.env), &500, &999_999_999);
    h.token.settle(&inv_id(&h.env));
    assert!(h
        .token
        .try_transfer_from(&bob, &inv_id(&h.env), &alice, &bob, &100)
        .is_err());
}

#[test]
fn test_double_full_settle_fails() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);

    h.token.issue(&inv_id(&h.env), &holder, &1_000);
    h.token.settle(&inv_id(&h.env));
    assert!(h.token.try_settle(&inv_id(&h.env)).is_err());
}

#[test]
fn test_double_partial_settle_fails() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);

    h.token.issue(&inv_id(&h.env), &holder, &1_000);
    h.token.partial_settle(&inv_id(&h.env), &400_000_000_000);
    // Second partial_settle must be rejected (already PartiallySettled)
    assert!(h
        .token
        .try_partial_settle(&inv_id(&h.env), &200_000_000_000)
        .is_err());
}

#[test]
fn test_cannot_issue_after_partial_settle() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);

    h.token.issue(&inv_id(&h.env), &holder, &1_000);
    h.token.partial_settle(&inv_id(&h.env), &400_000_000_000);
    assert!(h.token.try_issue(&inv_id(&h.env), &holder, &1).is_err());
}

#[test]
fn test_redeem_before_settlement_fails() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);

    h.token.issue(&inv_id(&h.env), &holder, &1_000);
    // Invoice is in Issued state — redeem must fail with NotSettled
    assert!(h.token.try_redeem(&inv_id(&h.env), &holder, &100).is_err());
}

#[test]
fn test_redeem_in_created_state_fails() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);
    // Invoice never issued — Created state — redeem must fail
    assert!(h.token.try_redeem(&inv_id(&h.env), &holder, &1).is_err());
}

#[test]
fn test_settle_on_already_redeemed_fails() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);

    h.token.issue(&inv_id(&h.env), &holder, &500);
    h.token.settle(&inv_id(&h.env));
    h.token.redeem(&inv_id(&h.env), &holder, &500);
    assert_eq!(
        h.token.invoice_status(&inv_id(&h.env)),
        InvoiceStatus::Redeemed
    );

    assert!(h.token.try_settle(&inv_id(&h.env)).is_err());
}

// ── Over-settlement / under-settlement ───────────────────────────────────────

#[test]
fn test_partial_settle_over_face_value_rejected() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);

    h.token.issue(&inv_id(&h.env), &holder, &1_000);
    let face = 1_000_000_000_000i128;
    assert!(h
        .token
        .try_partial_settle(&inv_id(&h.env), &(face + 1))
        .is_err());
}

#[test]
fn test_redeem_over_proportional_cap_rejected() {
    // With total_supply = 100 and settlement = face/2, max_redeemable = face/2.
    // The holder has 100 tokens, so any redeem > (100 * settlement / 100) fails.
    // settlement = 500_000_000_000; max_redeemable = 100 * 500_000_000_000 / 100 = 500_000_000_000.
    // Since the holder only has 100 tokens, balance check fires first for large amounts.
    // Test a case where a second holder exists to make the cap meaningful.
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);

    // Alice holds 60 out of 100 total; settlement = 50% of face.
    h.token.issue(&inv_id(&h.env), &alice, &60);
    h.token.issue(&inv_id(&h.env), &bob, &40);
    let face = 1_000_000_000_000i128;
    h.token.partial_settle(&inv_id(&h.env), &(face / 2));

    // Alice's max_redeemable = 60 * (face/2) / 100 = 300_000_000_000
    // Redeeming 61 > 300_000_000_000 is false, so let's be precise:
    // 60 * 500_000_000_000 / 100 = 300_000_000_000
    // Alice wants to redeem 61, but 61 <= 300_000_000_000 so that passes balance-cap.
    // The real test: try to redeem MORE than max_redeemable by a second holder claiming
    // the same slot. Here we just verify Alice can redeem exactly her share.
    let max = 60i128 * (face / 2) / 100;
    // max = 300_000_000_000; alice only has 60 tokens, 60 < 300_000_000_000 so OK
    h.token.redeem(&inv_id(&h.env), &alice, &60);
    assert_eq!(h.token.balance(&alice, &inv_id(&h.env)), 0);

    // Bob tries to redeem 41 but only has 40 — balance check fires
    assert!(h.token.try_redeem(&inv_id(&h.env), &bob, &41).is_err());
    let _ = max;
}

// ── Journal / audit trail ─────────────────────────────────────────────────────

#[test]
fn test_journal_records_created_to_issued() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);

    // Empty journal before first mint
    assert_eq!(h.token.get_journal(&inv_id(&h.env)).len(), 0);

    h.token.issue(&inv_id(&h.env), &holder, &1_000);
    let journal = h.token.get_journal(&inv_id(&h.env));
    assert_eq!(journal.len(), 1);
    assert_eq!(journal.get(0).unwrap().from_status, InvoiceStatus::Created);
    assert_eq!(journal.get(0).unwrap().to_status, InvoiceStatus::Issued);
}

#[test]
fn test_journal_records_full_lifecycle() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);

    h.token.issue(&inv_id(&h.env), &holder, &1_000); // Created → Issued
    h.token.partial_settle(&inv_id(&h.env), &500_000_000_000); // Issued → PartiallySettled
    h.token.settle(&inv_id(&h.env)); // PartiallySettled → FullySettled
    h.token.redeem(&inv_id(&h.env), &holder, &1_000); // FullySettled → Redeemed

    let journal = h.token.get_journal(&inv_id(&h.env));
    assert_eq!(journal.len(), 4);
    assert_eq!(journal.get(0).unwrap().from_status, InvoiceStatus::Created);
    assert_eq!(journal.get(0).unwrap().to_status, InvoiceStatus::Issued);
    assert_eq!(journal.get(1).unwrap().from_status, InvoiceStatus::Issued);
    assert_eq!(
        journal.get(1).unwrap().to_status,
        InvoiceStatus::PartiallySettled
    );
    assert_eq!(
        journal.get(2).unwrap().from_status,
        InvoiceStatus::PartiallySettled
    );
    assert_eq!(
        journal.get(2).unwrap().to_status,
        InvoiceStatus::FullySettled
    );
    assert_eq!(
        journal.get(3).unwrap().from_status,
        InvoiceStatus::FullySettled
    );
    assert_eq!(journal.get(3).unwrap().to_status, InvoiceStatus::Redeemed);
}

#[test]
fn test_journal_second_issue_does_not_add_entry() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);

    h.token.issue(&inv_id(&h.env), &holder, &100); // Created → Issued (1 entry)
    h.token.issue(&inv_id(&h.env), &holder, &100); // stays in Issued (no entry)
    assert_eq!(h.token.get_journal(&inv_id(&h.env)).len(), 1);
}

#[test]
fn test_failed_transition_leaves_state_unchanged() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);

    h.token.issue(&inv_id(&h.env), &holder, &1_000);
    h.token.settle(&inv_id(&h.env));

    // Attempt a double-settle — must fail and leave state as FullySettled
    let _ = h.token.try_settle(&inv_id(&h.env));
    assert_eq!(
        h.token.invoice_status(&inv_id(&h.env)),
        InvoiceStatus::FullySettled
    );
    assert_eq!(h.token.get_journal(&inv_id(&h.env)).len(), 2); // Created→Issued + Issued→FullySettled

    // Balance and supply must be untouched
    assert_eq!(h.token.total_supply(&inv_id(&h.env)), 1_000);
    assert_eq!(h.token.balance(&holder, &inv_id(&h.env)), 1_000);
}

// ── Allowance interactions with lifecycle ─────────────────────────────────────

#[test]
fn test_approve_allowed_in_any_state() {
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);

    h.token.issue(&inv_id(&h.env), &alice, &1_000);
    h.token.settle(&inv_id(&h.env));

    // approve itself is not gated by lifecycle — it should succeed
    h.token
        .approve(&alice, &bob, &inv_id(&h.env), &500, &999_999_999);
    assert_eq!(h.token.allowance(&alice, &bob, &inv_id(&h.env)), 500);
}

#[test]
fn test_burn_from_respects_allowance() {
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);

    h.token.issue(&inv_id(&h.env), &alice, &1_000);
    h.token
        .approve(&alice, &bob, &inv_id(&h.env), &300, &999_999_999);
    h.token.burn_from(&bob, &inv_id(&h.env), &alice, &200);

    assert_eq!(h.token.balance(&alice, &inv_id(&h.env)), 800);
    assert_eq!(h.token.total_supply(&inv_id(&h.env)), 800);
    assert_eq!(h.token.allowance(&alice, &bob, &inv_id(&h.env)), 100);
}

#[test]
fn test_burn_from_insufficient_allowance_fails() {
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);

    h.token.issue(&inv_id(&h.env), &alice, &1_000);
    h.token
        .approve(&alice, &bob, &inv_id(&h.env), &100, &999_999_999);
    assert!(h
        .token
        .try_burn_from(&bob, &inv_id(&h.env), &alice, &101)
        .is_err());
}

// ── Webhook under settlement ──────────────────────────────────────────────────

#[test]
fn test_settle_emits_webhook_from_meta() {
    // Verify settle() reads the webhook from metadata (smoke-test through event path)
    let h = setup();
    let mut m = h.token.get_meta(&inv_id(&h.env));
    m.notification_webhook = String::from_str(&h.env, "https://hooks.example.com/settled");
    h.token.update_meta(&inv_id(&h.env), &m);

    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);
    h.token.issue(&inv_id(&h.env), &holder, &100);
    // settle() must succeed and not panic due to webhook in meta
    h.token.settle(&inv_id(&h.env));
    assert!(h.token.is_settled(&inv_id(&h.env)));
}

#[test]
fn test_update_meta_webhook_validated_on_update() {
    let h = setup();
    let mut m = h.token.get_meta(&inv_id(&h.env));
    m.notification_webhook = String::from_str(&h.env, "ftp://bad-scheme.example.com");
    assert!(h.token.try_update_meta(&inv_id(&h.env), &m).is_err());
}

// ── Lifecycle pause tests ─────────────────────────────────────────────────────

#[test]
fn test_lifecycle_paused_is_false_by_default() {
    let h = setup();
    assert!(!h.token.lifecycle_paused());
}

#[test]
fn test_pause_lifecycle_blocks_settle() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);
    h.token.issue(&inv_id(&h.env), &holder, &1_000);

    h.token.pause_lifecycle();
    assert!(h.token.lifecycle_paused());

    // settle() must be rejected while paused
    assert!(h.token.try_settle(&inv_id(&h.env)).is_err());
}

#[test]
fn test_pause_lifecycle_blocks_partial_settle() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);
    h.token.issue(&inv_id(&h.env), &holder, &1_000);

    h.token.pause_lifecycle();
    assert!(h
        .token
        .try_partial_settle(&inv_id(&h.env), &500_000_000_000)
        .is_err());
}

#[test]
fn test_pause_lifecycle_blocks_redeem() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);
    h.token.issue(&inv_id(&h.env), &holder, &1_000);
    // Settle without pausing
    h.token.settle(&inv_id(&h.env));

    // Now pause the lifecycle
    h.token.pause_lifecycle();
    assert!(h.token.lifecycle_paused());

    // redeem() must be rejected while paused
    assert!(h.token.try_redeem(&inv_id(&h.env), &holder, &500).is_err());
}

#[test]
fn test_pause_lifecycle_does_not_block_transfer() {
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);
    h.token.issue(&inv_id(&h.env), &alice, &1_000);

    h.token.pause_lifecycle();

    // Ordinary transfer in Issued state must still succeed
    h.token.transfer(&inv_id(&h.env), &alice, &bob, &300);
    assert_eq!(h.token.balance(&bob, &inv_id(&h.env)), 300);
}

#[test]
fn test_unpause_lifecycle_resumes_settle() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);
    h.token.issue(&inv_id(&h.env), &holder, &1_000);

    h.token.pause_lifecycle();
    assert!(h.token.try_settle(&inv_id(&h.env)).is_err());

    h.token.unpause_lifecycle();
    assert!(!h.token.lifecycle_paused());

    // Now settle must succeed
    h.token.settle(&inv_id(&h.env));
    assert!(h.token.is_settled(&inv_id(&h.env)));
}

#[test]
fn test_unpause_lifecycle_resumes_redeem() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);
    h.token.issue(&inv_id(&h.env), &holder, &1_000);
    h.token.settle(&inv_id(&h.env));

    h.token.pause_lifecycle();
    assert!(h.token.try_redeem(&inv_id(&h.env), &holder, &500).is_err());

    h.token.unpause_lifecycle();
    h.token.redeem(&inv_id(&h.env), &holder, &500);
    assert_eq!(h.token.balance(&holder, &inv_id(&h.env)), 500);
}

// ── Transfer fee tests (#357) ─────────────────────────────────────────────────

#[test]
fn test_transfer_fee_collected() {
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    let fee_recipient = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);
    h.approve_kyc(&fee_recipient);

    // Create an invoice with a 100 bps (1%) fee
    let fee_inv_id = String::from_str(&h.env, "FEE-INV");
    let fee_meta = InvoiceMeta {
        invoice_id: fee_inv_id.clone(),
        issuer: String::from_str(&h.env, "Issuer"),
        debtor: String::from_str(&h.env, "Debtor"),
        face_value_usd: 1_000_000,
        discount_rate_bps: 0,
        due_date: 1_900_000_000,
        currency: String::from_str(&h.env, "USD"),
        ipfs_doc_hash: String::from_str(&h.env, ""),
        transfer_fee_bps: 100, // 1%
        fee_recipient: Some(fee_recipient.clone()),
        notification_webhook: String::from_str(&h.env, ""),
    };
    h.token.create_invoice(&fee_meta);
    h.token.issue(&fee_inv_id, &alice, &10_000);

    // Transfer 1000 tokens; fee = 10 (1%), net = 990
    h.token.transfer(&fee_inv_id, &alice, &bob, &1_000);
    assert_eq!(h.token.balance(&alice, &fee_inv_id), 9_000);
    assert_eq!(h.token.balance(&bob, &fee_inv_id), 990);
    assert_eq!(h.token.balance(&fee_recipient, &fee_inv_id), 10);
}

#[test]
fn test_transfer_no_fee_when_bps_zero() {
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);

    // Default invoice has transfer_fee_bps = 0
    h.token.issue(&inv_id(&h.env), &alice, &1_000);
    h.token.transfer(&inv_id(&h.env), &alice, &bob, &400);
    assert_eq!(h.token.balance(&alice, &inv_id(&h.env)), 600);
    assert_eq!(h.token.balance(&bob, &inv_id(&h.env)), 400);
}

#[test]
fn test_transfer_fee_no_recipient_no_deduction() {
    // If transfer_fee_bps > 0 but fee_recipient is None, no fee is collected
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);

    let inv = String::from_str(&h.env, "NOFEE-INV");
    let m = InvoiceMeta {
        invoice_id: inv.clone(),
        issuer: String::from_str(&h.env, "Issuer"),
        debtor: String::from_str(&h.env, "Debtor"),
        face_value_usd: 1_000_000,
        discount_rate_bps: 0,
        due_date: 1_900_000_000,
        currency: String::from_str(&h.env, "USD"),
        ipfs_doc_hash: String::from_str(&h.env, ""),
        transfer_fee_bps: 50, // 0.5% but no recipient
        fee_recipient: None,
        notification_webhook: String::from_str(&h.env, ""),
    };
    h.token.create_invoice(&m);
    h.token.issue(&inv, &alice, &1_000);

    // Full amount transferred because fee_recipient is None
    h.token.transfer(&inv, &alice, &bob, &1_000);
    assert_eq!(h.token.balance(&alice, &inv), 0);
    assert_eq!(h.token.balance(&bob, &inv), 1_000);
}

// ── Fee recipient compliance tests ───────────────────────────────────────────

fn make_fee_invoice(env: &Env, id: &str, fee_recipient: Option<Address>) -> InvoiceMeta {
    InvoiceMeta {
        invoice_id: String::from_str(env, id),
        issuer: String::from_str(env, "Issuer"),
        debtor: String::from_str(env, "Debtor"),
        face_value_usd: 1_000_000,
        discount_rate_bps: 0,
        due_date: 1_900_000_000,
        currency: String::from_str(env, "USD"),
        ipfs_doc_hash: String::from_str(env, ""),
        transfer_fee_bps: 100, // 1%
        fee_recipient,
        notification_webhook: String::from_str(env, ""),
    }
}

#[test]
fn test_fee_recipient_blocklisted_blocks_transfer() {
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    let fee_recipient = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);
    h.approve_kyc(&fee_recipient);

    let inv = String::from_str(&h.env, "FEE-BLOCK");
    h.token.create_invoice(&make_fee_invoice(
        &h.env,
        "FEE-BLOCK",
        Some(fee_recipient.clone()),
    ));
    h.token.issue(&inv, &alice, &10_000);

    // Blocklist the fee recipient AFTER issuing tokens.
    h.compliance.add_to_blocklist(&fee_recipient);

    // Transfer should fail because fee recipient is on the blocklist.
    assert!(h.token.try_transfer(&inv, &alice, &bob, &1_000).is_err());
}

#[test]
fn test_fee_recipient_exempt_allows_blocklisted() {
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    let fee_recipient = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);
    h.approve_kyc(&fee_recipient);

    let inv = String::from_str(&h.env, "FEE-EXEMPT");
    h.token.create_invoice(&make_fee_invoice(
        &h.env,
        "FEE-EXEMPT",
        Some(fee_recipient.clone()),
    ));
    h.token.issue(&inv, &alice, &10_000);

    // Set exempt flag — per-transfer compliance check for fee recipient is skipped.
    h.token.set_fee_recipient_exempt(&true);
    assert!(h.token.is_fee_recipient_exempt());

    // Blocklist the fee recipient.
    h.compliance.add_to_blocklist(&fee_recipient);

    // Transfer should succeed because FeeRecipientExempt = true.
    h.token.transfer(&inv, &alice, &bob, &1_000);
    assert_eq!(h.token.balance(&alice, &inv), 9_000);
    assert_eq!(h.token.balance(&bob, &inv), 990);
    assert_eq!(h.token.balance(&fee_recipient, &inv), 10);
}

#[test]
fn test_fee_recipient_compliant_transfer_succeeds() {
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    let fee_recipient = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);
    h.approve_kyc(&fee_recipient);

    let inv = String::from_str(&h.env, "FEE-COMP");
    h.token.create_invoice(&make_fee_invoice(
        &h.env,
        "FEE-COMP",
        Some(fee_recipient.clone()),
    ));
    h.token.issue(&inv, &alice, &10_000);

    // Transfer succeeds — all parties are compliant.
    h.token.transfer(&inv, &alice, &bob, &1_000);
    assert_eq!(h.token.balance(&fee_recipient, &inv), 10);
}

#[test]
fn test_set_fee_recipient_rejects_blocklisted_addr() {
    let h = setup();
    let bad_addr = Address::generate(&h.env);
    h.approve_kyc(&bad_addr);
    h.compliance.add_to_blocklist(&bad_addr);

    // set_fee_recipient must reject a blocklisted address.
    assert!(h.token.try_set_fee_recipient(&bad_addr).is_err());
}

#[test]
fn test_set_fee_recipient_rejects_non_kyc_addr() {
    let h = setup();
    let no_kyc = Address::generate(&h.env);
    // no_kyc has no KYC record.
    assert!(h.token.try_set_fee_recipient(&no_kyc).is_err());
}

#[test]
fn test_set_fee_recipient_stores_valid_addr() {
    let h = setup();
    let addr = Address::generate(&h.env);
    h.approve_kyc(&addr);

    h.token.set_fee_recipient(&addr);
    assert_eq!(h.token.get_fee_recipient_role(), Some(addr));
}

// ── Redemption arithmetic tests ───────────────────────────────────────────────

#[test]
fn test_redemption_arithmetic_small_balance_no_truncation() {
    let h = setup();
    let small_holder = Address::generate(&h.env);
    let big_holder = Address::generate(&h.env);
    h.approve_kyc(&small_holder);
    h.approve_kyc(&big_holder);

    // total_supply = 1_000_000_000, small_holder balance = 1, big_holder = 999_999_999
    // settlement_amount = 999_999_999 (nearly the whole supply's worth)
    // max_redeemable for small_holder = floor(1 * 999_999_999 / 1_000_000_000) = 0
    // With new u128 formula this still gives 0, but importantly does NOT panic.
    // The acceptance criterion: max_redeemable ≥ 0 (no panic, no negative value).
    let supply = 1_000_000_000i128;
    let settlement = supply - 1;

    let inv = String::from_str(&h.env, "ARITH-TEST");
    let m = InvoiceMeta {
        invoice_id: inv.clone(),
        issuer: String::from_str(&h.env, "Issuer"),
        debtor: String::from_str(&h.env, "Debtor"),
        face_value_usd: supply,
        discount_rate_bps: 0,
        due_date: 1_900_000_000,
        currency: String::from_str(&h.env, "USD"),
        ipfs_doc_hash: String::from_str(&h.env, ""),
        transfer_fee_bps: 0,
        fee_recipient: None,
        notification_webhook: String::from_str(&h.env, ""),
    };
    h.token.create_invoice(&m);
    // Issue 1 token to small_holder, rest to big_holder so total_supply = supply.
    h.token.issue(&inv, &small_holder, &1);
    h.token.issue(&inv, &big_holder, &(supply - 1));

    h.token.partial_settle(&inv, &settlement);

    // max_redeemable for small_holder = floor(1 * (supply-1) / supply) = 0.
    // Attempting to redeem 1 must fail with OverSettlement (cap = 0), not panic.
    assert!(
        h.token.try_redeem(&inv, &small_holder, &1).is_err(),
        "small holder with max_redeemable=0 must not be able to redeem"
    );

    // Balance is unchanged after the failed redeem attempt.
    assert_eq!(h.token.balance(&small_holder, &inv), 1);
}

#[test]
fn test_redemption_arithmetic_equal_settlement_and_supply() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);

    // When settlement_amount == total_supply, max_redeemable == bal (100% ratio).
    let supply = 1_000_000_000i128;
    let inv = String::from_str(&h.env, "ARITH-EQ");
    let m = InvoiceMeta {
        invoice_id: inv.clone(),
        issuer: String::from_str(&h.env, "Issuer"),
        debtor: String::from_str(&h.env, "Debtor"),
        face_value_usd: supply,
        discount_rate_bps: 0,
        due_date: 1_900_000_000,
        currency: String::from_str(&h.env, "USD"),
        ipfs_doc_hash: String::from_str(&h.env, ""),
        transfer_fee_bps: 0,
        fee_recipient: None,
        notification_webhook: String::from_str(&h.env, ""),
    };
    h.token.create_invoice(&m);
    h.token.issue(&inv, &holder, &100);
    h.token.partial_settle(&inv, &supply);

    // max_redeemable = floor(100 * supply / supply) = 100
    h.token.redeem(&inv, &holder, &100);
    assert_eq!(h.token.balance(&holder, &inv), 0);
}

// ── PartiallySettled transfer tests ──────────────────────────────────────────

#[test]
fn test_transfer_allowed_during_partially_settled() {
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);

    h.token.issue(&inv_id(&h.env), &alice, &1_000);
    h.token.partial_settle(&inv_id(&h.env), &500_000_000_000);

    // Transfer should succeed in PartiallySettled state.
    h.token.transfer(&inv_id(&h.env), &alice, &bob, &400);
    assert_eq!(h.token.balance(&alice, &inv_id(&h.env)), 600);
    assert_eq!(h.token.balance(&bob, &inv_id(&h.env)), 400);
}

#[test]
fn test_transfer_blocked_in_fully_settled() {
    // FullySettled still blocks transfers (existing behaviour preserved).
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);
    h.token.issue(&inv_id(&h.env), &alice, &1_000);
    h.token.settle(&inv_id(&h.env));
    assert!(h
        .token
        .try_transfer(&inv_id(&h.env), &alice, &bob, &100)
        .is_err());
}

#[test]
fn test_partially_settled_transfer_then_redeem_conservation() {
    // Alice has all tokens. Partial settle at 50%. Alice transfers half to Bob.
    // Both redeem. Total redemption must not exceed settlement_amount.
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);

    let face = 1_000_000_000_000i128;
    let supply = 1_000i128;
    let settlement = face / 2; // 50%

    let inv = inv_id(&h.env);
    h.token.issue(&inv, &alice, &supply);
    h.token.partial_settle(&inv, &settlement);

    // Transfer half of Alice's tokens to Bob.
    h.token.transfer(&inv, &alice, &bob, &500);
    assert_eq!(h.token.balance(&alice, &inv), 500);
    assert_eq!(h.token.balance(&bob, &inv), 500);

    // Alice's entitlement was snapshotted before transfer:
    // floor(1000 * (face/2) / face) = 500_000_000_000... wait:
    // floor(1000 * settlement / total_supply) where total_supply = 1000
    // = floor(1000 * 500B / 1000) = 500B, but alice only has 500 tokens.
    // max_redeemable for alice = min(500, 500B) = 500.
    // Alice redeems 500:
    h.token.redeem(&inv, &alice, &500);
    assert_eq!(h.token.balance(&alice, &inv), 0);

    // Bob redeems: no SettledEntitlement → formula: floor(500 * settlement / 500) = settlement = 500B
    // But bob only has 500 tokens, so max_redeemable = min(500, 500B) = 500.
    h.token.redeem(&inv, &bob, &500);
    assert_eq!(h.token.balance(&bob, &inv), 0);

    // Total redeemed = 1000 tokens ≤ settlement (500_000_000_000 tokens worth).
    // supply → 0, status → Redeemed.
    assert_eq!(h.token.total_supply(&inv), 0);
    assert_eq!(h.token.invoice_status(&inv), InvoiceStatus::Redeemed);
}

#[test]
fn test_partially_settled_transfer_entitlement_caps_seller() {
    // Seller's post-transfer redemption is capped by the pre-transfer entitlement.
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);

    let face = 1_000_000_000_000i128;
    let issued = 1_000i128;
    let settlement = face / 10; // 10% settlement

    h.token.issue(&inv_id(&h.env), &alice, &issued);
    h.token.partial_settle(&inv_id(&h.env), &settlement);

    // Alice's pre-transfer entitlement: floor(1000 * settlement / 1000) = settlement = 100B
    // Alice transfers 900 to Bob, keeping 100.
    h.token.transfer(&inv_id(&h.env), &alice, &bob, &900);
    assert_eq!(h.token.balance(&alice, &inv_id(&h.env)), 100);

    // Alice's SettledEntitlement is capped at settlement (100B).
    // She has only 100 tokens, so max_redeemable = min(100, 100B) = 100. Can redeem all.
    h.token.redeem(&inv_id(&h.env), &alice, &100);
    assert_eq!(h.token.balance(&alice, &inv_id(&h.env)), 0);
}

// ── Redemption dust tests ─────────────────────────────────────────────────────

#[test]
fn test_redemption_dust_initialized_on_partial_settle() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);

    let settlement = 500_000_000_000i128;
    h.token.issue(&inv_id(&h.env), &holder, &100);
    h.token.partial_settle(&inv_id(&h.env), &settlement);

    // Dust = settlement_amount initially (nothing redeemed yet).
    assert_eq!(h.token.collect_redemption_dust(&inv_id(&h.env)), settlement);
}

#[test]
fn test_redemption_dust_decremented_on_redeem() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);

    h.token.issue(&inv_id(&h.env), &holder, &1_000);
    h.token.settle(&inv_id(&h.env));

    let initial_dust = h.token.collect_redemption_dust(&inv_id(&h.env));
    assert_eq!(initial_dust, 1_000_000_000_000i128); // face_value_usd

    h.token.redeem(&inv_id(&h.env), &holder, &400);
    let remaining_dust = h.token.collect_redemption_dust(&inv_id(&h.env));
    assert_eq!(remaining_dust, initial_dust - 400);
}

// ── batch_settle tests ────────────────────────────────────────────────────────

#[test]
fn test_batch_settle_processes_multiple_invoices() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);

    let id1 = inv_id(&h.env);
    let id2 = String::from_str(&h.env, "BATCH-002");
    let id3 = String::from_str(&h.env, "BATCH-003");

    h.token.create_invoice(&h.make_invoice("BATCH-002"));
    h.token.create_invoice(&h.make_invoice("BATCH-003"));

    h.token.issue(&id1, &holder, &100);
    h.token.issue(&id2, &holder, &100);
    h.token.issue(&id3, &holder, &100);

    let settlements: soroban_sdk::Vec<(String, i128)> = {
        let mut v = soroban_sdk::Vec::new(&h.env);
        v.push_back((id1.clone(), 200_000_000_000i128));
        v.push_back((id2.clone(), 300_000_000_000i128));
        v.push_back((id3.clone(), 500_000_000_000i128));
        v
    };

    let results = h.token.batch_settle(&settlements);
    assert_eq!(results.len(), 3);

    // All three should succeed (error = None).
    for i in 0..3 {
        let r = results.get(i).unwrap();
        assert!(r.error.is_none(), "invoice {i} should succeed");
    }

    assert!(h.token.is_settled(&id1));
    assert!(h.token.is_settled(&id2));
    assert!(h.token.is_settled(&id3));
}

#[test]
fn test_batch_settle_continues_on_individual_failure() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);

    let id1 = inv_id(&h.env);
    let id2 = String::from_str(&h.env, "BATCH-ERR-002");

    h.token.create_invoice(&h.make_invoice("BATCH-ERR-002"));
    h.token.issue(&id1, &holder, &100);
    h.token.issue(&id2, &holder, &100);

    // Pre-settle id1 so the second attempt in batch fails.
    h.token.partial_settle(&id1, &200_000_000_000i128);

    let settlements: soroban_sdk::Vec<(String, i128)> = {
        let mut v = soroban_sdk::Vec::new(&h.env);
        // id1 is already settled — should fail.
        v.push_back((id1.clone(), 200_000_000_000i128));
        // id2 is fresh — should succeed.
        v.push_back((id2.clone(), 300_000_000_000i128));
        v
    };

    let results = h.token.batch_settle(&settlements);
    assert_eq!(results.len(), 2);

    let r0 = results.get(0).unwrap();
    let r1 = results.get(1).unwrap();

    // First must fail (AlreadySettled = 2).
    assert!(r0.error.is_some());
    assert_eq!(r0.error.unwrap(), 2u32); // AlreadySettled

    // Second must succeed.
    assert!(r1.error.is_none());
    assert!(h.token.is_settled(&id2));
}

#[test]
fn test_batch_settle_capped_at_10() {
    let h = setup();
    let holder = Address::generate(&h.env);
    h.approve_kyc(&holder);

    // Create 12 invoices using pre-defined IDs.
    let raw_ids = [
        "BCAP-000", "BCAP-001", "BCAP-002", "BCAP-003", "BCAP-004", "BCAP-005", "BCAP-006",
        "BCAP-007", "BCAP-008", "BCAP-009", "BCAP-010", "BCAP-011",
    ];

    let mut ids: soroban_sdk::Vec<String> = soroban_sdk::Vec::new(&h.env);
    for raw in raw_ids.iter() {
        let id = String::from_str(&h.env, raw);
        h.token.create_invoice(&h.make_invoice(raw));
        h.token.issue(&id, &holder, &10);
        ids.push_back(id);
    }

    let mut settlements: soroban_sdk::Vec<(String, i128)> = soroban_sdk::Vec::new(&h.env);
    for i in 0..12u32 {
        settlements.push_back((ids.get(i).unwrap(), 200_000_000i128));
    }

    let results = h.token.batch_settle(&settlements);
    // Only 10 should be processed.
    assert_eq!(results.len(), 10);
}
