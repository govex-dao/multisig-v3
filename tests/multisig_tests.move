#[test_only]
module account_multisig::multisig_tests;

use std::string::String;
use account_multisig::multisig::{Self, MultisigConfig, Approvals};
use account_multisig::config;
use account_multisig::actions_staging;
use account_multisig::version;
use account_protocol::account::{Self, Account};
use account_protocol::intents;
use account_protocol::package_registry::{
    Self as package_registry,
    PackageRegistry,
    PackageAdminCap
};
use sui::coin;
use sui::clock::{Self, Clock};
use sui::event;
use sui::test_scenario::{Self as ts, Scenario};
use sui::test_utils::destroy;

// === Constants ===

const OWNER: address = @0xCAFE;
const MEMBER_A: address = @0xA;
const MEMBER_B: address = @0xB;
const MEMBER_C: address = @0xC;

// === Test-only structs ===

public struct TestAction has drop {}
public struct DirectStageIntent has copy, drop {}

// === Helpers ===

/// Creates scenario + registry with AccountMultisig registered.
fun start(): (Scenario, PackageRegistry, Clock) {
    let mut scenario = ts::begin(OWNER);
    package_registry::init_for_testing(scenario.ctx());
    scenario.next_tx(OWNER);
    let mut registry = scenario.take_shared<PackageRegistry>();
    let cap = scenario.take_from_sender<PackageAdminCap>();
    package_registry::add_for_testing(
        &mut registry,
        b"AccountMultisig".to_string(),
        @account_multisig,
        1,
    );
    let clock = clock::create_for_testing(scenario.ctx());
    destroy(cap);
    (scenario, registry, clock)
}

fun end(scenario: Scenario, registry: PackageRegistry, clock: Clock) {
    destroy(registry);
    destroy(clock);
    ts::end(scenario);
}

fun new_params_from_account(
    account: &Account,
    key: String,
    description: String,
    clock: &Clock,
    ctx: &mut TxContext,
): intents::Params {
    multisig::new_params_from_config(
        account,
        key,
        description,
        0, // execution_time_ms
        clock,
        ctx,
    )
}

/// Helper to create a config change intent on an account.
/// Uses the account's current single-group config echoed back via flat vectors.
fun create_test_intent(
    account: &mut Account,
    registry: &PackageRegistry,
    clock: &Clock,
    key: vector<u8>,
    ctx: &mut TxContext,
): String {
    let key_str = key.to_string();
    let auth = multisig::authenticate(account, ctx);
    let params = new_params_from_account(
        account,
        key_str,
        b"Test intent".to_string(),
        clock,
        ctx,
    );
    let intent_expiry_ms = {
        let config_ref: &MultisigConfig = account::config(account);
        multisig::intent_expiry_ms(config_ref)
    };
    config::request_config_change(
        auth,
        account,
        registry,
        params,
        // Groups: single group "default" with the sender
        vector[b"default".to_string()],
        vector[1], // group_member_counts
        vector[ctx.sender()], // all_member_addresses
        vector[1], // all_member_weights
        vector[0], // time_band_counts
        vector[], // all_time_band_afters
        vector[], // all_time_band_weights
        // Approve policy: 1 path, 1 requirement
        vector[1], // approve_path_req_counts
        vector[0], // all_approve_group_indices
        vector[1], // all_approve_thresholds
        // Cancel policy: 1 path, 1 requirement
        vector[1], // cancel_path_req_counts
        vector[0], // all_cancel_group_indices
        vector[1], // all_cancel_thresholds
        // Permission groups
        vector[0], // propose_groups
        vector[0], // execute_groups
        vector[0], // cancel_groups
        // Timing
        intent_expiry_ms,
        ctx,
    );
    key_str
}

/// Helper to create a non-ConfigChange intent (ActionsIntent).
/// Raw cancel functions use this to avoid config-change cleanup routing.
fun create_actions_intent(
    account: &mut Account,
    registry: &PackageRegistry,
    clock: &Clock,
    key: vector<u8>,
    ctx: &mut TxContext,
): String {
    let key_str = key.to_string();
    let auth = multisig::authenticate(account, ctx);
    let params = new_params_from_account(
        account,
        key_str,
        b"Test actions intent".to_string(),
        clock,
        ctx,
    );
    let spec = intents::new_action_spec(TestAction {}, vector[], 1);
    actions_staging::request_actions(
        auth,
        account,
        registry,
        params,
        vector[spec],
        ctx,
    );
    key_str
}

/// Create a multi-group account with OWNER in group 0, MEMBER_A and MEMBER_B in group 0.
/// Vote policy threshold = 2 on group 0. MEMBER_C is not a member.
fun create_multi_member_account(
    scenario: &mut Scenario,
    registry: &PackageRegistry,
): Account {
    let mut account = multisig::new_account_for_testing(
        registry, vector[], vector[], scenario.ctx(),
    );
    let config: &mut MultisigConfig = account::config_mut(
        &mut account, multisig::config_witness(),
    );
    // Add MEMBER_A and MEMBER_B to group 0 (default)
    multisig::add_member_to_group(config, 0, MEMBER_A, 1);
    multisig::add_member_to_group(config, 0, MEMBER_B, 1);
    // Threshold 2 on both policies so single member approval/rejection does not auto-resolve.
    multisig::set_approve_threshold(config, 2);
    multisig::set_cancel_threshold(config, 2);
    account
}

// ============================================================
// 1. test_new_account_creates_single_group
// ============================================================

#[test]
fun test_new_account_creates_single_group() {
    let (mut scenario, registry, clock) = start();

    let account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );
    let config: &MultisigConfig = account::config(&account);

    // 1 group named "default"
    assert!(multisig::group_count(config) == 1);
    let group = multisig::group_at(config, 0);
    assert!(*multisig::group_name(group) == b"default".to_string());

    // 1 member (the creator)
    let members = multisig::group_members(group);
    assert!(members.length() == 1);
    assert!(multisig::member_addr(&members[0]) == OWNER);
    assert!(multisig::member_weight(&members[0]) == 1);

    // No time bands
    assert!(multisig::group_time_bands(group).length() == 0);

    // Approve policy: 1 path with 1 requirement (group 0, threshold 1)
    let approve_paths = multisig::policy_paths(multisig::approve_policy(config));
    assert!(approve_paths.length() == 1);
    let reqs = multisig::path_requirements(&approve_paths[0]);
    assert!(reqs.length() == 1);
    assert!(multisig::requirement_group_idx(&reqs[0]) == 0);
    assert!(multisig::requirement_threshold(&reqs[0]) == 1);
    // Cancel policy defaults to the same shape as approve_policy for new accounts.
    let cancel_paths = multisig::policy_paths(multisig::cancel_policy(config));
    assert!(cancel_paths.length() == 1);
    let cancel_reqs = multisig::path_requirements(&cancel_paths[0]);
    assert!(cancel_reqs.length() == 1);
    assert!(multisig::requirement_group_idx(&cancel_reqs[0]) == 0);
    assert!(multisig::requirement_threshold(&cancel_reqs[0]) == 1);

    // propose_groups and execute_groups both [0]
    assert!(*multisig::propose_groups(config) == vector[0]);
    assert!(*multisig::execute_groups(config) == vector[0]);

    // Defaults
    assert!(multisig::config_nonce(config) == 0);
    assert!(multisig::intent_expiry_ms(config) == multisig::default_intent_expiry_ms());

    destroy(account);
    end(scenario, registry, clock);
}

// ============================================================
// 2. test_new_account_fee_payment
// ============================================================

#[test]
fun test_new_account_fee_payment() {
    let (mut scenario, registry, clock) = start();

    let mut vault = multisig::create_fee_vault_for_testing(scenario.ctx());
    let fee_amount = multisig::creation_fee(&vault);
    let payment = coin::mint_for_testing<sui::sui::SUI>(fee_amount, scenario.ctx());

    let account = multisig::new_account(
        &mut vault,
        &registry,
        payment,
        vector[],
        vector[],
        // Single group with the creator
        vector[b"default".to_string()],
        vector[1],
        vector[scenario.ctx().sender()],
        vector[1],
        vector[0],
        vector[],
        vector[],
        // Approve policy
        vector[1],
        vector[0],
        vector[1],
        // Cancel policy (explicit, not defaulted)
        vector[1],
        vector[0],
        vector[1],
        // Permission groups
        vector[0],
        vector[0],
        vector[0],
        604800000,
        scenario.ctx(),
    );

    // Fee is retained in the shared multisig fee vault for later admin sweep.
    assert!(multisig::vault_balance(&vault) == fee_amount);

    destroy(account);
    destroy(vault);
    end(scenario, registry, clock);
}

#[test]
fun test_admin_can_update_creation_fee_and_recipient() {
    let (mut scenario, registry, clock) = start();

    let mut vault = multisig::create_fee_vault_for_testing(scenario.ctx());
    let cap = multisig::create_admin_cap_for_testing(scenario.ctx());

    multisig::update_creation_fee(&cap, &mut vault, 42);
    multisig::update_fee_recipient(&cap, &mut vault, MEMBER_A);

    assert!(multisig::creation_fee(&vault) == 42);
    assert!(multisig::fee_recipient(&vault) == MEMBER_A);

    destroy(cap);
    destroy(vault);
    end(scenario, registry, clock);
}

#[test]
fun test_admin_sweep_fees_transfers_balance_to_recipient() {
    let (mut scenario, registry, clock) = start();

    let mut vault = multisig::create_fee_vault_for_testing(scenario.ctx());
    let cap = multisig::create_admin_cap_for_testing(scenario.ctx());
    let fee_amount = multisig::creation_fee(&vault);
    let payment = coin::mint_for_testing<sui::sui::SUI>(fee_amount, scenario.ctx());

    let account = multisig::new_account(
        &mut vault,
        &registry,
        payment,
        vector[],
        vector[],
        vector[b"default".to_string()],
        vector[1],
        vector[scenario.ctx().sender()],
        vector[1],
        vector[0],
        vector[],
        vector[],
        vector[1],
        vector[0],
        vector[1],
        vector[1],
        vector[0],
        vector[1],
        vector[0],
        vector[0],
        vector[0],
        604800000,
        scenario.ctx(),
    );

    multisig::update_fee_recipient(&cap, &mut vault, MEMBER_A);
    multisig::sweep_fees(&cap, &mut vault, scenario.ctx());

    assert!(multisig::vault_balance(&vault) == 0);

    scenario.next_tx(MEMBER_A);
    {
        let swept = scenario.take_from_sender<coin::Coin<sui::sui::SUI>>();
        assert!(coin::value(&swept) == fee_amount);
        destroy(swept);
    };

    destroy(account);
    destroy(cap);
    destroy(vault);
    end(scenario, registry, clock);
}

// ============================================================
// 3. test_new_account_insufficient_fee_aborts
// ============================================================

#[test]
#[expected_failure(abort_code = multisig::EInsufficientFee)]
fun test_new_account_insufficient_fee_aborts() {
    let (mut scenario, registry, clock) = start();

    let mut vault = multisig::create_fee_vault_for_testing(scenario.ctx());
    // Pay 1 MIST less than required
    let payment = coin::mint_for_testing<sui::sui::SUI>(
        multisig::creation_fee(&vault) - 1,
        scenario.ctx(),
    );

    let account = multisig::new_account(
        &mut vault,
        &registry,
        payment,
        vector[],
        vector[],
        vector[b"default".to_string()],
        vector[1],
        vector[scenario.ctx().sender()],
        vector[1],
        vector[0],
        vector[],
        vector[],
        vector[1],
        vector[0],
        vector[1],
        vector[1],
        vector[0],
        vector[1],
        vector[0],
        vector[0],
        vector[0],
        604800000,
        scenario.ctx(),
    );

    destroy(account);
    destroy(vault);
    end(scenario, registry, clock);
}

// ============================================================
// 4. test_authenticate_proposer_succeeds
// ============================================================

#[test]
fun test_authenticate_proposer_succeeds() {
    let (mut scenario, registry, clock) = start();
    let account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    let auth = multisig::authenticate(&account, scenario.ctx());
    account.verify(auth);

    destroy(account);
    end(scenario, registry, clock);
}

// ============================================================
// 5. test_authenticate_non_member_aborts
// ============================================================

#[test]
#[expected_failure(abort_code = multisig::ECallerIsNotMember)]
fun test_authenticate_non_member_aborts() {
    let (mut scenario, registry, clock) = start();
    let account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    scenario.next_tx(MEMBER_A);
    let auth = multisig::authenticate(&account, scenario.ctx());

    account.verify(auth);
    destroy(account);
    end(scenario, registry, clock);
}

// ============================================================
// 6. test_approve_single_member_auto_approves
// ============================================================

#[test]
fun test_approve_single_member_auto_approves() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    let key = create_test_intent(
        &mut account, &registry, &clock, b"auto_approve", scenario.ctx(),
    );
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());

    let intent = account.intents().get<Approvals>(key);
    let outcome = intents::outcome(intent);
    assert!(multisig::outcome_status(outcome) == multisig::status_approved());
    assert!(multisig::approved(outcome).length() == 1);
    assert!(multisig::matched_vote_path(outcome).is_some());
    assert!(*multisig::matched_vote_path(outcome).borrow() == 0);

    destroy(account);
    end(scenario, registry, clock);
}

// ============================================================
// 7. test_approve_two_member_threshold
// ============================================================

#[test]
fun test_approve_two_member_threshold() {
    let (mut scenario, registry, clock) = start();
    let mut account = create_multi_member_account(&mut scenario, &registry);

    let key = create_test_intent(
        &mut account, &registry, &clock, b"two_member", scenario.ctx(),
    );

    // First approval: OWNER (weight 1), threshold 2 -- still ACTIVE
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    {
        let intent = account.intents().get<Approvals>(key);
        let outcome = intents::outcome(intent);
        assert!(multisig::outcome_status(outcome) == multisig::status_active());
    };

    // Second approval: MEMBER_A (weight 1), total weight 2 >= threshold 2
    scenario.next_tx(MEMBER_A);
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    {
        let intent = account.intents().get<Approvals>(key);
        let outcome = intents::outcome(intent);
        assert!(multisig::outcome_status(outcome) == multisig::status_approved());
        assert!(multisig::approved(outcome).length() == 2);
    };

    destroy(account);
    end(scenario, registry, clock);
}

// ============================================================
// 8. test_approve_with_time_band_after_delay
// ============================================================

#[test]
fun test_approve_with_time_band_after_delay() {
    let (mut scenario, registry, mut clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    // Configure: single group with OWNER weight=1, time band at 1000ms giving weight 1.
    // Vote policy: threshold 2 on group 0. So OWNER's weight 1 alone is not enough,
    // but after 1000ms, time band adds 1, making effective weight = 2.
    let config: &mut MultisigConfig = account::config_mut(
        &mut account, multisig::config_witness(),
    );
    multisig::set_groups(config, vector[
        multisig::new_group(
            b"default".to_string(),
            vector[multisig::new_group_member(OWNER, 1)],
            vector[multisig::new_time_band(1000, 1)],
        ),
    ]);
    multisig::set_approve_threshold(config, 2);
    multisig::set_cancel_threshold(config, 2);

    let key = create_test_intent(
        &mut account, &registry, &clock, b"time_band", scenario.ctx(),
    );

    // Approve at t=0: weight 1, no time band yet, still ACTIVE
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    {
        let intent = account.intents().get<Approvals>(key);
        let outcome = intents::outcome(intent);
        assert!(multisig::outcome_status(outcome) == multisig::status_active());
    };

    // Advance clock by 1000ms, then re-approve is not needed since the vote is already in.
    // We need a second member to trigger re-evaluation, OR we can use a second vote.
    // Actually, the check happens on each approve_intent call. Let's add MEMBER_A to the
    // group so we can trigger re-evaluation.
    // But config_mut requires non-initialized account. Let's restructure.
    // Actually since we set up the account before sharing, config_mut works.

    // We already approved as OWNER. Now advance time and have a no-weight member approve
    // to trigger path check. But the time band check uses elapsed_ms from the *intent
    // creation time*. So let's add MEMBER_A with weight 0... no, weight must be > 0.
    // Instead, let's just make the threshold achievable with 1 member + time band.
    // Actually, we already set threshold=2 and OWNER has weight=1 + time_band=1 after 1s.
    // The problem is approve_intent checks on each vote. OWNER already approved.
    // We need another vote to trigger re-evaluation. Let's disapprove and re-approve.

    // Disapprove first (only allowed in ACTIVE state)
    multisig::disapprove_intent(&mut account, key, scenario.ctx());

    // Advance clock
    clock::increment_for_testing(&mut clock, 1000);

    // Re-approve: now elapsed >= 1000ms, effective weight = 1 (member) + 1 (time band) = 2
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    {
        let intent = account.intents().get<Approvals>(key);
        let outcome = intents::outcome(intent);
        assert!(multisig::outcome_status(outcome) == multisig::status_approved());
    };

    destroy(account);
    end(scenario, registry, clock);
}

// ============================================================
// 9. test_approve_time_band_highest_qualifies
// ============================================================

#[test]
fun test_approve_time_band_highest_qualifies() {
    let (mut scenario, registry, mut clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    // Group with OWNER weight=1, time bands: {after 500ms: weight 2}, {after 1000ms: weight 5}
    // Threshold = 4. At t=500, effective = 1 + 2 = 3 (not enough).
    // At t=1000, effective = 1 + 5 = 6 (enough).
    let config: &mut MultisigConfig = account::config_mut(
        &mut account, multisig::config_witness(),
    );
    multisig::set_groups(config, vector[
        multisig::new_group(
            b"default".to_string(),
            vector[multisig::new_group_member(OWNER, 1)],
            vector[
                multisig::new_time_band(500, 2),
                multisig::new_time_band(1000, 5),
            ],
        ),
    ]);
    multisig::set_approve_threshold(config, 4);
    multisig::set_cancel_threshold(config, 4);

    let key = create_test_intent(
        &mut account, &registry, &clock, b"highest_band", scenario.ctx(),
    );

    // Approve at t=0 -> effective = 1, ACTIVE
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    {
        let outcome = intents::outcome(account.intents().get<Approvals>(key));
        assert!(multisig::outcome_status(outcome) == multisig::status_active());
    };

    // Advance 500ms, disapprove+re-approve -> effective = 1+2 = 3, still ACTIVE
    clock::increment_for_testing(&mut clock, 500);
    multisig::disapprove_intent(&mut account, key, scenario.ctx());
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    {
        let outcome = intents::outcome(account.intents().get<Approvals>(key));
        assert!(multisig::outcome_status(outcome) == multisig::status_active());
    };

    // Advance to 1000ms total, disapprove+re-approve -> effective = 1+5 = 6, APPROVED
    clock::increment_for_testing(&mut clock, 500);
    multisig::disapprove_intent(&mut account, key, scenario.ctx());
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    {
        let outcome = intents::outcome(account.intents().get<Approvals>(key));
        assert!(multisig::outcome_status(outcome) == multisig::status_approved());
    };

    destroy(account);
    end(scenario, registry, clock);
}

// ============================================================
// 10. test_reject_terminal_when_no_path_satisfiable
// ============================================================

#[test]
fun test_reject_terminal_when_no_path_satisfiable() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    // Single member, threshold 1. If that member rejects, no path can be satisfied.
    let key = create_test_intent(
        &mut account, &registry, &clock, b"reject_terminal", scenario.ctx(),
    );

    multisig::reject_intent(&mut account, key, &clock, scenario.ctx());

    let intent = account.intents().get<Approvals>(key);
    let outcome = intents::outcome(intent);
    assert!(multisig::outcome_status(outcome) == multisig::status_rejected());
    assert!(multisig::rejected(outcome).length() == 1);

    destroy(account);
    end(scenario, registry, clock);
}

// ============================================================
// 11. test_reject_not_terminal_when_path_still_possible
// ============================================================

#[test]
fun test_reject_not_terminal_when_path_still_possible() {
    let (mut scenario, registry, clock) = start();
    let mut account = create_multi_member_account(&mut scenario, &registry);

    // 3 members (OWNER, MEMBER_A, MEMBER_B) with weight 1 each, threshold 2.
    // If OWNER rejects, MEMBER_A + MEMBER_B can still reach threshold 2.
    let key = create_test_intent(
        &mut account, &registry, &clock, b"reject_not_terminal", scenario.ctx(),
    );

    multisig::reject_intent(&mut account, key, &clock, scenario.ctx());

    let intent = account.intents().get<Approvals>(key);
    let outcome = intents::outcome(intent);
    assert!(multisig::outcome_status(outcome) == multisig::status_active());
    assert!(multisig::rejected(outcome).length() == 1);

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
fun test_vote_against_unlocks_cancel_even_when_time_band_can_later_approve() {
    let (mut scenario, registry, mut clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    let config: &mut MultisigConfig = account::config_mut(
        &mut account, multisig::config_witness(),
    );
    multisig::set_groups(config, vector[
        multisig::new_group(
            b"members".to_string(),
            vector[
                multisig::new_group_member(OWNER, 1),
                multisig::new_group_member(MEMBER_A, 1),
                multisig::new_group_member(MEMBER_B, 1),
                multisig::new_group_member(MEMBER_C, 1),
            ],
            vector[multisig::new_time_band(7_776_000_000, 2)], // 90 days
        ),
        multisig::new_group(
            b"cancellers".to_string(),
            vector[multisig::new_group_member(OWNER, 1)],
            vector[],
        ),
    ]);
    multisig::set_approve_policy(config, multisig::new_role_policy(vector[
        multisig::new_policy_path(vector[
            multisig::new_path_requirement(0, 3),
        ]),
    ]));
    multisig::set_cancel_policy(config, multisig::new_role_policy(vector[
        multisig::new_policy_path(vector[
            multisig::new_path_requirement(0, 3),
        ]),
    ]));
    multisig::set_propose_groups(config, vector[0]);
    multisig::set_execute_groups(config, vector[0]);
    multisig::set_cancel_groups(config, vector[1]);
    multisig::set_intent_expiry_for_testing(config, 8_640_000_000); // 100 days

    let key = create_actions_intent(
        &mut account, &registry, &clock, b"against_unlocks_cancel", scenario.ctx(),
    );

    // 1/4 for is not enough now, but would become enough after the 90-day band.
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());

    scenario.next_tx(MEMBER_A);
    multisig::reject_intent(&mut account, key, &clock, scenario.ctx());
    scenario.next_tx(MEMBER_B);
    multisig::reject_intent(&mut account, key, &clock, scenario.ctx());
    scenario.next_tx(MEMBER_C);
    multisig::reject_intent(&mut account, key, &clock, scenario.ctx());

    {
        let outcome = intents::outcome(account.intents().get<Approvals>(key));
        assert!(multisig::outcome_status(outcome) == multisig::status_rejected());
        assert!(multisig::approved(outcome).length() == 1);
        assert!(multisig::rejected(outcome).length() == 3);
    };

    // The delayed approval path would now be numerically satisfied, but the
    // against threshold has already made the intent cancelable instead.
    clock::increment_for_testing(&mut clock, 7_776_000_001);
    {
        let outcome = intents::outcome(account.intents().get<Approvals>(key));
        assert!(multisig::outcome_status(outcome) == multisig::status_rejected());
    };

    scenario.next_tx(OWNER);
    let expired = multisig::cancel_rejected_intent(&mut account, key, scenario.ctx());
    intents::drain_and_destroy_expired(expired);
    assert!(!account.intents().contains(key));

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
#[expected_failure(abort_code = multisig::EInvalidIntentStatus)]
fun test_cancel_pending_active_intent_reject_time_band_does_not_mature() {
    let (mut scenario, registry, mut clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    let config: &mut MultisigConfig = account::config_mut(
        &mut account, multisig::config_witness(),
    );
    multisig::set_groups(config, vector[
        multisig::new_group(
            b"members".to_string(),
            vector[
                multisig::new_group_member(OWNER, 1),
                multisig::new_group_member(MEMBER_A, 1),
                multisig::new_group_member(MEMBER_B, 1),
                multisig::new_group_member(MEMBER_C, 1),
            ],
            vector[multisig::new_time_band(7_776_000_000, 2)], // 90 days
        ),
        multisig::new_group(
            b"cancellers".to_string(),
            vector[multisig::new_group_member(OWNER, 1)],
            vector[],
        ),
    ]);
    multisig::set_approve_policy(config, multisig::new_role_policy(vector[
        multisig::new_policy_path(vector[
            multisig::new_path_requirement(0, 3),
        ]),
    ]));
    multisig::set_cancel_policy(config, multisig::new_role_policy(vector[
        multisig::new_policy_path(vector[
            multisig::new_path_requirement(0, 3),
        ]),
    ]));
    multisig::set_propose_groups(config, vector[0]);
    multisig::set_execute_groups(config, vector[0]);
    multisig::set_cancel_groups(config, vector[1]);
    multisig::set_intent_expiry_for_testing(config, 8_640_000_000); // 100 days

    let key = create_actions_intent(
        &mut account, &registry, &clock, b"reject_time_matures", scenario.ctx(),
    );

    scenario.next_tx(MEMBER_A);
    multisig::reject_intent(&mut account, key, &clock, scenario.ctx());
    {
        let outcome = intents::outcome(account.intents().get<Approvals>(key));
        assert!(multisig::outcome_status(outcome) == multisig::status_active());
        assert!(multisig::rejected(outcome).length() == 1);
    };

    clock::increment_for_testing(&mut clock, 7_776_000_001);

    scenario.next_tx(OWNER);
    let _expired = multisig::cancel_pending_intent(
        &mut account, key, &clock, scenario.ctx(),
    );
    destroy(_expired);
    abort 0
}

// ============================================================
// 12. test_vote_switch_approve_to_reject
// ============================================================

#[test]
fun test_vote_switch_approve_to_reject() {
    let (mut scenario, registry, clock) = start();
    let mut account = create_multi_member_account(&mut scenario, &registry);

    let key = create_test_intent(
        &mut account, &registry, &clock, b"switch_a_to_r", scenario.ctx(),
    );

    // OWNER approves
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    {
        let outcome = intents::outcome(account.intents().get<Approvals>(key));
        assert!(multisig::approved(outcome).length() == 1);
        assert!(multisig::rejected(outcome).length() == 0);
    };

    // OWNER switches to reject (clears approval, adds rejection)
    multisig::reject_intent(&mut account, key, &clock, scenario.ctx());
    {
        let outcome = intents::outcome(account.intents().get<Approvals>(key));
        assert!(multisig::approved(outcome).length() == 0);
        assert!(multisig::rejected(outcome).length() == 1);
    };

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
fun test_reject_approved_intent_can_downgrade_to_active() {
    let (mut scenario, registry, clock) = start();
    let mut account = create_multi_member_account(&mut scenario, &registry);

    let key = create_actions_intent(
        &mut account, &registry, &clock, b"approved_reject_downgrade", scenario.ctx(),
    );

    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    scenario.next_tx(MEMBER_A);
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    {
        let outcome = intents::outcome(account.intents().get<Approvals>(key));
        assert!(multisig::outcome_status(outcome) == multisig::status_approved());
    };

    scenario.next_tx(OWNER);
    multisig::reject_intent(&mut account, key, &clock, scenario.ctx());
    {
        let outcome = intents::outcome(account.intents().get<Approvals>(key));
        assert!(multisig::outcome_status(outcome) == multisig::status_active());
        assert!(multisig::approved(outcome).length() == 1);
        assert!(multisig::rejected(outcome).length() == 1);
    };

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
fun test_reject_approved_intent_can_unlock_cancel() {
    let (mut scenario, registry, clock) = start();
    let mut account = create_multi_member_account(&mut scenario, &registry);

    let key = create_actions_intent(
        &mut account, &registry, &clock, b"approved_reject_unlock", scenario.ctx(),
    );

    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    scenario.next_tx(MEMBER_A);
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());

    scenario.next_tx(MEMBER_B);
    multisig::reject_intent(&mut account, key, &clock, scenario.ctx());
    {
        let outcome = intents::outcome(account.intents().get<Approvals>(key));
        assert!(multisig::outcome_status(outcome) == multisig::status_approved());
        assert!(multisig::rejected(outcome).length() == 1);
    };

    scenario.next_tx(OWNER);
    multisig::reject_intent(&mut account, key, &clock, scenario.ctx());
    {
        let outcome = intents::outcome(account.intents().get<Approvals>(key));
        assert!(multisig::outcome_status(outcome) == multisig::status_rejected());
        assert!(multisig::approved(outcome).length() == 1);
        assert!(multisig::rejected(outcome).length() == 2);
    };

    destroy(account);
    end(scenario, registry, clock);
}

// ============================================================
// 13. test_vote_switch_reject_to_approve
// ============================================================

#[test]
fun test_vote_switch_reject_to_approve() {
    let (mut scenario, registry, clock) = start();
    let mut account = create_multi_member_account(&mut scenario, &registry);

    let key = create_test_intent(
        &mut account, &registry, &clock, b"switch_r_to_a", scenario.ctx(),
    );

    // OWNER rejects
    multisig::reject_intent(&mut account, key, &clock, scenario.ctx());
    {
        let outcome = intents::outcome(account.intents().get<Approvals>(key));
        assert!(multisig::rejected(outcome).length() == 1);
        assert!(multisig::approved(outcome).length() == 0);
    };

    // OWNER switches to approve (clears rejection, adds approval)
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    {
        let outcome = intents::outcome(account.intents().get<Approvals>(key));
        assert!(multisig::rejected(outcome).length() == 0);
        assert!(multisig::approved(outcome).length() == 1);
    };

    destroy(account);
    end(scenario, registry, clock);
}

// ============================================================
// 14. test_disapprove_removes_approval
// ============================================================

#[test]
fun test_disapprove_removes_approval() {
    let (mut scenario, registry, clock) = start();
    let mut account = create_multi_member_account(&mut scenario, &registry);

    let key = create_test_intent(
        &mut account, &registry, &clock, b"disapprove", scenario.ctx(),
    );

    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    {
        let outcome = intents::outcome(account.intents().get<Approvals>(key));
        assert!(multisig::approved(outcome).length() == 1);
    };

    multisig::disapprove_intent(&mut account, key, scenario.ctx());
    {
        let outcome = intents::outcome(account.intents().get<Approvals>(key));
        assert!(multisig::approved(outcome).length() == 0);
    };

    destroy(account);
    end(scenario, registry, clock);
}

// ============================================================
// 15. test_execute_approved_intent
// ============================================================

#[test]
fun test_execute_approved_intent() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    let key = create_test_intent(
        &mut account, &registry, &clock, b"exec_test", scenario.ctx(),
    );
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());

    let mut executable = multisig::execute_intent(
        &mut account, &registry, key, &clock, scenario.ctx(),
    );
    config::execute_config_change(&mut executable, &mut account, &registry);
    account.confirm_execution(executable);

    // Config nonce should have been bumped
    let config: &MultisigConfig = account::config(&account);
    assert!(multisig::config_nonce(config) == 1);

    destroy(account);
    end(scenario, registry, clock);
}

// ============================================================
// 18. test_cancel_pending_intent
// ============================================================

#[test]
fun test_cancel_pending_intent() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    // Use actions intent so raw cancel works (no managed config data)
    let key = create_actions_intent(
        &mut account, &registry, &clock, b"pending_cancel", scenario.ctx(),
    );
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());

    // Cancel requires cancel_policy to be met. With threshold 1, OWNER rejecting
    // (vote-switch clears prior approval) raises reject weight to 1 → status REJECTED.
    multisig::reject_intent(&mut account, key, &clock, scenario.ctx());

    let expired = multisig::cancel_pending_intent(
        &mut account, key, &clock, scenario.ctx(),
    );
    intents::drain_and_destroy_expired(expired);

    let events = event::events_by_type<multisig::IntentCancelledEvent>();
    assert!(events.length() == 1);
    let emitted = &events[0];
    assert!(multisig::intent_cancelled_event_account_addr(emitted) == account.addr());
    assert!(multisig::intent_cancelled_event_key(emitted) == key);
    assert!(multisig::intent_cancelled_event_canceller(emitted) == OWNER);
    assert!(multisig::intent_cancelled_event_reason(emitted) == multisig::cancel_reason_pending());

    destroy(account);
    end(scenario, registry, clock);
}

// ============================================================
// 19. test_cancel_stale_intent
// ============================================================

#[test]
fun test_cancel_stale_intent() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    let key = create_actions_intent(
        &mut account, &registry, &clock, b"stale_test", scenario.ctx(),
    );

    // Bump config nonce to make intent stale
    let config: &mut MultisigConfig = account::config_mut(
        &mut account, multisig::config_witness(),
    );
    multisig::set_config_nonce_for_testing(config, 1);

    let expired = multisig::cancel_stale_intent(&mut account, key, scenario.ctx());
    intents::drain_and_destroy_expired(expired);

    destroy(account);
    end(scenario, registry, clock);
}

// ============================================================
// 20. test_cancel_rejected_intent
// ============================================================

#[test]
fun test_cancel_rejected_intent() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    let key = create_actions_intent(
        &mut account, &registry, &clock, b"rejected_cancel", scenario.ctx(),
    );

    // Single member rejects -> terminal rejection
    multisig::reject_intent(&mut account, key, &clock, scenario.ctx());
    {
        let outcome = intents::outcome(account.intents().get<Approvals>(key));
        assert!(multisig::outcome_status(outcome) == multisig::status_rejected());
    };

    let expired = multisig::cancel_rejected_intent(&mut account, key, scenario.ctx());
    intents::drain_and_destroy_expired(expired);

    destroy(account);
    end(scenario, registry, clock);
}

// ============================================================
// 21. test_cancel_expired_intent
// ============================================================

#[test]
fun test_cancel_expired_intent() {
    let (mut scenario, registry, mut clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    // Set very short expiry for testing
    let config: &mut MultisigConfig = account::config_mut(
        &mut account, multisig::config_witness(),
    );
    multisig::set_intent_expiry_for_testing(config, 1);

    let key = create_actions_intent(
        &mut account, &registry, &clock, b"expired_cleanup", scenario.ctx(),
    );

    // Advance past expiry
    clock::increment_for_testing(&mut clock, 2);

    let expired = multisig::cancel_expired_intent(
        &mut account, key, &clock, scenario.ctx(),
    );
    intents::drain_and_destroy_expired(expired);

    destroy(account);
    end(scenario, registry, clock);
}

// ============================================================
// 22. test_config_validation_empty_groups_aborts
// ============================================================

#[test]
#[expected_failure(abort_code = multisig::EEmptyGroups)]
fun test_config_validation_empty_groups_aborts() {
    let _config = multisig::new_config(
        vector[], // empty groups
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
            ]),
        ]),
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
            ]),
        ]),
        vector[0],
        vector[0],
        vector[0],
        604800000,
    );
}

// ============================================================
// 23. test_config_validation_empty_vote_policy_aborts
// ============================================================

#[test]
#[expected_failure(abort_code = multisig::EEmptyVotePolicy)]
fun test_config_validation_empty_vote_policy_aborts() {
    let _config = multisig::new_config(
        vector[
            multisig::new_group(
                b"default".to_string(),
                vector[multisig::new_group_member(MEMBER_A, 1)],
                vector[],
            ),
        ],
        multisig::new_role_policy(vector[]), // empty approve policy
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
            ]),
        ]),
        vector[0],
        vector[0],
        vector[0],
        604800000,
    );
}

#[test]
#[expected_failure(abort_code = multisig::EEmptyPolicyPath)]
fun test_config_validation_empty_policy_path_aborts() {
    let _config = multisig::new_config(
        vector[
            multisig::new_group(
                b"default".to_string(),
                vector[multisig::new_group_member(MEMBER_A, 1)],
                vector[],
            ),
        ],
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[]),
        ]),
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
            ]),
        ]),
        vector[0],
        vector[0],
        vector[0],
        604800000,
    );
}

#[test]
#[expected_failure(abort_code = multisig::EZeroPathThreshold)]
fun test_config_validation_zero_path_threshold_aborts() {
    let _config = multisig::new_config(
        vector[
            multisig::new_group(
                b"default".to_string(),
                vector[multisig::new_group_member(MEMBER_A, 1)],
                vector[],
            ),
        ],
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 0),
            ]),
        ]),
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
            ]),
        ]),
        vector[0],
        vector[0],
        vector[0],
        604800000,
    );
}

#[test]
#[expected_failure(abort_code = multisig::EEmptyGroups)]
fun test_config_validation_too_many_groups_aborts() {
    let mut groups = vector[];
    let mut i = 0;
    while (i < multisig::max_groups() + 1) {
        groups.push_back(multisig::new_group(
            b"group".to_string(),
            vector[multisig::new_group_member(MEMBER_A, 1)],
            vector[],
        ));
        i = i + 1;
    };

    let _config = multisig::new_config(
        groups,
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
            ]),
        ]),
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
            ]),
        ]),
        vector[0],
        vector[0],
        vector[0],
        604800000,
    );
}

#[test]
#[expected_failure(abort_code = multisig::EEmptyVotePolicy)]
fun test_config_validation_too_many_policy_paths_aborts() {
    let mut paths = vector[];
    let mut i = 0;
    while (i < multisig::max_paths() + 1) {
        paths.push_back(multisig::new_policy_path(vector[
            multisig::new_path_requirement(0, 1),
        ]));
        i = i + 1;
    };

    let _config = multisig::new_config(
        vector[
            multisig::new_group(
                b"default".to_string(),
                vector[multisig::new_group_member(MEMBER_A, 1)],
                vector[],
            ),
        ],
        multisig::new_role_policy(paths),
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
            ]),
        ]),
        vector[0],
        vector[0],
        vector[0],
        604800000,
    );
}

#[test]
#[expected_failure(abort_code = multisig::ETimeBandsNotSorted)]
fun test_config_validation_too_many_time_bands_aborts() {
    let mut bands = vector[];
    let mut i = 0;
    while (i < multisig::max_time_bands() + 1) {
        bands.push_back(multisig::new_time_band(i + 1, i + 1));
        i = i + 1;
    };

    let _config = multisig::new_config(
        vector[
            multisig::new_group(
                b"default".to_string(),
                vector[multisig::new_group_member(MEMBER_A, 1)],
                bands,
            ),
        ],
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
            ]),
        ]),
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
            ]),
        ]),
        vector[0],
        vector[0],
        vector[0],
        604800000,
    );
}

// ============================================================
// 24. test_config_validation_invalid_group_index_aborts
// ============================================================

#[test]
#[expected_failure(abort_code = multisig::EInvalidGroupIndex)]
fun test_config_validation_invalid_group_index_aborts() {
    // Approve policy references group index 1 but only 1 group (index 0) exists
    let _config = multisig::new_config(
        vector[
            multisig::new_group(
                b"default".to_string(),
                vector[multisig::new_group_member(MEMBER_A, 1)],
                vector[],
            ),
        ],
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(1, 1), // invalid index
            ]),
        ]),
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
            ]),
        ]),
        vector[0],
        vector[0],
        vector[0],
        604800000,
    );
}

// ============================================================
// 25. test_config_validation_duplicate_address_in_group_aborts
// ============================================================

#[test]
#[expected_failure(abort_code = multisig::EDuplicateAddressInGroup)]
fun test_config_validation_duplicate_address_in_group_aborts() {
    let _config = multisig::new_config(
        vector[
            multisig::new_group(
                b"default".to_string(),
                vector[
                    multisig::new_group_member(MEMBER_A, 1),
                    multisig::new_group_member(MEMBER_A, 2), // duplicate
                ],
                vector[],
            ),
        ],
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
            ]),
        ]),
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
            ]),
        ]),
        vector[0],
        vector[0],
        vector[0],
        604800000,
    );
}

// ============================================================
// 26. test_config_validation_zero_weight_aborts
// ============================================================

#[test]
#[expected_failure(abort_code = multisig::EZeroMemberWeight)]
fun test_config_validation_zero_weight_aborts() {
    let _config = multisig::new_config(
        vector[
            multisig::new_group(
                b"default".to_string(),
                vector[multisig::new_group_member(MEMBER_A, 0)], // zero weight
                vector[],
            ),
        ],
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
            ]),
        ]),
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
            ]),
        ]),
        vector[0],
        vector[0],
        vector[0],
        604800000,
    );
}

// ============================================================
// 27. test_config_validation_unsorted_time_bands_aborts
// ============================================================

#[test]
#[expected_failure(abort_code = multisig::ETimeBandsNotSorted)]
fun test_config_validation_unsorted_time_bands_aborts() {
    let _config = multisig::new_config(
        vector[
            multisig::new_group(
                b"default".to_string(),
                vector[multisig::new_group_member(MEMBER_A, 1)],
                vector[
                    multisig::new_time_band(1000, 5),
                    multisig::new_time_band(500, 3), // out of order
                ],
            ),
        ],
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
            ]),
        ]),
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
            ]),
        ]),
        vector[0],
        vector[0],
        vector[0],
        604800000,
    );
}

// ============================================================
// 28. test_config_validation_unsatisfiable_path_aborts
// ============================================================

#[test]
#[expected_failure(abort_code = multisig::EUnsatisfiablePath)]
fun test_config_validation_unsatisfiable_path_aborts() {
    // Group has 1 member with weight 1, but path requires threshold 100
    let _config = multisig::new_config(
        vector[
            multisig::new_group(
                b"default".to_string(),
                vector[multisig::new_group_member(MEMBER_A, 1)],
                vector[],
            ),
        ],
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 100), // unsatisfiable
            ]),
        ]),
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
            ]),
        ]),
        vector[0],
        vector[0],
        vector[0],
        604800000,
    );
}

#[test]
#[expected_failure(abort_code = multisig::EUnsatisfiablePath)]
fun test_config_validation_time_band_cannot_satisfy_without_members() {
    let _config = multisig::new_config(
        vector[
            multisig::new_group(
                b"members".to_string(),
                vector[multisig::new_group_member(MEMBER_A, 1)],
                vector[],
            ),
            multisig::new_group(
                b"time_only".to_string(),
                vector[],
                vector[multisig::new_time_band(1000, 5)],
            ),
        ],
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(1, 5),
            ]),
        ]),
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
            ]),
        ]),
        vector[0],
        vector[0],
        vector[0],
        604800000,
    );
}

// ============================================================
// 29. test_config_change_full_flow
// ============================================================

#[test]
fun test_config_change_full_flow() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    // Propose a config change that adds MEMBER_A to the group
    let key_str = b"config_change".to_string();
    let auth = multisig::authenticate(&account, scenario.ctx());
    let params = new_params_from_account(
        &account,
        key_str,
        b"Add member A".to_string(),
        &clock,
        scenario.ctx(),
    );
    config::request_config_change(
        auth,
        &mut account,
        &registry,
        params,
        // New groups: single group with OWNER + MEMBER_A
        vector[b"founders".to_string()],
        vector[2], // 2 members
        vector[OWNER, MEMBER_A],
        vector[1, 1],
        vector[0], // no time bands
        vector[],
        vector[],
        // Approve policy: threshold 1
        vector[1],
        vector[0],
        vector[1],
        // Cancel policy: threshold 1
        vector[1],
        vector[0],
        vector[1],
        // Permission groups
        vector[0],
        vector[0],
        vector[0],
        // Timing
        604800000,
        scenario.ctx(),
    );

    // Approve
    multisig::approve_intent(&mut account, key_str, &clock, scenario.ctx());

    // Execute
    let mut executable = multisig::execute_intent(
        &mut account, &registry, key_str, &clock, scenario.ctx(),
    );
    config::execute_config_change(&mut executable, &mut account, &registry);
    account.confirm_execution(executable);

    // Verify new config
    let config: &MultisigConfig = account::config(&account);
    assert!(multisig::config_nonce(config) == 1);
    assert!(multisig::group_count(config) == 1);
    let group = multisig::group_at(config, 0);
    assert!(*multisig::group_name(group) == b"founders".to_string());
    assert!(multisig::group_members(group).length() == 2);
    assert!(multisig::is_member_of_any_group(config, MEMBER_A));

    destroy(account);
    end(scenario, registry, clock);
}

// ============================================================
// Additional regression / edge case tests
// ============================================================

#[test]
#[expected_failure(abort_code = multisig::EAlreadyApproved)]
fun test_approve_twice_fails() {
    let (mut scenario, registry, clock) = start();
    let mut account = create_multi_member_account(&mut scenario, &registry);

    let key = create_test_intent(
        &mut account, &registry, &clock, b"approve_twice", scenario.ctx(),
    );

    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx()); // should fail

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
#[expected_failure(abort_code = multisig::EAlreadyRejected)]
fun test_reject_twice_fails() {
    let (mut scenario, registry, clock) = start();
    let mut account = create_multi_member_account(&mut scenario, &registry);

    let key = create_test_intent(
        &mut account, &registry, &clock, b"reject_twice", scenario.ctx(),
    );

    multisig::reject_intent(&mut account, key, &clock, scenario.ctx());
    multisig::reject_intent(&mut account, key, &clock, scenario.ctx()); // should fail

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
#[expected_failure(abort_code = multisig::ENotApproved)]
fun test_disapprove_without_approval_fails() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    let key = create_test_intent(
        &mut account, &registry, &clock, b"disapprove_none", scenario.ctx(),
    );

    multisig::disapprove_intent(&mut account, key, scenario.ctx());

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
#[expected_failure(abort_code = multisig::ECallerIsNotMember)]
fun test_approve_non_member_fails() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    let key = create_test_intent(
        &mut account, &registry, &clock, b"non_member_approve", scenario.ctx(),
    );

    scenario.next_tx(MEMBER_A);
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
#[expected_failure(abort_code = multisig::ECallerIsNotMember)]
fun test_execute_non_member_fails() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    let key = create_test_intent(
        &mut account, &registry, &clock, b"exec_non_member", scenario.ctx(),
    );
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());

    scenario.next_tx(MEMBER_A);
    let executable = multisig::execute_intent(
        &mut account, &registry, key, &clock, scenario.ctx(),
    );
    destroy(executable);

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
#[expected_failure(abort_code = multisig::ENotInExecutorGroup)]
fun test_execute_without_execute_group_fails() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    // Add MEMBER_A to group 0 (proposer+voter) but set execute_groups to empty group 1
    let config: &mut MultisigConfig = account::config_mut(
        &mut account, multisig::config_witness(),
    );
    multisig::add_member_to_group(config, 0, MEMBER_A, 1);
    // Add a second group for executors only (just OWNER)
    let new_groups = vector[
        multisig::new_group(
            b"default".to_string(),
            vector[
                multisig::new_group_member(OWNER, 1),
                multisig::new_group_member(MEMBER_A, 1),
            ],
            vector[],
        ),
        multisig::new_group(
            b"executors".to_string(),
            vector[multisig::new_group_member(OWNER, 1)],
            vector[],
        ),
    ];
    multisig::set_groups(config, new_groups);
    multisig::set_execute_groups(config, vector[1]); // only group 1 can execute

    let key = create_test_intent(
        &mut account, &registry, &clock, b"no_exec_group", scenario.ctx(),
    );
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());

    // MEMBER_A is in group 0 but not in execute_groups=[1]
    scenario.next_tx(MEMBER_A);
    let executable = multisig::execute_intent(
        &mut account, &registry, key, &clock, scenario.ctx(),
    );
    destroy(executable);

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
#[expected_failure(abort_code = multisig::ENotInProposerGroup)]
fun test_authenticate_non_proposer_group_aborts() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    // Set up two groups: group 0 with OWNER, group 1 with MEMBER_A.
    // propose_groups = [0], so MEMBER_A cannot propose.
    let config: &mut MultisigConfig = account::config_mut(
        &mut account, multisig::config_witness(),
    );
    multisig::set_groups(config, vector[
        multisig::new_group(
            b"proposers".to_string(),
            vector[multisig::new_group_member(OWNER, 1)],
            vector[],
        ),
        multisig::new_group(
            b"voters".to_string(),
            vector[multisig::new_group_member(MEMBER_A, 1)],
            vector[],
        ),
    ]);
    multisig::set_propose_groups(config, vector[0]); // only group 0
    multisig::set_execute_groups(config, vector[0, 1]);

    scenario.next_tx(MEMBER_A);
    let auth = multisig::authenticate(&account, scenario.ctx());

    // Must consume auth before returning
    account.verify(auth);
    destroy(account);
    end(scenario, registry, clock);
}

#[test]
#[expected_failure(abort_code = multisig::EInvalidIntentStatus)]
fun test_approve_after_rejected_fails() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    let key = create_test_intent(
        &mut account, &registry, &clock, b"reject_then_approve", scenario.ctx(),
    );

    // Single member rejects -> terminal
    multisig::reject_intent(&mut account, key, &clock, scenario.ctx());
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx()); // should fail

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
#[expected_failure(abort_code = multisig::EInvalidIntentStatus)]
fun test_disapprove_after_approved_fails() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    let key = create_test_intent(
        &mut account, &registry, &clock, b"disapprove_after_approved", scenario.ctx(),
    );
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    // Intent is now APPROVED, disapprove only works on ACTIVE
    multisig::disapprove_intent(&mut account, key, scenario.ctx());

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
#[expected_failure(abort_code = multisig::EStaleIntent)]
fun test_approve_stale_intent_fails() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    let key = create_test_intent(
        &mut account, &registry, &clock, b"stale_approve", scenario.ctx(),
    );

    let config: &mut MultisigConfig = account::config_mut(
        &mut account, multisig::config_witness(),
    );
    multisig::set_config_nonce_for_testing(config, 1);

    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
#[expected_failure(abort_code = multisig::EStaleIntent)]
fun test_execute_stale_intent_fails() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    let key = create_test_intent(
        &mut account, &registry, &clock, b"stale_exec", scenario.ctx(),
    );
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());

    let config: &mut MultisigConfig = account::config_mut(
        &mut account, multisig::config_witness(),
    );
    multisig::set_config_nonce_for_testing(config, 1);

    let executable = multisig::execute_intent(
        &mut account, &registry, key, &clock, scenario.ctx(),
    );
    destroy(executable);

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
#[expected_failure(abort_code = multisig::ENotStale)]
fun test_cancel_non_stale_intent_fails() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    let key = create_actions_intent(
        &mut account, &registry, &clock, b"fresh_test", scenario.ctx(),
    );

    let expired = multisig::cancel_stale_intent(&mut account, key, scenario.ctx());
    destroy(expired);

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
#[expected_failure(abort_code = multisig::EConfigChangeRequiresConfigModule)]
fun test_raw_cancel_pending_config_change_aborts() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    // ConfigChange intents must use config-module cleanup.
    let key = create_test_intent(
        &mut account, &registry, &clock, b"raw_pending", scenario.ctx(),
    );
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    // Reject to satisfy cancel_policy (threshold 1) so only the ConfigChange
    // routing guard can stop raw cancellation.
    multisig::reject_intent(&mut account, key, &clock, scenario.ctx());
    let expired = multisig::cancel_pending_intent(
        &mut account, key, &clock, scenario.ctx(),
    );
    destroy(expired);

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
#[expected_failure(abort_code = multisig::EConfigChangeRequiresConfigModule)]
fun test_raw_cancel_stale_config_change_aborts() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    let key = create_test_intent(
        &mut account, &registry, &clock, b"raw_stale", scenario.ctx(),
    );
    let cfg: &mut MultisigConfig = account::config_mut(
        &mut account, multisig::config_witness(),
    );
    multisig::set_config_nonce_for_testing(cfg, 1);
    let expired = multisig::cancel_stale_intent(&mut account, key, scenario.ctx());
    destroy(expired);

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
#[expected_failure(abort_code = multisig::EConfigChangeRequiresConfigModule)]
fun test_raw_cancel_expired_config_change_aborts() {
    let (mut scenario, registry, mut clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );
    let config: &mut MultisigConfig = account::config_mut(
        &mut account, multisig::config_witness(),
    );
    multisig::set_intent_expiry_for_testing(config, 1);

    let key = create_test_intent(
        &mut account, &registry, &clock, b"raw_expired", scenario.ctx(),
    );
    clock::increment_for_testing(&mut clock, 2);
    let expired = multisig::cancel_expired_intent(
        &mut account, key, &clock, scenario.ctx(),
    );
    destroy(expired);

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
fun test_raw_cancel_actions_ignores_unrelated_proposed_config_key() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    let key = create_actions_intent(
        &mut account, &registry, &clock, b"actions_with_side_data", scenario.ctx(),
    );
    let planted_config: MultisigConfig = *account::config(&account);
    account::add_managed_data_with_package_witness(
        &mut account,
        &registry,
        multisig::new_proposed_config_key(key),
        planted_config,
        version::current(),
    );

    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    multisig::reject_intent(&mut account, key, &clock, scenario.ctx());
    let expired = multisig::cancel_pending_intent(
        &mut account, key, &clock, scenario.ctx(),
    );
    intents::drain_and_destroy_expired(expired);

    let _planted: MultisigConfig = account::remove_managed_data_with_package_witness(
        &mut account,
        &registry,
        multisig::new_proposed_config_key(key),
        version::current(),
    );

    destroy(account);
    end(scenario, registry, clock);
}

// ============================================================
// stage_intent boundary checks
// ============================================================

#[test, expected_failure(abort_code = multisig::ECallerIsNotMember)]
fun test_stage_intent_direct_non_member_fails() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    scenario.next_tx(MEMBER_A);

    let params = new_params_from_account(
        &account,
        b"direct_stage".to_string(),
        b"unauthorized direct stage".to_string(),
        &clock,
        scenario.ctx(),
    );
    let outcome = multisig::new_outcome(&account);
    let iw = DirectStageIntent {};
    let mut intent = account::create_intent(
        &account,
        &registry,
        params,
        outcome,
        version::current(),
        copy iw,
        scenario.ctx(),
    );
    intents::add_action_spec(&mut intent, TestAction {}, vector[], copy iw);

    multisig::stage_intent(
        &mut account,
        &registry,
        intent,
        version::current(),
        iw,
        scenario.ctx(),
    );

    destroy(account);
    end(scenario, registry, clock);
}

#[test, expected_failure(abort_code = multisig::EInvalidIntentStatus)]
fun test_stage_intent_rejects_copied_approved_outcome() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    let approved_key = create_actions_intent(
        &mut account,
        &registry,
        &clock,
        b"approved_actions",
        scenario.ctx(),
    );
    multisig::approve_intent(&mut account, approved_key, &clock, scenario.ctx());

    let approved_outcome = *account.intents().get<Approvals>(approved_key).outcome();
    let params = new_params_from_account(
        &account,
        b"reused_outcome".to_string(),
        b"reused approved outcome".to_string(),
        &clock,
        scenario.ctx(),
    );
    let iw = DirectStageIntent {};
    let mut intent = account::create_intent(
        &account,
        &registry,
        params,
        approved_outcome,
        version::current(),
        copy iw,
        scenario.ctx(),
    );
    intents::add_action_spec(&mut intent, TestAction {}, vector[], copy iw);

    multisig::stage_intent(
        &mut account,
        &registry,
        intent,
        version::current(),
        iw,
        scenario.ctx(),
    );

    destroy(account);
    end(scenario, registry, clock);
}

// ============================================================
// Whitelisted cancel flow
// ============================================================

#[test]
fun test_cancel_pending_after_cancel_threshold_met_closes_approved_intent() {
    let (mut scenario, registry, clock) = start();
    let mut account = create_multi_member_account(&mut scenario, &registry);

    let key = create_actions_intent(
        &mut account, &registry, &clock, b"cancel_threshold", scenario.ctx(),
    );

    // OWNER and MEMBER_A approve to reach APPROVED status (threshold=2).
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    scenario.next_tx(MEMBER_A);
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());

    // Two reject votes (cancel_policy threshold=2) flip status to REJECTED.
    // Vote-switching: these two had approved, now switch to reject.
    scenario.next_tx(OWNER);
    multisig::reject_intent(&mut account, key, &clock, scenario.ctx());
    scenario.next_tx(MEMBER_A);
    multisig::reject_intent(&mut account, key, &clock, scenario.ctx());

    {
        let outcome = intents::outcome(account.intents().get<Approvals>(key));
        assert!(multisig::outcome_status(outcome) == multisig::status_rejected());
    };

    // MEMBER_A is in cancel_groups=[0] and cancel_policy is met, so finalization succeeds.
    let expired = multisig::cancel_pending_intent(
        &mut account, key, &clock, scenario.ctx(),
    );
    intents::drain_and_destroy_expired(expired);

    destroy(account);
    end(scenario, registry, clock);
}

/// Whitelist alone must NOT bypass the cancel_policy threshold. An APPROVED intent
/// with zero reject weight cannot be finalized to CANCELLED just because the caller
/// is in cancel_groups — that was the pre-split bug.
#[test]
#[expected_failure(abort_code = multisig::EInvalidIntentStatus)]
fun test_cancel_pending_whitelisted_alone_cannot_kill_approved_intent() {
    let (mut scenario, registry, clock) = start();
    let mut account = create_multi_member_account(&mut scenario, &registry);

    let key = create_actions_intent(
        &mut account, &registry, &clock, b"cancel_no_bypass", scenario.ctx(),
    );

    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    scenario.next_tx(MEMBER_A);
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());

    // No reject votes. Even though MEMBER_A is in cancel_groups, the cancel_policy
    // threshold has not been met, so finalization must abort.
    let _expired = multisig::cancel_pending_intent(
        &mut account, key, &clock, scenario.ctx(),
    );

    abort 0
}

#[test]
#[expected_failure(abort_code = multisig::ENotInCancelGroup)]
fun test_cancel_pending_rejects_member_outside_cancel_groups() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    let config: &mut MultisigConfig = account::config_mut(
        &mut account, multisig::config_witness(),
    );
    multisig::set_groups(config, vector[
        multisig::new_group(
            b"members".to_string(),
            vector[multisig::new_group_member(MEMBER_A, 1)],
            vector[],
        ),
        multisig::new_group(
            b"cancellers".to_string(),
            vector[multisig::new_group_member(OWNER, 1)],
            vector[],
        ),
    ]);
    multisig::set_approve_policy(config, multisig::new_role_policy(vector[
        multisig::new_policy_path(vector[
            multisig::new_path_requirement(0, 1),
        ]),
    ]));
    multisig::set_cancel_policy(config, multisig::new_role_policy(vector[
        multisig::new_policy_path(vector[
            multisig::new_path_requirement(0, 1),
        ]),
    ]));
    multisig::set_propose_groups(config, vector[0, 1]);
    multisig::set_execute_groups(config, vector[0, 1]);
    multisig::set_cancel_groups(config, vector[1]);

    let key = create_actions_intent(
        &mut account, &registry, &clock, b"cancel_group_gate", scenario.ctx(),
    );

    scenario.next_tx(MEMBER_A);
    let _expired = multisig::cancel_pending_intent(
        &mut account, key, &clock, scenario.ctx(),
    );
    destroy(_expired);

    destroy(account);
    end(scenario, registry, clock);
}

// ============================================================
// Config accessors on new config
// ============================================================

#[test]
fun test_config_accessors() {
    let config = multisig::new_config(
        vector[
            multisig::new_group(
                b"founders".to_string(),
                vector[
                    multisig::new_group_member(MEMBER_A, 3),
                    multisig::new_group_member(MEMBER_B, 2),
                ],
                vector[multisig::new_time_band(1000, 5)],
            ),
            multisig::new_group(
                b"auditors".to_string(),
                vector[multisig::new_group_member(MEMBER_C, 1)],
                vector[],
            ),
        ],
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 3),
                multisig::new_path_requirement(1, 1),
            ]),
        ]),
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 3),
                multisig::new_path_requirement(1, 1),
            ]),
        ]),
        vector[0, 1],
        vector[0],
        vector[0],
        604800000,
    );

    assert!(multisig::group_count(&config) == 2);
    assert!(multisig::is_member_of_any_group(&config, MEMBER_A));
    assert!(multisig::is_member_of_any_group(&config, MEMBER_B));
    assert!(multisig::is_member_of_any_group(&config, MEMBER_C));
    assert!(!multisig::is_member_of_any_group(&config, OWNER));
    assert!(multisig::config_nonce(&config) == 0);
    assert!(multisig::intent_expiry_ms(&config) == 604800000);

    // Group accessors
    let g0 = multisig::group_at(&config, 0);
    assert!(*multisig::group_name(g0) == b"founders".to_string());
    assert!(multisig::group_members(g0).length() == 2);
    assert!(multisig::group_time_bands(g0).length() == 1);
    assert!(multisig::time_band_after_ms(&multisig::group_time_bands(g0)[0]) == 1000);
    assert!(multisig::time_band_weight(&multisig::group_time_bands(g0)[0]) == 5);

    // Policy accessors
    let approve_paths = multisig::policy_paths(multisig::approve_policy(&config));
    assert!(approve_paths.length() == 1);
    let reqs = multisig::path_requirements(&approve_paths[0]);
    assert!(reqs.length() == 2);
    assert!(multisig::requirement_group_idx(&reqs[0]) == 0);
    assert!(multisig::requirement_threshold(&reqs[0]) == 3);
    assert!(multisig::requirement_group_idx(&reqs[1]) == 1);
    assert!(multisig::requirement_threshold(&reqs[1]) == 1);
    // Cancel policy exists separately
    let cancel_paths = multisig::policy_paths(multisig::cancel_policy(&config));
    assert!(cancel_paths.length() >= 1);

    // propose/execute/cancel groups
    assert!(*multisig::propose_groups(&config) == vector[0, 1]);
    assert!(*multisig::execute_groups(&config) == vector[0]);
    assert!(*multisig::cancel_groups(&config) == vector[0]);
}

// ============================================================
// Outcome accessors
// ============================================================

#[test]
fun test_outcome_accessors() {
    let (mut scenario, registry, clock) = start();
    let account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    let outcome = multisig::new_outcome(&account);
    assert!(multisig::outcome_config_nonce(&outcome) == 0);
    assert!(multisig::outcome_status(&outcome) == multisig::status_active());
    assert!(multisig::approved(&outcome).length() == 0);
    assert!(multisig::rejected(&outcome).length() == 0);
    assert!(multisig::matched_vote_path(&outcome).is_none());
    assert!(multisig::approved_at_ms(&outcome) == 0);

    destroy(account);
    end(scenario, registry, clock);
}

// ============================================================
// Config validation: duplicate group names
// ============================================================

#[test]
#[expected_failure(abort_code = multisig::EDuplicateGroupName)]
fun test_config_validation_duplicate_group_name_aborts() {
    let _config = multisig::new_config(
        vector[
            multisig::new_group(
                b"same".to_string(),
                vector[multisig::new_group_member(MEMBER_A, 1)],
                vector[],
            ),
            multisig::new_group(
                b"same".to_string(),
                vector[multisig::new_group_member(MEMBER_B, 1)],
                vector[],
            ),
        ],
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
            ]),
        ]),
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
            ]),
        ]),
        vector[0],
        vector[0],
        vector[0],
        604800000,
    );
}

// ============================================================
// Config validation: empty group name
// ============================================================

#[test]
#[expected_failure(abort_code = multisig::EEmptyGroupName)]
fun test_config_validation_empty_group_name_aborts() {
    let _config = multisig::new_config(
        vector[
            multisig::new_group(
                b"".to_string(), // empty name
                vector[multisig::new_group_member(MEMBER_A, 1)],
                vector[],
            ),
        ],
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
            ]),
        ]),
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
            ]),
        ]),
        vector[0],
        vector[0],
        vector[0],
        604800000,
    );
}

// ============================================================
// Config validation: no proposer member
// ============================================================

#[test]
#[expected_failure(abort_code = multisig::ENoProposerMember)]
fun test_config_validation_no_proposer_member_aborts() {
    // propose_groups points to group 1 which has no members
    // (we cheat by having group 0 with a member for satisfiability, but group 1 is empty)
    // Actually, groups can't have 0 members if they're in propose_groups because
    // validate_config checks. Let's use propose_groups pointing at an empty group.
    // But empty members in a group won't pass satisfiability either.
    // The simplest approach: group 0 has members, group 1 has members,
    // but propose_groups = [1] where group 1 has 0 members... no, can't have 0 members.
    // Actually let's re-read the validation: it just checks
    // `propose_groups.any!(|idx| groups[*idx].members.length() > 0)`.
    // So if propose_groups = [1] and group 1 has 0 members, it fails.
    // But we can't create a group with 0 members because it won't pass validation.
    // Hmm, actually the check is: at least one propose group has at least one member.
    // An empty group would fail the vote policy satisfiability check earlier.
    // Let's use a group with members but set propose_groups to an empty vector.
    // Wait: ENoProposerMember fires if no propose group has any members.
    // propose_groups = [] would make the any! return false. Let's try that.
    let _config = multisig::new_config(
        vector[
            multisig::new_group(
                b"default".to_string(),
                vector[multisig::new_group_member(MEMBER_A, 1)],
                vector[],
            ),
        ],
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
            ]),
        ]),
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
            ]),
        ]),
        vector[], // no propose groups -> ENoProposerMember
        vector[0],
        vector[0],
        604800000,
    );
}

#[test]
#[expected_failure(abort_code = multisig::ENoExecutorMember)]
fun test_config_validation_restricted_execute_groups_need_member() {
    let _config = multisig::new_config(
        vector[
            multisig::new_group(
                b"default".to_string(),
                vector[multisig::new_group_member(MEMBER_A, 1)],
                vector[],
            ),
            multisig::new_group(b"empty-executor".to_string(), vector[], vector[]),
        ],
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
            ]),
        ]),
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
            ]),
        ]),
        vector[0],
        vector[1], // non-empty execute_groups is restricted, so it needs an executable member
        vector[0],
        604800000,
    );
}

#[test]
fun test_config_validation_empty_execute_groups_stays_permissionless() {
    let config = multisig::new_config(
        vector[
            multisig::new_group(
                b"default".to_string(),
                vector[multisig::new_group_member(MEMBER_A, 1)],
                vector[],
            ),
        ],
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
            ]),
        ]),
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
            ]),
        ]),
        vector[0],
        vector[],
        vector[0],
        604800000,
    );
    assert!(multisig::execute_groups(&config).is_empty(), 0);
}

#[test]
#[expected_failure(abort_code = multisig::ETooManyPolicyRequirements)]
fun test_config_validation_too_many_requirements_in_path_aborts() {
    let mut requirements = vector[];
    let mut i = 0;
    while (i < multisig::max_groups() + 1) {
        requirements.push_back(multisig::new_path_requirement(0, 1));
        i = i + 1;
    };

    let _config = multisig::new_config(
        vector[
            multisig::new_group(
                b"default".to_string(),
                vector[multisig::new_group_member(MEMBER_A, 1)],
                vector[],
            ),
        ],
        multisig::new_role_policy(vector[
            multisig::new_policy_path(requirements),
        ]),
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
            ]),
        ]),
        vector[0],
        vector[0],
        vector[0],
        604800000,
    );
}

#[test]
#[expected_failure(abort_code = multisig::EDuplicateGroupIndex)]
fun test_config_validation_duplicate_group_indices_abort() {
    let _config = multisig::new_config(
        vector[
            multisig::new_group(
                b"default".to_string(),
                vector[multisig::new_group_member(MEMBER_A, 1)],
                vector[],
            ),
        ],
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
            ]),
        ]),
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
            ]),
        ]),
        vector[0, 0],
        vector[0],
        vector[0],
        604800000,
    );
}

#[test]
#[expected_failure(abort_code = multisig::EDuplicateGroupIndex)]
fun test_config_validation_duplicate_group_in_policy_path_aborts() {
    let _config = multisig::new_config(
        vector[
            multisig::new_group(
                b"default".to_string(),
                vector[multisig::new_group_member(MEMBER_A, 1)],
                vector[],
            ),
        ],
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
                multisig::new_path_requirement(0, 1),
            ]),
        ]),
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
            ]),
        ]),
        vector[0],
        vector[0],
        vector[0],
        604800000,
    );
}

// ============================================================
// Config change cancel via config module (with cleanup)
// ============================================================

#[test]
fun test_config_change_cancel_stale_via_config_module() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    let key = create_test_intent(
        &mut account, &registry, &clock, b"config_stale", scenario.ctx(),
    );

    // Bump nonce to make intent stale
    let cfg: &mut MultisigConfig = account::config_mut(
        &mut account, multisig::config_witness(),
    );
    multisig::set_config_nonce_for_testing(cfg, 1);

    // Use config module cancel which cleans up managed data
    config::cancel_stale_config_change(&mut account, &registry, key, scenario.ctx());

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
fun test_config_change_cancel_rejected_via_config_module() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    let key = create_test_intent(
        &mut account, &registry, &clock, b"config_rejected", scenario.ctx(),
    );

    // Reject (single member -> terminal)
    multisig::reject_intent(&mut account, key, &clock, scenario.ctx());

    config::cancel_rejected_config_change(&mut account, &registry, key, scenario.ctx());

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
fun test_config_change_cancel_expired_via_config_module() {
    let (mut scenario, registry, mut clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    let cfg: &mut MultisigConfig = account::config_mut(
        &mut account, multisig::config_witness(),
    );
    multisig::set_intent_expiry_for_testing(cfg, 1);

    let key = create_test_intent(
        &mut account, &registry, &clock, b"config_expired", scenario.ctx(),
    );
    clock::increment_for_testing(&mut clock, 2);

    config::cancel_expired_config_change(
        &mut account, &registry, key, &clock, scenario.ctx(),
    );

    destroy(account);
    end(scenario, registry, clock);
}

// ============================================================
// Approvals test helper
// ============================================================

#[test]
fun test_new_approvals_for_testing() {
    let approvals = multisig::new_approvals_for_testing(5);
    assert!(multisig::outcome_config_nonce(&approvals) == 5);
    assert!(multisig::outcome_status(&approvals) == multisig::status_active());
    assert!(multisig::approved(&approvals).length() == 0);
    assert!(multisig::rejected(&approvals).length() == 0);
}

// ============================================================
// Status constants
// ============================================================

#[test]
fun test_status_constants() {
    assert!(multisig::status_active() == 0);
    assert!(multisig::status_approved() == 1);
    assert!(multisig::status_rejected() == 2);
    assert!(multisig::status_executed() == 4);
}

// ============================================================
// evaluate_intent tests
// ============================================================

#[test]
fun test_evaluate_intent_triggers_approval_via_time_band() {
    let (mut scenario, registry, mut clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    // Configure: group 0 with OWNER(weight 10) + MEMBER_A(weight 10),
    // time band at 1000ms giving weight 10.
    // Vote policy: threshold 20 on group 0.
    // Two approvals (10+10=20) would suffice, but one approval (10) + time band (10) also works.
    let config: &mut MultisigConfig = account::config_mut(
        &mut account, multisig::config_witness(),
    );
    multisig::set_groups(config, vector[
        multisig::new_group(
            b"default".to_string(),
            vector[
                multisig::new_group_member(OWNER, 10),
                multisig::new_group_member(MEMBER_A, 10),
            ],
            vector[multisig::new_time_band(1000, 10)],
        ),
    ]);
    multisig::set_approve_threshold(config, 20);
    multisig::set_cancel_threshold(config, 20);

    let key = create_actions_intent(
        &mut account, &registry, &clock, b"eval_time_band", scenario.ctx(),
    );

    // Member A approves (weight 10, threshold 20 — not enough)
    scenario.next_tx(MEMBER_A);
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    {
        let outcome = intents::outcome(account.intents().get<Approvals>(key));
        assert!(multisig::outcome_status(outcome) == multisig::status_active());
    };

    // Clock at 0, evaluate_intent — still ACTIVE (10 + 0 < 20)
    scenario.next_tx(OWNER);
    multisig::evaluate_intent(&mut account, key, &clock, scenario.ctx());
    {
        let outcome = intents::outcome(account.intents().get<Approvals>(key));
        assert!(multisig::outcome_status(outcome) == multisig::status_active());
    };

    // Advance clock past 1000ms
    clock::increment_for_testing(&mut clock, 1001);

    // Call evaluate_intent — now 10 (member) + 10 (time band) = 20 >= 20 → APPROVED
    multisig::evaluate_intent(&mut account, key, &clock, scenario.ctx());
    {
        let outcome = intents::outcome(account.intents().get<Approvals>(key));
        assert!(multisig::outcome_status(outcome) == multisig::status_approved());
        assert!(multisig::matched_vote_path(outcome).is_some());
    };

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
fun test_evaluate_intent_time_band_does_not_count_as_reject_weight() {
    let (mut scenario, registry, mut clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    let config: &mut MultisigConfig = account::config_mut(
        &mut account, multisig::config_witness(),
    );
    multisig::set_groups(config, vector[
        multisig::new_group(
            b"default".to_string(),
            vector[multisig::new_group_member(OWNER, 1)],
            vector[multisig::new_time_band(1000, 1)],
        ),
    ]);
    multisig::set_approve_threshold(config, 2);
    multisig::set_cancel_threshold(config, 1);

    let key = create_actions_intent(
        &mut account, &registry, &clock, b"eval_no_phantom_reject", scenario.ctx(),
    );

    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    clock::increment_for_testing(&mut clock, 1001);
    multisig::evaluate_intent(&mut account, key, &clock, scenario.ctx());

    let outcome = intents::outcome(account.intents().get<Approvals>(key));
    assert!(multisig::outcome_status(outcome) == multisig::status_approved());
    assert!(multisig::rejected(outcome).length() == 0);

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
fun test_evaluate_intent_noop_when_not_satisfied() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    // Configure: group 0 with OWNER(weight 10), time band at 1000ms giving weight 10.
    // Vote policy: threshold 20 on group 0.
    // At clock=0 with one approval: 10 + 0 = 10 < 20.
    let config: &mut MultisigConfig = account::config_mut(
        &mut account, multisig::config_witness(),
    );
    multisig::set_groups(config, vector[
        multisig::new_group(
            b"default".to_string(),
            vector[multisig::new_group_member(OWNER, 10)],
            vector[multisig::new_time_band(1000, 10)],
        ),
    ]);
    multisig::set_approve_threshold(config, 20);
    multisig::set_cancel_threshold(config, 20);

    let key = create_actions_intent(
        &mut account, &registry, &clock, b"eval_noop", scenario.ctx(),
    );

    // OWNER approves (weight 10)
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());

    // evaluate_intent at clock=0 — time band not yet active, still ACTIVE
    multisig::evaluate_intent(&mut account, key, &clock, scenario.ctx());
    {
        let outcome = intents::outcome(account.intents().get<Approvals>(key));
        assert!(multisig::outcome_status(outcome) == multisig::status_active());
        assert!(multisig::matched_vote_path(outcome).is_none());
    };

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
#[expected_failure(abort_code = multisig::ENotInExecutorGroup)]
fun test_evaluate_intent_respects_execute_groups() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    // Set up two groups: group 0 with OWNER, group 1 with MEMBER_A.
    // execute_groups = [0] — only group 0 members can evaluate.
    let config: &mut MultisigConfig = account::config_mut(
        &mut account, multisig::config_witness(),
    );
    multisig::set_groups(config, vector[
        multisig::new_group(
            b"default".to_string(),
            vector[multisig::new_group_member(OWNER, 1)],
            vector[],
        ),
        multisig::new_group(
            b"voters".to_string(),
            vector[multisig::new_group_member(MEMBER_A, 1)],
            vector[],
        ),
    ]);
    multisig::set_execute_groups(config, vector[0]); // only group 0

    let key = create_actions_intent(
        &mut account, &registry, &clock, b"eval_exec_group", scenario.ctx(),
    );

    // MEMBER_A is in group 1 but not in execute_groups=[0] → should abort
    scenario.next_tx(MEMBER_A);
    multisig::evaluate_intent(&mut account, key, &clock, scenario.ctx());

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
fun test_evaluate_intent_permissionless_when_execute_groups_empty() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    // Set execute_groups to empty — anyone can call evaluate_intent
    let config: &mut MultisigConfig = account::config_mut(
        &mut account, multisig::config_witness(),
    );
    multisig::set_execute_groups(config, vector[]);

    let key = create_actions_intent(
        &mut account, &registry, &clock, b"eval_permissionless", scenario.ctx(),
    );

    // Random non-member calls evaluate_intent → should succeed (no abort)
    scenario.next_tx(@0xDEAD);
    multisig::evaluate_intent(&mut account, key, &clock, scenario.ctx());

    // Intent still ACTIVE (no approvals, so no path satisfied), but no abort
    {
        let outcome = intents::outcome(account.intents().get<Approvals>(key));
        assert!(multisig::outcome_status(outcome) == multisig::status_active());
    };

    destroy(account);
    end(scenario, registry, clock);
}

// ============================================================
// Cancel whitelist tests
// ============================================================

#[test]
#[expected_failure(abort_code = multisig::ECallerIsNotMember)]
fun test_cancel_pending_requires_cancel_group_member() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    // Use actions intent (no managed config data)
    let key = create_actions_intent(
        &mut account, &registry, &clock, b"permissionless_cancel", scenario.ctx(),
    );

    // Approve to APPROVED status (single member, threshold 1)
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    {
        let outcome = intents::outcome(account.intents().get<Approvals>(key));
        assert!(multisig::outcome_status(outcome) == multisig::status_approved());
    };

    // Non-member calls cancel_pending_intent → aborts before cancellation.
    scenario.next_tx(@0xDEAD);
    let expired = multisig::cancel_pending_intent(
        &mut account, key, &clock, scenario.ctx(),
    );
    intents::drain_and_destroy_expired(expired);

    destroy(account);
    end(scenario, registry, clock);
}

// ============================================================
// Permissionless execute tests
// ============================================================

#[test]
fun test_execute_permissionless_when_execute_groups_empty() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    // Set execute_groups to empty — anyone can call execute_intent
    let config: &mut MultisigConfig = account::config_mut(
        &mut account, multisig::config_witness(),
    );
    multisig::set_execute_groups(config, vector[]);

    // Use actions intent, approve it
    let key = create_actions_intent(
        &mut account, &registry, &clock, b"exec_permissionless", scenario.ctx(),
    );
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    {
        let outcome = intents::outcome(account.intents().get<Approvals>(key));
        assert!(multisig::outcome_status(outcome) == multisig::status_approved());
    };

    // Non-member calls execute_intent → should succeed (no abort)
    scenario.next_tx(@0xDEAD);
    let executable = multisig::execute_intent(
        &mut account, &registry, key, &clock, scenario.ctx(),
    );
    destroy(executable);

    destroy(account);
    end(scenario, registry, clock);
}

// ============================================================
// evaluate_intent — error cases
// ============================================================

#[test]
#[expected_failure(abort_code = multisig::EInvalidIntentStatus)]
fun test_evaluate_intent_on_approved_intent_fails() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    let key = create_actions_intent(
        &mut account, &registry, &clock, b"eval_approved", scenario.ctx(),
    );

    // Approve (single member, threshold 1 → instant APPROVED)
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    {
        let outcome = intents::outcome(account.intents().get<Approvals>(key));
        assert!(multisig::outcome_status(outcome) == multisig::status_approved());
    };

    // evaluate_intent on APPROVED → should abort EInvalidIntentStatus
    multisig::evaluate_intent(&mut account, key, &clock, scenario.ctx());

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
#[expected_failure(abort_code = multisig::EStaleIntent)]
fun test_evaluate_intent_on_stale_intent_fails() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    let key = create_actions_intent(
        &mut account, &registry, &clock, b"eval_stale", scenario.ctx(),
    );

    // Bump config nonce to make intent stale
    let config: &mut MultisigConfig = account::config_mut(
        &mut account, multisig::config_witness(),
    );
    multisig::set_config_nonce_for_testing(config, 99);

    // evaluate_intent on stale intent → should abort EStaleIntent
    multisig::evaluate_intent(&mut account, key, &clock, scenario.ctx());

    destroy(account);
    end(scenario, registry, clock);
}

// ============================================================
// Config validation — non-decreasing time band weights
// ============================================================

#[test]
#[expected_failure(abort_code = multisig::ETimeBandsNotSorted)]
fun test_config_validation_decreasing_time_band_weights_aborts() {
    let (mut scenario, registry, _clock) = start();

    // Time bands with decreasing weights: 50 then 20. after_ms is ascending
    // but weights are decreasing → should abort.
    let groups = vector[
        multisig::new_group(
            b"team".to_string(),
            vector[multisig::new_group_member(OWNER, 1)],
            vector[
                multisig::new_time_band(1000, 50),
                multisig::new_time_band(2000, 20), // weight decreased!
            ],
        ),
    ];
    let approve_policy = multisig::new_role_policy(vector[
        multisig::new_policy_path(vector[
            multisig::new_path_requirement(0, 1),
        ]),
    ]);
    let cancel_policy = multisig::new_role_policy(vector[
        multisig::new_policy_path(vector[
            multisig::new_path_requirement(0, 1),
        ]),
    ]);

    // This should abort during validation
    let _config = multisig::new_config(
        groups,
        approve_policy,
        cancel_policy,
        vector[0],
        vector[0],
        vector[0],
        604800000,
    );

    destroy(_config);
    end(scenario, registry, _clock);
}

// ============================================================
// Cancel by non-member is rejected by whitelist
// ============================================================

#[test]
#[expected_failure(abort_code = multisig::ECallerIsNotMember)]
fun test_cancel_non_member_aborts() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    // Create and approve an intent
    let key = create_actions_intent(
        &mut account, &registry, &clock, b"cancel_no_effect", scenario.ctx(),
    );
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    {
        let outcome = intents::outcome(account.intents().get<Approvals>(key));
        assert!(multisig::outcome_status(outcome) == multisig::status_approved());
    };

    // Non-member cannot finalize cancellation.
    scenario.next_tx(@0xDEAD);
    let expired = multisig::cancel_pending_intent(
        &mut account, key, &clock, scenario.ctx(),
    );
    intents::drain_and_destroy_expired(expired);

    destroy(account);
    end(scenario, registry, clock);
}

// ============================================================
// Member in multiple groups — single approve counts per group
// ============================================================

/// A member who is in multiple groups should have their vote counted toward
/// each group's threshold. The vote-path AND semantics (all requirements met
/// simultaneously) must be satisfied by a single approver when that approver
/// is in every required group. Without this, legitimate governance configs
/// that intentionally overlap groups (e.g. a principal member serving in
/// both team and auditor roles) would need redundant voters.
#[test]
fun test_member_in_multiple_groups_vote_counts_per_group() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(
        &registry, vector[], vector[], scenario.ctx(),
    );

    // Configure two disjoint-looking groups, but MEMBER_A is in both.
    // Path requires group 0 threshold >= 1 AND group 1 threshold >= 1.
    let config: &mut MultisigConfig = account::config_mut(
        &mut account, multisig::config_witness(),
    );
    multisig::set_groups(config, vector[
        multisig::new_group(
            b"team".to_string(),
            vector[multisig::new_group_member(MEMBER_A, 1)],
            vector[],
        ),
        multisig::new_group(
            b"auditors".to_string(),
            vector[multisig::new_group_member(MEMBER_A, 1)],
            vector[],
        ),
    ]);
    multisig::set_approve_policy(
        config,
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
                multisig::new_path_requirement(1, 1),
            ]),
        ]),
    );
    multisig::set_cancel_policy(
        config,
        multisig::new_role_policy(vector[
            multisig::new_policy_path(vector[
                multisig::new_path_requirement(0, 1),
                multisig::new_path_requirement(1, 1),
            ]),
        ]),
    );
    multisig::set_propose_groups(config, vector[0, 1]);
    multisig::set_execute_groups(config, vector[0, 1]);
    multisig::set_cancel_groups(config, vector[0, 1]);

    // MEMBER_A proposes (OWNER is not in any group after the reconfig above).
    scenario.next_tx(MEMBER_A);
    let key = create_test_intent(
        &mut account, &registry, &clock, b"cross_group", scenario.ctx(),
    );

    // Single MEMBER_A approval must satisfy both group thresholds because the
    // same voter is a member of both groups.
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());

    let outcome = intents::outcome(account.intents().get<Approvals>(key));
    assert!(multisig::outcome_status(outcome) == multisig::status_approved());

    destroy(account);
    end(scenario, registry, clock);
}
