#[test_only]
/// Integration tests for the 4 design spec scenarios documented in multisig.move.
///
/// These are realistic multi-member scenarios that prove the group-based
/// tiered policy model works end-to-end with time bands, multi-group paths,
/// and cancel finalizer whitelists.
///
/// Setup:
///   founders group: [Alice(10), Bob(10), Carol(10)]
///     time_bands: [{ after: 30 days, weight: 20 }, { after: 180 days, weight: 50 }]
///   auditors group: [Deloitte(10), Trail(10), Zellic(10)]
///     time_bands: []
///   approve_policy paths:
///     path 0: founders(10) + auditors(10) — 1 founder + 1 auditor, instant
///     path 1: founders(20) + auditors(10) — 2 founders + 1 auditor, instant
///     path 2: founders(30)                — 3 founders, no auditor needed
///     path 3: auditors(30)                — 3 auditors, no founders needed
///   cancel_policy paths:
///     path 0: founders(10)                — any single founder at base weight
///     path 1: auditors(10)                — any single auditor at base weight
///   propose_groups: [0] (founders)
///   execute_groups: [0] (founders)
module account_multisig::integration_tests;

use std::string::String;
use account_multisig::multisig::{Self, MultisigConfig, Approvals};
use account_multisig::actions_staging;
use account_protocol::account::{Self, Account};
use account_protocol::intents;
use account_protocol::package_registry::{
    Self as package_registry,
    PackageRegistry,
    PackageAdminCap
};
use sui::clock::{Self, Clock};
use sui::test_scenario::{Self as ts, Scenario};
use sui::test_utils::destroy;

// === Constants ===

const ALICE: address = @0xA11CE;
const BOB: address = @0xB0B;
const CAROL: address = @0xCA201;
const DELOITTE: address = @0xDE101;
const TRAIL: address = @0x7A11;
const ZELLIC: address = @0x2E111C;

const THIRTY_DAYS_MS: u64 = 2_592_000_000;
const ONE_EIGHTY_DAYS_MS: u64 = 15_552_000_000;
const ONE_YEAR_MS: u64 = 31_536_000_000;

// === Test-only structs ===

public struct TestAction has drop {}

// === Helpers ===

/// Creates scenario + registry with AccountMultisig registered.
fun start_with(sender: address): (Scenario, PackageRegistry, Clock) {
    let mut scenario = ts::begin(sender);
    package_registry::init_for_testing(scenario.ctx());
    scenario.next_tx(sender);
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

/// Build the design spec account with 2 groups and 4 shared vote paths.
/// Must be called from ALICE's tx context (ALICE is the default creator).
fun create_spec_account(scenario: &mut Scenario, registry: &PackageRegistry): Account {
    let mut account = multisig::new_account_for_testing(
        registry, vector[], vector[], scenario.ctx(),
    );

    let config: &mut MultisigConfig = account::config_mut(
        &mut account, multisig::config_witness(),
    );

    // Replace default groups with spec groups
    let founders = multisig::new_group(
        b"founders".to_string(),
        vector[
            multisig::new_group_member(ALICE, 10),
            multisig::new_group_member(BOB, 10),
            multisig::new_group_member(CAROL, 10),
        ],
        vector[
            multisig::new_time_band(THIRTY_DAYS_MS, 20),
            multisig::new_time_band(ONE_EIGHTY_DAYS_MS, 50),
        ],
    );
    let auditors = multisig::new_group(
        b"auditors".to_string(),
        vector[
            multisig::new_group_member(DELOITTE, 10),
            multisig::new_group_member(TRAIL, 10),
            multisig::new_group_member(ZELLIC, 10),
        ],
        vector[],
    );
    multisig::set_groups(config, vector[founders, auditors]);

    // Approve policy: 4 paths
    multisig::set_approve_policy(config, multisig::new_role_policy(vector[
        // path 0: 1 founder + 1 auditor (instant)
        multisig::new_policy_path(vector[
            multisig::new_path_requirement(0, 10),
            multisig::new_path_requirement(1, 10),
        ]),
        // path 1: 2 founders + 1 auditor (instant)
        multisig::new_policy_path(vector[
            multisig::new_path_requirement(0, 20),
            multisig::new_path_requirement(1, 10),
        ]),
        // path 2: 3 founders, no auditor
        multisig::new_policy_path(vector[
            multisig::new_path_requirement(0, 30),
        ]),
        // path 3: 3 auditors, no founders
        multisig::new_policy_path(vector[
            multisig::new_path_requirement(1, 30),
        ]),
    ]));
    // Cancel policy: any single founder or auditor at their base weight (10)
    multisig::set_cancel_policy(config, multisig::new_role_policy(vector[
        multisig::new_policy_path(vector[multisig::new_path_requirement(0, 10)]),
        multisig::new_policy_path(vector[multisig::new_path_requirement(1, 10)]),
    ]));

    // Propose: founders only (group 0)
    multisig::set_propose_groups(config, vector[0]);
    // Execute: founders only (group 0)
    multisig::set_execute_groups(config, vector[0]);

    // Set long expiry so time band tests work (default 7 days is too short)
    multisig::set_intent_expiry_for_testing(config, ONE_YEAR_MS);

    account
}

/// Create a non-config-change intent using actions_staging.
/// Returns the intent key string.
fun create_test_intent(
    account: &mut Account,
    registry: &PackageRegistry,
    clock: &Clock,
    key: vector<u8>,
    ctx: &mut TxContext,
): String {
    let key_str = key.to_string();
    let auth = multisig::authenticate(account, ctx);
    let params = multisig::new_params_from_config(
        account,
        key_str,
        b"Test intent".to_string(),
        0,
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

/// Read the outcome from a live intent.
fun get_outcome(account: &Account, key: String): &Approvals {
    let intent = account.intents().get<Approvals>(key);
    intents::outcome(intent)
}

// ============================================================
// Scenario 1 — 1 founder + time band + 1 auditor
// ============================================================
//
// Alice approves (founder effective = 10). Not enough for any path.
// 30 days pass. Time band adds 20 to founders.
// Deloitte approves, triggering path re-check.
// Path 0: founders effective = 10 + 20 = 30 >= 10, auditors = 10 >= 10. SATISFIED.
// Intent becomes APPROVED via path 0.

#[test]
fun test_scenario_1_founder_plus_time_band() {
    let (mut scenario, registry, mut clock) = start_with(ALICE);
    let mut account = create_spec_account(&mut scenario, &registry);

    // Alice creates the intent
    let key = create_test_intent(
        &mut account, &registry, &clock, b"scenario_1", scenario.ctx(),
    );

    // Alice approves — founders effective = 10, not enough for any path
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    let outcome = get_outcome(&account, key);
    assert!(multisig::outcome_status(outcome) == multisig::status_active());
    assert!(multisig::matched_vote_path(outcome).is_none());

    // Advance clock by 30 days
    clock.increment_for_testing(THIRTY_DAYS_MS);

    // Deloitte approves — triggers path re-check with elapsed time
    // Founders: member weight 10 + time band 20 = 30 >= 10 (path 0 threshold)
    // Auditors: member weight 10 >= 10 (path 0 threshold)
    // Path 0 is satisfied.
    scenario.next_tx(DELOITTE);
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());

    let outcome = get_outcome(&account, key);
    assert!(multisig::outcome_status(outcome) == multisig::status_approved());
    assert!(multisig::matched_vote_path(outcome) == &option::some(0));

    destroy(account);
    end(scenario, registry, clock);
}

// ============================================================
// Scenario 2 — 2 founders + 1 auditor (instant)
// ============================================================
//
// Alice and Bob approve (founder effective = 20).
// Deloitte approves (auditor effective = 10).
// Path 0: founders 20 >= 10, auditors 10 >= 10. SATISFIED immediately.

#[test]
fun test_scenario_2_two_founders_one_auditor_instant() {
    let (mut scenario, registry, clock) = start_with(ALICE);
    let mut account = create_spec_account(&mut scenario, &registry);

    // Alice creates the intent
    let key = create_test_intent(
        &mut account, &registry, &clock, b"scenario_2", scenario.ctx(),
    );

    // Alice approves — founders = 10, no path satisfied
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    let outcome = get_outcome(&account, key);
    assert!(multisig::outcome_status(outcome) == multisig::status_active());

    // Bob approves — founders = 20, still no path satisfied
    // (path 0 needs auditors >= 10 which is 0, path 1 needs auditors too,
    //  path 2 needs founders >= 30)
    scenario.next_tx(BOB);
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    let outcome = get_outcome(&account, key);
    assert!(multisig::outcome_status(outcome) == multisig::status_active());

    // Deloitte approves — auditors = 10
    // Path 0: founders 20 >= 10, auditors 10 >= 10. SATISFIED.
    scenario.next_tx(DELOITTE);
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());

    let outcome = get_outcome(&account, key);
    assert!(multisig::outcome_status(outcome) == multisig::status_approved());
    assert!(multisig::matched_vote_path(outcome) == &option::some(0));

    destroy(account);
    end(scenario, registry, clock);
}

// ============================================================
// Scenario 3 — 3 founders, no auditor needed
// ============================================================
//
// Alice, Bob, Carol approve (founder effective = 30).
// Path 2: founders 30 >= 30. SATISFIED immediately.

#[test]
fun test_scenario_3_three_founders_no_auditor() {
    let (mut scenario, registry, clock) = start_with(ALICE);
    let mut account = create_spec_account(&mut scenario, &registry);

    // Alice creates the intent
    let key = create_test_intent(
        &mut account, &registry, &clock, b"scenario_3", scenario.ctx(),
    );

    // Alice approves — founders = 10
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    let outcome = get_outcome(&account, key);
    assert!(multisig::outcome_status(outcome) == multisig::status_active());

    // Bob approves — founders = 20, path 2 needs 30
    scenario.next_tx(BOB);
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    let outcome = get_outcome(&account, key);
    assert!(multisig::outcome_status(outcome) == multisig::status_active());

    // Carol approves — founders = 30
    // Path 0: founders 30 >= 10 but auditors 0 < 10. NOT satisfied.
    // Path 1: founders 30 >= 20 but auditors 0 < 10. NOT satisfied.
    // Path 2: founders 30 >= 30. SATISFIED.
    scenario.next_tx(CAROL);
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());

    let outcome = get_outcome(&account, key);
    assert!(multisig::outcome_status(outcome) == multisig::status_approved());
    assert!(multisig::matched_vote_path(outcome) == &option::some(2));

    destroy(account);
    end(scenario, registry, clock);
}

// ============================================================
// Scenario 4 — 3 auditors approve, founder cancels
// ============================================================
//
// Alice (founder) proposes the intent.
// Deloitte, Trail, Zellic approve (auditor effective = 30).
// Path 3: auditors 30 >= 30. SATISFIED. Intent becomes APPROVED.
// Alice (founder, weight 10) rejects — satisfies cancel_policy path 0 (founders >= 10)
// and vote-switches her approval. Status → REJECTED. Alice then finalizes the cancel.

#[test]
fun test_scenario_4_three_auditors_founder_cancels() {
    let (mut scenario, registry, clock) = start_with(ALICE);
    let mut account = create_spec_account(&mut scenario, &registry);

    // Alice (founder) creates the intent
    let key = create_test_intent(
        &mut account, &registry, &clock, b"scenario_4", scenario.ctx(),
    );

    // Deloitte approves — auditors = 10
    scenario.next_tx(DELOITTE);
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    let outcome = get_outcome(&account, key);
    assert!(multisig::outcome_status(outcome) == multisig::status_active());

    // Trail approves — auditors = 20, path 3 needs 30
    scenario.next_tx(TRAIL);
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    let outcome = get_outcome(&account, key);
    assert!(multisig::outcome_status(outcome) == multisig::status_active());

    // Zellic approves — auditors = 30
    // Path 3: auditors 30 >= 30. SATISFIED.
    scenario.next_tx(ZELLIC);
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    let outcome = get_outcome(&account, key);
    assert!(multisig::outcome_status(outcome) == multisig::status_approved());
    assert!(multisig::matched_vote_path(outcome) == &option::some(3));

    // Alice rejects — founder weight 10 satisfies cancel_policy path (founders >= 10).
    scenario.next_tx(ALICE);
    multisig::reject_intent(&mut account, key, &clock, scenario.ctx());
    let outcome = get_outcome(&account, key);
    assert!(multisig::outcome_status(outcome) == multisig::status_rejected());

    // Alice finalizes the cancellation.
    actions_staging::cancel_pending_actions(&mut account, key, &clock, scenario.ctx());

    // Intent should be removed from the account
    assert!(!account.intents().contains(key));

    destroy(account);
    end(scenario, registry, clock);
}

// ============================================================
// Bonus: Pure time escalation (1 founder + 180-day time band)
// ============================================================
//
// Alice approves (founder = 10). Not enough alone.
// 180 days pass. Time band adds 50 to founders.
// Bob approves, triggering re-check.
// Founders: 20 (members) + 50 (time band) = 70 >= 30.
// Path 2 (founders >= 30) is satisfied.

#[test]
fun test_time_band_pure_time_escalation() {
    let (mut scenario, registry, mut clock) = start_with(ALICE);
    let mut account = create_spec_account(&mut scenario, &registry);

    // Alice creates the intent
    let key = create_test_intent(
        &mut account, &registry, &clock, b"time_escalation", scenario.ctx(),
    );

    // Alice approves — founders = 10, no path satisfied
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    let outcome = get_outcome(&account, key);
    assert!(multisig::outcome_status(outcome) == multisig::status_active());

    // Advance clock by 180 days
    clock.increment_for_testing(ONE_EIGHTY_DAYS_MS);

    // Bob approves, triggering path re-check with 180 days elapsed
    // Founders: member weight 10 (Alice) + 10 (Bob) = 20 + time band 50 = 70
    // Path 0: founders 70 >= 10 but auditors 0 < 10. NOT satisfied.
    // Path 2: founders 70 >= 30. SATISFIED.
    scenario.next_tx(BOB);
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());

    let outcome = get_outcome(&account, key);
    assert!(multisig::outcome_status(outcome) == multisig::status_approved());
    assert!(multisig::matched_vote_path(outcome) == &option::some(2));

    destroy(account);
    end(scenario, registry, clock);
}
