#[test_only]
module account_multisig::config_tests;

use std::string::String;
use account_multisig::multisig::{Self, MultisigConfig};
use account_multisig::config;
use account_multisig::actions_staging;
use account_protocol::account::{Self, Account};
use account_protocol::intents;
use account_protocol::package_registry::{
    Self as package_registry,
    PackageRegistry,
    PackageAdminCap
};
use sui::bcs;
use sui::clock::{Self, Clock};
use sui::event;
use sui::test_scenario::{Self as ts, Scenario};
use sui::test_utils::destroy;

// === Constants ===

const OWNER: address = @0xCAFE;
const MEMBER_A: address = @0xA;
const MEMBER_B: address = @0xB;
const DEFAULT_INTENT_EXPIRY_MS: u64 = 7 * 24 * 60 * 60 * 1000;

// === Helpers ===

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
        0,
        clock,
        ctx,
    )
}

/// Helper to propose a config change intent with a single group and return the key.
fun propose_config_change(
    account: &mut Account,
    registry: &PackageRegistry,
    clock: &Clock,
    key: vector<u8>,
    addresses: vector<address>,
    weights: vector<u64>,
    threshold: u64,
    ctx: &mut TxContext,
): String {
    let key_str = key.to_string();
    let auth = multisig::authenticate(account, ctx);
    let params = new_params_from_account(
        account,
        key_str,
        b"Config change".to_string(),
        clock,
        ctx,
    );
    let intent_expiry_ms = {
        let config_ref: &MultisigConfig = account::config(account);
        multisig::intent_expiry_ms(config_ref)
    };
    let num_members = addresses.length();
    config::request_config_change(
        auth,
        account,
        registry,
        params,
        // Groups: single group "default"
        vector[b"default".to_string()],
        vector[num_members],
        addresses,
        weights,
        vector[0], // no time bands
        vector[],
        vector[],
        // Approve policy: single path
        vector[1],
        vector[0],
        vector[threshold],
        // Cancel policy: single path (symmetric — mirrors approve threshold)
        vector[1],
        vector[0],
        vector[threshold],
        // Permission groups
        vector[0],
        vector[0],
        vector[0],
        // Timing
        intent_expiry_ms,
        ctx,
    );
    key_str
}

fun propose_config_change_with_vote_policy(
    account: &mut Account,
    registry: &PackageRegistry,
    clock: &Clock,
    key: vector<u8>,
    vote_path_req_counts: vector<u64>,
    all_vote_group_indices: vector<u64>,
    all_vote_thresholds: vector<u64>,
    ctx: &mut TxContext,
): String {
    let key_str = key.to_string();
    let auth = multisig::authenticate(account, ctx);
    let params = new_params_from_account(
        account,
        key_str,
        b"Config change".to_string(),
        clock,
        ctx,
    );
    let intent_expiry_ms = {
        let config_ref: &MultisigConfig = account::config(account);
        multisig::intent_expiry_ms(config_ref)
    };
    // Approve and cancel get the same flat vectors — this helper predates the
    // split and is used for tests of shared policy shape.
    config::request_config_change(
        auth,
        account,
        registry,
        params,
        vector[b"default".to_string()],
        vector[1],
        vector[OWNER],
        vector[1],
        vector[0],
        vector[],
        vector[],
        vote_path_req_counts,
        all_vote_group_indices,
        all_vote_thresholds,
        vote_path_req_counts,
        all_vote_group_indices,
        all_vote_thresholds,
        vector[0],
        vector[0],
        vector[0],
        intent_expiry_ms,
        ctx,
    );
    key_str
}

/// Helper to stage a raw ConfigChange action spec without managed-data setup.
/// Used to test defensive checks in execute_config_change.
fun propose_raw_config_action(
    account: &mut Account,
    registry: &PackageRegistry,
    clock: &Clock,
    intent_key: vector<u8>,
    spec_intent_key: vector<u8>,
    spec_version: u8,
    ctx: &mut TxContext,
): String {
    let key_str = intent_key.to_string();
    let auth = multisig::authenticate(account, ctx);
    let params = new_params_from_account(
        account,
        key_str,
        b"Raw config action".to_string(),
        clock,
        ctx,
    );
    let action_data = bcs::to_bytes(&spec_intent_key.to_string());
    let spec = intents::new_action_spec(config::config_change_marker(), action_data, spec_version);
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

// === Tests ===

#[test]
fun test_new_account_for_testing_defaults_intent_expiry() {
    let (mut scenario, registry, clock) = start();
    let account = multisig::new_account_for_testing(&registry, vector[], vector[], scenario.ctx());
    let config: &MultisigConfig = account::config(&account);

    assert!(multisig::intent_expiry_ms(config) == DEFAULT_INTENT_EXPIRY_MS);

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
#[expected_failure(abort_code = multisig::EEmptyPolicyPath)]
fun test_request_config_change_rejects_empty_vote_path() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(&registry, vector[], vector[], scenario.ctx());

    propose_config_change_with_vote_policy(
        &mut account,
        &registry,
        &clock,
        b"empty_vote_path",
        vector[0],
        vector[],
        vector[],
        scenario.ctx(),
    );

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
#[expected_failure(abort_code = multisig::EZeroPathThreshold)]
fun test_request_config_change_rejects_zero_vote_threshold() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(&registry, vector[], vector[], scenario.ctx());

    propose_config_change_with_vote_policy(
        &mut account,
        &registry,
        &clock,
        b"zero_vote_threshold",
        vector[1],
        vector[0],
        vector[0],
        scenario.ctx(),
    );

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
#[expected_failure(abort_code = multisig::ETimeBandAfterIntentExpiry)]
fun test_request_config_change_rejects_time_band_at_new_expiry() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(&registry, vector[], vector[], scenario.ctx());

    let key = b"time_band_at_new_expiry".to_string();
    let auth = multisig::authenticate(&account, scenario.ctx());
    let params = new_params_from_account(
        &account,
        key,
        b"Config change".to_string(),
        &clock,
        scenario.ctx(),
    );

    config::request_config_change(
        auth,
        &mut account,
        &registry,
        params,
        vector[b"default".to_string()],
        vector[1],
        vector[OWNER],
        vector[1],
        vector[1],
        vector[1000],
        vector[1],
        vector[1],
        vector[0],
        vector[1],
        vector[1],
        vector[0],
        vector[1],
        vector[0],
        vector[0],
        vector[0],
        1000,
        scenario.ctx(),
    );

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
fun test_config_change_add_member() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(&registry, vector[], vector[], scenario.ctx());

    // Propose: add MEMBER_A to the multisig
    let key = propose_config_change(
        &mut account, &registry, &clock, b"add_member",
        vector[OWNER, MEMBER_A],
        vector[1, 1],
        1,
        scenario.ctx(),
    );

    // Approve and execute
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    let mut executable = multisig::execute_intent(
        &mut account, &registry, key, &clock, scenario.ctx(),
    );
    config::execute_config_change(&mut executable, &mut account, &registry);
    account.confirm_execution(executable);

    // Verify new config
    let config: &MultisigConfig = account::config(&account);
    assert!(multisig::group_count(config) == 1);
    let group = multisig::group_at(config, 0);
    assert!(multisig::group_members(group).length() == 2);
    assert!(multisig::is_member_of_any_group(config, OWNER));
    assert!(multisig::is_member_of_any_group(config, MEMBER_A));
    assert!(multisig::config_nonce(config) == 1);

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
fun test_config_changed_event_includes_config_nonce() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(&registry, vector[], vector[], scenario.ctx());

    let key = propose_config_change(
        &mut account, &registry, &clock, b"event_test",
        vector[OWNER],
        vector[1],
        1,
        scenario.ctx(),
    );

    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    let mut executable = multisig::execute_intent(
        &mut account, &registry, key, &clock, scenario.ctx(),
    );
    config::execute_config_change(&mut executable, &mut account, &registry);
    account.confirm_execution(executable);

    let events = event::events_by_type<multisig::ConfigChangedEvent>();
    assert!(events.length() == 1);
    let emitted = &events[0];
    assert!(multisig::config_changed_event_config_nonce(emitted) == 1);

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
fun test_config_change_remove_member() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(&registry, vector[], vector[], scenario.ctx());

    // First add MEMBER_A
    let key1 = propose_config_change(
        &mut account, &registry, &clock, b"add",
        vector[OWNER, MEMBER_A],
        vector[1, 1],
        1,
        scenario.ctx(),
    );
    multisig::approve_intent(&mut account, key1, &clock, scenario.ctx());
    let mut exec1 = multisig::execute_intent(
        &mut account, &registry, key1, &clock, scenario.ctx(),
    );
    config::execute_config_change(&mut exec1, &mut account, &registry);
    account.confirm_execution(exec1);

    // Now propose removing MEMBER_A (back to just OWNER)
    let key2 = propose_config_change(
        &mut account, &registry, &clock, b"remove",
        vector[OWNER],
        vector[1],
        1,
        scenario.ctx(),
    );
    multisig::approve_intent(&mut account, key2, &clock, scenario.ctx());
    let mut exec2 = multisig::execute_intent(
        &mut account, &registry, key2, &clock, scenario.ctx(),
    );
    config::execute_config_change(&mut exec2, &mut account, &registry);
    account.confirm_execution(exec2);

    let config: &MultisigConfig = account::config(&account);
    assert!(multisig::group_count(config) == 1);
    let group = multisig::group_at(config, 0);
    assert!(multisig::group_members(group).length() == 1);
    assert!(multisig::is_member_of_any_group(config, OWNER));
    assert!(!multisig::is_member_of_any_group(config, MEMBER_A));
    assert!(multisig::config_nonce(config) == 2);

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
fun test_config_change_update_threshold() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(&registry, vector[], vector[], scenario.ctx());

    // Add MEMBER_A and raise threshold to 2
    let key = propose_config_change(
        &mut account, &registry, &clock, b"update_thresh",
        vector[OWNER, MEMBER_A],
        vector[1, 1],
        2, // new threshold
        scenario.ctx(),
    );
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    let mut executable = multisig::execute_intent(
        &mut account, &registry, key, &clock, scenario.ctx(),
    );
    config::execute_config_change(&mut executable, &mut account, &registry);
    account.confirm_execution(executable);

    let config: &MultisigConfig = account::config(&account);
    let approve_paths = multisig::policy_paths(multisig::approve_policy(config));
    let reqs = multisig::path_requirements(&approve_paths[0]);
    assert!(multisig::requirement_threshold(&reqs[0]) == 2);

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
fun test_config_change_nonce_bump_invalidates_pending() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(&registry, vector[], vector[], scenario.ctx());

    // Create two intents
    let key1 = propose_config_change(
        &mut account, &registry, &clock, b"change1",
        vector[OWNER],
        vector[1],
        1,
        scenario.ctx(),
    );
    let key2 = propose_config_change(
        &mut account, &registry, &clock, b"change2",
        vector[OWNER, MEMBER_A],
        vector[1, 1],
        1,
        scenario.ctx(),
    );

    // Execute first -- nonce bumps to 1
    multisig::approve_intent(&mut account, key1, &clock, scenario.ctx());
    let mut exec1 = multisig::execute_intent(
        &mut account, &registry, key1, &clock, scenario.ctx(),
    );
    config::execute_config_change(&mut exec1, &mut account, &registry);
    account.confirm_execution(exec1);

    // Second intent is now stale -- cancel via config wrapper (cleans up managed data)
    config::cancel_stale_config_change(&mut account, &registry, key2, scenario.ctx());

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
fun test_config_change_update_weights() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(&registry, vector[], vector[], scenario.ctx());

    // Change OWNER's weight from 1 to 5
    let key = propose_config_change(
        &mut account, &registry, &clock, b"update_weight",
        vector[OWNER],
        vector[5],
        3, // threshold now 3, OWNER weight 5 so still reachable
        scenario.ctx(),
    );
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    let mut executable = multisig::execute_intent(
        &mut account, &registry, key, &clock, scenario.ctx(),
    );
    config::execute_config_change(&mut executable, &mut account, &registry);
    account.confirm_execution(executable);

    let config: &MultisigConfig = account::config(&account);
    let group = multisig::group_at(config, 0);
    let members = multisig::group_members(group);
    assert!(multisig::member_weight(&members[0]) == 5);

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
fun test_delete_config_change_cleanup() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(&registry, vector[], vector[], scenario.ctx());

    // Create an intent
    let key = propose_config_change(
        &mut account, &registry, &clock, b"to_delete",
        vector[OWNER],
        vector[1],
        1,
        scenario.ctx(),
    );

    // Make it stale by bumping nonce
    let config: &mut MultisigConfig = account::config_mut(
        &mut account, multisig::config_witness(),
    );
    multisig::set_config_nonce_for_testing(config, 1);

    // Cancel and delete -- should clean up proposed config from managed data
    config::cancel_stale_config_change(&mut account, &registry, key, scenario.ctx());

    // Account should be clean
    destroy(account);
    end(scenario, registry, clock);
}

#[test]
fun test_cancel_pending_config_change_wrapper_cleans_managed_data() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(&registry, vector[], vector[], scenario.ctx());

    let key1 = propose_config_change(
        &mut account, &registry, &clock, b"reuse_pending_key",
        vector[OWNER],
        vector[1],
        1,
        scenario.ctx(),
    );
    multisig::approve_intent(&mut account, key1, &clock, scenario.ctx());
    // Vote-switch to reject to satisfy cancel_policy (threshold 1).
    multisig::reject_intent(&mut account, key1, &clock, scenario.ctx());
    config::cancel_pending_config_change(&mut account, &registry, key1, &clock, scenario.ctx());

    // Reusing the same key should succeed only if staged managed data was deleted.
    let key2 = propose_config_change(
        &mut account, &registry, &clock, b"reuse_pending_key",
        vector[OWNER],
        vector[1],
        1,
        scenario.ctx(),
    );
    multisig::approve_intent(&mut account, key2, &clock, scenario.ctx());
    multisig::reject_intent(&mut account, key2, &clock, scenario.ctx());
    config::cancel_pending_config_change(&mut account, &registry, key2, &clock, scenario.ctx());

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
fun test_cleanup_expired_config_changes_batch() {
    let (mut scenario, registry, mut clock) = start();
    let mut account = multisig::new_account_for_testing(&registry, vector[], vector[], scenario.ctx());
    let config: &mut MultisigConfig = account::config_mut(
        &mut account,
        multisig::config_witness(),
    );
    multisig::set_intent_expiry_for_testing(config, 1);

    let key1 = propose_config_change(
        &mut account, &registry, &clock, b"batch_expired_1",
        vector[OWNER],
        vector[1],
        1,
        scenario.ctx(),
    );
    let key2 = propose_config_change(
        &mut account, &registry, &clock, b"batch_expired_2",
        vector[OWNER],
        vector[1],
        1,
        scenario.ctx(),
    );

    clock::increment_for_testing(&mut clock, 2);
    let cleaned1 = config::cleanup_expired_config_changes(
        &mut account,
        &registry,
        vector[key1, key2],
        1,
        &clock,
        scenario.ctx(),
    );
    assert!(cleaned1 == 1);

    let cleaned2 = config::cleanup_expired_config_changes(
        &mut account,
        &registry,
        vector[key1, key2],
        10,
        &clock,
        scenario.ctx(),
    );
    assert!(cleaned2 == 1);

    // Both keys should now be reusable.
    let key3 = propose_config_change(
        &mut account, &registry, &clock, b"batch_expired_1",
        vector[OWNER],
        vector[1],
        1,
        scenario.ctx(),
    );
    let key4 = propose_config_change(
        &mut account, &registry, &clock, b"batch_expired_2",
        vector[OWNER],
        vector[1],
        1,
        scenario.ctx(),
    );
    multisig::approve_intent(&mut account, key3, &clock, scenario.ctx());
    multisig::approve_intent(&mut account, key4, &clock, scenario.ctx());
    // Vote-switch to reject so cancel_policy threshold (1) is met.
    multisig::reject_intent(&mut account, key3, &clock, scenario.ctx());
    multisig::reject_intent(&mut account, key4, &clock, scenario.ctx());
    config::cancel_pending_config_change(&mut account, &registry, key3, &clock, scenario.ctx());
    config::cancel_pending_config_change(&mut account, &registry, key4, &clock, scenario.ctx());

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
#[expected_failure(abort_code = config::ECleanupLimitExceeded)]
fun test_cleanup_expired_config_changes_limit_guard() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(&registry, vector[], vector[], scenario.ctx());

    let too_many = config::max_cleanup_per_call() + 1;
    let _ = config::cleanup_expired_config_changes(
        &mut account,
        &registry,
        vector[],
        too_many,
        &clock,
        scenario.ctx(),
    );

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
#[expected_failure(abort_code = actions_staging::EConfigChangeNotAllowed)]
fun test_request_actions_rejects_config_change_specs() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(&registry, vector[], vector[], scenario.ctx());

    // Attempting to smuggle a ConfigChange spec into a generic ActionsIntent
    // should be rejected at proposal time.
    let _key = propose_raw_config_action(
        &mut account,
        &registry,
        &clock,
        b"smuggled_config_change",
        b"smuggled_config_change",
        1,
        scenario.ctx(),
    );

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
fun test_cleanup_expired_config_changes_skips_non_config_intent() {
    let (mut scenario, registry, mut clock) = start();
    let mut account = multisig::new_account_for_testing(&registry, vector[], vector[], scenario.ctx());
    let config: &mut MultisigConfig = account::config_mut(
        &mut account,
        multisig::config_witness(),
    );
    multisig::set_intent_expiry_for_testing(config, 1);

    let key = b"non_config_cleanup".to_string();
    let auth = multisig::authenticate(&account, scenario.ctx());
    let params = new_params_from_account(
        &account,
        key,
        b"Non-config action".to_string(),
        &clock,
        scenario.ctx(),
    );
    let spec = intents::new_action_spec(PoisonPillAction {}, vector[], 1);
    actions_staging::request_actions(
        auth,
        &mut account,
        &registry,
        params,
        vector[spec],
        scenario.ctx(),
    );

    clock::increment_for_testing(&mut clock, 2);
    let cleaned = config::cleanup_expired_config_changes(
        &mut account,
        &registry,
        vector[b"non_config_cleanup".to_string()],
        1,
        &clock,
        scenario.ctx(),
    );
    assert!(cleaned == 0);
    assert!(account.intents().contains(b"non_config_cleanup".to_string()));

    actions_staging::cancel_expired_actions(
        &mut account,
        b"non_config_cleanup".to_string(),
        &clock,
        scenario.ctx(),
    );

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
fun test_sequential_config_changes() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(&registry, vector[], vector[], scenario.ctx());

    // Change 1: add MEMBER_A
    let key1 = propose_config_change(
        &mut account, &registry, &clock, b"change1",
        vector[OWNER, MEMBER_A],
        vector[1, 1],
        1,
        scenario.ctx(),
    );
    multisig::approve_intent(&mut account, key1, &clock, scenario.ctx());
    let mut exec1 = multisig::execute_intent(
        &mut account, &registry, key1, &clock, scenario.ctx(),
    );
    config::execute_config_change(&mut exec1, &mut account, &registry);
    account.confirm_execution(exec1);
    let cfg: &MultisigConfig = account::config(&account);
    assert!(multisig::config_nonce(cfg) == 1);

    // Change 2: add MEMBER_B (proposed by OWNER who is still a member)
    let key2 = propose_config_change(
        &mut account, &registry, &clock, b"change2",
        vector[OWNER, MEMBER_A, MEMBER_B],
        vector[1, 1, 1],
        2,
        scenario.ctx(),
    );
    multisig::approve_intent(&mut account, key2, &clock, scenario.ctx());

    let mut exec2 = multisig::execute_intent(
        &mut account, &registry, key2, &clock, scenario.ctx(),
    );
    config::execute_config_change(&mut exec2, &mut account, &registry);
    account.confirm_execution(exec2);

    let config: &MultisigConfig = account::config(&account);
    let group = multisig::group_at(config, 0);
    assert!(multisig::group_members(group).length() == 3);
    assert!(multisig::config_nonce(config) == 2);

    destroy(account);
    end(scenario, registry, clock);
}

// === Bug 4 regression: poison-pill multi-action config intent staging ===

/// Dummy action type to simulate a trailing non-ConfigChange action in a config intent.
public struct PoisonPillAction has drop {}

#[test, expected_failure(abort_code = multisig::EInvalidConfigChangeIntent)]
/// Verify that staging rejects config change intents with trailing extra actions.
fun test_stage_multi_action_config_intent_aborts() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(&registry, vector[], vector[], scenario.ctx());

    // Build a config intent with TWO actions: ConfigChange + PoisonPillAction
    let intent_key = b"poison_pill".to_string();
    let outcome = multisig::new_outcome(&account);
    let params = multisig::new_params_from_config(
        &account, intent_key, b"Poison pill test".to_string(), 0, &clock, scenario.ctx(),
    );
    let iw = config::config_change_intent_witness();

    // Build proposed config to store as managed data
    let new_config = multisig::new_config(
        vector[
            multisig::new_group(
                b"default".to_string(),
                vector[multisig::new_group_member(OWNER, 1)],
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
        DEFAULT_INTENT_EXPIRY_MS,
    );
    account::add_managed_data_with_package_witness(
        &mut account,
        &registry,
        multisig::new_proposed_config_key(intent_key),
        new_config,
        account_multisig::version::current(),
    );

    // Create intent and add TWO action specs
    let mut intent = account::create_intent(
        &account, &registry, params, outcome,
        account_multisig::version::current(), copy iw, scenario.ctx(),
    );
    // Action 1: legitimate ConfigChange
    let action_data = bcs::to_bytes(&intent_key);
    intents::add_action_spec<_, config::ConfigChange, _>(
        &mut intent, config::config_change_marker(), action_data, copy iw,
    );
    // Action 2: trailing poison pill
    intents::add_action_spec<_, PoisonPillAction, _>(
        &mut intent, PoisonPillAction {}, vector[], copy iw,
    );

    multisig::stage_intent(
        &mut account, &registry, intent,
        account_multisig::version::current(), iw, scenario.ctx(),
    );

    destroy(account);
    end(scenario, registry, clock);
}

#[test, expected_failure(abort_code = multisig::EInvalidConfigChangeIntent)]
/// Verify that the config-change witness cannot stage non-config action specs.
fun test_stage_config_witness_non_config_action_aborts() {
    let (mut scenario, registry, clock) = start();
    let mut account = multisig::new_account_for_testing(&registry, vector[], vector[], scenario.ctx());

    let intent_key = b"wrong_config_witness_action".to_string();
    let outcome = multisig::new_outcome(&account);
    let params = multisig::new_params_from_config(
        &account,
        intent_key,
        b"Wrong config witness action".to_string(),
        0,
        &clock,
        scenario.ctx(),
    );
    let iw = config::config_change_intent_witness();
    let mut intent = account::create_intent(
        &account,
        &registry,
        params,
        outcome,
        account_multisig::version::current(),
        copy iw,
        scenario.ctx(),
    );
    intents::add_action_spec<_, PoisonPillAction, _>(
        &mut intent,
        PoisonPillAction {},
        vector[],
        copy iw,
    );

    multisig::stage_intent(
        &mut account,
        &registry,
        intent,
        account_multisig::version::current(),
        iw,
        scenario.ctx(),
    );

    destroy(account);
    end(scenario, registry, clock);
}
