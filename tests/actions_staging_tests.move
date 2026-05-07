#[test_only]
/// Tests for actions_staging + multisig::stage_intent.
/// Verifies max action spec enforcement and basic staging flow.
module account_multisig::actions_staging_tests;

use std::string::String;
use account_multisig::multisig::{Self, MultisigConfig, Approvals};
use account_multisig::actions_staging;
use account_multisig::config;
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
// === Test-only structs ===

/// Dummy action type for building test action specs.
public struct TestAction has drop {}
public struct StageIntentWitness has copy, drop {}

// === Helpers ===

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
    package_registry::add_for_testing(
        &mut registry,
        b"AccountProtocol".to_string(),
        @account_protocol,
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

fun create_account(scenario: &mut Scenario, registry: &PackageRegistry): Account {
    multisig::new_account_for_testing(registry, vector[], vector[], scenario.ctx())
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

fun make_specs(count: u64): vector<intents::ActionSpec> {
    let mut specs = vector[];
    let mut i = 0;
    while (i < count) {
        specs.push_back(intents::new_action_spec(TestAction {}, vector[], 1));
        i = i + 1;
    };
    specs
}

// === Tests ===

#[test]
fun test_request_actions_single_spec() {
    let (mut scenario, registry, clock) = start_with(ALICE);
    let mut account = create_account(&mut scenario, &registry);
    account::share_account(account);
    scenario.next_tx(ALICE);
    let mut account = scenario.take_shared<Account>();

    let auth = multisig::authenticate(&account, scenario.ctx());
    let params = new_params_from_account(
        &account,
        b"test_intent".to_string(),
        b"test".to_string(),
        &clock,
        scenario.ctx(),
    );

    let specs = make_specs(1);
    actions_staging::request_actions(
        auth, &mut account, &registry, params, specs, scenario.ctx(),
    );

    assert!(account.intents().contains(b"test_intent".to_string()));
    let intent = account.intents().get<Approvals>(b"test_intent".to_string());
    assert!(intent.action_count() == 1);

    ts::return_shared(account);
    end(scenario, registry, clock);
}

#[test]
fun test_request_actions_max_specs() {
    let (mut scenario, registry, clock) = start_with(ALICE);
    let mut account = create_account(&mut scenario, &registry);
    account::share_account(account);
    scenario.next_tx(ALICE);
    let mut account = scenario.take_shared<Account>();

    let auth = multisig::authenticate(&account, scenario.ctx());
    let params = new_params_from_account(
        &account,
        b"max_intent".to_string(),
        b"test".to_string(),
        &clock,
        scenario.ctx(),
    );

    // 10 specs = exactly at limit
    let specs = make_specs(10);
    actions_staging::request_actions(
        auth, &mut account, &registry, params, specs, scenario.ctx(),
    );

    let intent = account.intents().get<Approvals>(b"max_intent".to_string());
    assert!(intent.action_count() == 10);

    ts::return_shared(account);
    end(scenario, registry, clock);
}

#[test, expected_failure(abort_code = multisig::ETooManyActionSpecs)]
fun test_request_actions_too_many_specs() {
    let (mut scenario, registry, clock) = start_with(ALICE);
    let mut account = create_account(&mut scenario, &registry);
    account::share_account(account);
    scenario.next_tx(ALICE);
    let mut account = scenario.take_shared<Account>();

    let auth = multisig::authenticate(&account, scenario.ctx());
    let params = new_params_from_account(
        &account,
        b"too_many".to_string(),
        b"test".to_string(),
        &clock,
        scenario.ctx(),
    );

    // 11 specs = over limit
    let specs = make_specs(11);
    actions_staging::request_actions(
        auth, &mut account, &registry, params, specs, scenario.ctx(),
    );

    ts::return_shared(account);
    end(scenario, registry, clock);
}

#[test, expected_failure(abort_code = multisig::ENoActionSpecs)]
fun test_request_actions_empty_specs() {
    let (mut scenario, registry, clock) = start_with(ALICE);
    let mut account = create_account(&mut scenario, &registry);
    account::share_account(account);
    scenario.next_tx(ALICE);
    let mut account = scenario.take_shared<Account>();

    let auth = multisig::authenticate(&account, scenario.ctx());
    let params = new_params_from_account(
        &account,
        b"empty".to_string(),
        b"test".to_string(),
        &clock,
        scenario.ctx(),
    );

    let specs = vector[];
    actions_staging::request_actions(
        auth, &mut account, &registry, params, specs, scenario.ctx(),
    );

    ts::return_shared(account);
    end(scenario, registry, clock);
}

#[test]
fun test_stage_intent_accepts_action_from_package_added_to_global_registry() {
    let (mut scenario, mut registry, clock) = start_with(ALICE);
    let mut account = create_account(&mut scenario, &registry);

    package_registry::add_for_testing(
        &mut registry,
        b"FutarchyCore".to_string(),
        @futarchy_core,
        1,
    );

    let params = new_params_from_account(
        &account,
        b"future_pkg".to_string(),
        b"future package action".to_string(),
        &clock,
        scenario.ctx(),
    );
    let outcome = multisig::new_outcome(&account);
    let mut intent = account::create_intent(
        &account,
        &registry,
        params,
        outcome,
        account_multisig::version::current(),
        StageIntentWitness {},
        scenario.ctx(),
    );
    intents::add_existing_action_spec(
        &mut intent,
        intents::new_action_spec(TestAction {}, vector[], 1),
        StageIntentWitness {},
    );

    multisig::stage_intent(
        &mut account,
        &registry,
        intent,
        account_multisig::version::current(),
        StageIntentWitness {},
        scenario.ctx(),
    );

    destroy(account);
    end(scenario, registry, clock);
}

#[test, expected_failure(abort_code = multisig::EInvalidConfigChangeIntent)]
fun test_stage_intent_rejects_config_change_under_non_config_witness() {
    let (mut scenario, registry, clock) = start_with(ALICE);
    let mut account = create_account(&mut scenario, &registry);

    let params = new_params_from_account(
        &account,
        b"direct_smuggled_config".to_string(),
        b"direct smuggle test".to_string(),
        &clock,
        scenario.ctx(),
    );
    let outcome = multisig::new_outcome(&account);
    let mut intent = account::create_intent(
        &account,
        &registry,
        params,
        outcome,
        account_multisig::version::current(),
        StageIntentWitness {},
        scenario.ctx(),
    );
    intents::add_action_spec<_, config::ConfigChange, _>(
        &mut intent,
        config::config_change_marker(),
        vector[],
        StageIntentWitness {},
    );

    multisig::stage_intent(
        &mut account,
        &registry,
        intent,
        account_multisig::version::current(),
        StageIntentWitness {},
        scenario.ctx(),
    );

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
fun test_max_action_specs_constant() {
    assert!(multisig::max_action_specs_per_intent() == 10);
}

#[test]
fun test_cancel_pending_actions_closes_on_reaching_cancel_quorum() {
    let (mut scenario, registry, clock) = start_with(ALICE);
    let mut account = create_account(&mut scenario, &registry);
    account::share_account(account);
    scenario.next_tx(ALICE);
    let mut account = scenario.take_shared<Account>();

    let auth = multisig::authenticate(&account, scenario.ctx());
    let params = new_params_from_account(
        &account,
        b"cancel_me".to_string(),
        b"test cancel flow".to_string(),
        &clock,
        scenario.ctx(),
    );
    let specs = make_specs(1);
    actions_staging::request_actions(
        auth, &mut account, &registry, params, specs, scenario.ctx(),
    );

    let key = b"cancel_me".to_string();
    multisig::approve_intent(&mut account, key, &clock, scenario.ctx());
    // Vote-switch to reject so cancel_policy threshold (1) is met.
    multisig::reject_intent(&mut account, key, &clock, scenario.ctx());
    actions_staging::cancel_pending_actions(&mut account, key, &clock, scenario.ctx());
    assert!(!account.intents().contains(b"cancel_me".to_string()));

    ts::return_shared(account);
    end(scenario, registry, clock);
}

#[test]
fun test_cancel_stale_actions_closes_stale_intent() {
    let (mut scenario, registry, clock) = start_with(ALICE);
    let mut account = create_account(&mut scenario, &registry);

    let auth = multisig::authenticate(&account, scenario.ctx());
    let params = new_params_from_account(
        &account,
        b"cancel_stale".to_string(),
        b"test stale cancel".to_string(),
        &clock,
        scenario.ctx(),
    );
    let specs = make_specs(1);
    actions_staging::request_actions(
        auth, &mut account, &registry, params, specs, scenario.ctx(),
    );

    let cfg: &mut MultisigConfig = account::config_mut(
        &mut account, multisig::config_witness(),
    );
    multisig::set_config_nonce_for_testing(cfg, 1);

    actions_staging::cancel_stale_actions(
        &mut account, b"cancel_stale".to_string(), scenario.ctx(),
    );
    assert!(!account.intents().contains(b"cancel_stale".to_string()));

    destroy(account);
    end(scenario, registry, clock);
}

#[test]
fun test_cancel_expired_actions_closes_expired_intent() {
    let (mut scenario, registry, mut clock) = start_with(ALICE);
    let mut account = create_account(&mut scenario, &registry);
    let config: &mut MultisigConfig = account::config_mut(
        &mut account,
        multisig::config_witness(),
    );
    multisig::set_intent_expiry_for_testing(config, 1);
    account::share_account(account);
    scenario.next_tx(ALICE);
    let mut account = scenario.take_shared<Account>();

    let auth = multisig::authenticate(&account, scenario.ctx());
    let params = new_params_from_account(
        &account,
        b"cancel_expired".to_string(),
        b"test expired cancel".to_string(),
        &clock,
        scenario.ctx(),
    );
    let specs = make_specs(1);
    actions_staging::request_actions(
        auth, &mut account, &registry, params, specs, scenario.ctx(),
    );

    clock::increment_for_testing(&mut clock, 2);
    actions_staging::cancel_expired_actions(
        &mut account, b"cancel_expired".to_string(), &clock, scenario.ctx(),
    );
    assert!(!account.intents().contains(b"cancel_expired".to_string()));

    ts::return_shared(account);
    end(scenario, registry, clock);
}

// === Bug #4: cancel_stale_actions must reject ConfigChange intents ===

/// Helper: create a ConfigChange intent on an unshared account.
fun create_config_change_intent(
    account: &mut Account,
    registry: &PackageRegistry,
    clock: &Clock,
    key: vector<u8>,
    ctx: &mut TxContext,
) {
    let auth = multisig::authenticate(account, ctx);
    let params = new_params_from_account(
        account,
        key.to_string(),
        b"config change".to_string(),
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
        // Groups
        vector[b"default".to_string()],
        vector[1], // group_member_counts
        vector[ctx.sender()], // all_member_addresses
        vector[1], // all_member_weights
        vector[0], // time_band_counts
        vector[], // all_time_band_afters
        vector[], // all_time_band_weights
        // Approve policy
        vector[1], // approve_path_req_counts
        vector[0], // all_approve_group_indices
        vector[1], // all_approve_thresholds
        // Cancel policy
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
}

#[test, expected_failure(abort_code = actions_staging::EWrongCancelFunction)]
fun test_cancel_stale_actions_rejects_config_change_intent() {
    let (mut scenario, registry, clock) = start_with(ALICE);
    let mut account = create_account(&mut scenario, &registry);

    create_config_change_intent(
        &mut account, &registry, &clock, b"cfg_change", scenario.ctx(),
    );

    // Make the intent stale by bumping config nonce.
    let cfg: &mut MultisigConfig = account::config_mut(
        &mut account, multisig::config_witness(),
    );
    multisig::set_config_nonce_for_testing(cfg, 1);

    // Should abort: ConfigChange intents must use config::cancel_stale_config_change.
    actions_staging::cancel_stale_actions(
        &mut account, b"cfg_change".to_string(), scenario.ctx(),
    );

    destroy(account);
    end(scenario, registry, clock);
}

#[test, expected_failure(abort_code = actions_staging::EWrongCancelFunction)]
fun test_cancel_expired_actions_rejects_config_change_intent() {
    let (mut scenario, registry, mut clock) = start_with(ALICE);
    let mut account = create_account(&mut scenario, &registry);
    let config: &mut MultisigConfig = account::config_mut(
        &mut account,
        multisig::config_witness(),
    );
    multisig::set_intent_expiry_for_testing(config, 1);

    create_config_change_intent(
        &mut account, &registry, &clock, b"cfg_expired", scenario.ctx(),
    );

    clock::increment_for_testing(&mut clock, 2);
    // Should abort: ConfigChange intents must use config::cancel_expired_config_change.
    actions_staging::cancel_expired_actions(
        &mut account, b"cfg_expired".to_string(), &clock, scenario.ctx(),
    );

    destroy(account);
    end(scenario, registry, clock);
}

#[test, expected_failure(abort_code = actions_staging::EWrongCancelFunction)]
fun test_cancel_pending_actions_rejects_config_change_intent() {
    let (mut scenario, registry, clock) = start_with(ALICE);
    let mut account = create_account(&mut scenario, &registry);

    create_config_change_intent(
        &mut account, &registry, &clock, b"cfg_pending", scenario.ctx(),
    );

    // Approve it first (required by cancel_pending).
    multisig::approve_intent(
        &mut account, b"cfg_pending".to_string(), &clock, scenario.ctx(),
    );

    // Should abort: ConfigChange intents must use config::cancel_pending_config_change.
    actions_staging::cancel_pending_actions(
        &mut account, b"cfg_pending".to_string(), &clock, scenario.ctx(),
    );

    destroy(account);
    end(scenario, registry, clock);
}

// === ConfigChange smuggling via request_actions ===

#[test, expected_failure(abort_code = actions_staging::EConfigChangeNotAllowed)]
/// ConfigChange action specs passed to request_actions must be blocked.
/// The actions_staging module checks each spec and rejects ConfigChange types
/// to prevent smuggling config changes outside the dedicated config flow.
fun test_request_actions_rejects_config_change_spec() {
    let (mut scenario, registry, clock) = start_with(ALICE);
    let mut account = create_account(&mut scenario, &registry);
    account::share_account(account);
    scenario.next_tx(ALICE);
    let mut account = scenario.take_shared<Account>();

    let auth = multisig::authenticate(&account, scenario.ctx());
    let params = new_params_from_account(
        &account,
        b"smuggled_config".to_string(),
        b"smuggle test".to_string(),
        &clock,
        scenario.ctx(),
    );

    // Build specs with a ConfigChange action — should be rejected
    let specs = vector[intents::new_action_spec(config::config_change_marker(), vector[], 1)];
    actions_staging::request_actions(
        auth, &mut account, &registry, params, specs, scenario.ctx(),
    );

    ts::return_shared(account);
    end(scenario, registry, clock);
}
