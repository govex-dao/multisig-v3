// Copyright (c) Govex DAO LLC
// SPDX-License-Identifier: BUSL-1.1

/// Config change action for multisig accounts.
///
/// Allows modifying the multisig configuration (groups, policies, roles)
/// via an approved intent. The entire config is replaced atomically.
///
/// The proposed config is validated at proposal time and stored as managed data
/// on the account. At execution, the stored config is applied and config_nonce
/// is bumped, invalidating all other pending intents.
///
/// Flow:
/// 1. A Proposer calls `request_config_change` with new config params
/// 2. Voters approve the intent via `multisig::approve_intent`
/// 3. An Executor calls `execute_config_change` to apply it

module account_multisig::config;

use std::string::{Self, String};
use account_protocol::account::{Self, Account, Auth};
use account_protocol::executable::{Self, Executable};
use account_protocol::intents::{Self, Expired, Params};
use account_protocol::package_registry::PackageRegistry;
use account_multisig::multisig::{Self, MultisigConfig, Approvals, ProposedConfigKey};
use account_multisig::version;
use sui::bcs;
use sui::clock::Clock;

// === Structs ===

/// Execution progress witness for config change actions.
public struct ExecutionProgressWitness has drop {}

/// Intent witness for config changes.
public struct ConfigChangeIntent() has copy, drop;

/// Action type marker. The actual config data is stored as managed data.
public struct ConfigChange has drop {}

// === Errors ===

const EUnsupportedActionVersion: u64 = 0;
const EIntentKeyMismatch: u64 = 1;
const ECleanupLimitExceeded: u64 = 2;
const EConfigChangeActionCountMismatch: u64 = 3;

const MAX_CLEANUP_PER_CALL: u64 = 128;

// === Public Functions ===

/// Propose a config change. Caller must have Propose permission.
/// Uses flat vectors with count arrays for nested structure.
///
/// Groups are specified via:
///   group_names[i] = name of group i
///   group_member_counts[i] = number of members in group i
///   all_member_addresses = concatenated member addresses for all groups
///   all_member_weights = concatenated member weights for all groups
///   time_band_counts[i] = number of time bands for group i
///   all_time_band_afters = concatenated time band after_ms for all groups
///   all_time_band_weights = concatenated time band weights for all groups
///
/// Approve and cancel policies are independent; each has its own path-count /
/// group-index / threshold flat vectors:
///   approve_path_req_counts[j] = number of requirements in approve path j
///   all_approve_group_indices / all_approve_thresholds = concatenated requirements
///   cancel_path_req_counts[j]  = number of requirements in cancel path j
///   all_cancel_group_indices / all_cancel_thresholds   = concatenated requirements
public fun request_config_change(
    auth: Auth,
    account: &mut Account,
    registry: &PackageRegistry,
    params: Params,
    // Groups
    group_names: vector<String>,
    group_member_counts: vector<u64>,
    all_member_addresses: vector<address>,
    all_member_weights: vector<u64>,
    time_band_counts: vector<u64>,
    all_time_band_afters: vector<u64>,
    all_time_band_weights: vector<u64>,
    // Approve policy
    approve_path_req_counts: vector<u64>,
    all_approve_group_indices: vector<u64>,
    all_approve_thresholds: vector<u64>,
    // Cancel policy
    cancel_path_req_counts: vector<u64>,
    all_cancel_group_indices: vector<u64>,
    all_cancel_thresholds: vector<u64>,
    // Permission groups
    propose_groups: vector<u64>,
    execute_groups: vector<u64>,
    cancel_groups: vector<u64>,
    // Timing
    intent_expiry_ms: u64,
    ctx: &mut TxContext,
) {
    account.verify(auth);
    multisig::assert_sender_can_propose(account, ctx.sender());
    let outcome = multisig::new_outcome(account);
    intents::assert_single_execution(&params);

    let new_config = multisig::build_config_from_flat_vectors(
        group_names,
        group_member_counts,
        all_member_addresses,
        all_member_weights,
        time_band_counts,
        all_time_band_afters,
        all_time_band_weights,
        approve_path_req_counts,
        all_approve_group_indices,
        all_approve_thresholds,
        cancel_path_req_counts,
        all_cancel_group_indices,
        all_cancel_thresholds,
        propose_groups,
        execute_groups,
        cancel_groups,
        intent_expiry_ms,
    );

    let intent_key = params.key();
    let intent_description = params.description();
    let action_data = bcs::to_bytes(&intent_key);

    account::add_managed_data_with_package_witness(
        account,
        registry,
        multisig::new_proposed_config_key(intent_key),
        new_config,
        version::current(),
    );

    let iw = ConfigChangeIntent();
    let mut intent = account::create_intent(
        account,
        registry,
        params,
        outcome,
        version::current(),
        copy iw,
        ctx,
    );
    intents::add_action_spec<_, ConfigChange, _>(
        &mut intent,
        ConfigChange {},
        action_data,
        copy iw,
    );
    multisig::stage_intent(account, registry, intent, version::current(), iw, ctx);

    multisig::emit_intent_created(account, intent_key, intent_description, ctx.sender());
}

/// Execute the config change. Replaces the entire MultisigConfig.
/// Bumps config_nonce which invalidates all other pending intents.
public fun execute_config_change(
    executable: &mut Executable<Approvals>,
    account: &mut Account,
    registry: &PackageRegistry,
) {
    executable.intent().assert_is_account(account::addr(account));

    let specs = executable.intent().action_specs();
    assert!(specs.length() == 1, EConfigChangeActionCountMismatch);
    let action_spec = specs.borrow(executable.action_idx());
    account_protocol::action_validation::assert_action_type<ConfigChange>(action_spec);

    let spec_version = account_protocol::intents::action_spec_version(action_spec);
    assert!(spec_version == 1, EUnsupportedActionVersion);

    let action_data = account_protocol::intents::action_spec_data(action_spec);
    let mut reader = bcs::new(*action_data);
    let intent_key = string::utf8(bcs::peel_vec_u8(&mut reader));
    account_protocol::bcs_validation::validate_all_bytes_consumed(reader);
    let expected_intent_key = executable.intent().key();
    assert!(intent_key == expected_intent_key, EIntentKeyMismatch);

    let key = multisig::new_proposed_config_key(intent_key);
    let mut new_config: MultisigConfig = account::remove_managed_data<
        ProposedConfigKey,
        MultisigConfig,
        Approvals,
        ExecutionProgressWitness,
    >(account, registry, key, executable, ExecutionProgressWitness {});

    let config_ref = account::config_mut_authorized<MultisigConfig>(
        account, registry, version::current(),
    );
    let next_nonce = config_ref.config_nonce() + 1;
    new_config.set_config_nonce(next_nonce);
    *config_ref = new_config;

    multisig::emit_config_changed(account);

    executable::increment_action_idx<_, ConfigChange, _>(executable, registry, ExecutionProgressWitness {});
}

/// Cast a cancellation vote for an approved config change.
public fun cancel_pending_config_change(
    account: &mut Account,
    registry: &PackageRegistry,
    key: String,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let mut expired = multisig::cancel_pending_intent_for_cleanup(account, key, clock, ctx);
    delete_config_change(account, registry, &mut expired);
    intents::drain_and_destroy_expired(expired);
}

/// Cancel a stale config change and delete its staged managed data.
public fun cancel_stale_config_change(
    account: &mut Account,
    registry: &PackageRegistry,
    key: String,
    ctx: &mut TxContext,
) {
    let mut expired = multisig::cancel_stale_intent_for_cleanup(account, key, ctx);
    delete_config_change(account, registry, &mut expired);
    intents::drain_and_destroy_expired(expired);
}

/// Cancel a rejected config change.
public fun cancel_rejected_config_change(
    account: &mut Account,
    registry: &PackageRegistry,
    key: String,
    ctx: &mut TxContext,
) {
    let mut expired = multisig::cancel_rejected_intent_for_cleanup(account, key, ctx);
    delete_config_change(account, registry, &mut expired);
    intents::drain_and_destroy_expired(expired);
}

/// Delete an expired config change.
public fun cancel_expired_config_change(
    account: &mut Account,
    registry: &PackageRegistry,
    key: String,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let mut expired = multisig::cancel_expired_intent_for_cleanup(account, key, clock, ctx);
    delete_config_change(account, registry, &mut expired);
    intents::drain_and_destroy_expired(expired);
}

/// Best-effort janitor for expired config-change intents.
public fun cleanup_expired_config_changes(
    account: &mut Account,
    registry: &PackageRegistry,
    keys: vector<String>,
    max_to_clean: u64,
    clock: &Clock,
    ctx: &mut TxContext,
): u64 {
    assert!(max_to_clean <= MAX_CLEANUP_PER_CALL, ECleanupLimitExceeded);
    let mut cleaned = 0u64;
    let mut i = 0u64;
    while (i < keys.length() && cleaned < max_to_clean) {
        let key = keys[i];
        let should_cleanup = {
            let intents_store = account::intents(account);
            if (!intents::contains(intents_store, key)) {
                false
            } else {
                let intent = intents::get<Approvals>(intents_store, key);
                if (clock.timestamp_ms() < intent.expiration_time()) {
                    false
                } else {
                    let specs = intent.action_specs();
                    if (
                        specs.length() > 0 &&
                            account_protocol::action_validation::is_action_type<ConfigChange>(&specs[0])
                    ) {
                        assert!(specs.length() == 1, EConfigChangeActionCountMismatch);
                        true
                    } else {
                        false
                    }
                }
            }
        };

        if (should_cleanup) {
            let mut expired = multisig::cancel_expired_intent_for_cleanup(
                account, key, clock, ctx,
            );
            delete_config_change(account, registry, &mut expired);
            intents::drain_and_destroy_expired(expired);
            cleaned = cleaned + 1;
        };

        i = i + 1;
    };

    cleaned
}

/// Upper bound for cleanup_expired_config_changes max_to_clean.
public fun max_cleanup_per_call(): u64 {
    MAX_CLEANUP_PER_CALL
}

/// Clean up a config change from an expired/cancelled intent.
public fun delete_config_change(
    account: &mut Account,
    registry: &PackageRegistry,
    expired: &mut Expired,
) {
    expired.assert_is_account(account::addr(account));
    assert!(intents::expired_action_count(expired) == 1, EConfigChangeActionCountMismatch);
    let (action_spec, _executed) = expired.remove_action_spec();
    account_protocol::action_validation::assert_action_type<ConfigChange>(&action_spec);

    let spec_version = account_protocol::intents::action_spec_version(&action_spec);
    assert!(spec_version == 1, EUnsupportedActionVersion);

    let action_data = account_protocol::intents::action_spec_data(&action_spec);
    let mut reader = bcs::new(*action_data);
    let intent_key = string::utf8(bcs::peel_vec_u8(&mut reader));
    account_protocol::bcs_validation::validate_all_bytes_consumed(reader);
    assert!(intent_key == expired.key(), EIntentKeyMismatch);

    let key = multisig::new_proposed_config_key(intent_key);
    if (account::has_managed_data(account, key)) {
        let _config: MultisigConfig = account::remove_managed_data_with_package_witness(
            account, registry, key, version::current(),
        );
    };
}

// === Test Helpers ===

#[test_only]
public fun config_change_intent_witness(): ConfigChangeIntent { ConfigChangeIntent() }

#[test_only]
public fun config_change_marker(): ConfigChange { ConfigChange {} }
