// Copyright (c) Govex DAO LLC
// SPDX-License-Identifier: BUSL-1.1

/// Thin witness module for generic action intents on multisig accounts.
///
/// Defines `ActionsIntent` — the intent witness type for non-config intents
/// (mint, transfer, vault ops, etc.). Mirrors futarchy's `governance_intents`
/// pattern: witness lives here, staging goes through `multisig::stage_intent`.
///
/// Flow:
/// 1. PTB builds `vector<ActionSpec>` via `action_spec_builder`
/// 2. Proposer calls `request_actions` with the specs vector
/// 3. Voters approve via `multisig::approve_intent`
/// 4. Executor calls `multisig::execute_intent` + do_* functions + `confirm_execution`

module account_multisig::actions_staging;

use account_protocol::account::{Self, Account, Auth};
use account_protocol::intents::{Self, ActionSpec, Params};
use account_protocol::package_registry::PackageRegistry;
use account_multisig::config::ConfigChange;
use account_multisig::multisig;
use account_multisig::version;
use sui::clock::Clock;

// === Errors ===

/// Caller used the wrong cancel function for this intent type.
/// ConfigChange intents must be cancelled via `config::cancel_*` functions.
const EWrongCancelFunction: u64 = 0;
/// ConfigChange actions cannot be smuggled into generic ActionsIntents.
const EConfigChangeNotAllowed: u64 = 1;

// === Structs ===

/// Intent witness for generic action intents.
public struct ActionsIntent() has copy, drop;

// === Public Functions ===

/// Create an ActionsIntent witness for PTB construction and do_* execution.
public fun witness(): ActionsIntent {
    ActionsIntent()
}

/// Propose a generic actions intent. Caller must have Propose permission.
public fun request_actions(
    auth: Auth,
    account: &mut Account,
    registry: &PackageRegistry,
    params: Params,
    specs: vector<ActionSpec>,
    ctx: &mut TxContext,
) {
    account.verify(auth);
    multisig::assert_sender_can_propose(account, ctx.sender());
    let outcome = multisig::new_outcome(account);
    intents::assert_single_execution(&params);

    let intent_key = params.key();
    let intent_description = params.description();

    let iw = ActionsIntent();
    let mut intent = account::create_intent(
        account,
        registry,
        params,
        outcome,
        version::current(),
        copy iw,
        ctx,
    );

    let mut i = 0;
    while (i < specs.length()) {
        let spec = specs.borrow(i);
        assert!(
            !account_protocol::action_validation::is_action_type<ConfigChange>(spec),
            EConfigChangeNotAllowed,
        );
        intents::add_existing_action_spec(&mut intent, *spec, copy iw);
        i = i + 1;
    };

    multisig::stage_intent(account, registry, intent, version::current(), iw, ctx);

    multisig::emit_intent_created(account, intent_key, intent_description, ctx.sender());
}

// === Cancellation ===

/// Cast a cancellation vote for an approved actions intent.
public fun cancel_pending_actions(
    account: &mut Account,
    key: std::string::String,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert_not_config_change(account, key);
    let expired = multisig::cancel_pending_intent(account, key, clock, ctx);
    intents::drain_and_destroy_expired(expired);
}

/// Cancel a stale actions intent (config nonce changed).
public fun cancel_stale_actions(
    account: &mut Account,
    key: std::string::String,
    ctx: &mut TxContext,
) {
    assert_not_config_change(account, key);
    let expired = multisig::cancel_stale_intent(account, key, ctx);
    intents::drain_and_destroy_expired(expired);
}

/// Cancel a rejected actions intent.
public fun cancel_rejected_actions(
    account: &mut Account,
    key: std::string::String,
    ctx: &mut TxContext,
) {
    assert_not_config_change(account, key);
    let expired = multisig::cancel_rejected_intent(account, key, ctx);
    intents::drain_and_destroy_expired(expired);
}

/// Cancel an expired actions intent.
public fun cancel_expired_actions(
    account: &mut Account,
    key: std::string::String,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert_not_config_change(account, key);
    let expired = multisig::cancel_expired_intent(account, key, clock, ctx);
    intents::drain_and_destroy_expired(expired);
}

// === Private Helpers ===

/// Abort early if this intent is a ConfigChange.
fun assert_not_config_change(account: &Account, key: std::string::String) {
    assert!(
        !multisig::intent_has_config_change_action(account, key),
        EWrongCancelFunction,
    );
}
