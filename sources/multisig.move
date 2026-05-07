// Copyright (c) Govex DAO LLC
// SPDX-License-Identifier: BUSL-1.1

/// Group-based multisig with tiered vote policies, time bands, and per-role whitelists.
///
/// # Policy Model
///
/// Members belong to **groups**. Each group has members with weights and optional
/// **time bands** — stepped weight bonuses that unlock after elapsed time.
/// A group's effective approval weight = sum(participating members' weights) + highest qualifying time band.
/// A group's cancellation weight = sum(participating reject voters' weights); time bands do not count as rejections.
///
/// Each `MultisigConfig` carries **two independent policies**:
///   - `approve_policy` — paths evaluated against vote-for weight. Intent is APPROVED
///     when any path's (group, threshold) requirements are all met.
///   - `cancel_policy`  — paths evaluated against vote-against weight. Cancellation
///     unlocks when any path is met.
///
/// Both policies share the same group infrastructure but express independent
/// thresholds. Time bands are approval-only delayed quorum weight. A permissive
/// approve policy paired with a conservative cancel policy (or vice versa) is
/// first-class.
///
/// # Design Rationale
///
/// Post-Drift ($280M social engineering attack via 2-of-5 multisig, zero timelock, April 2026), the industry needs
/// independent checks on every transaction. But making auditors mandatory on every
/// approval gives them a permanent veto — they go on holiday, get acquired, or
/// disagree, and your org is frozen.
///
/// Time bands solve this: auditors are a checkpoint, not a chokepoint. They can
/// speed things up (approve instantly) or slow things down (don't approve, wait for
/// time band). But they cannot permanently block the organization.
///
/// Full consensus from both team and auditors bypasses all delays (hot-fix path).
///
/// Each feature maps to a specific requirement:
///   Groups           → auditors on every approval
///   Time bands       → auditors can't permanently block
///   Multiple paths   → full consensus bypasses delays (hot-fixes)
///   Split policies   → cancel quorum can be lower (or higher) than approve quorum
///   Cancel groups    → whitelisted finalizers can remove bad or abandoned intents
///
/// # Approval & Cancellation Logic
///
/// Approve (OR):  intent APPROVED when ANY single `approve_policy` path is fully satisfied.
/// Against (OR):  cancellation unlocks when ANY single `cancel_policy` path is
///                 satisfied by vote-against weight.
/// Cancellation removes the intent, so execution is permanently blocked.
///   Time bands on delayed paths provide a reaction window before execution.
///   After a delayed approval matures, execution and cancellation are first-finalized wins.
///
/// `cancel_pending_intent` requires: status == REJECTED, OR a cancel_policy path is
/// currently satisfied by the vote-against set. Being in `cancel_groups` alone is NOT
/// sufficient; the cancel quorum must actually have been reached by reject votes.
///
/// Within a path (AND): ALL group requirements must be met simultaneously.
/// Across paths (OR):   ANY one path being satisfied is sufficient.
///
/// Key constraint: auditor-only approve paths should always include a time band delay,
/// so that team has a reaction window to cancel before execution. Without a time
/// delay, auditor-only approval + permissionless execution = no team oversight.
///
/// # Design Spec — Reference Scenarios
///
/// Given:
///   team group: [Alice(10), Bob(10), Carol(10)]
///     time_bands: [{ after: 7 days, weight: 10 }, { after: 30 days, weight: 20 }]
///   auditors group: [Deloitte(10), Trail(10), Zellic(10)]
///     time_bands: [{ after: 30 days, weight: 20 }]
///
///   approve_policy (approve if ANY path satisfied):
///     path 0: (team >= 30) AND (auditors >= 30)     — 3/3 both, instant (hot-fix)
///     path 1: (team >= 20) AND (auditors >= 10)     — 2/3 team + 1/3 auditor, instant
///     path 2: (team >= 10) AND (auditors >= 10)     — 1/3 team + 1/3 auditor, instant (light)
///     path 3: (team >= 30)                          — 3/3 team instant, or 2/3 + 7d, or 1/3 + 30d
///     path 4: (auditors >= 50)                      — 3/3 auditors (30) + 30d time band (20) = 50
///       (auditor-only path requires time delay so team can cancel)
///
///   cancel_policy (cancel if ANY path satisfied):
///     path 0: (team >= 10)                          — any one team member can object
///     path 1: (auditors >= 20)                      — any two auditors can object
///     (cancel quorum may legitimately be lower than approve quorum)
///
///   Invariant: vote-against can unlock cancellation during a delayed approval window.
///   Invariant: whitelisted cancellers can finalize cancellation only after cancel_policy is met.
///   Invariant: delayed approve paths give cancel_policy voters a reaction window before execution.
///   Invariant: time-band delays mature approve paths; approved intents have no separate execution timelock.
///
/// Scenario 1 — Hot-fix (full consensus, instant):
///   All 3 team + all 3 auditors approve.
///   Approve path 0: (team=30 >= 30) AND (auditors=30 >= 30) → satisfied. Zero delay.
///   Use case: critical bug, everyone agrees, ship now.
///
/// Scenario 2 — Standard (2/3 team + 1 auditor, instant):
///   Alice, Bob approve (team=20). Deloitte approves (auditors=10).
///   Approve path 1: (team=20 >= 20) AND (auditors=10 >= 10) → satisfied immediately.
///   Use case: routine operations.
///
/// Scenario 3 — Team only (3/3 team, no auditor):
///   Alice, Bob, Carol approve (team=30).
///   Approve path 3: (team=30 >= 30) → satisfied immediately. No auditor needed.
///   Use case: internal ops where audit oversight isn't required.
///
/// Scenario 4 — Auditors slow, team proceeds with time:
///   Alice, Bob approve (team=20). No auditor responds.
///   7 days pass. Team effective = 20 + 10 (7d time band) = 30.
///   Approve path 3: (team=30 >= 30) → satisfied after 7 days.
///   Use case: auditors unresponsive, 2/3 team proceeds after delay.
///   Note: 1/3 team alone (10) must wait 30 days for band (+20) = 30.
///
/// Scenario 5 — Attacker compromises 2 team members (Drift-style):
///   Attacker tricks Alice, Bob into pre-signing (team=20). No auditor involved.
///   Approve path 3 requires team(30). 20 < 30 → NOT satisfied instantly.
///   After 7 days, team effective = 20 + 10 (7d band) = 30 → path satisfied.
///   But during those 7 days, Carol calls reject. Cancel path 0: (team >= 10). Met.
///   Carol then finalizes cancellation and deletes the intent. The 7-day forced wait is the detection window.
///
/// Scenario 6 — Auditors approve, team cancels:
///   Deloitte, Trail, Zellic approve (auditors=30). No team member approves.
///   Approve path 4 requires auditors(50). 30 < 50 → NOT satisfied instantly.
///   30 days pass. Auditors effective = 30 + 20 (30d band) = 50 → satisfied.
///   During that 30 days, Alice rejects. Cancel path 0: (team >= 10). Met.
///   Alice then finalizes cancellation and deletes the intent. Execute is permanently blocked.
///   Use case: auditors act without team, but team has a cancellation window before maturity.
///
/// # Module Contents
///
/// - MultisigConfig (stored as Account config)
/// - Approvals (Outcome for intents)
/// - Account creation, authentication, approval, execution

module account_multisig::multisig;

use std::string::String;
use sui::vec_set::{Self, VecSet};
use sui::clock::Clock;
use sui::coin::{Self, Coin};
use sui::balance::{Self, Balance};
use sui::sui::SUI;
use sui::event;
use account_protocol::account::{Self, Account, Auth};
use account_protocol::metadata;
use account_protocol::deps;
use account_protocol::executable::Executable;
use account_protocol::version_witness::VersionWitness;
use account_protocol::intents::{Self, ActionSpec, Intent, PendingIntent, Expired, Params};
use account_protocol::package_registry::PackageRegistry;
use std::type_name;

// === Constants ===

/// Intent lifecycle states.
const STATUS_ACTIVE: u8 = 0;
const STATUS_APPROVED: u8 = 1;
const STATUS_REJECTED: u8 = 2;
const STATUS_EXECUTED: u8 = 4;

/// Cancellation event reasons.
const CANCEL_REASON_PENDING: u8 = 0;
const CANCEL_REASON_STALE: u8 = 1;
const CANCEL_REASON_REJECTED: u8 = 2;
const CANCEL_REASON_EXPIRED: u8 = 3;

// === Errors ===

// -- Membership & permissions --
const ECallerIsNotMember: u64 = 0;
const ENotInProposerGroup: u64 = 1;
const ENotInExecutorGroup: u64 = 2;
const ENotInCancelGroup: u64 = 34;

// -- Voting --
const EAlreadyApproved: u64 = 3;
const EAlreadyRejected: u64 = 4;
const ENotApproved: u64 = 5;

// -- Intent lifecycle --
const EInvalidIntentStatus: u64 = 6;
const EStaleIntent: u64 = 7;
const ENotStale: u64 = 8;
const ENoMatchedPath: u64 = 9;
const EConfigChangeRequiresConfigModule: u64 = 10;

// -- Intent staging --
const ETooManyActionSpecs: u64 = 11;
const ENoActionSpecs: u64 = 12;
const ESingleExecutionIntentRequired: u64 = 13;
const EInvalidIntentExpiry: u64 = 14;
const EInvalidIntentExpiryConfig: u64 = 15;
const EInvalidConfigChangeIntent: u64 = 16;

// -- Config validation --
const EEmptyGroups: u64 = 21;
const EEmptyVotePolicy: u64 = 22;
const EInvalidGroupIndex: u64 = 23;
const EDuplicateAddressInGroup: u64 = 24;
const EZeroMemberWeight: u64 = 25;
const ETimeBandsNotSorted: u64 = 26;
const EZeroTimeBandWeight: u64 = 27;
const EUnsatisfiablePath: u64 = 28;
const ENoProposerMember: u64 = 29;
const EDuplicateGroupName: u64 = 30;
const EEmptyGroupName: u64 = 31;
const ETooManyMembers: u64 = 32;
const ENoCancellerMember: u64 = 35;
const EEmptyPolicyPath: u64 = 36;
const EZeroPathThreshold: u64 = 37;
const EMemberCountMismatch: u64 = 39;
const ETimeBandCountMismatch: u64 = 40;
const EPathReqCountMismatch: u64 = 41;
const ETimeBandAfterIntentExpiry: u64 = 42;
const EZeroTimeBandDelay: u64 = 43;
const ENoExecutorMember: u64 = 44;
const ETooManyPolicyRequirements: u64 = 45;
const EDuplicateGroupIndex: u64 = 46;
const ETooManyGroupIndices: u64 = 47;

// -- Fee --
const EInsufficientFee: u64 = 33;

/// Maximum action specs per multisig intent.
const MAX_ACTION_SPECS_PER_INTENT: u64 = 10;
const MAX_MEMBERS: u64 = 200;
const MAX_GROUPS: u64 = 20;
const MAX_PATHS: u64 = 20;
const MAX_TIME_BANDS: u64 = 10;

/// Multisig account creation fee (20 SUI, in MIST).
const MULTISIG_CREATION_FEE: u64 = 20_000_000_000;
#[test_only]
const DEFAULT_INTENT_EXPIRY_MS: u64 = 7 * 24 * 60 * 60 * 1000;

// === Structs ===

/// Config witness. Only this module can create it.
public struct ConfigWitness() has drop;

/// Key for storing proposed config as managed data on the account.
public struct ProposedConfigKey has copy, drop, store {
    intent_key: String,
}

/// Admin capability for sweeping collected creation fees.
public struct MultisigAdminCap has key, store {
    id: UID,
}

/// Shared vault that collects multisig creation fees.
public struct MultisigFeeVault has key {
    id: UID,
    balance: Balance<SUI>,
    /// Adjustable creation fee (in MIST). Admin can update via `update_creation_fee`.
    creation_fee: u64,
    /// Address that receives creation fees (set to deployer at init).
    fee_recipient: address,
}

/// A stepped time-weight bonus within a group.
/// After `after_ms` milliseconds since intent creation, this band's `weight`
/// is added to the group's effective weight (highest qualifying band wins,
/// not cumulative).
public struct TimeBand has copy, drop, store {
    after_ms: u64,
    weight: u64,
}

/// A member within a group, with a voting weight specific to that group.
/// The same address may appear in multiple groups with different weights.
public struct GroupMember has copy, drop, store {
    addr: address,
    weight: u64,
}

/// A named group of members with optional time bands.
public struct Group has copy, drop, store {
    name: String,
    members: vector<GroupMember>,
    /// Sorted ascending by `after_ms`. Optional (empty = no time weight).
    time_bands: vector<TimeBand>,
}

/// One requirement within a policy path: a specific group must reach a
/// weight threshold.
public struct PathRequirement has copy, drop, store {
    group_idx: u64,
    threshold: u64,
}

/// A single approval/cancellation path. ALL requirements must be met
/// for the path to be satisfied.
public struct PolicyPath has copy, drop, store {
    requirements: vector<PathRequirement>,
}

/// A role policy: a list of paths. The role is satisfied when ANY
/// single path is fully met (first satisfied path wins).
public struct RolePolicy has copy, drop, store {
    paths: vector<PolicyPath>,
}

/// The multisig configuration stored as Account config.
public struct MultisigConfig has copy, drop, store {
    /// Named groups of members with weights and optional time bands.
    groups: vector<Group>,
    /// Approval quorum paths — intent APPROVED when any path is satisfied by vote-for weight.
    approve_policy: RolePolicy,
    /// Cancellation quorum paths — cancellation unlocks when any path is satisfied by vote-against weight.
    /// Independent from `approve_policy`; thresholds may be lower, higher, or structurally different.
    cancel_policy: RolePolicy,
    /// Group indices whose members may propose intents.
    propose_groups: vector<u64>,
    /// Group indices whose members may execute approved intents.
    execute_groups: vector<u64>,
    /// Group indices whose members may finalize cancellation once cancellation is unlocked.
    cancel_groups: vector<u64>,
    /// Exact lifetime for newly staged intents, relative to creation time.
    intent_expiry_ms: u64,
    /// Incremented on every config change; stales intents with older nonce.
    config_nonce: u64,
}

/// Outcome stored in intents, tracks approval/rejection progress.
public struct Approvals has copy, drop, store {
    /// Config nonce at intent creation time. Stale if mismatch.
    config_nonce: u64,
    /// Current lifecycle status.
    status: u8,
    /// Addresses that have approved.
    approved: VecSet<address>,
    /// Addresses that have rejected.
    rejected: VecSet<address>,
    /// Which approve_policy path was satisfied (set on APPROVED).
    matched_vote_path: Option<u64>,
    /// Timestamp when the vote path was first satisfied.
    approved_at_ms: u64,
}

// === Events ===

/// Emitted when a new multisig account is created.
public struct AccountCreatedEvent has copy, drop {
    account_addr: address,
    creator: address,
}

/// Emitted when a config change is executed.
/// Flat structured fields for indexer discoverability.
/// Groups are flattened with count arrays (same pattern as config.move API).
public struct ConfigChangedEvent has copy, drop {
    account_addr: address,
    // Groups (flattened)
    group_names: vector<String>,
    group_member_counts: vector<u64>,
    all_member_addresses: vector<address>,
    all_member_weights: vector<u64>,
    time_band_counts: vector<u64>,
    all_time_band_afters: vector<u64>,
    all_time_band_weights: vector<u64>,
    // Approve policy (flattened)
    approve_path_req_counts: vector<u64>,
    all_approve_group_indices: vector<u64>,
    all_approve_thresholds: vector<u64>,
    // Cancel policy (flattened)
    cancel_path_req_counts: vector<u64>,
    all_cancel_group_indices: vector<u64>,
    all_cancel_thresholds: vector<u64>,
    // Permission groups
    propose_groups: vector<u64>,
    execute_groups: vector<u64>,
    cancel_groups: vector<u64>,
    // Timing
    intent_expiry_ms: u64,
    config_nonce: u64,
}

/// Emitted when a new intent is created (proposed).
public struct IntentCreatedEvent has copy, drop {
    account_addr: address,
    key: String,
    description: String,
    creator: address,
}

/// Emitted when an intent is executed.
public struct IntentExecutedEvent has copy, drop {
    account_addr: address,
    key: String,
    executor: address,
}

/// Emitted when an intent is cancelled/deleted before execution.
public struct IntentCancelledEvent has copy, drop {
    account_addr: address,
    key: String,
    canceller: address,
    reason: u8,
}

// === Module Init ===

fun init(ctx: &mut TxContext) {
    let deployer = ctx.sender();
    transfer::transfer(MultisigAdminCap { id: object::new(ctx) }, deployer);
    transfer::share_object(MultisigFeeVault {
        id: object::new(ctx),
        balance: balance::zero(),
        creation_fee: MULTISIG_CREATION_FEE,
        fee_recipient: deployer,
    });
}

// === Core Policy Algorithm ===

/// Compute a group's effective weight given a set of voters and elapsed time.
/// Approval checks include time bands; cancellation checks pass `false` so only
/// actual reject voters count.
fun group_member_vote_weight(
    group: &Group,
    voters: &VecSet<address>,
): u64 {
    let mut weight = 0u64;
    group.members.do_ref!(|m| {
        if (voters.contains(&m.addr)) {
            weight = weight + m.weight;
        };
    });
    weight
}

fun active_time_band_weight(
    group: &Group,
    elapsed_ms: u64,
    include_time_bands: bool,
): u64 {
    let mut time_weight = 0u64;
    if (include_time_bands) {
        // Empty time_bands means no time bonus.
        // Time bands are sorted ascending by after_ms.
        // Walk forward, taking the last qualifying band (highest weight).
        group.time_bands.do_ref!(|band| {
            if (elapsed_ms >= band.after_ms) {
                time_weight = band.weight;
            };
        });
    };
    time_weight
}

/// Check if a single policy path is satisfied.
fun path_satisfied(
    config: &MultisigConfig,
    path: &PolicyPath,
    voters: &VecSet<address>,
    elapsed_ms: u64,
    include_time_bands: bool,
): bool {
    if (path.requirements.is_empty()) {
        return false
    };
    let mut satisfied = true;
    path.requirements.do_ref!(|req| {
        let group = &config.groups[req.group_idx];
        let member_weight = group_member_vote_weight(group, voters);
        let effective_weight =
            member_weight + active_time_band_weight(group, elapsed_ms, include_time_bands);
        if (req.threshold == 0 || effective_weight < req.threshold) {
            satisfied = false;
        };
        // A time band may top up real approvals, but it must never satisfy a
        // requirement on its own. This prevents memberless or vote-less groups
        // from approving after time passes.
        if (include_time_bands && member_weight == 0) {
            satisfied = false;
        };
    });
    satisfied
}

/// Find the first satisfied approve_policy path. Returns its index or none.
fun find_satisfied_vote_path(
    config: &MultisigConfig,
    voters: &VecSet<address>,
    elapsed_ms: u64,
): Option<u64> {
    find_satisfied_path(&config.approve_policy, config, voters, elapsed_ms, true)
}

/// Find the first satisfied cancel_policy path. Returns its index or none.
fun find_satisfied_reject_path(
    config: &MultisigConfig,
    voters: &VecSet<address>,
    elapsed_ms: u64,
): Option<u64> {
    find_satisfied_path(&config.cancel_policy, config, voters, elapsed_ms, false)
}

/// Generic path finder for a role policy.
fun find_satisfied_path(
    policy: &RolePolicy,
    config: &MultisigConfig,
    voters: &VecSet<address>,
    elapsed_ms: u64,
    include_time_bands: bool,
): Option<u64> {
    let mut i = 0;
    while (i < policy.paths.length()) {
        if (path_satisfied(config, &policy.paths[i], voters, elapsed_ms, include_time_bands)) {
            return option::some(i)
        };
        i = i + 1;
    };
    option::none()
}

/// Check if any approve_policy path can still be satisfied, given current rejections.
/// Uses maximum possible weight (all non-rejecting members + max time band)
/// because time bands are "free" weight that accrues automatically.
fun can_any_approve_path_be_satisfied(
    config: &MultisigConfig,
    rejected: &VecSet<address>,
): bool {
    let mut i = 0;
    while (i < config.approve_policy.paths.length()) {
        if (path_can_be_satisfied(config, &config.approve_policy.paths[i], rejected, true)) {
            return true
        };
        i = i + 1;
    };
    false
}

/// Check if a single path can ever be satisfied (assuming max time, all non-rejecters approve).
fun path_can_be_satisfied(
    config: &MultisigConfig,
    path: &PolicyPath,
    rejected: &VecSet<address>,
    include_time_bands: bool,
): bool {
    if (path.requirements.is_empty()) {
        return false
    };
    let mut satisfiable = true;
    path.requirements.do_ref!(|req| {
        let group = &config.groups[req.group_idx];
        let max_member_weight = max_possible_group_member_weight(group, rejected);
        let max_weight = max_possible_group_weight(group, rejected, include_time_bands);
        if (
            req.threshold == 0
                || max_weight < req.threshold
                || (include_time_bands && max_member_weight == 0)
        ) {
            satisfiable = false;
        };
    });
    satisfiable
}

fun max_possible_group_member_weight(
    group: &Group,
    rejected: &VecSet<address>,
): u64 {
    let mut weight = 0u64;
    group.members.do_ref!(|m| {
        if (!rejected.contains(&m.addr)) {
            weight = weight + m.weight;
        };
    });
    weight
}

/// Maximum weight a group can ever reach: all non-rejected members, optionally
/// plus the highest time band for approval policy checks.
fun max_possible_group_weight(
    group: &Group,
    rejected: &VecSet<address>,
    include_time_bands: bool,
): u64 {
    let mut weight = max_possible_group_member_weight(group, rejected);
    if (include_time_bands) {
        // Add highest time band weight (last element if any, since sorted ascending)
        let band_count = group.time_bands.length();
        if (band_count > 0) {
            weight = weight + group.time_bands[band_count - 1].weight;
        };
    };
    weight
}

// === Group Membership Helpers ===

/// Check if an address is a member of any group.
public fun is_member_of_any_group(config: &MultisigConfig, addr: address): bool {
    config.groups.any!(|g| g.members.any!(|m| m.addr == addr))
}

/// Check if an address is in any of the propose groups.
fun is_in_propose_groups(config: &MultisigConfig, addr: address): bool {
    config.propose_groups.any!(|idx| {
        config.groups[*idx].members.any!(|m| m.addr == addr)
    })
}

/// Check if an address is in any of the execute groups.
fun is_in_execute_groups(config: &MultisigConfig, addr: address): bool {
    config.execute_groups.any!(|idx| {
        config.groups[*idx].members.any!(|m| m.addr == addr)
    })
}

/// Check if an address is in any of the cancel groups.
fun is_in_cancel_groups(config: &MultisigConfig, addr: address): bool {
    config.cancel_groups.any!(|idx| {
        config.groups[*idx].members.any!(|m| m.addr == addr)
    })
}

// === Account Lifecycle ===

/// Creates a new multisig-governed Account from a fully specified config.
///
/// The caller provides both `approve_policy` and `cancel_policy` explicitly as
/// flat vectors — there is no defaulting of cancel from approve.
///
/// Returns an unshared Account — caller must call `account::share_account()` after init.
#[allow(lint(self_transfer))]
public fun new_account(
    vault: &mut MultisigFeeVault,
    registry: &PackageRegistry,
    mut payment: Coin<SUI>,
    metadata_keys: vector<String>,
    metadata_values: vector<String>,
    // Groups (flat-vector form)
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
    // Cancel policy (MUST be explicitly provided — no silent copy of approve)
    cancel_path_req_counts: vector<u64>,
    all_cancel_group_indices: vector<u64>,
    all_cancel_thresholds: vector<u64>,
    // Permission groups
    propose_groups: vector<u64>,
    execute_groups: vector<u64>,
    cancel_groups: vector<u64>,
    intent_expiry_ms: u64,
    ctx: &mut TxContext,
): Account {
    let required_fee = vault.creation_fee;
    assert!(payment.value() >= required_fee, EInsufficientFee);
    if (required_fee > 0) {
        let fee = coin::split(&mut payment, required_fee, ctx);
        balance::join(&mut vault.balance, coin::into_balance(fee));
    };
    if (payment.value() > 0) {
        transfer::public_transfer(payment, ctx.sender());
    } else {
        payment.destroy_zero();
    };

    let config = build_config_from_flat_vectors(
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

    let deps = deps::new(registry);

    let account = account::new(
        config,
        metadata::from_keys_values(metadata_keys, metadata_values),
        deps,
        ConfigWitness(),
        ctx,
    );

    event::emit(AccountCreatedEvent {
        account_addr: account::addr(&account),
        creator: ctx.sender(),
    });

    account
}

/// Share the account (convenience wrapper).
public fun share(account: Account) {
    account::share_account(account);
}

// === Fee Management ===

/// Sweep any residual balance in the vault to the fee recipient.
#[allow(lint(self_transfer))]
public fun sweep_fees(
    _cap: &MultisigAdminCap,
    vault: &mut MultisigFeeVault,
    ctx: &mut TxContext,
) {
    let amount = vault.balance.value();
    if (amount == 0) return;
    transfer::public_transfer(
        coin::from_balance(vault.balance.split(amount), ctx),
        vault.fee_recipient,
    );
}

/// Update the multisig creation fee. Admin only.
public fun update_creation_fee(
    _cap: &MultisigAdminCap,
    vault: &mut MultisigFeeVault,
    new_fee: u64,
) {
    vault.creation_fee = new_fee;
}

/// Update the address that receives creation fees. Admin only.
public fun update_fee_recipient(
    _cap: &MultisigAdminCap,
    vault: &mut MultisigFeeVault,
    new_recipient: address,
) {
    vault.fee_recipient = new_recipient;
}

/// Get the current balance held in the fee vault.
public fun vault_balance(vault: &MultisigFeeVault): u64 {
    vault.balance.value()
}

/// Get the current creation fee (in MIST).
public fun creation_fee(vault: &MultisigFeeVault): u64 {
    vault.creation_fee
}

/// Get the current fee recipient address.
public fun fee_recipient(vault: &MultisigFeeVault): address {
    vault.fee_recipient
}

// === Authentication ===

/// Authenticate the caller as a member with Propose permission.
public fun authenticate(
    account: &Account,
    ctx: &TxContext,
): Auth {
    assert_sender_can_propose(account, ctx.sender());
    account::new_auth<MultisigConfig, ConfigWitness>(account, ConfigWitness())
}

/// Re-check proposer permission at the staging boundary.
public(package) fun assert_sender_can_propose(account: &Account, sender: address) {
    let config: &MultisigConfig = account::config(account);
    assert!(is_member_of_any_group(config, sender), ECallerIsNotMember);
    assert!(is_in_propose_groups(config, sender), ENotInProposerGroup);
}

// === Intent Flow ===

/// Construct a ProposedConfigKey for managed data operations.
public(package) fun new_proposed_config_key(intent_key: String): ProposedConfigKey {
    ProposedConfigKey { intent_key }
}

/// Create a new outcome capturing the current config nonce.
public fun new_outcome(account: &Account): Approvals {
    let config: &MultisigConfig = account::config(account);
    Approvals {
        config_nonce: config.config_nonce,
        status: STATUS_ACTIVE,
        approved: vec_set::empty(),
        rejected: vec_set::empty(),
        matched_vote_path: option::none(),
        approved_at_ms: 0,
    }
}

fun assert_fresh_pending_outcome(account: &Account, outcome: &Approvals) {
    let config: &MultisigConfig = account::config(account);
    assert!(outcome.config_nonce == config.config_nonce, EStaleIntent);
    assert!(outcome.status == STATUS_ACTIVE, EInvalidIntentStatus);
    assert!(outcome.approved.keys().is_empty(), EInvalidIntentStatus);
    assert!(outcome.rejected.keys().is_empty(), EInvalidIntentStatus);
    assert!(outcome.matched_vote_path.is_none(), EInvalidIntentStatus);
    assert!(outcome.approved_at_ms == 0, EInvalidIntentStatus);
}

/// Approve an intent. Caller must be a member of any group.
/// On each vote, all approve_policy paths are checked (including time bands).
public fun approve_intent(
    account: &mut Account,
    key: String,
    clock: &Clock,
    ctx: &TxContext,
) {
    let config: MultisigConfig = *account::config(account);
    assert!(is_member_of_any_group(&config, ctx.sender()), ECallerIsNotMember);

    let intents = account::intents_mut<MultisigConfig, ConfigWitness>(account, ConfigWitness());
    let intent = intents::get_mut<Approvals>(intents, key);
    let creation_time = intents::creation_time(intent);
    let outcome = intents::outcome_mut(intent);

    assert!(outcome.config_nonce == config.config_nonce, EStaleIntent);
    assert!(outcome.status == STATUS_ACTIVE, EInvalidIntentStatus);

    // Vote-switching: approving clears any previous reject vote.
    if (outcome.rejected.contains(&ctx.sender())) {
        outcome.rejected.remove(&ctx.sender());
    };

    assert!(!outcome.approved.contains(&ctx.sender()), EAlreadyApproved);
    outcome.approved.insert(ctx.sender());

    // Check if any vote path is now satisfied.
    let elapsed_ms = clock.timestamp_ms() - creation_time;
    let path_opt = find_satisfied_vote_path(&config, &outcome.approved, elapsed_ms);
    if (path_opt.is_some()) {
        outcome.status = STATUS_APPROVED;
        outcome.matched_vote_path = path_opt;
        outcome.approved_at_ms = clock.timestamp_ms();
    };
}

/// Re-evaluate an ACTIVE intent's vote paths against current time.
/// Allows crank bots to trigger ACTIVE→APPROVED transitions when time bands
/// make a path satisfiable without new votes. No-op if no path is satisfied yet.
/// Access follows the same rule as execute: if execute_groups is non-empty,
/// caller must be in one; if empty, permissionless.
public fun evaluate_intent(
    account: &mut Account,
    key: String,
    clock: &Clock,
    ctx: &TxContext,
) {
    let config: MultisigConfig = *account::config(account);
    if (!config.execute_groups.is_empty()) {
        assert!(is_member_of_any_group(&config, ctx.sender()), ECallerIsNotMember);
        assert!(is_in_execute_groups(&config, ctx.sender()), ENotInExecutorGroup);
    };

    let intents = account::intents_mut<MultisigConfig, ConfigWitness>(account, ConfigWitness());
    let intent = intents::get_mut<Approvals>(intents, key);
    let creation_time = intents::creation_time(intent);
    let outcome = intents::outcome_mut(intent);

    assert!(outcome.config_nonce == config.config_nonce, EStaleIntent);
    assert!(outcome.status == STATUS_ACTIVE, EInvalidIntentStatus);

    let elapsed_ms = clock.timestamp_ms() - creation_time;
    // Cancel overrides approve: if actual reject votes satisfy the reject path,
    // mark REJECTED before considering approval. Mirrors reject_intent.
    if (find_satisfied_reject_path(&config, &outcome.rejected, elapsed_ms).is_some()) {
        outcome.status = STATUS_REJECTED;
        outcome.matched_vote_path = option::none();
        outcome.approved_at_ms = 0;
        return
    };
    let path_opt = find_satisfied_vote_path(&config, &outcome.approved, elapsed_ms);
    if (path_opt.is_some()) {
        outcome.status = STATUS_APPROVED;
        outcome.matched_vote_path = path_opt;
        outcome.approved_at_ms = clock.timestamp_ms();
    };
}

/// Vote against an active or approved-but-unexecuted intent. Caller must be a member of any group.
/// Cancellation unlocks when vote-against weight satisfies the cancel_policy,
/// or when no approve_policy path can ever be satisfied.
public fun reject_intent(
    account: &mut Account,
    key: String,
    clock: &Clock,
    ctx: &TxContext,
) {
    let config: MultisigConfig = *account::config(account);
    assert!(is_member_of_any_group(&config, ctx.sender()), ECallerIsNotMember);

    let intents = account::intents_mut<MultisigConfig, ConfigWitness>(account, ConfigWitness());
    let intent = intents::get_mut<Approvals>(intents, key);
    let creation_time = intents::creation_time(intent);
    let outcome = intents::outcome_mut(intent);

    assert!(outcome.config_nonce == config.config_nonce, EStaleIntent);
    assert!(
        outcome.status == STATUS_ACTIVE || outcome.status == STATUS_APPROVED,
        EInvalidIntentStatus,
    );

    // Vote-switching: rejecting clears any previous approval.
    if (outcome.approved.contains(&ctx.sender())) {
        outcome.approved.remove(&ctx.sender());
    };

    assert!(!outcome.rejected.contains(&ctx.sender()), EAlreadyRejected);
    outcome.rejected.insert(ctx.sender());

    let elapsed_ms = clock.timestamp_ms() - creation_time;
    if (find_satisfied_reject_path(&config, &outcome.rejected, elapsed_ms).is_some()) {
        // Cancellation unlock: enough vote-against weight has objected.
        outcome.status = STATUS_REJECTED;
        outcome.matched_vote_path = option::none();
        outcome.approved_at_ms = 0;
    } else if (!can_any_approve_path_be_satisfied(&config, &outcome.rejected)) {
        // Fallback terminal rejection: no approve_policy path can ever be satisfied.
        outcome.status = STATUS_REJECTED;
        outcome.matched_vote_path = option::none();
        outcome.approved_at_ms = 0;
    } else {
        let approval_path_opt = find_satisfied_vote_path(&config, &outcome.approved, elapsed_ms);
        if (approval_path_opt.is_some()) {
            outcome.status = STATUS_APPROVED;
            outcome.matched_vote_path = approval_path_opt;
            if (outcome.approved_at_ms == 0) {
                outcome.approved_at_ms = clock.timestamp_ms();
            };
        } else {
            outcome.status = STATUS_ACTIVE;
            outcome.matched_vote_path = option::none();
            outcome.approved_at_ms = 0;
        };
    };
}

/// Remove approval from an intent. Only for ACTIVE intents.
public fun disapprove_intent(
    account: &mut Account,
    key: String,
    ctx: &TxContext,
) {
    let config: MultisigConfig = *account::config(account);
    assert!(is_member_of_any_group(&config, ctx.sender()), ECallerIsNotMember);

    let intents = account::intents_mut<MultisigConfig, ConfigWitness>(account, ConfigWitness());
    let intent = intents::get_mut<Approvals>(intents, key);
    let outcome = intents::outcome_mut(intent);

    assert!(outcome.config_nonce == config.config_nonce, EStaleIntent);
    assert!(outcome.status == STATUS_ACTIVE, EInvalidIntentStatus);

    assert!(outcome.approved.contains(&ctx.sender()), ENotApproved);
    outcome.approved.remove(&ctx.sender());
}

/// Execute an approved intent.
/// If execute_groups is non-empty, caller must be in one of those groups.
/// If execute_groups is empty, execution is permissionless (crank/keeper pattern).
public fun execute_intent(
    account: &mut Account,
    registry: &PackageRegistry,
    key: String,
    clock: &Clock,
    ctx: &mut TxContext,
): Executable<Approvals> {
    let config: MultisigConfig = *account::config(account);
    if (!config.execute_groups.is_empty()) {
        assert!(is_member_of_any_group(&config, ctx.sender()), ECallerIsNotMember);
        assert!(is_in_execute_groups(&config, ctx.sender()), ENotInExecutorGroup);
    };

    {
        let intents = account::intents_mut<MultisigConfig, ConfigWitness>(account, ConfigWitness());
        let intent = intents::get_mut<Approvals>(intents, key);
        let creation_time = intents::creation_time(intent);
        let outcome = intents::outcome_mut(intent);

        assert!(outcome.config_nonce == config.config_nonce, EStaleIntent);
        assert!(outcome.status == STATUS_APPROVED, EInvalidIntentStatus);

        // Defense in depth: re-verify the matched approve path still holds.
        let path_idx = *outcome.matched_vote_path.borrow();
        let elapsed_ms = clock.timestamp_ms() - creation_time;
        assert!(
            path_satisfied(&config, &config.approve_policy.paths[path_idx], &outcome.approved, elapsed_ms, true),
            ENoMatchedPath,
        );

        outcome.status = STATUS_EXECUTED;
    };

    event::emit(IntentExecutedEvent {
        account_addr: account::addr(account),
        key,
        executor: ctx.sender(),
    });

    let (_, executable) = account::create_executable<MultisigConfig, Approvals, ConfigWitness>(
        account, registry, key, clock, ConfigWitness(), ctx,
    );
    executable
}

/// Generic intent staging gateway for multisig accounts.
public fun stage_intent<IW: drop>(
    account: &mut Account,
    registry: &PackageRegistry,
    intent: PendingIntent<Approvals>,
    caller_witness: VersionWitness,
    intent_witness: IW,
    ctx: &TxContext,
) {
    assert_sender_can_propose(account, ctx.sender());
    account::assert_package_witness_authorized(account, registry, caller_witness);

    let intent_ref = intents::pending_inner(&intent);
    let action_count = intent_ref.action_count();
    assert!(action_count > 0, ENoActionSpecs);
    assert!(action_count <= MAX_ACTION_SPECS_PER_INTENT, ETooManyActionSpecs);
    assert_valid_config_change_intent<IW>(intent_ref);
    assert_intent_matches_config_policy(account, intent_ref);
    assert_fresh_pending_outcome(account, intent_ref.outcome());

    account::insert_intent<MultisigConfig, Approvals, ConfigWitness, IW>(
        account,
        registry,
        intent,
        ConfigWitness(),
        intent_witness,
    );
}

fun assert_valid_intent_expiry_ms(intent_expiry_ms: u64) {
    assert!(intent_expiry_ms > 0, EInvalidIntentExpiryConfig);
}

fun assert_valid_intent_policy(intent_expiry_ms: u64) {
    assert_valid_intent_expiry_ms(intent_expiry_ms);
}

fun assert_intent_matches_config_policy(account: &Account, intent: &Intent<Approvals>) {
    let config: &MultisigConfig = account::config(account);
    let execution_times = intents::execution_times(intent);
    assert!(execution_times.length() == 1, ESingleExecutionIntentRequired);

    let expiration_time = intents::expiration_time(intent);
    assert!(expiration_time > 0, EInvalidIntentExpiry);

    let expected_expiration = intents::creation_time(intent) + config.intent_expiry_ms;
    assert!(expiration_time == expected_expiration, EInvalidIntentExpiry);
    assert!(execution_times[0] < expiration_time, EInvalidIntentExpiry);
}

fun assert_valid_config_change_intent<IW: drop>(intent: &Intent<Approvals>) {
    let specs = intent.action_specs();
    let mut config_change_count = 0u64;
    let mut i = 0;
    while (i < specs.length()) {
        if (is_config_change_action_spec(&specs[i])) {
            config_change_count = config_change_count + 1;
        };
        i = i + 1;
    };

    let config_witness = is_config_change_intent_witness<IW>();
    assert!(
        (
            config_change_count == 0 &&
                !config_witness
        ) || (
            config_change_count == 1 &&
                specs.length() == 1 &&
                config_witness
        ),
        EInvalidConfigChangeIntent,
    );
}

/// Build single-execution intent params using the multisig's configured expiry.
public fun new_params_from_config(
    account: &Account,
    key: String,
    description: String,
    execution_time_ms: u64,
    clock: &Clock,
    ctx: &mut TxContext,
): Params {
    let config: &MultisigConfig = account::config(account);
    intents::new_params(
        key,
        description,
        vector[execution_time_ms],
        clock.timestamp_ms() + config.intent_expiry_ms,
        clock,
        ctx,
    )
}

/// Maximum action specs allowed per multisig intent.
public fun max_action_specs_per_intent(): u64 {
    MAX_ACTION_SPECS_PER_INTENT
}

public fun max_members(): u64 { MAX_MEMBERS }
public fun max_groups(): u64 { MAX_GROUPS }
public fun max_paths(): u64 { MAX_PATHS }
public fun max_time_bands(): u64 { MAX_TIME_BANDS }

// === Cancellation ===

/// Finalize cancellation for an approved or cancellation-unlocked intent.
/// Caller must be in one of the configured cancel groups.
/// Returns `Expired` after removing the intent.
///
/// Aborts if intent is a ConfigChange (use `config::cancel_pending_config_change`).
public fun cancel_pending_intent(
    account: &mut Account,
    key: String,
    clock: &Clock,
    ctx: &mut TxContext,
): Expired {
    assert_not_config_change_intent(account, key);
    cancel_pending_intent_inner(account, key, clock, ctx)
}

/// Package-internal variant without ConfigChange guard.
public(package) fun cancel_pending_intent_for_cleanup(
    account: &mut Account,
    key: String,
    clock: &Clock,
    ctx: &mut TxContext,
): Expired {
    cancel_pending_intent_inner(account, key, clock, ctx)
}

/// Cancel a stale intent (config changed since creation).
/// Permissionless — stale intents can never execute.
///
/// Aborts if intent is a ConfigChange.
public fun cancel_stale_intent(
    account: &mut Account,
    key: String,
    ctx: &mut TxContext,
): Expired {
    assert_not_config_change_intent(account, key);
    cancel_stale_intent_inner(account, key, ctx)
}

/// Package-internal variant without ConfigChange guard.
public(package) fun cancel_stale_intent_for_cleanup(
    account: &mut Account,
    key: String,
    ctx: &mut TxContext,
): Expired {
    cancel_stale_intent_inner(account, key, ctx)
}

/// Delete a cancellation-unlocked intent.
/// Caller must be in one of the configured cancel groups.
///
/// Aborts if intent is a ConfigChange.
public fun cancel_rejected_intent(
    account: &mut Account,
    key: String,
    ctx: &mut TxContext,
): Expired {
    assert_not_config_change_intent(account, key);
    cancel_rejected_intent_inner(account, key, ctx)
}

/// Package-internal variant without ConfigChange guard.
public(package) fun cancel_rejected_intent_for_cleanup(
    account: &mut Account,
    key: String,
    ctx: &mut TxContext,
): Expired {
    cancel_rejected_intent_inner(account, key, ctx)
}

/// Delete an expired intent. Permissionless.
///
/// Aborts if intent is a ConfigChange.
public fun cancel_expired_intent(
    account: &mut Account,
    key: String,
    clock: &Clock,
    ctx: &mut TxContext,
): Expired {
    assert_not_config_change_intent(account, key);
    cancel_expired_intent_inner(account, key, clock, ctx)
}

/// Package-internal variant without ConfigChange guard.
public(package) fun cancel_expired_intent_for_cleanup(
    account: &mut Account,
    key: String,
    clock: &Clock,
    ctx: &mut TxContext,
): Expired {
    cancel_expired_intent_inner(account, key, clock, ctx)
}

// --- Private cancel implementations ---

fun cancel_pending_intent_inner(
    account: &mut Account,
    key: String,
    clock: &Clock,
    ctx: &mut TxContext,
): Expired {
    let config: MultisigConfig = *account::config(account);
    assert_sender_can_cancel(&config, ctx.sender());

    {
        let intents = account::intents_mut<MultisigConfig, ConfigWitness>(account, ConfigWitness());
        let intent = intents::get_mut<Approvals>(intents, key);
        let creation_time = intents::creation_time(intent);
        let outcome = intents::outcome_mut(intent);

        // Cancellation is permitted when the intent is still in a pre-terminal state
        // (ACTIVE / APPROVED / REJECTED) AND either:
        //   (a) status is already REJECTED — the cancel_policy quorum was met earlier
        //       (or approval became unreachable), or
        //   (b) the cancel_policy is currently satisfied by the vote-against set.
        // EXECUTED is terminal and must NOT be reachable from here.
        // Being in `cancel_groups` alone is NOT sufficient; the cancel_policy quorum
        // must have been reached by vote-against weight. This closes the prior bypass
        // where any cancel_groups member could unilaterally kill an APPROVED intent.
        assert!(
            outcome.status == STATUS_ACTIVE ||
                outcome.status == STATUS_APPROVED ||
                outcome.status == STATUS_REJECTED,
            EInvalidIntentStatus,
        );
        let cancel_path_satisfied = {
            let elapsed_ms = clock.timestamp_ms() - creation_time;
            find_satisfied_reject_path(&config, &outcome.rejected, elapsed_ms).is_some()
        };
        assert!(
            outcome.status == STATUS_REJECTED || cancel_path_satisfied,
            EInvalidIntentStatus,
        );
    };

    emit_intent_cancelled(account, key, ctx.sender(), CANCEL_REASON_PENDING);
    account::cancel_intent<Approvals, ConfigWitness>(account, key, ConfigWitness(), ctx)
}

fun assert_sender_can_cancel(config: &MultisigConfig, sender: address) {
    assert!(is_member_of_any_group(config, sender), ECallerIsNotMember);
    assert!(is_in_cancel_groups(config, sender), ENotInCancelGroup);
}

fun cancel_stale_intent_inner(
    account: &mut Account,
    key: String,
    ctx: &mut TxContext,
): Expired {
    // Permissionless: stale intents can never execute, so cleanup is a public good.
    let config: &MultisigConfig = account::config(account);
    let config_nonce = config.config_nonce;
    let outcome = account.intents().get<Approvals>(key).outcome();
    assert!(outcome.config_nonce != config_nonce, ENotStale);

    emit_intent_cancelled(account, key, ctx.sender(), CANCEL_REASON_STALE);
    account::cancel_intent<Approvals, ConfigWitness>(account, key, ConfigWitness(), ctx)
}

fun cancel_rejected_intent_inner(
    account: &mut Account,
    key: String,
    ctx: &mut TxContext,
): Expired {
    let config: MultisigConfig = *account::config(account);
    assert_sender_can_cancel(&config, ctx.sender());
    let outcome = account.intents().get<Approvals>(key).outcome();
    assert!(outcome.status == STATUS_REJECTED, EInvalidIntentStatus);

    emit_intent_cancelled(account, key, ctx.sender(), CANCEL_REASON_REJECTED);
    account::cancel_intent<Approvals, ConfigWitness>(account, key, ConfigWitness(), ctx)
}

fun cancel_expired_intent_inner(
    account: &mut Account,
    key: String,
    clock: &Clock,
    ctx: &mut TxContext,
): Expired {
    emit_intent_cancelled(account, key, ctx.sender(), CANCEL_REASON_EXPIRED);
    account::delete_expired_intent<Approvals, ConfigWitness>(account, key, clock, ConfigWitness(), ctx)
}

fun emit_intent_cancelled(
    account: &Account,
    key: String,
    canceller: address,
    reason: u8,
) {
    event::emit(IntentCancelledEvent {
        account_addr: account::addr(account),
        key,
        canceller,
        reason,
    });
}

/// ConfigChange intents have managed side data and must use config-specific cleanup.
fun assert_not_config_change_intent(account: &Account, key: String) {
    assert!(
        !intent_has_config_change_action(account, key),
        EConfigChangeRequiresConfigModule,
    );
}

public(package) fun intent_has_config_change_action(account: &Account, key: String): bool {
    let intent = account.intents().get<Approvals>(key);
    let specs = intent.action_specs();
    let mut i = 0;
    while (i < specs.length()) {
        if (is_config_change_action_spec(&specs[i])) {
            return true
        };
        i = i + 1;
    };
    false
}

fun is_config_change_action_spec(spec: &ActionSpec): bool {
    let action_type = intents::action_spec_type(spec);
    if (type_name::is_primitive(&action_type)) return false;

    intents::action_spec_package_addr(spec) == @account_multisig
        && type_name::module_string(&action_type).as_bytes() == b"config"
        && type_name::datatype_string(&action_type).as_bytes() == b"ConfigChange"
}

fun is_config_change_intent_witness<IW: drop>(): bool {
    let witness_type = type_name::with_original_ids<IW>();
    if (type_name::is_primitive(&witness_type)) return false;

    type_name::original_id<IW>() == @account_multisig
        && type_name::module_string(&witness_type).as_bytes() == b"config"
        && type_name::datatype_string(&witness_type).as_bytes() == b"ConfigChangeIntent"
}

// === Config Validation ===

/// Validate a MultisigConfig. Aborts on any invalid state.
/// Called by config.move after constructing from flat vectors.
public(package) fun validate_config(config: &MultisigConfig) {
    // Timing policy is validated before group time bands so the band checks use
    // the new config's own expiry, including during config-change validation.
    assert_valid_intent_policy(config.intent_expiry_ms);

    // Groups not empty
    assert!(config.groups.length() > 0, EEmptyGroups);
    assert!(config.groups.length() <= MAX_GROUPS, EEmptyGroups);

    // Both policies non-empty and within bounds
    assert!(config.approve_policy.paths.length() > 0, EEmptyVotePolicy);
    assert!(config.approve_policy.paths.length() <= MAX_PATHS, EEmptyVotePolicy);
    assert!(config.cancel_policy.paths.length() > 0, EEmptyVotePolicy);
    assert!(config.cancel_policy.paths.length() <= MAX_PATHS, EEmptyVotePolicy);

    // Validate groups
    let mut total_members = 0u64;
    let mut group_names = vec_set::empty<String>();
    config.groups.do_ref!(|group| {
        // Non-empty name, unique
        assert!(group.name.length() > 0, EEmptyGroupName);
        assert!(!group_names.contains(&group.name), EDuplicateGroupName);
        group_names.insert(group.name);

        // No duplicate addresses within group, positive weights
        let mut seen = vec_set::empty<address>();
        group.members.do_ref!(|m| {
            assert!(!seen.contains(&m.addr), EDuplicateAddressInGroup);
            seen.insert(m.addr);
            assert!(m.weight > 0, EZeroMemberWeight);
        });
        total_members = total_members + group.members.length();

        // Time bands sorted ascending by after_ms, weights non-decreasing, positive weights.
        // Non-decreasing weights ensures time never makes approval harder, and that
        // max_possible_group_weight (when including bands) is correct.
        let mut prev_after = 0u64;
        let mut prev_weight = 0u64;
        let mut first = true;
        group.time_bands.do_ref!(|band| {
            assert!(band.weight > 0, EZeroTimeBandWeight);
            assert!(band.after_ms > 0, EZeroTimeBandDelay);
            assert!(band.after_ms < config.intent_expiry_ms, ETimeBandAfterIntentExpiry);
            if (!first) {
                assert!(band.after_ms > prev_after, ETimeBandsNotSorted);
                assert!(band.weight >= prev_weight, ETimeBandsNotSorted);
            };
            prev_after = band.after_ms;
            prev_weight = band.weight;
            first = false;
        });
        assert!(group.time_bands.length() <= MAX_TIME_BANDS, ETimeBandsNotSorted);
    });
    assert!(total_members <= MAX_MEMBERS, ETooManyMembers);

    // Validate group indices in all paths for both policies
    validate_role_policy(&config.approve_policy, config);
    validate_role_policy(&config.cancel_policy, config);
    validate_group_indices(&config.propose_groups, config.groups.length());
    validate_group_indices(&config.execute_groups, config.groups.length());
    validate_group_indices(&config.cancel_groups, config.groups.length());

    // At least one member must be in a propose group.
    // Execute groups may be empty (= permissionless execution / crank pattern).
    assert!(config.propose_groups.any!(|idx| config.groups[*idx].members.length() > 0), ENoProposerMember);
    assert!(config.cancel_groups.any!(|idx| config.groups[*idx].members.length() > 0), ENoCancellerMember);
    assert!(
        config.execute_groups.is_empty()
            || config.execute_groups.any!(|idx| config.groups[*idx].members.length() > 0),
        ENoExecutorMember,
    );

    // Each policy path must be theoretically satisfiable
    let empty_rejected = vec_set::empty<address>();
    config.approve_policy.paths.do_ref!(|path| {
        assert!(path_can_be_satisfied(config, path, &empty_rejected, true), EUnsatisfiablePath);
    });
    config.cancel_policy.paths.do_ref!(|path| {
        assert!(path_can_be_satisfied(config, path, &empty_rejected, false), EUnsatisfiablePath);
    });

}

fun validate_role_policy(policy: &RolePolicy, config: &MultisigConfig) {
    policy.paths.do_ref!(|path| {
        assert!(path.requirements.length() > 0, EEmptyPolicyPath);
        assert!(path.requirements.length() <= MAX_GROUPS, ETooManyPolicyRequirements);
        let mut seen_groups = vec_set::empty<u64>();
        path.requirements.do_ref!(|req| {
            assert!(req.group_idx < config.groups.length(), EInvalidGroupIndex);
            assert!(!seen_groups.contains(&req.group_idx), EDuplicateGroupIndex);
            seen_groups.insert(req.group_idx);
            assert!(req.threshold > 0, EZeroPathThreshold);
        });
    });
}

fun validate_group_indices(indices: &vector<u64>, group_count: u64) {
    assert!(indices.length() <= MAX_GROUPS, ETooManyGroupIndices);
    let mut seen_groups = vec_set::empty<u64>();
    indices.do_ref!(|idx| {
        assert!(*idx < group_count, EInvalidGroupIndex);
        assert!(!seen_groups.contains(idx), EDuplicateGroupIndex);
        seen_groups.insert(*idx);
    });
}

/// Build a MultisigConfig from flat vectors (package-scoped). Used by both
/// `new_account` and `config::request_config_change` so the on-chain flat-vector
/// surface has a single canonical validator. Approve and cancel policies are
/// independent — callers must provide both; there is no defaulting.
public(package) fun build_config_from_flat_vectors(
    group_names: vector<String>,
    group_member_counts: vector<u64>,
    all_member_addresses: vector<address>,
    all_member_weights: vector<u64>,
    time_band_counts: vector<u64>,
    all_time_band_afters: vector<u64>,
    all_time_band_weights: vector<u64>,
    approve_path_req_counts: vector<u64>,
    all_approve_group_indices: vector<u64>,
    all_approve_thresholds: vector<u64>,
    cancel_path_req_counts: vector<u64>,
    all_cancel_group_indices: vector<u64>,
    all_cancel_thresholds: vector<u64>,
    propose_groups: vector<u64>,
    execute_groups: vector<u64>,
    cancel_groups: vector<u64>,
    intent_expiry_ms: u64,
): MultisigConfig {
    let num_groups = group_names.length();
    assert!(num_groups > 0, EEmptyGroups);
    assert!(num_groups <= MAX_GROUPS, EEmptyGroups);
    assert!(group_member_counts.length() == num_groups, EMemberCountMismatch);
    assert!(time_band_counts.length() == num_groups, ETimeBandCountMismatch);
    assert!(all_member_addresses.length() == all_member_weights.length(), EMemberCountMismatch);
    assert!(all_member_addresses.length() <= MAX_MEMBERS, ETooManyMembers);
    assert!(all_time_band_afters.length() == all_time_band_weights.length(), ETimeBandCountMismatch);
    assert!(all_time_band_afters.length() <= MAX_GROUPS * MAX_TIME_BANDS, ETimeBandsNotSorted);
    assert!(all_approve_group_indices.length() == all_approve_thresholds.length(), EPathReqCountMismatch);
    assert!(all_cancel_group_indices.length() == all_cancel_thresholds.length(), EPathReqCountMismatch);

    let mut groups = vector[];
    let mut member_offset = 0u64;
    let mut band_offset = 0u64;
    let mut gi = 0u64;
    while (gi < num_groups) {
        let mc = group_member_counts[gi];
        assert!(mc <= MAX_MEMBERS, ETooManyMembers);
        assert!(member_offset + mc <= all_member_addresses.length(), EMemberCountMismatch);
        let mut members = vector[];
        let mut mi = 0u64;
        while (mi < mc) {
            members.push_back(GroupMember {
                addr: all_member_addresses[member_offset + mi],
                weight: all_member_weights[member_offset + mi],
            });
            mi = mi + 1;
        };
        member_offset = member_offset + mc;

        let tc = time_band_counts[gi];
        assert!(tc <= MAX_TIME_BANDS, ETimeBandsNotSorted);
        assert!(band_offset + tc <= all_time_band_afters.length(), ETimeBandCountMismatch);
        let mut time_bands = vector[];
        let mut ti = 0u64;
        while (ti < tc) {
            time_bands.push_back(TimeBand {
                after_ms: all_time_band_afters[band_offset + ti],
                weight: all_time_band_weights[band_offset + ti],
            });
            ti = ti + 1;
        };
        band_offset = band_offset + tc;

        groups.push_back(Group {
            name: group_names[gi],
            members,
            time_bands,
        });
        gi = gi + 1;
    };
    assert!(member_offset == all_member_addresses.length(), EMemberCountMismatch);
    assert!(band_offset == all_time_band_afters.length(), ETimeBandCountMismatch);

    let approve_policy = build_role_policy_from_flat(
        approve_path_req_counts,
        all_approve_group_indices,
        all_approve_thresholds,
    );
    let cancel_policy = build_role_policy_from_flat(
        cancel_path_req_counts,
        all_cancel_group_indices,
        all_cancel_thresholds,
    );

    new_config(
        groups,
        approve_policy,
        cancel_policy,
        propose_groups,
        execute_groups,
        cancel_groups,
        intent_expiry_ms,
    )
}

fun build_role_policy_from_flat(
    path_req_counts: vector<u64>,
    all_group_indices: vector<u64>,
    all_thresholds: vector<u64>,
): RolePolicy {
    assert!(path_req_counts.length() <= MAX_PATHS, EEmptyVotePolicy);
    assert!(all_group_indices.length() <= MAX_PATHS * MAX_GROUPS, ETooManyPolicyRequirements);
    let mut paths = vector[];
    let mut offset = 0u64;
    let mut pi = 0u64;
    while (pi < path_req_counts.length()) {
        let rc = path_req_counts[pi];
        assert!(rc > 0, EEmptyPolicyPath);
        assert!(rc <= MAX_GROUPS, ETooManyPolicyRequirements);
        assert!(offset + rc <= all_group_indices.length(), EPathReqCountMismatch);
        let mut requirements = vector[];
        let mut ri = 0u64;
        while (ri < rc) {
            assert!(all_thresholds[offset + ri] > 0, EZeroPathThreshold);
            requirements.push_back(PathRequirement {
                group_idx: all_group_indices[offset + ri],
                threshold: all_thresholds[offset + ri],
            });
            ri = ri + 1;
        };
        offset = offset + rc;
        paths.push_back(PolicyPath { requirements });
        pi = pi + 1;
    };
    assert!(offset == all_group_indices.length(), EPathReqCountMismatch);
    RolePolicy { paths }
}

/// Construct a MultisigConfig from structured parameters (package-scoped).
/// config_nonce is set to 0 for new configs.
public(package) fun new_config(
    groups: vector<Group>,
    approve_policy: RolePolicy,
    cancel_policy: RolePolicy,
    propose_groups: vector<u64>,
    execute_groups: vector<u64>,
    cancel_groups: vector<u64>,
    intent_expiry_ms: u64,
): MultisigConfig {
    let config = MultisigConfig {
        groups,
        approve_policy,
        cancel_policy,
        propose_groups,
        execute_groups,
        cancel_groups,
        intent_expiry_ms,
        config_nonce: 0,
    };
    validate_config(&config);
    config
}

/// Set the config nonce (package-scoped, used by config action).
public(package) fun set_config_nonce(config: &mut MultisigConfig, nonce: u64) {
    config.config_nonce = nonce;
}

/// Set intent expiry (package-scoped).
public(package) fun set_intent_expiry_ms(config: &mut MultisigConfig, intent_expiry_ms: u64) {
    assert_valid_intent_policy(intent_expiry_ms);
    config.intent_expiry_ms = intent_expiry_ms;
}

/// Get the config witness (package-scoped).
public(package) fun witness(): ConfigWitness {
    ConfigWitness()
}

/// Emit an IntentCreatedEvent (package-scoped).
public(package) fun emit_intent_created(
    account: &Account,
    key: String,
    description: String,
    creator: address,
) {
    event::emit(IntentCreatedEvent {
        account_addr: account::addr(account),
        key,
        description,
        creator,
    });
}

/// Emit a ConfigChangedEvent with structured fields (package-scoped).
public(package) fun emit_config_changed(account: &Account) {
    let config: &MultisigConfig = account::config(account);

    // Flatten groups
    let mut group_names = vector[];
    let mut group_member_counts = vector[];
    let mut all_member_addresses = vector[];
    let mut all_member_weights = vector[];
    let mut time_band_counts = vector[];
    let mut all_time_band_afters = vector[];
    let mut all_time_band_weights = vector[];
    config.groups.do_ref!(|group| {
        group_names.push_back(group.name);
        group_member_counts.push_back(group.members.length());
        group.members.do_ref!(|m| {
            all_member_addresses.push_back(m.addr);
            all_member_weights.push_back(m.weight);
        });
        time_band_counts.push_back(group.time_bands.length());
        group.time_bands.do_ref!(|band| {
            all_time_band_afters.push_back(band.after_ms);
            all_time_band_weights.push_back(band.weight);
        });
    });

    // Flatten approve policy
    let mut approve_path_req_counts = vector[];
    let mut all_approve_group_indices = vector[];
    let mut all_approve_thresholds = vector[];
    config.approve_policy.paths.do_ref!(|path| {
        approve_path_req_counts.push_back(path.requirements.length());
        path.requirements.do_ref!(|req| {
            all_approve_group_indices.push_back(req.group_idx);
            all_approve_thresholds.push_back(req.threshold);
        });
    });

    // Flatten cancel policy
    let mut cancel_path_req_counts = vector[];
    let mut all_cancel_group_indices = vector[];
    let mut all_cancel_thresholds = vector[];
    config.cancel_policy.paths.do_ref!(|path| {
        cancel_path_req_counts.push_back(path.requirements.length());
        path.requirements.do_ref!(|req| {
            all_cancel_group_indices.push_back(req.group_idx);
            all_cancel_thresholds.push_back(req.threshold);
        });
    });

    event::emit(ConfigChangedEvent {
        account_addr: account::addr(account),
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
        propose_groups: config.propose_groups,
        execute_groups: config.execute_groups,
        cancel_groups: config.cancel_groups,
        intent_expiry_ms: config.intent_expiry_ms,
        config_nonce: config.config_nonce,
    });
}

// === Config Accessors ===

/// Get the groups.
public fun groups(config: &MultisigConfig): &vector<Group> {
    &config.groups
}

/// Get a group by index.
public fun group_at(config: &MultisigConfig, idx: u64): &Group {
    &config.groups[idx]
}

/// Get number of groups.
public fun group_count(config: &MultisigConfig): u64 {
    config.groups.length()
}

/// Get the approve policy.
public fun approve_policy(config: &MultisigConfig): &RolePolicy {
    &config.approve_policy
}

/// Get the cancel policy.
public fun cancel_policy(config: &MultisigConfig): &RolePolicy {
    &config.cancel_policy
}

/// Get propose group indices.
public fun propose_groups(config: &MultisigConfig): &vector<u64> {
    &config.propose_groups
}

/// Get execute group indices.
public fun execute_groups(config: &MultisigConfig): &vector<u64> {
    &config.execute_groups
}

/// Get cancel group indices.
public fun cancel_groups(config: &MultisigConfig): &vector<u64> {
    &config.cancel_groups
}

/// Get the current config nonce.
public fun config_nonce(config: &MultisigConfig): u64 {
    config.config_nonce
}

/// Get intent expiry in milliseconds.
public fun intent_expiry_ms(config: &MultisigConfig): u64 {
    config.intent_expiry_ms
}

// === Group Accessors ===

/// Get group name.
public fun group_name(group: &Group): &String {
    &group.name
}

/// Get group members.
public fun group_members(group: &Group): &vector<GroupMember> {
    &group.members
}

/// Get group time bands.
public fun group_time_bands(group: &Group): &vector<TimeBand> {
    &group.time_bands
}

/// Get member address.
public fun member_addr(member: &GroupMember): address {
    member.addr
}

/// Get member weight.
public fun member_weight(member: &GroupMember): u64 {
    member.weight
}

/// Get time band after_ms.
public fun time_band_after_ms(band: &TimeBand): u64 {
    band.after_ms
}

/// Get time band weight.
public fun time_band_weight(band: &TimeBand): u64 {
    band.weight
}

// === RolePolicy / PolicyPath Accessors ===

/// Get paths from a role policy.
public fun policy_paths(policy: &RolePolicy): &vector<PolicyPath> {
    &policy.paths
}

/// Get requirements from a policy path.
public fun path_requirements(path: &PolicyPath): &vector<PathRequirement> {
    &path.requirements
}

/// Get group index from a path requirement.
public fun requirement_group_idx(req: &PathRequirement): u64 {
    req.group_idx
}

/// Get threshold from a path requirement.
public fun requirement_threshold(req: &PathRequirement): u64 {
    req.threshold
}

// === Outcome Accessors ===

/// Get the config nonce captured by this outcome.
public fun outcome_config_nonce(outcome: &Approvals): u64 {
    outcome.config_nonce
}

/// Get current intent status.
public fun outcome_status(outcome: &Approvals): u8 {
    outcome.status
}

/// Get addresses that approved.
public fun approved(outcome: &Approvals): vector<address> {
    *outcome.approved.keys()
}

/// Get addresses that rejected.
public fun rejected(outcome: &Approvals): vector<address> {
    *outcome.rejected.keys()
}

/// Get the matched vote path index (if approved).
public fun matched_vote_path(outcome: &Approvals): &Option<u64> {
    &outcome.matched_vote_path
}

/// Get approval timestamp in milliseconds.
public fun approved_at_ms(outcome: &Approvals): u64 {
    outcome.approved_at_ms
}

// === Event Accessors ===

public fun intent_cancelled_event_account_addr(event: &IntentCancelledEvent): address {
    event.account_addr
}

public fun intent_cancelled_event_key(event: &IntentCancelledEvent): String {
    event.key
}

public fun intent_cancelled_event_canceller(event: &IntentCancelledEvent): address {
    event.canceller
}

public fun intent_cancelled_event_reason(event: &IntentCancelledEvent): u8 {
    event.reason
}

// === Status Constants ===

public fun status_active(): u8 { STATUS_ACTIVE }
public fun status_approved(): u8 { STATUS_APPROVED }
public fun status_rejected(): u8 { STATUS_REJECTED }
public fun status_executed(): u8 { STATUS_EXECUTED }

public fun cancel_reason_pending(): u8 { CANCEL_REASON_PENDING }
public fun cancel_reason_stale(): u8 { CANCEL_REASON_STALE }
public fun cancel_reason_rejected(): u8 { CANCEL_REASON_REJECTED }
public fun cancel_reason_expired(): u8 { CANCEL_REASON_EXPIRED }

// === Test Helpers ===

#[test_only]
public fun config_witness(): ConfigWitness {
    ConfigWitness()
}

#[test_only]
public fun init_for_testing(ctx: &mut TxContext) {
    init(ctx);
}

#[test_only]
public fun new_account_for_testing(
    registry: &PackageRegistry,
    metadata_keys: vector<String>,
    metadata_values: vector<String>,
    ctx: &mut TxContext,
): Account {
    // Test fixture: single-member group, single-requirement policies.
    // Approve and cancel policies are written independently — no copy-from-approve.
    let default_group = Group {
        name: b"default".to_string(),
        members: vector[GroupMember { addr: ctx.sender(), weight: 1 }],
        time_bands: vector[],
    };
    let approve_policy = RolePolicy {
        paths: vector[PolicyPath {
            requirements: vector[PathRequirement { group_idx: 0, threshold: 1 }],
        }],
    };
    let cancel_policy = RolePolicy {
        paths: vector[PolicyPath {
            requirements: vector[PathRequirement { group_idx: 0, threshold: 1 }],
        }],
    };
    let config = MultisigConfig {
        groups: vector[default_group],
        approve_policy,
        cancel_policy,
        propose_groups: vector[0],
        execute_groups: vector[0],
        cancel_groups: vector[0],
        intent_expiry_ms: DEFAULT_INTENT_EXPIRY_MS,
        config_nonce: 0,
    };

    let deps = deps::new(registry);

    account::new(
        config,
        metadata::from_keys_values(metadata_keys, metadata_values),
        deps,
        ConfigWitness(),
        ctx,
    )
}

#[test_only]
public fun create_fee_vault_for_testing(ctx: &mut TxContext): MultisigFeeVault {
    MultisigFeeVault {
        id: object::new(ctx),
        balance: balance::zero(),
        creation_fee: MULTISIG_CREATION_FEE,
        fee_recipient: ctx.sender(),
    }
}

#[test_only]
public fun create_admin_cap_for_testing(ctx: &mut TxContext): MultisigAdminCap {
    MultisigAdminCap { id: object::new(ctx) }
}

#[test_only]
public fun new_group(name: String, members: vector<GroupMember>, time_bands: vector<TimeBand>): Group {
    Group { name, members, time_bands }
}

#[test_only]
public fun new_group_member(addr: address, weight: u64): GroupMember {
    GroupMember { addr, weight }
}

#[test_only]
public fun new_time_band(after_ms: u64, weight: u64): TimeBand {
    TimeBand { after_ms, weight }
}

#[test_only]
public fun new_path_requirement(group_idx: u64, threshold: u64): PathRequirement {
    PathRequirement { group_idx, threshold }
}

#[test_only]
public fun new_policy_path(requirements: vector<PathRequirement>): PolicyPath {
    PolicyPath { requirements }
}

#[test_only]
public fun new_role_policy(paths: vector<PolicyPath>): RolePolicy {
    RolePolicy { paths }
}

#[test_only]
public fun set_approve_policy(config: &mut MultisigConfig, policy: RolePolicy) {
    config.approve_policy = policy;
}

#[test_only]
public fun set_cancel_policy(config: &mut MultisigConfig, policy: RolePolicy) {
    config.cancel_policy = policy;
}

#[test_only]
public fun set_propose_groups(config: &mut MultisigConfig, groups: vector<u64>) {
    config.propose_groups = groups;
}

#[test_only]
public fun set_execute_groups(config: &mut MultisigConfig, groups: vector<u64>) {
    config.execute_groups = groups;
}

#[test_only]
public fun set_cancel_groups(config: &mut MultisigConfig, groups: vector<u64>) {
    config.cancel_groups = groups;
}

#[test_only]
public fun set_groups(config: &mut MultisigConfig, groups: vector<Group>) {
    config.groups = groups;
}

#[test_only]
/// Set only the approve threshold (single-path, group 0). Tests must set cancel
/// threshold separately via `set_cancel_threshold` — there is no combined helper.
public fun set_approve_threshold(config: &mut MultisigConfig, threshold: u64) {
    config.approve_policy = RolePolicy {
        paths: vector[PolicyPath {
            requirements: vector[PathRequirement { group_idx: 0, threshold }],
        }],
    };
}

#[test_only]
/// Set only the cancel threshold (single-path, group 0).
public fun set_cancel_threshold(config: &mut MultisigConfig, threshold: u64) {
    config.cancel_policy = RolePolicy {
        paths: vector[PolicyPath {
            requirements: vector[PathRequirement { group_idx: 0, threshold }],
        }],
    };
}

#[test_only]
public fun set_intent_expiry_for_testing(config: &mut MultisigConfig, intent_expiry_ms: u64) {
    config.intent_expiry_ms = intent_expiry_ms;
    assert_valid_intent_policy(intent_expiry_ms);
}

#[test_only]
public fun set_config_nonce_for_testing(config: &mut MultisigConfig, nonce: u64) {
    config.config_nonce = nonce;
}

#[test_only]
public fun config_changed_event_config_nonce(event: &ConfigChangedEvent): u64 {
    event.config_nonce
}

#[test_only]
public fun new_approvals_for_testing(
    config_nonce: u64,
): Approvals {
    Approvals {
        config_nonce,
        status: STATUS_ACTIVE,
        approved: vec_set::empty(),
        rejected: vec_set::empty(),
        matched_vote_path: option::none(),
        approved_at_ms: 0,
    }
}

#[test_only]
public fun default_intent_expiry_ms(): u64 {
    DEFAULT_INTENT_EXPIRY_MS
}

#[test_only]
/// Add a member to a group for testing.
public fun add_member_to_group(config: &mut MultisigConfig, group_idx: u64, addr: address, weight: u64) {
    config.groups[group_idx].members.push_back(GroupMember { addr, weight });
}

#[test_only]
/// Remove a member from a group by address for testing.
public fun remove_member_from_group(config: &mut MultisigConfig, group_idx: u64, addr: address) {
    let members = &mut config.groups[group_idx].members;
    let idx = members.find_index!(|m| m.addr == addr);
    assert!(idx.is_some());
    members.remove(idx.destroy_some());
}
