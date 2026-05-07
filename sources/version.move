// Copyright (c) Govex DAO LLC
// SPDX-License-Identifier: BUSL-1.1

module account_multisig::version;

use account_protocol::version_witness::{Self, VersionWitness};

const VERSION: u64 = 1;

public struct V1 has drop {}

public(package) fun current(): VersionWitness {
    version_witness::new(V1 {})
}

public fun get(): u64 {
    VERSION
}
