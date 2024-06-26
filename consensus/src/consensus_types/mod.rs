// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::{consensus_service::ChainTransaction, ConsensusOutput};
use address::AccountAddress;
use base_types::ObjectID;
use messages_consensus::ConsensusTransaction;
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use sui_types::base_types::SequenceNumber;
use tokio_stream::Stream;
use tonic::{Response, Status};
pub(crate) mod address;
pub mod base_types;
pub(crate) mod committee_api;
pub(crate) mod consensus_output_api;
pub(crate) mod message_envelope;
pub(crate) mod messages_consensus;
pub(crate) mod messages_grpc;
pub(crate) mod signature_verification;
pub mod sui_serde;
pub(crate) mod transaction;

pub mod error {
    pub use sui_types::error::*;
}
pub use messages_grpc::HandleVerifyMessageResponse;
pub use sui_types::object::OBJECT_START_VERSION;
pub use transaction::RawTransaction;
/// An unique integer ID for a validator used by consensus.
/// In Narwhal, this is the inner value of the `AuthorityIdentifier` type.
/// In Mysticeti, this is used the same way as the AuthorityIndex type there.
pub type AuthorityIndex = u32;
pub type ScalarisAddress = AccountAddress;
pub type ConsensusStreamItem = Result<ConsensusOutput, Status>;
pub type ConsensusServiceResult<T> = Result<Response<T>, Status>;
pub type ResponseStream = Pin<Box<dyn Stream<Item = ConsensusStreamItem> + Send>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InternalConsensusTransaction {
    ExternalChain(ChainTransaction),
    Consensus(ConsensusTransaction),
}

const fn builtin_address(suffix: u16) -> AccountAddress {
    let mut addr = [0u8; AccountAddress::LENGTH];
    let [hi, lo] = suffix.to_be_bytes();
    addr[AccountAddress::LENGTH - 2] = hi;
    addr[AccountAddress::LENGTH - 1] = lo;
    AccountAddress::new(addr)
}

macro_rules! built_in_ids {
    ($($addr:ident / $id:ident = $init:expr);* $(;)?) => {
        $(
            pub const $addr: AccountAddress = builtin_address($init);
            pub const $id: ObjectID = ObjectID::from_address($addr);
        )*
    }
}

macro_rules! built_in_pkgs {
    ($($addr:ident / $id:ident = $init:expr);* $(;)?) => {
        built_in_ids! { $($addr / $id = $init;)* }
        pub const SYSTEM_PACKAGE_ADDRESSES: &[AccountAddress] = &[$($addr),*];
        pub fn is_system_package(addr: impl Into<AccountAddress>) -> bool {
            matches!(addr.into(), $($addr)|*)
        }
    }
}

built_in_pkgs! {
    MOVE_STDLIB_ADDRESS / MOVE_STDLIB_PACKAGE_ID = 0x1;
    SUI_FRAMEWORK_ADDRESS / SUI_FRAMEWORK_PACKAGE_ID = 0x2;
    SUI_SYSTEM_ADDRESS / SUI_SYSTEM_PACKAGE_ID = 0x3;
    BRIDGE_ADDRESS / BRIDGE_PACKAGE_ID = 0xb;
    DEEPBOOK_ADDRESS / DEEPBOOK_PACKAGE_ID = 0xdee9;
}

built_in_ids! {
    SUI_SYSTEM_STATE_ADDRESS / SUI_SYSTEM_STATE_OBJECT_ID = 0x5;
    SUI_CLOCK_ADDRESS / SUI_CLOCK_OBJECT_ID = 0x6;
    SUI_AUTHENTICATOR_STATE_ADDRESS / SUI_AUTHENTICATOR_STATE_OBJECT_ID = 0x7;
    SUI_RANDOMNESS_STATE_ADDRESS / SUI_RANDOMNESS_STATE_OBJECT_ID = 0x8;
    SUI_BRIDGE_ADDRESS / SUI_BRIDGE_OBJECT_ID = 0x9;
    SUI_DENY_LIST_ADDRESS / SUI_DENY_LIST_OBJECT_ID = 0x403;
}

pub const SUI_SYSTEM_STATE_OBJECT_SHARED_VERSION: SequenceNumber = OBJECT_START_VERSION;
pub const SUI_CLOCK_OBJECT_SHARED_VERSION: SequenceNumber = OBJECT_START_VERSION;
pub const SUI_AUTHENTICATOR_STATE_OBJECT_SHARED_VERSION: SequenceNumber = OBJECT_START_VERSION;
