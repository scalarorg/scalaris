// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::address::AccountAddress;
use super::{
    base_types::*, error::*, ScalarisAddress, SUI_BRIDGE_OBJECT_ID, SUI_RANDOMNESS_STATE_OBJECT_ID,
};
use super::{
    SUI_AUTHENTICATOR_STATE_OBJECT_ID, SUI_SYSTEM_STATE_OBJECT_ID,
    SUI_SYSTEM_STATE_OBJECT_SHARED_VERSION,
};
use crate::authenticator_state::ActiveJwk;
use crate::committee::{EpochId, ProtocolVersion};
use crate::crypto::{
    default_hash, AuthoritySignInfo, AuthorityStrongQuorumSignInfo, DefaultHash,
    Ed25519SuiSignature, EmptySignInfo, RandomnessRound, Signature, SuiSignatureInner, ToFromBytes,
};
use crate::digests::ChainIdentifier;
use crate::digests::SenderSignedDataDigest;
use crate::message_envelope::{Envelope, Message, TrustedEnvelope, VerifiedEnvelope};
use crate::messages_consensus::{
    ConsensusCommitPrologue, ConsensusCommitPrologueV2, ConsensusCommitPrologueV3,
};
use crate::object::Object;
use crate::signature::GenericSignature;
use fastcrypto::hash::HashFunction;
use itertools::Either;
use serde::{Deserialize, Serialize};
use shared_crypto::intent::{Intent, IntentMessage, IntentScope};
use std::fmt::Write;
use std::fmt::{Debug, Display, Formatter};
use std::io::Write as _;
use std::{hash::Hash, iter};
use strum::IntoStaticStr;
use sui_protocol_config::ProtocolConfig;
use sui_types::crypto::Signable;
use sui_types::digests::ObjectDigest;
use sui_types::transaction::ProgrammableTransaction;
use tap::Pipe;

pub const TEST_ONLY_GAS_UNIT_FOR_TRANSFER: u64 = 10_000;
pub const TEST_ONLY_GAS_UNIT_FOR_OBJECT_BASICS: u64 = 50_000;
pub const TEST_ONLY_GAS_UNIT_FOR_PUBLISH: u64 = 70_000;
pub const TEST_ONLY_GAS_UNIT_FOR_STAKING: u64 = 50_000;
pub const TEST_ONLY_GAS_UNIT_FOR_GENERIC: u64 = 50_000;
pub const TEST_ONLY_GAS_UNIT_FOR_SPLIT_COIN: u64 = 10_000;
// For some transactions we may either perform heavy operations or touch
// objects that are storage expensive. That may happen (and often is the case)
// because the object touched are set up in genesis and carry no storage cost
// (and thus rebate) on first usage.
pub const TEST_ONLY_GAS_UNIT_FOR_HEAVY_COMPUTATION_STORAGE: u64 = 5_000_000;

pub const GAS_PRICE_FOR_SYSTEM_TX: u64 = 1;

pub const DEFAULT_VALIDATOR_GAS_PRICE: u64 = 1000;

const BLOCKED_MOVE_FUNCTIONS: [(ObjectID, &str, &str); 0] = [];

// #[cfg(test)]
// #[cfg(feature = "test-utils")]
// #[path = "unit_tests/messages_tests.rs"]
// mod messages_tests;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub enum TransactionData {
    V1(TransactionDataV1),
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct TransactionDataV1 {
    pub kind: TransactionKind,
    pub sender: ScalarisAddress,
    pub gas_data: GasData,
    pub expiration: TransactionExpiration,
}
/// Something that we know how to hash and sign.
impl<W> Signable<W> for TransactionData
where
    W: std::io::Write,
{
    fn write(&self, writer: &mut W) {
        let name = serde_name::trace_name::<Self>().expect("Self must be a struct or an enum");
        write!(writer, "{}::", name).expect("Hasher should not fail");
        bcs::serialize_into(writer, &self).expect("Message serialization should not fail");
    }
}

impl TransactionData {
    fn new_system_transaction(kind: TransactionKind) -> Self {
        // assert transaction kind if a system transaction
        assert!(kind.is_system_tx());
        let sender = ScalarisAddress::default();
        TransactionData::V1(TransactionDataV1 {
            kind,
            sender,
            gas_data: GasData {
                price: GAS_PRICE_FOR_SYSTEM_TX,
                owner: sender,
                payment: vec![(ObjectID::ZERO, SequenceNumber::default(), ObjectDigest::MIN)],
                budget: 0,
            },
            expiration: TransactionExpiration::None,
        })
    }
    // pub fn uses_randomness(&self) -> bool {
    //     self.shared_input_objects()
    //         .iter()
    //         .any(|obj| obj.id() == SUI_RANDOMNESS_STATE_OBJECT_ID)
    // }
}
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, Serialize, Deserialize)]
pub enum ObjectArg {
    // A Move object, either immutable, or owned mutable.
    ImmOrOwnedObject(ObjectRef),
    // A Move object that's shared.
    // SharedObject::mutable controls whether caller asks for a mutable reference to shared object.
    SharedObject {
        id: ObjectID,
        initial_shared_version: SequenceNumber,
        mutable: bool,
    },
    // A Move object that can be received in this transaction.
    Receiving(ObjectRef),
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct ChangeEpoch {
    /// The next (to become) epoch ID.
    pub epoch: EpochId,
    /// The protocol version in effect in the new epoch.
    pub protocol_version: ProtocolVersion,
    /// The total amount of gas charged for storage during the epoch.
    pub storage_charge: u64,
    /// The total amount of gas charged for computation during the epoch.
    pub computation_charge: u64,
    /// The amount of storage rebate refunded to the txn senders.
    pub storage_rebate: u64,
    /// The non-refundable storage fee.
    pub non_refundable_storage_fee: u64,
    /// Unix timestamp when epoch started
    pub epoch_start_timestamp_ms: u64,
    /// System packages (specifically framework and move stdlib) that are written before the new
    /// epoch starts. This tracks framework upgrades on chain. When executing the ChangeEpoch txn,
    /// the validator must write out the modules below.  Modules are provided with the version they
    /// will be upgraded to, their modules in serialized form (which include their package ID), and
    /// a list of their transitive dependencies.
    pub system_packages: Vec<(SequenceNumber, Vec<Vec<u8>>, Vec<ObjectID>)>,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct GenesisTransaction {
    pub objects: Vec<GenesisObject>,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub enum GenesisObject {
    RawObject {
        data: crate::object::Data,
        owner: crate::object::Owner,
    },
}

// impl GenesisObject {
//     pub fn id(&self) -> ObjectID {
//         match self {
//             GenesisObject::RawObject { data, .. } => data.id(),
//         }
//     }
// }

#[derive(Debug, Hash, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct AuthenticatorStateExpire {
    /// expire JWKs that have a lower epoch than this
    pub min_epoch: u64,
    /// The initial version of the authenticator object that it was shared at.
    pub authenticator_obj_initial_shared_version: SequenceNumber,
}

impl AuthenticatorStateExpire {
    pub fn authenticator_obj_initial_shared_version(&self) -> SequenceNumber {
        self.authenticator_obj_initial_shared_version
    }
}

#[derive(Debug, Hash, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct AuthenticatorStateUpdate {
    /// Epoch of the authenticator state update transaction
    pub epoch: u64,
    /// Consensus round of the authenticator state update
    pub round: u64,
    /// newly active jwks
    pub new_active_jwks: Vec<ActiveJwk>,
    /// The initial version of the authenticator object that it was shared at.
    pub authenticator_obj_initial_shared_version: SequenceNumber,
    // to version this struct, do not add new fields. Instead, add a AuthenticatorStateUpdateV2 to
    // TransactionKind.
}

impl AuthenticatorStateUpdate {
    pub fn authenticator_obj_initial_shared_version(&self) -> SequenceNumber {
        self.authenticator_obj_initial_shared_version
    }
}

#[derive(Debug, Hash, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct RandomnessStateUpdate {
    /// Epoch of the randomness state update transaction
    pub epoch: u64,
    /// Randomness round of the update
    pub randomness_round: RandomnessRound,
    /// Updated random bytes
    pub random_bytes: Vec<u8>,
    /// The initial version of the randomness object that it was shared at.
    pub randomness_obj_initial_shared_version: SequenceNumber,
    // to version this struct, do not add new fields. Instead, add a RandomnessStateUpdateV2 to
    // TransactionKind.
}

impl RandomnessStateUpdate {
    pub fn randomness_obj_initial_shared_version(&self) -> SequenceNumber {
        self.randomness_obj_initial_shared_version
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, IntoStaticStr)]
pub enum TransactionKind {
    // A transaction that allows the interleaving of native commands and Move calls
    ProgrammableTransaction(ProgrammableTransaction),
    /// A system transaction that will update epoch information on-chain.
    /// It will only ever be executed once in an epoch.
    /// The argument is the next epoch number, which is critical
    /// because it ensures that this transaction has a unique digest.
    /// This will eventually be translated to a Move call during execution.
    /// It also doesn't require/use a gas object.
    /// A validator will not sign a transaction of this kind from outside. It only
    /// signs internally during epoch changes.
    ///
    /// The ChangeEpoch enumerant is now deprecated (but the ChangeEpoch struct is still used by
    /// EndOfEpochTransaction below).
    ChangeEpoch(ChangeEpoch),
    Genesis(GenesisTransaction),
    ConsensusCommitPrologue(ConsensusCommitPrologue),
    AuthenticatorStateUpdate(AuthenticatorStateUpdate),

    /// EndOfEpochTransaction replaces ChangeEpoch with a list of transactions that are allowed to
    /// run at the end of the epoch.
    EndOfEpochTransaction(Vec<EndOfEpochTransactionKind>),

    RandomnessStateUpdate(RandomnessStateUpdate),
    // V2 ConsensusCommitPrologue also includes the digest of the current consensus output.
    ConsensusCommitPrologueV2(ConsensusCommitPrologueV2),

    ConsensusCommitPrologueV3(ConsensusCommitPrologueV3),
    // .. more transaction types go here
}

/// EndOfEpochTransactionKind
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, IntoStaticStr)]
pub enum EndOfEpochTransactionKind {
    ChangeEpoch(ChangeEpoch),
    AuthenticatorStateCreate,
    AuthenticatorStateExpire(AuthenticatorStateExpire),
    RandomnessStateCreate,
    DenyListStateCreate,
    BridgeStateCreate(ChainIdentifier),
    BridgeCommitteeInit(SequenceNumber),
}

impl EndOfEpochTransactionKind {
    pub fn new_change_epoch(
        next_epoch: EpochId,
        protocol_version: ProtocolVersion,
        storage_charge: u64,
        computation_charge: u64,
        storage_rebate: u64,
        non_refundable_storage_fee: u64,
        epoch_start_timestamp_ms: u64,
        system_packages: Vec<(SequenceNumber, Vec<Vec<u8>>, Vec<ObjectID>)>,
    ) -> Self {
        Self::ChangeEpoch(ChangeEpoch {
            epoch: next_epoch,
            protocol_version,
            storage_charge,
            computation_charge,
            storage_rebate,
            non_refundable_storage_fee,
            epoch_start_timestamp_ms,
            system_packages,
        })
    }

    pub fn new_authenticator_state_expire(
        min_epoch: u64,
        authenticator_obj_initial_shared_version: SequenceNumber,
    ) -> Self {
        Self::AuthenticatorStateExpire(AuthenticatorStateExpire {
            min_epoch,
            authenticator_obj_initial_shared_version,
        })
    }

    pub fn new_authenticator_state_create() -> Self {
        Self::AuthenticatorStateCreate
    }

    pub fn new_randomness_state_create() -> Self {
        Self::RandomnessStateCreate
    }

    pub fn new_deny_list_state_create() -> Self {
        Self::DenyListStateCreate
    }

    pub fn new_bridge_create(chain_identifier: ChainIdentifier) -> Self {
        Self::BridgeStateCreate(chain_identifier)
    }

    pub fn init_bridge_committee(bridge_shared_version: SequenceNumber) -> Self {
        Self::BridgeCommitteeInit(bridge_shared_version)
    }

    fn input_objects(&self) -> Vec<InputObjectKind> {
        match self {
            Self::ChangeEpoch(_) => {
                vec![InputObjectKind::SharedMoveObject {
                    id: SUI_SYSTEM_STATE_OBJECT_ID,
                    initial_shared_version: SUI_SYSTEM_STATE_OBJECT_SHARED_VERSION,
                    mutable: true,
                }]
            }
            Self::AuthenticatorStateCreate => vec![],
            Self::AuthenticatorStateExpire(expire) => {
                vec![InputObjectKind::SharedMoveObject {
                    id: SUI_AUTHENTICATOR_STATE_OBJECT_ID,
                    initial_shared_version: expire.authenticator_obj_initial_shared_version(),
                    mutable: true,
                }]
            }
            Self::RandomnessStateCreate => vec![],
            Self::DenyListStateCreate => vec![],
            Self::BridgeStateCreate(_) => vec![],
            Self::BridgeCommitteeInit(bridge_version) => vec![
                InputObjectKind::SharedMoveObject {
                    id: SUI_BRIDGE_OBJECT_ID,
                    initial_shared_version: *bridge_version,
                    mutable: true,
                },
                InputObjectKind::SharedMoveObject {
                    id: SUI_SYSTEM_STATE_OBJECT_ID,
                    initial_shared_version: SUI_SYSTEM_STATE_OBJECT_SHARED_VERSION,
                    mutable: true,
                },
            ],
        }
    }

    fn shared_input_objects(&self) -> impl Iterator<Item = SharedInputObject> + '_ {
        match self {
            Self::ChangeEpoch(_) => {
                Either::Left(vec![SharedInputObject::SUI_SYSTEM_OBJ].into_iter())
            }
            Self::AuthenticatorStateExpire(expire) => Either::Left(
                vec![SharedInputObject {
                    id: SUI_AUTHENTICATOR_STATE_OBJECT_ID,
                    initial_shared_version: expire.authenticator_obj_initial_shared_version(),
                    mutable: true,
                }]
                .into_iter(),
            ),
            Self::AuthenticatorStateCreate => Either::Right(iter::empty()),
            Self::RandomnessStateCreate => Either::Right(iter::empty()),
            Self::DenyListStateCreate => Either::Right(iter::empty()),
            Self::BridgeStateCreate(_) => Either::Right(iter::empty()),
            Self::BridgeCommitteeInit(bridge_version) => Either::Left(
                vec![
                    SharedInputObject {
                        id: SUI_BRIDGE_OBJECT_ID,
                        initial_shared_version: *bridge_version,
                        mutable: true,
                    },
                    SharedInputObject::SUI_SYSTEM_OBJ,
                ]
                .into_iter(),
            ),
        }
    }

    fn validity_check(&self, config: &ProtocolConfig) -> UserInputResult {
        match self {
            Self::ChangeEpoch(_) => (),
            Self::AuthenticatorStateCreate | Self::AuthenticatorStateExpire(_) => {
                // Transaction should have been rejected earlier (or never formed).
                assert!(config.enable_jwk_consensus_updates());
            }
            Self::RandomnessStateCreate => {
                // Transaction should have been rejected earlier (or never formed).
                assert!(config.random_beacon());
            }
            Self::DenyListStateCreate => {
                // Transaction should have been rejected earlier (or never formed).
                assert!(config.enable_coin_deny_list());
            }
            Self::BridgeStateCreate(_) | Self::BridgeCommitteeInit(_) => {
                // Transaction should have been rejected earlier (or never formed).
                assert!(config.enable_bridge());
            }
        }
        Ok(())
    }
}
pub type RawData = Vec<u8>;
impl Message for RawData {
    type DigestType = TransactionDigest;
    const SCOPE: IntentScope = IntentScope::SenderSignedTransaction;

    fn digest(&self) -> Self::DigestType {
        let mut digest = DefaultHash::default();
        let _ = digest.write(self.as_slice());
        let hash = digest.finalize();
        TransactionDigest::new(hash.into())
    }
}

pub type RawTransaction = Envelope<RawData, EmptySignInfo>;
/// A transaction that is signed by a sender but not yet by an authority.
pub type Transaction = Envelope<SenderSignedData, EmptySignInfo>;
pub type VerifiedTransaction = VerifiedEnvelope<SenderSignedData, EmptySignInfo>;
pub type TrustedTransaction = TrustedEnvelope<SenderSignedData, EmptySignInfo>;

/// A transaction that is signed by a sender and also by an authority.
pub type SignedTransaction = Envelope<SenderSignedData, AuthoritySignInfo>;
pub type VerifiedSignedTransaction = VerifiedEnvelope<SenderSignedData, AuthoritySignInfo>;
pub type CertifiedTransaction = Envelope<SenderSignedData, AuthorityStrongQuorumSignInfo>;

// impl VersionedProtocolMessage for TransactionKind {
//     fn check_version_and_features_supported(&self, protocol_config: &ProtocolConfig) -> SuiResult {
//         // When adding new cases, they must be guarded by a feature flag and return
//         // UnsupportedFeatureError if the flag is not set.
//         match &self {
//             TransactionKind::ChangeEpoch(_)
//             | TransactionKind::Genesis(_)
//             | TransactionKind::ConsensusCommitPrologue(_) => Ok(()),
//             TransactionKind::ProgrammableTransaction(pt) => {
//                 // NB: we don't use the `receiving_objects` method here since we don't want to check
//                 // for any validity requirements such as duplicate receiving inputs at this point.
//                 if !protocol_config.receiving_objects_supported() {
//                     let has_receiving_objects = pt
//                         .inputs
//                         .iter()
//                         .any(|arg| !arg.receiving_objects().is_empty());
//                     if has_receiving_objects {
//                         return Err(SuiError::UnsupportedFeatureError {
//                             error: format!(
//                                 "receiving objects is not supported at {:?}",
//                                 protocol_config.version
//                             ),
//                         });
//                     }
//                 }
//                 Ok(())
//             }
//             TransactionKind::AuthenticatorStateUpdate(_) => {
//                 if protocol_config.enable_jwk_consensus_updates() {
//                     Ok(())
//                 } else {
//                     Err(SuiError::UnsupportedFeatureError {
//                         error: "authenticator state updates not enabled".to_string(),
//                     })
//                 }
//             }
//             TransactionKind::RandomnessStateUpdate(_) => {
//                 if protocol_config.random_beacon() {
//                     Ok(())
//                 } else {
//                     Err(SuiError::UnsupportedFeatureError {
//                         error: "randomness state updates not enabled".to_string(),
//                     })
//                 }
//             }
//             TransactionKind::EndOfEpochTransaction(txns) => {
//                 if !protocol_config.end_of_epoch_transaction_supported() {
//                     Err(SuiError::UnsupportedFeatureError {
//                         error: "EndOfEpochTransaction is not supported".to_string(),
//                     })
//                 } else {
//                     for tx in txns {
//                         match tx {
//                             EndOfEpochTransactionKind::ChangeEpoch(_) => (),
//                             EndOfEpochTransactionKind::AuthenticatorStateCreate
//                             | EndOfEpochTransactionKind::AuthenticatorStateExpire(_) => {
//                                 if !protocol_config.enable_jwk_consensus_updates() {
//                                     return Err(SuiError::UnsupportedFeatureError {
//                                         error: "authenticator state updates not enabled"
//                                             .to_string(),
//                                     });
//                                 }
//                             }
//                             EndOfEpochTransactionKind::RandomnessStateCreate => {
//                                 if !protocol_config.random_beacon() {
//                                     return Err(SuiError::UnsupportedFeatureError {
//                                         error: "random beacon not enabled".to_string(),
//                                     });
//                                 }
//                             }
//                             EndOfEpochTransactionKind::DenyListStateCreate => {
//                                 if !protocol_config.enable_coin_deny_list() {
//                                     return Err(SuiError::UnsupportedFeatureError {
//                                         error: "coin deny list not enabled".to_string(),
//                                     });
//                                 }
//                             }
//                             EndOfEpochTransactionKind::BridgeStateCreate(_) => {
//                                 if !protocol_config.enable_bridge() {
//                                     return Err(SuiError::UnsupportedFeatureError {
//                                         error: "bridge not enabled".to_string(),
//                                     });
//                                 }
//                             }
//                             EndOfEpochTransactionKind::BridgeCommitteeInit(_) => {
//                                 if !protocol_config.enable_bridge() {
//                                     return Err(SuiError::UnsupportedFeatureError {
//                                         error: "bridge not enabled".to_string(),
//                                     });
//                                 }
//                             }
//                         }
//                     }

//                     Ok(())
//                 }
//             }
//             TransactionKind::ConsensusCommitPrologueV2(_) => {
//                 if protocol_config.include_consensus_digest_in_prologue() {
//                     Ok(())
//                 } else {
//                     Err(SuiError::UnsupportedFeatureError {
//                         error: "ConsensusCommitPrologueV2 is not supported".to_string(),
//                     })
//                 }
//             }
//             TransactionKind::ConsensusCommitPrologueV3(_) => {
//                 if protocol_config.record_consensus_determined_version_assignments_in_prologue() {
//                     Ok(())
//                 } else {
//                     Err(SuiError::UnsupportedFeatureError {
//                         error: "ConsensusCommitPrologueV3 is not supported".to_string(),
//                     })
//                 }
//             }
//         }
//     }
// }

// impl CallArg {
//     fn input_objects(&self) -> Vec<InputObjectKind> {
//         match self {
//             CallArg::Pure(_) => vec![],
//             CallArg::Object(ObjectArg::ImmOrOwnedObject(object_ref)) => {
//                 vec![InputObjectKind::ImmOrOwnedMoveObject(*object_ref)]
//             }
//             CallArg::Object(ObjectArg::SharedObject {
//                 id,
//                 initial_shared_version,
//                 mutable,
//             }) => {
//                 let id = *id;
//                 let initial_shared_version = *initial_shared_version;
//                 let mutable = *mutable;
//                 vec![InputObjectKind::SharedMoveObject {
//                     id,
//                     initial_shared_version,
//                     mutable,
//                 }]
//             }
//             // Receiving objects are not part of the input objects.
//             CallArg::Object(ObjectArg::Receiving(_)) => vec![],
//         }
//     }

//     fn receiving_objects(&self) -> Vec<ObjectRef> {
//         match self {
//             CallArg::Pure(_) => vec![],
//             CallArg::Object(o) => match o {
//                 ObjectArg::ImmOrOwnedObject(_) => vec![],
//                 ObjectArg::SharedObject { .. } => vec![],
//                 ObjectArg::Receiving(obj_ref) => vec![*obj_ref],
//             },
//         }
//     }

//     pub fn validity_check(&self, config: &ProtocolConfig) -> UserInputResult {
//         match self {
//             CallArg::Pure(p) => {
//                 fp_ensure!(
//                     p.len() < config.max_pure_argument_size() as usize,
//                     UserInputError::SizeLimitExceeded {
//                         limit: "maximum pure argument size".to_string(),
//                         value: config.max_pure_argument_size().to_string()
//                     }
//                 );
//             }
//             CallArg::Object(_) => (),
//         }
//         Ok(())
//     }
// }

// impl From<bool> for CallArg {
//     fn from(b: bool) -> Self {
//         // unwrap safe because every u8 value is BCS-serializable
//         CallArg::Pure(bcs::to_bytes(&b).unwrap())
//     }
// }

// impl From<u8> for CallArg {
//     fn from(n: u8) -> Self {
//         // unwrap safe because every u8 value is BCS-serializable
//         CallArg::Pure(bcs::to_bytes(&n).unwrap())
//     }
// }

// impl From<u16> for CallArg {
//     fn from(n: u16) -> Self {
//         // unwrap safe because every u16 value is BCS-serializable
//         CallArg::Pure(bcs::to_bytes(&n).unwrap())
//     }
// }

// impl From<u32> for CallArg {
//     fn from(n: u32) -> Self {
//         // unwrap safe because every u32 value is BCS-serializable
//         CallArg::Pure(bcs::to_bytes(&n).unwrap())
//     }
// }

// impl From<u64> for CallArg {
//     fn from(n: u64) -> Self {
//         // unwrap safe because every u64 value is BCS-serializable
//         CallArg::Pure(bcs::to_bytes(&n).unwrap())
//     }
// }

// impl From<u128> for CallArg {
//     fn from(n: u128) -> Self {
//         // unwrap safe because every u128 value is BCS-serializable
//         CallArg::Pure(bcs::to_bytes(&n).unwrap())
//     }
// }

// impl From<&Vec<u8>> for CallArg {
//     fn from(v: &Vec<u8>) -> Self {
//         // unwrap safe because every vec<u8> value is BCS-serializable
//         CallArg::Pure(bcs::to_bytes(v).unwrap())
//     }
// }

// impl From<ObjectRef> for CallArg {
//     fn from(obj: ObjectRef) -> Self {
//         CallArg::Object(ObjectArg::ImmOrOwnedObject(obj))
//     }
// }

// impl ObjectArg {
//     pub const SUI_SYSTEM_MUT: Self = Self::SharedObject {
//         id: SUI_SYSTEM_STATE_OBJECT_ID,
//         initial_shared_version: SUI_SYSTEM_STATE_OBJECT_SHARED_VERSION,
//         mutable: true,
//     };

//     pub fn id(&self) -> ObjectID {
//         match self {
//             ObjectArg::Receiving((id, _, _))
//             | ObjectArg::ImmOrOwnedObject((id, _, _))
//             | ObjectArg::SharedObject { id, .. } => *id,
//         }
//     }
// }

/// An argument to a programmable transaction command
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, Serialize, Deserialize)]
pub enum Argument {
    /// The gas coin. The gas coin can only be used by-ref, except for with
    /// `TransferObjects`, which can use it by-value.
    GasCoin,
    /// One of the input objects or primitive values (from
    /// `ProgrammableTransaction` inputs)
    Input(u16),
    /// The result of another command (from `ProgrammableTransaction` commands)
    Result(u16),
    /// Like a `Result` but it accesses a nested result. Currently, the only usage
    /// of this is to access a value from a Move call with multiple return values.
    NestedResult(u16, u16),
}

pub fn write_sep<T: Display>(
    f: &mut Formatter<'_>,
    items: impl IntoIterator<Item = T>,
    sep: &str,
) -> std::fmt::Result {
    let mut xs = items.into_iter();
    let Some(x) = xs.next() else {
        return Ok(());
    };
    write!(f, "{x}")?;
    for x in xs {
        write!(f, "{sep}{x}")?;
    }
    Ok(())
}

impl Display for Argument {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Argument::GasCoin => write!(f, "GasCoin"),
            Argument::Input(i) => write!(f, "Input({i})"),
            Argument::Result(i) => write!(f, "Result({i})"),
            Argument::NestedResult(i, j) => write!(f, "NestedResult({i},{j})"),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct SharedInputObject {
    pub id: ObjectID,
    pub initial_shared_version: SequenceNumber,
    pub mutable: bool,
}

impl SharedInputObject {
    pub const SUI_SYSTEM_OBJ: Self = Self {
        id: SUI_SYSTEM_STATE_OBJECT_ID,
        initial_shared_version: SUI_SYSTEM_STATE_OBJECT_SHARED_VERSION,
        mutable: true,
    };

    pub fn id(&self) -> ObjectID {
        self.id
    }

    pub fn into_id_and_version(self) -> (ObjectID, SequenceNumber) {
        (self.id, self.initial_shared_version)
    }
}

impl TransactionKind {
    pub fn is_system_tx(&self) -> bool {
        // Keep this as an exhaustive match so that we can't forget to update it.
        match self {
            TransactionKind::ChangeEpoch(_)
            | TransactionKind::Genesis(_)
            | TransactionKind::ConsensusCommitPrologue(_)
            | TransactionKind::ConsensusCommitPrologueV2(_)
            | TransactionKind::ConsensusCommitPrologueV3(_)
            | TransactionKind::AuthenticatorStateUpdate(_)
            | TransactionKind::RandomnessStateUpdate(_)
            | TransactionKind::EndOfEpochTransaction(_) => true,
            TransactionKind::ProgrammableTransaction(_) => false,
        }
    }

    pub fn is_end_of_epoch_tx(&self) -> bool {
        matches!(
            self,
            TransactionKind::EndOfEpochTransaction(_) | TransactionKind::ChangeEpoch(_)
        )
    }

    /// If this is advance epoch transaction, returns (total gas charged, total gas rebated).
    /// TODO: We should use GasCostSummary directly in ChangeEpoch struct, and return that
    /// directly.
    pub fn get_advance_epoch_tx_gas_summary(&self) -> Option<(u64, u64)> {
        let e = match self {
            Self::ChangeEpoch(e) => e,
            Self::EndOfEpochTransaction(txns) => {
                if let EndOfEpochTransactionKind::ChangeEpoch(e) =
                    txns.last().expect("at least one end-of-epoch txn required")
                {
                    e
                } else {
                    panic!("final end-of-epoch txn must be ChangeEpoch")
                }
            }
            _ => return None,
        };

        Some((e.computation_charge + e.storage_charge, e.storage_rebate))
    }

    // pub fn contains_shared_object(&self) -> bool {
    //     self.shared_input_objects().next().is_some()
    // }

    // /// Returns an iterator of all shared input objects used by this transaction.
    // /// It covers both Call and ChangeEpoch transaction kind, because both makes Move calls.
    // pub fn shared_input_objects(&self) -> impl Iterator<Item = SharedInputObject> + '_ {
    //     match &self {
    //         Self::ChangeEpoch(_) => {
    //             Either::Left(Either::Left(iter::once(SharedInputObject::SUI_SYSTEM_OBJ)))
    //         }

    //         Self::ConsensusCommitPrologue(_)
    //         | Self::ConsensusCommitPrologueV2(_)
    //         | Self::ConsensusCommitPrologueV3(_) => {
    //             Either::Left(Either::Left(iter::once(SharedInputObject {
    //                 id: SUI_CLOCK_OBJECT_ID,
    //                 initial_shared_version: SUI_CLOCK_OBJECT_SHARED_VERSION,
    //                 mutable: true,
    //             })))
    //         }
    //         Self::AuthenticatorStateUpdate(update) => {
    //             Either::Left(Either::Left(iter::once(SharedInputObject {
    //                 id: SUI_AUTHENTICATOR_STATE_OBJECT_ID,
    //                 initial_shared_version: update.authenticator_obj_initial_shared_version,
    //                 mutable: true,
    //             })))
    //         }
    //         Self::RandomnessStateUpdate(update) => {
    //             Either::Left(Either::Left(iter::once(SharedInputObject {
    //                 id: SUI_RANDOMNESS_STATE_OBJECT_ID,
    //                 initial_shared_version: update.randomness_obj_initial_shared_version,
    //                 mutable: true,
    //             })))
    //         }
    //         Self::EndOfEpochTransaction(txns) => Either::Left(Either::Right(
    //             txns.iter().flat_map(|txn| txn.shared_input_objects()),
    //         )),
    //         Self::ProgrammableTransaction(pt) => {
    //             Either::Right(Either::Left(pt.shared_input_objects()))
    //         }
    //         _ => Either::Right(Either::Right(iter::empty())),
    //     }
    // }

    // pub fn receiving_objects(&self) -> Vec<ObjectRef> {
    //     match &self {
    //         TransactionKind::ChangeEpoch(_)
    //         | TransactionKind::Genesis(_)
    //         | TransactionKind::ConsensusCommitPrologue(_)
    //         | TransactionKind::ConsensusCommitPrologueV2(_)
    //         | TransactionKind::ConsensusCommitPrologueV3(_)
    //         | TransactionKind::AuthenticatorStateUpdate(_)
    //         | TransactionKind::RandomnessStateUpdate(_)
    //         | TransactionKind::EndOfEpochTransaction(_) => vec![],
    //         TransactionKind::ProgrammableTransaction(pt) => pt.receiving_objects(),
    //     }
    // }

    // /// Return the metadata of each of the input objects for the transaction.
    // /// For a Move object, we attach the object reference;
    // /// for a Move package, we provide the object id only since they never change on chain.
    // /// TODO: use an iterator over references here instead of a Vec to avoid allocations.
    // pub fn input_objects(&self) -> UserInputResult<Vec<InputObjectKind>> {
    //     let input_objects = match &self {
    //         Self::ChangeEpoch(_) => {
    //             vec![InputObjectKind::SharedMoveObject {
    //                 id: SUI_SYSTEM_STATE_OBJECT_ID,
    //                 initial_shared_version: SUI_SYSTEM_STATE_OBJECT_SHARED_VERSION,
    //                 mutable: true,
    //             }]
    //         }
    //         Self::Genesis(_) => {
    //             vec![]
    //         }
    //         Self::ConsensusCommitPrologue(_)
    //         | Self::ConsensusCommitPrologueV2(_)
    //         | Self::ConsensusCommitPrologueV3(_) => {
    //             vec![InputObjectKind::SharedMoveObject {
    //                 id: SUI_CLOCK_OBJECT_ID,
    //                 initial_shared_version: SUI_CLOCK_OBJECT_SHARED_VERSION,
    //                 mutable: true,
    //             }]
    //         }
    //         Self::AuthenticatorStateUpdate(update) => {
    //             vec![InputObjectKind::SharedMoveObject {
    //                 id: SUI_AUTHENTICATOR_STATE_OBJECT_ID,
    //                 initial_shared_version: update.authenticator_obj_initial_shared_version(),
    //                 mutable: true,
    //             }]
    //         }
    //         Self::RandomnessStateUpdate(update) => {
    //             vec![InputObjectKind::SharedMoveObject {
    //                 id: SUI_RANDOMNESS_STATE_OBJECT_ID,
    //                 initial_shared_version: update.randomness_obj_initial_shared_version(),
    //                 mutable: true,
    //             }]
    //         }
    //         Self::EndOfEpochTransaction(txns) => {
    //             // Dedup since transactions may have a overlap in input objects.
    //             // Note: it's critical to ensure the order of inputs are deterministic.
    //             let before_dedup: Vec<_> =
    //                 txns.iter().flat_map(|txn| txn.input_objects()).collect();
    //             let mut has_seen = HashSet::new();
    //             let mut after_dedup = vec![];
    //             for obj in before_dedup {
    //                 if has_seen.insert(obj) {
    //                     after_dedup.push(obj);
    //                 }
    //             }
    //             after_dedup
    //         }
    //         Self::ProgrammableTransaction(p) => return p.input_objects(),
    //     };
    //     // Ensure that there are no duplicate inputs. This cannot be removed because:
    //     // In [`AuthorityState::check_locks`], we check that there are no duplicate mutable
    //     // input objects, which would have made this check here unnecessary. However we
    //     // do plan to allow shared objects show up more than once in multiple single
    //     // transactions down the line. Once we have that, we need check here to make sure
    //     // the same shared object doesn't show up more than once in the same single
    //     // transaction.
    //     let mut used = HashSet::new();
    //     if !input_objects.iter().all(|o| used.insert(o.object_id())) {
    //         return Err(UserInputError::DuplicateObjectRefInput);
    //     }
    //     Ok(input_objects)
    // }

    // pub fn validity_check(&self, config: &ProtocolConfig) -> UserInputResult {
    //     match self {
    //         TransactionKind::ProgrammableTransaction(p) => p.validity_check(config)?,
    //         // All transactiond kinds below are assumed to be system,
    //         // and no validity or limit checks are performed.
    //         TransactionKind::ChangeEpoch(_)
    //         | TransactionKind::Genesis(_)
    //         | TransactionKind::ConsensusCommitPrologue(_)
    //         | TransactionKind::ConsensusCommitPrologueV2(_)
    //         | TransactionKind::ConsensusCommitPrologueV3(_) => (),
    //         TransactionKind::EndOfEpochTransaction(txns) => {
    //             // The transaction should have been rejected earlier if the feature is not enabled.
    //             assert!(config.end_of_epoch_transaction_supported());

    //             for tx in txns {
    //                 tx.validity_check(config)?;
    //             }
    //         }

    //         TransactionKind::AuthenticatorStateUpdate(_) => {
    //             // The transaction should have been rejected earlier if the feature is not enabled.
    //             assert!(config.enable_jwk_consensus_updates());
    //         }
    //         TransactionKind::RandomnessStateUpdate(_) => {
    //             // The transaction should have been rejected earlier if the feature is not enabled.
    //             assert!(config.random_beacon());
    //         }
    //     };
    //     Ok(())
    // }

    pub fn name(&self) -> &'static str {
        match self {
            Self::ChangeEpoch(_) => "ChangeEpoch",
            Self::Genesis(_) => "Genesis",
            Self::ConsensusCommitPrologue(_) => "ConsensusCommitPrologue",
            Self::ConsensusCommitPrologueV2(_) => "ConsensusCommitPrologueV2",
            Self::ConsensusCommitPrologueV3(_) => "ConsensusCommitPrologueV3",
            Self::ProgrammableTransaction(_) => "ProgrammableTransaction",
            Self::AuthenticatorStateUpdate(_) => "AuthenticatorStateUpdate",
            Self::RandomnessStateUpdate(_) => "RandomnessStateUpdate",
            Self::EndOfEpochTransaction(_) => "EndOfEpochTransaction",
        }
    }
}

impl Display for TransactionKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut writer = String::new();
        match &self {
            Self::ChangeEpoch(e) => {
                writeln!(writer, "Transaction Kind : Epoch Change")?;
                writeln!(writer, "New epoch ID : {}", e.epoch)?;
                writeln!(writer, "Storage gas reward : {}", e.storage_charge)?;
                writeln!(writer, "Computation gas reward : {}", e.computation_charge)?;
                writeln!(writer, "Storage rebate : {}", e.storage_rebate)?;
                writeln!(writer, "Timestamp : {}", e.epoch_start_timestamp_ms)?;
            }
            Self::Genesis(_) => {
                writeln!(writer, "Transaction Kind : Genesis")?;
            }
            Self::ConsensusCommitPrologue(p) => {
                writeln!(writer, "Transaction Kind : Consensus Commit Prologue")?;
                writeln!(writer, "Timestamp : {}", p.commit_timestamp_ms)?;
            }
            Self::ConsensusCommitPrologueV2(p) => {
                writeln!(writer, "Transaction Kind : Consensus Commit Prologue V2")?;
                writeln!(writer, "Timestamp : {}", p.commit_timestamp_ms)?;
                writeln!(writer, "Consensus Digest: {}", p.consensus_commit_digest)?;
            }
            Self::ConsensusCommitPrologueV3(p) => {
                writeln!(writer, "Transaction Kind : Consensus Commit Prologue V3")?;
                writeln!(writer, "Timestamp : {}", p.commit_timestamp_ms)?;
                writeln!(writer, "Consensus Digest: {}", p.consensus_commit_digest)?;
                writeln!(
                    writer,
                    "Consensus determined version assignment: {:?}",
                    p.consensus_determined_version_assignments
                )?;
            }
            Self::ProgrammableTransaction(p) => {
                writeln!(writer, "Transaction Kind : Programmable")?;
                write!(writer, "{:?}", p)?;
            }
            Self::AuthenticatorStateUpdate(_) => {
                writeln!(writer, "Transaction Kind : Authenticator State Update")?;
            }
            Self::RandomnessStateUpdate(_) => {
                writeln!(writer, "Transaction Kind : Randomness State Update")?;
            }
            Self::EndOfEpochTransaction(_) => {
                writeln!(writer, "Transaction Kind : End of Epoch Transaction")?;
            }
        }
        write!(f, "{}", writer)
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct GasData {
    pub payment: Vec<ObjectRef>,
    pub owner: AccountAddress,
    pub price: u64,
    pub budget: u64,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, Serialize, Deserialize)]
pub enum TransactionExpiration {
    /// The transaction has no expiration
    None,
    /// Validators wont sign a transaction unless the expiration Epoch
    /// is greater than or equal to the current epoch
    Epoch(EpochId),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SenderSignedData(SizeOneVec<SenderSignedTransaction>);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SenderSignedTransaction {
    pub intent_message: IntentMessage<TransactionData>,
    /// A list of signatures signed by all transaction participants.
    /// 1. non participant signature must not be present.
    /// 2. signature order does not matter.
    pub tx_signatures: Vec<GenericSignature>,
}

impl Serialize for SenderSignedTransaction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        #[serde(rename = "SenderSignedTransaction")]
        struct SignedTxn<'a> {
            intent_message: &'a IntentMessage<TransactionData>,
            tx_signatures: &'a Vec<GenericSignature>,
        }

        if self.intent_message().intent != Intent::sui_transaction() {
            return Err(serde::ser::Error::custom("invalid Intent for Transaction"));
        }

        let txn = SignedTxn {
            intent_message: self.intent_message(),
            tx_signatures: &self.tx_signatures,
        };
        txn.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SenderSignedTransaction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename = "SenderSignedTransaction")]
        struct SignedTxn {
            intent_message: IntentMessage<TransactionData>,
            tx_signatures: Vec<GenericSignature>,
        }

        let SignedTxn {
            intent_message,
            tx_signatures,
        } = Deserialize::deserialize(deserializer)?;

        if intent_message.intent != Intent::sui_transaction() {
            return Err(serde::de::Error::custom("invalid Intent for Transaction"));
        }

        Ok(Self {
            intent_message,
            tx_signatures,
        })
    }
}

impl SenderSignedTransaction {
    // pub(crate) fn get_signer_sig_mapping(
    //     &self,
    //     verify_legacy_zklogin_address: bool,
    // ) -> SuiResult<BTreeMap<SuiAddress, &GenericSignature>> {
    //     let mut mapping = BTreeMap::new();
    //     for sig in &self.tx_signatures {
    //         if verify_legacy_zklogin_address {
    //             // Try deriving the address from the legacy padded way.
    //             if let GenericSignature::ZkLoginAuthenticator(z) = sig {
    //                 mapping.insert(SuiAddress::try_from_padded(&z.inputs)?, sig);
    //             };
    //         }
    //         let address = sig.try_into()?;
    //         mapping.insert(address, sig);
    //     }
    //     Ok(mapping)
    // }

    pub fn intent_message(&self) -> &IntentMessage<TransactionData> {
        &self.intent_message
    }
}

impl SenderSignedData {
    pub fn new(tx_data: TransactionData, tx_signatures: Vec<GenericSignature>) -> Self {
        Self(SizeOneVec::new(SenderSignedTransaction {
            intent_message: IntentMessage::new(Intent::sui_transaction(), tx_data),
            tx_signatures,
        }))
    }

    pub fn new_from_sender_signature(tx_data: TransactionData, tx_signature: Signature) -> Self {
        Self(SizeOneVec::new(SenderSignedTransaction {
            intent_message: IntentMessage::new(Intent::sui_transaction(), tx_data),
            tx_signatures: vec![tx_signature.into()],
        }))
    }

    pub fn inner(&self) -> &SenderSignedTransaction {
        self.0.element()
    }

    pub fn inner_mut(&mut self) -> &mut SenderSignedTransaction {
        self.0.element_mut()
    }

    // This function does not check validity of the signature
    // or perform any de-dup checks.
    pub fn add_signature(&mut self, new_signature: Signature) {
        self.inner_mut().tx_signatures.push(new_signature.into());
    }

    // pub(crate) fn get_signer_sig_mapping(
    //     &self,
    //     verify_legacy_zklogin_address: bool,
    // ) -> SuiResult<BTreeMap<SuiAddress, &GenericSignature>> {
    //     self.inner()
    //         .get_signer_sig_mapping(verify_legacy_zklogin_address)
    // }

    pub fn transaction_data(&self) -> &TransactionData {
        &self.intent_message().value
    }

    pub fn intent_message(&self) -> &IntentMessage<TransactionData> {
        self.inner().intent_message()
    }

    pub fn tx_signatures(&self) -> &[GenericSignature] {
        &self.inner().tx_signatures
    }

    pub fn has_zklogin_sig(&self) -> bool {
        self.tx_signatures().iter().any(|sig| sig.is_zklogin())
    }

    pub fn has_upgraded_multisig(&self) -> bool {
        self.tx_signatures()
            .iter()
            .any(|sig| sig.is_upgraded_multisig())
    }

    #[cfg(test)]
    pub fn intent_message_mut_for_testing(&mut self) -> &mut IntentMessage<TransactionData> {
        &mut self.inner_mut().intent_message
    }

    // used cross-crate, so cannot be #[cfg(test)]
    pub fn tx_signatures_mut_for_testing(&mut self) -> &mut Vec<GenericSignature> {
        &mut self.inner_mut().tx_signatures
    }

    pub fn full_message_digest(&self) -> SenderSignedDataDigest {
        let mut digest = DefaultHash::default();
        bcs::serialize_into(&mut digest, self).expect("serialization should not fail");
        let hash = digest.finalize();
        SenderSignedDataDigest::new(hash.into())
    }

    pub fn serialized_size(&self) -> SuiResult<usize> {
        bcs::serialized_size(self).map_err(|e| SuiError::TransactionSerializationError {
            error: e.to_string(),
        })
    }

    fn check_user_signature_protocol_compatibility(&self, config: &ProtocolConfig) -> SuiResult {
        if !config.zklogin_auth() && self.has_zklogin_sig() {
            return Err(SuiError::UnsupportedFeatureError {
                error: "zklogin is not enabled on this network".to_string(),
            });
        }

        if !config.supports_upgraded_multisig() && self.has_upgraded_multisig() {
            return Err(SuiError::UnsupportedFeatureError {
                error: "upgraded multisig format not enabled on this network".to_string(),
            });
        }

        Ok(())
    }

    // /// Validate untrusted user transaction, including its size, input count, command count, etc.
    // pub fn validity_check(&self, config: &ProtocolConfig, epoch: EpochId) -> SuiResult {
    //     // Check that the features used by the user signatures are enabled on the network.
    //     self.check_user_signature_protocol_compatibility(config)?;

    //     // CRITICAL!!
    //     // Users cannot send system transactions.
    //     let tx_data = &self.transaction_data();
    //     fp_ensure!(
    //         !tx_data.is_system_tx(),
    //         SuiError::UserInputError {
    //             error: UserInputError::Unsupported(
    //                 "SenderSignedData must not contain system transaction".to_string()
    //             )
    //         }
    //     );

    //     // Checks to see if the transaction has expired
    //     if match &tx_data.expiration() {
    //         TransactionExpiration::None => false,
    //         TransactionExpiration::Epoch(exp_poch) => *exp_poch < epoch,
    //     } {
    //         return Err(SuiError::TransactionExpired);
    //     }

    //     // Enforce overall transaction size limit.
    //     let tx_size = self.serialized_size()?;
    //     let max_tx_size_bytes = config.max_tx_size_bytes();
    //     fp_ensure!(
    //         tx_size as u64 <= max_tx_size_bytes,
    //         SuiError::UserInputError {
    //             error: UserInputError::SizeLimitExceeded {
    //                 limit: format!(
    //                     "serialized transaction size exceeded maximum of {max_tx_size_bytes}"
    //                 ),
    //                 value: tx_size.to_string(),
    //             }
    //         }
    //     );

    //     tx_data
    //         .check_version_and_features_supported(config)
    //         .map_err(Into::<SuiError>::into)?;
    //     tx_data
    //         .validity_check(config)
    //         .map_err(Into::<SuiError>::into)?;

    //     Ok(())
    // }
}

// impl VersionedProtocolMessage for SenderSignedData {
//     fn message_version(&self) -> Option<u64> {
//         self.transaction_data().message_version()
//     }

//     fn check_version_and_features_supported(&self, protocol_config: &ProtocolConfig) -> SuiResult {
//         self.transaction_data()
//             .check_version_and_features_supported(protocol_config)?;

//         // This code does nothing right now. Its purpose is to cause a compiler error when a
//         // new signature type is added.
//         //
//         // When adding a new signature type, check if current_protocol_version
//         // predates support for the new type. If it does, return
//         // SuiError::WrongMessageVersion
//         for sig in &self.inner().tx_signatures {
//             match sig {
//                 GenericSignature::MultiSig(_) => {
//                     if !protocol_config.supports_upgraded_multisig() {
//                         return Err(SuiError::UnsupportedFeatureError {
//                             error: "multisig format not enabled on this network".to_string(),
//                         });
//                     }
//                 }
//                 GenericSignature::Signature(_)
//                 | GenericSignature::MultiSigLegacy(_)
//                 | GenericSignature::ZkLoginAuthenticator(_) => (),
//             }
//         }
//         Ok(())
//     }
// }

impl Message for SenderSignedData {
    type DigestType = TransactionDigest;
    const SCOPE: IntentScope = IntentScope::SenderSignedTransaction;

    fn digest(&self) -> Self::DigestType {
        // let data = self.intent_message().value.as_slice();
        // let mut digest = DefaultHash::default();
        // digest.write(data);
        // let hash = digest.finalize();
        // TransactionDigest::new(hash.into())
        TransactionDigest::new(default_hash(&self.intent_message().value))
    }
}

// impl<S> Envelope<SenderSignedData, S> {
// pub fn sender_address(&self) -> SuiAddress {
//     self.data().intent_message().value.sender()
// }

// pub fn gas(&self) -> &[ObjectRef] {
//     self.data().intent_message().value.gas()
// }

// pub fn contains_shared_object(&self) -> bool {
//     self.shared_input_objects().next().is_some()
// }

// pub fn shared_input_objects(&self) -> impl Iterator<Item = SharedInputObject> + '_ {
//     self.data()
//         .inner()
//         .intent_message
//         .value
//         .shared_input_objects()
//         .into_iter()
// }

// Returns the primary key for this transaction.
// pub fn key(&self) -> TransactionKey {
//     match &self.data().intent_message().value.kind() {
//         TransactionKind::RandomnessStateUpdate(rsu) => {
//             TransactionKey::RandomnessRound(rsu.epoch, rsu.randomness_round)
//         }
//         _ => TransactionKey::Digest(*self.digest()),
//     }
// }

// Returns non-Digest keys that could be used to refer to this transaction.
//
// At the moment this returns a single Option for efficiency, but if more key types are added,
// the return type could change to Vec<TransactionKey>.
// pub fn non_digest_key(&self) -> Option<TransactionKey> {
//     match &self.data().intent_message().value.kind() {
//         TransactionKind::RandomnessStateUpdate(rsu) => Some(TransactionKey::RandomnessRound(
//             rsu.epoch,
//             rsu.randomness_round,
//         )),
//         _ => None,
//     }
// }

// pub fn is_system_tx(&self) -> bool {
//     self.data().intent_message().value.is_system_tx()
// }

// pub fn is_sponsored_tx(&self) -> bool {
//     self.data().intent_message().value.is_sponsored_tx()
// }
// }

// impl Transaction {
//     pub fn from_data_and_signer(
//         data: TransactionData,
//         signers: Vec<&dyn Signer<Signature>>,
//     ) -> Self {
//         let signatures = {
//             let intent_msg = IntentMessage::new(Intent::sui_transaction(), &data);
//             signers
//                 .into_iter()
//                 .map(|s| Signature::new_secure(&intent_msg, s))
//                 .collect()
//         };
//         Self::from_data(data, signatures)
//     }

//     // TODO: Rename this function and above to make it clearer.
//     pub fn from_data(data: TransactionData, signatures: Vec<Signature>) -> Self {
//         Self::from_generic_sig_data(data, signatures.into_iter().map(|s| s.into()).collect())
//     }

//     pub fn signature_from_signer(
//         data: TransactionData,
//         intent: Intent,
//         signer: &dyn Signer<Signature>,
//     ) -> Signature {
//         let intent_msg = IntentMessage::new(intent, data);
//         Signature::new_secure(&intent_msg, signer)
//     }

//     pub fn from_generic_sig_data(data: TransactionData, signatures: Vec<GenericSignature>) -> Self {
//         Self::new(SenderSignedData::new(data, signatures))
//     }

//     /// Returns the Base64 encoded tx_bytes
//     /// and a list of Base64 encoded [enum GenericSignature].
//     pub fn to_tx_bytes_and_signatures(&self) -> (Base64, Vec<Base64>) {
//         (
//             Base64::from_bytes(&bcs::to_bytes(&self.data().intent_message().value).unwrap()),
//             self.data()
//                 .inner()
//                 .tx_signatures
//                 .iter()
//                 .map(|s| Base64::from_bytes(s.as_ref()))
//                 .collect(),
//         )
//     }
// }

impl VerifiedTransaction {
    //     pub fn new_change_epoch(
    //         next_epoch: EpochId,
    //         protocol_version: ProtocolVersion,
    //         storage_charge: u64,
    //         computation_charge: u64,
    //         storage_rebate: u64,
    //         non_refundable_storage_fee: u64,
    //         epoch_start_timestamp_ms: u64,
    //         system_packages: Vec<(SequenceNumber, Vec<Vec<u8>>, Vec<ObjectID>)>,
    //     ) -> Self {
    //         ChangeEpoch {
    //             epoch: next_epoch,
    //             protocol_version,
    //             storage_charge,
    //             computation_charge,
    //             storage_rebate,
    //             non_refundable_storage_fee,
    //             epoch_start_timestamp_ms,
    //             system_packages,
    //         }
    //         .pipe(TransactionKind::ChangeEpoch)
    //         .pipe(Self::new_system_transaction)
    //     }

    //     pub fn new_genesis_transaction(objects: Vec<GenesisObject>) -> Self {
    //         GenesisTransaction { objects }
    //             .pipe(TransactionKind::Genesis)
    //             .pipe(Self::new_system_transaction)
    //     }

    //     pub fn new_consensus_commit_prologue(
    //         epoch: u64,
    //         round: u64,
    //         commit_timestamp_ms: CheckpointTimestamp,
    //     ) -> Self {
    //         ConsensusCommitPrologue {
    //             epoch,
    //             round,
    //             commit_timestamp_ms,
    //         }
    //         .pipe(TransactionKind::ConsensusCommitPrologue)
    //         .pipe(Self::new_system_transaction)
    //     }

    //     pub fn new_consensus_commit_prologue_v2(
    //         epoch: u64,
    //         round: u64,
    //         commit_timestamp_ms: CheckpointTimestamp,
    //         consensus_commit_digest: ConsensusCommitDigest,
    //     ) -> Self {
    //         ConsensusCommitPrologueV2 {
    //             epoch,
    //             round,
    //             commit_timestamp_ms,
    //             consensus_commit_digest,
    //         }
    //         .pipe(TransactionKind::ConsensusCommitPrologueV2)
    //         .pipe(Self::new_system_transaction)
    //     }

    //     pub fn new_consensus_commit_prologue_v3(
    //         epoch: u64,
    //         round: u64,
    //         commit_timestamp_ms: CheckpointTimestamp,
    //         consensus_commit_digest: ConsensusCommitDigest,
    //         cancelled_txn_version_assignment: Vec<(TransactionDigest, Vec<(ObjectID, SequenceNumber)>)>,
    //     ) -> Self {
    //         ConsensusCommitPrologueV3 {
    //             epoch,
    //             round,
    //             // sub_dag_index is reserved for when we have multi commits per round.
    //             sub_dag_index: None,
    //             commit_timestamp_ms,
    //             consensus_commit_digest,
    //             consensus_determined_version_assignments:
    //                 ConsensusDeterminedVersionAssignments::CancelledTransactions(
    //                     cancelled_txn_version_assignment,
    //                 ),
    //         }
    //         .pipe(TransactionKind::ConsensusCommitPrologueV3)
    //         .pipe(Self::new_system_transaction)
    //     }

    pub fn new_authenticator_state_update(
        epoch: u64,
        round: u64,
        new_active_jwks: Vec<ActiveJwk>,
        authenticator_obj_initial_shared_version: SequenceNumber,
    ) -> Self {
        AuthenticatorStateUpdate {
            epoch,
            round,
            new_active_jwks,
            authenticator_obj_initial_shared_version,
        }
        .pipe(TransactionKind::AuthenticatorStateUpdate)
        .pipe(Self::new_system_transaction)
    }

    //     pub fn new_randomness_state_update(
    //         epoch: u64,
    //         randomness_round: RandomnessRound,
    //         random_bytes: Vec<u8>,
    //         randomness_obj_initial_shared_version: SequenceNumber,
    //     ) -> Self {
    //         RandomnessStateUpdate {
    //             epoch,
    //             randomness_round,
    //             random_bytes,
    //             randomness_obj_initial_shared_version,
    //         }
    //         .pipe(TransactionKind::RandomnessStateUpdate)
    //         .pipe(Self::new_system_transaction)
    //     }

    //     pub fn new_end_of_epoch_transaction(txns: Vec<EndOfEpochTransactionKind>) -> Self {
    //         TransactionKind::EndOfEpochTransaction(txns).pipe(Self::new_system_transaction)
    //     }

    fn new_system_transaction(system_transaction: TransactionKind) -> Self {
        system_transaction
            .pipe(TransactionData::new_system_transaction)
            .pipe(|data| {
                SenderSignedData::new_from_sender_signature(
                    data,
                    Ed25519SuiSignature::from_bytes(&[0; Ed25519SuiSignature::LENGTH])
                        .unwrap()
                        .into(),
                )
            })
            .pipe(Transaction::new)
            .pipe(Self::new_from_verified)
    }
}

// impl VerifiedSignedTransaction {
//     /// Use signing key to create a signed object.
//     pub fn new(
//         epoch: EpochId,
//         transaction: VerifiedTransaction,
//         authority: AuthorityName,
//         secret: &dyn Signer<AuthoritySignature>,
//     ) -> Self {
//         Self::new_from_verified(SignedTransaction::new(
//             epoch,
//             transaction.into_inner().into_data(),
//             secret,
//             authority,
//         ))
//     }
// }

// impl Transaction {
//     pub fn verify_signature_for_testing(
//         &self,
//         current_epoch: EpochId,
//         verify_params: &VerifyParams,
//     ) -> SuiResult {
//         verify_sender_signed_data_message_signatures(
//             self.data(),
//             current_epoch,
//             verify_params,
//             Arc::new(VerifiedDigestCache::new_empty()),
//         )
//     }

//     pub fn try_into_verified_for_testing(
//         self,
//         current_epoch: EpochId,
//         verify_params: &VerifyParams,
//     ) -> SuiResult<VerifiedTransaction> {
//         self.verify_signature_for_testing(current_epoch, verify_params)?;
//         Ok(VerifiedTransaction::new_from_verified(self))
//     }
// }

// impl SignedTransaction {
//     pub fn verify_signatures_authenticated_for_testing(
//         &self,
//         committee: &Committee,
//         verify_params: &VerifyParams,
//     ) -> SuiResult {
//         verify_sender_signed_data_message_signatures(
//             self.data(),
//             committee.epoch(),
//             verify_params,
//             Arc::new(VerifiedDigestCache::new_empty()),
//         )?;

//         self.auth_sig().verify_secure(
//             self.data(),
//             Intent::sui_app(IntentScope::SenderSignedTransaction),
//             committee,
//         )
//     }

//     pub fn try_into_verified_for_testing(
//         self,
//         committee: &Committee,
//         verify_params: &VerifyParams,
//     ) -> SuiResult<VerifiedSignedTransaction> {
//         self.verify_signatures_authenticated_for_testing(committee, verify_params)?;
//         Ok(VerifiedSignedTransaction::new_from_verified(self))
//     }
// }

// impl CertifiedTransaction {
//     pub fn certificate_digest(&self) -> CertificateDigest {
//         let mut digest = DefaultHash::default();
//         bcs::serialize_into(&mut digest, self).expect("serialization should not fail");
//         let hash = digest.finalize();
//         CertificateDigest::new(hash.into())
//     }

//     // pub fn gas_price(&self) -> u64 {
//     //     self.data().transaction_data().gas_price()
//     // }

//     // TODO: Eventually we should remove all calls to verify_signature
//     // and make sure they all call verify to avoid repeated verifications.
//     pub fn verify_signatures_authenticated(
//         &self,
//         committee: &Committee,
//         verify_params: &VerifyParams,
//         zklogin_inputs_cache: Arc<VerifiedDigestCache<ZKLoginInputsDigest>>,
//     ) -> SuiResult {
//         verify_sender_signed_data_message_signatures(
//             self.data(),
//             committee.epoch(),
//             verify_params,
//             zklogin_inputs_cache,
//         )?;
//         self.auth_sig().verify_secure(
//             self.data(),
//             Intent::sui_app(IntentScope::SenderSignedTransaction),
//             committee,
//         )
//     }

//     pub fn try_into_verified_for_testing(
//         self,
//         committee: &Committee,
//         verify_params: &VerifyParams,
//     ) -> SuiResult<VerifiedCertificate> {
//         self.verify_signatures_authenticated(
//             committee,
//             verify_params,
//             Arc::new(VerifiedDigestCache::new_empty()),
//         )?;
//         Ok(VerifiedCertificate::new_from_verified(self))
//     }

//     pub fn verify_committee_sigs_only(&self, committee: &Committee) -> SuiResult {
//         self.auth_sig().verify_secure(
//             self.data(),
//             Intent::sui_app(IntentScope::SenderSignedTransaction),
//             committee,
//         )
//     }
// }

pub type VerifiedCertificate = VerifiedEnvelope<SenderSignedData, AuthorityStrongQuorumSignInfo>;
pub type TrustedCertificate = TrustedEnvelope<SenderSignedData, AuthorityStrongQuorumSignInfo>;

pub trait VersionedProtocolMessage {
    /// Return version of message. Some messages depend on their enclosing messages to know the
    /// version number, so not every implementor implements this.
    fn message_version(&self) -> Option<u64> {
        None
    }

    /// Check that the version of the message is the correct one to use at this protocol version.
    /// Also checks whether the feauures used by the message are supported by the protocol config.
    fn check_version_and_features_supported(&self, protocol_config: &ProtocolConfig) -> SuiResult;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, PartialOrd, Ord, Hash)]
pub enum InputObjectKind {
    // A Move package, must be immutable.
    MovePackage(ObjectID),
    // A Move object, either immutable, or owned mutable.
    ImmOrOwnedMoveObject(ObjectRef),
    // A Move object that's shared and mutable.
    SharedMoveObject {
        id: ObjectID,
        initial_shared_version: SequenceNumber,
        mutable: bool,
    },
}

impl InputObjectKind {
    // pub fn object_id(&self) -> ObjectID {
    //     match self {
    //         Self::MovePackage(id) => *id,
    //         Self::ImmOrOwnedMoveObject((id, _, _)) => *id,
    //         Self::SharedMoveObject { id, .. } => *id,
    //     }
    // }

    pub fn version(&self) -> Option<SequenceNumber> {
        match self {
            Self::MovePackage(..) => None,
            Self::ImmOrOwnedMoveObject((_, version, _)) => Some(*version),
            Self::SharedMoveObject { .. } => None,
        }
    }

    // pub fn object_not_found_error(&self) -> UserInputError {
    //     match *self {
    //         Self::MovePackage(package_id) => {
    //             UserInputError::DependentPackageNotFound { package_id }
    //         }
    //         Self::ImmOrOwnedMoveObject((object_id, version, _)) => UserInputError::ObjectNotFound {
    //             object_id,
    //             version: Some(version),
    //         },
    //         Self::SharedMoveObject { id, .. } => UserInputError::ObjectNotFound {
    //             object_id: id,
    //             version: None,
    //         },
    //     }
    // }

    pub fn is_shared_object(&self) -> bool {
        matches!(self, Self::SharedMoveObject { .. })
    }

    pub fn is_mutable(&self) -> bool {
        match self {
            Self::MovePackage(..) => false,
            Self::ImmOrOwnedMoveObject((_, _, _)) => true,
            Self::SharedMoveObject { mutable, .. } => *mutable,
        }
    }
}

// Result of attempting to read a receiving object (currently only at signing time).
// Because an object may have been previously received and deleted, the result may be
// ReceivingObjectReadResultKind::PreviouslyReceivedObject.
#[derive(Clone, Debug)]
pub enum ReceivingObjectReadResultKind {
    Object(Object),
    // The object was received by some other transaction, and we were not able to read it
    PreviouslyReceivedObject,
}

impl ReceivingObjectReadResultKind {
    pub fn as_object(&self) -> Option<&Object> {
        match &self {
            Self::Object(object) => Some(object),
            Self::PreviouslyReceivedObject => None,
        }
    }
}

pub struct ReceivingObjectReadResult {
    pub object_ref: ObjectRef,
    pub object: ReceivingObjectReadResultKind,
}

impl ReceivingObjectReadResult {
    pub fn new(object_ref: ObjectRef, object: ReceivingObjectReadResultKind) -> Self {
        Self { object_ref, object }
    }

    pub fn is_previously_received(&self) -> bool {
        matches!(
            self.object,
            ReceivingObjectReadResultKind::PreviouslyReceivedObject
        )
    }
}

impl From<Object> for ReceivingObjectReadResultKind {
    fn from(object: Object) -> Self {
        Self::Object(object)
    }
}

pub struct ReceivingObjects {
    pub objects: Vec<ReceivingObjectReadResult>,
}

impl ReceivingObjects {
    pub fn iter(&self) -> impl Iterator<Item = &ReceivingObjectReadResult> {
        self.objects.iter()
    }

    pub fn iter_objects(&self) -> impl Iterator<Item = &Object> {
        self.objects.iter().filter_map(|o| o.object.as_object())
    }
}

impl From<Vec<ReceivingObjectReadResult>> for ReceivingObjects {
    fn from(objects: Vec<ReceivingObjectReadResult>) -> Self {
        Self { objects }
    }
}

// impl Display for CertifiedTransaction {
//     fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
//         let mut writer = String::new();
//         writeln!(writer, "Transaction Hash: {:?}", self.digest())?;
//         writeln!(
//             writer,
//             "Signed Authorities Bitmap : {:?}",
//             self.auth_sig().signers_map
//         )?;
//         write!(writer, "{}", &self.data().intent_message().value.kind())?;
//         write!(f, "{}", writer)
//     }
// }

/// TransactionKey uniquely identifies a transaction across all epochs.
/// Note that a single transaction may have multiple keys, for example a RandomnessStateUpdate
/// could be identified by both `Digest` and `RandomnessRound`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TransactionKey {
    Digest(TransactionDigest),
    RandomnessRound(EpochId, RandomnessRound),
}

impl TransactionKey {
    pub fn unwrap_digest(&self) -> &TransactionDigest {
        match self {
            TransactionKey::Digest(d) => d,
            _ => panic!("called expect_digest on a non-Digest TransactionKey: {self:?}"),
        }
    }
}
