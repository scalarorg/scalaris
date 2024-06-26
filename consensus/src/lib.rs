pub mod authority;
pub mod checkpoints;
pub mod consensus_client;
pub mod consensus_handler;
pub mod consensus_manager;
pub mod consensus_service;
pub mod consensus_throughput_calculator;
pub(crate) mod consensus_types;
pub mod consensus_validator;
pub mod epoch;
pub mod metrics;
pub mod network;
pub mod node;
pub mod post_consensus_tx_reorder;
pub mod proto;
pub mod scoring_decision;
// pub mod signature_verifier;
mod stake_aggregator;
// pub mod storage;
pub(crate) use consensus_types::{message_envelope, messages_consensus, transaction};
pub use node::ConsensusNode;
pub use sui_config::NodeConfig;
mod transaction_input_loader;
use fastcrypto::hash::HashFunction;
pub use proto::{ConsensusApi, ConsensusApiServer, ConsensusOutput, ExternalTransaction};
/*
* Re export modules from sui_types
*/
pub mod authenticator_state {
    pub use sui_types::authenticator_state::*;
}
pub mod base_types {
    pub use sui_types::base_types::*;
}
pub mod committee {
    pub use sui_types::committee::*;
}
pub mod crypto {
    pub use sui_types::crypto::*;
}
pub mod digests {
    pub use sui_types::digests::*;
}
pub mod error {
    pub use sui_types::error::*;
}
pub mod execution {
    pub use sui_types::execution::*;
}
pub mod execution_cache {
    pub use sui_core::execution_cache::*;
}
pub mod executable_transaction {
    pub use sui_types::executable_transaction::*;
}
pub mod messages_checkpoint {
    pub use sui_types::messages_checkpoint::*;
}
pub mod module_cache_metrics {
    pub use sui_core::module_cache_metrics::ResolverMetrics;
}
pub mod object {
    pub use sui_types::object::*;
}

pub mod signature {
    pub use sui_types::signature::*;
}

pub mod signature_verification {
    pub use crate::consensus_types::signature_verification::*;
}

pub mod programmable_transaction_builder {
    pub use sui_types::programmable_transaction_builder::*;
}

pub fn to_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = fastcrypto::hash::Blake2b256::new();
    hasher.update(bytes);
    let digest = <[u8; 32]>::from(hasher.finalize());
    digest
}
