pub use authority_per_epoch_store::{
    AuthorityPerEpochStore, ConsensusStats, ConsensusStatsAPI, ExecutionIndicesWithStats,
};
pub use metrics::AuthorityMetrics;
use mysten_metrics::spawn_monitored_task;
use once_cell::sync::OnceCell;
pub use state::AuthorityState;
use std::{pin::Pin, sync::Arc};
pub use sui_core::authority::{
    test_authority_builder::TestAuthorityBuilder, AuthorityStore, ResolverWrapper,
};
use sui_types::committee::EpochId;
use sui_types::crypto::Signer;
use sui_types::digests::ChainIdentifier;
pub use verify_state::AuthorityVerifyState;

use sui_types::crypto::AuthoritySignature;
use sui_types::crypto::RandomnessRound;
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{info, instrument, warn};
pub mod authority_aggregator;
pub mod authority_per_epoch_store;
pub mod metrics;
pub mod state;
pub mod test_authority_builder;
pub mod verify_state;
pub mod authority_store_tables {
    pub(crate) const ENV_VAR_LOCKS_BLOCK_CACHE_SIZE: &str = "LOCKS_BLOCK_CACHE_MB";
    pub use sui_core::authority::authority_store_tables::*;
}
pub mod epoch_start_configuration {
    pub use sui_core::authority::epoch_start_configuration::*;
}
pub mod shared_object_version_manager {
    pub use sui_core::authority::shared_object_version_manager::*;
}
pub mod shared_object_congestion_tracker {
    pub use sui_core::authority::shared_object_congestion_tracker::*;
}
pub mod transaction_deferral {
    pub use sui_core::authority::transaction_deferral::*;
}

/// a Trait object for `Signer` that is:
/// - Pin, i.e. confined to one place in memory (we don't want to copy private keys).
/// - Sync, i.e. can be safely shared between threads.
///
/// Typically instantiated with Box::pin(keypair) where keypair is a `KeyPair`
///
pub type StableSyncAuthoritySigner = Pin<Arc<dyn Signer<AuthoritySignature> + Send + Sync>>;
pub static CHAIN_IDENTIFIER: OnceCell<ChainIdentifier> = OnceCell::new();

pub struct RandomnessRoundReceiver {
    authority_state: Arc<AuthorityState>,
    randomness_rx: mpsc::Receiver<(EpochId, RandomnessRound, Vec<u8>)>,
}

impl RandomnessRoundReceiver {
    pub fn spawn(
        authority_state: Arc<AuthorityState>,
        randomness_rx: mpsc::Receiver<(EpochId, RandomnessRound, Vec<u8>)>,
    ) -> JoinHandle<()> {
        let rrr = RandomnessRoundReceiver {
            authority_state,
            randomness_rx,
        };
        spawn_monitored_task!(rrr.run())
    }

    async fn run(mut self) {
        info!("RandomnessRoundReceiver event loop started");

        loop {
            tokio::select! {
                maybe_recv = self.randomness_rx.recv() => {
                    if let Some((epoch, round, bytes)) = maybe_recv {
                        self.handle_new_randomness(epoch, round, bytes);
                    } else {
                        break;
                    }
                },
            }
        }

        info!("RandomnessRoundReceiver event loop ended");
    }
    #[instrument(level = "debug", skip_all, fields(?epoch, ?round))]
    fn handle_new_randomness(&self, epoch: EpochId, round: RandomnessRound, bytes: Vec<u8>) {
        //TODO: Send transaction to TransactionManager for execution.
    }
}
