mod checkpoint_output;
mod metrics;
use std::{path::Path, sync::Arc};

pub use checkpoint_output::{
    CertifiedCheckpointOutput, CheckpointOutput, SendCheckpointToStateSync,
    SubmitCheckpointToConsensus,
};
use sui_types::{
    committee::EpochId,
    digests::{CheckpointContentsDigest, CheckpointDigest},
    error::SuiResult,
    messages_checkpoint::{
        CheckpointContents, CheckpointSequenceNumber, CheckpointSignatureMessage,
        TrustedCheckpoint, VerifiedCheckpoint,
    },
};
use tokio::sync::watch;
use tracing::{info, instrument};
use typed_store::{
    rocks::{DBMap, MetricConf},
    TypedStoreError,
};
use typed_store::{
    traits::{TableSummary, TypedStoreDebug},
    Map,
};
use typed_store_derive::DBMapUtils;

use crate::authority::{AuthorityPerEpochStore, AuthorityState};
pub use metrics::CheckpointMetrics;
pub trait CheckpointServiceNotify {
    fn notify_checkpoint_signature(
        &self,
        epoch_store: &AuthorityPerEpochStore,
        info: &CheckpointSignatureMessage,
    ) -> SuiResult;

    fn notify_checkpoint(&self) -> SuiResult;
}

pub struct CheckpointService {}
impl CheckpointService {
    pub fn spawn(
        metrics: Arc<CheckpointMetrics>,
        max_transactions_per_checkpoint: usize,
        max_checkpoint_size_bytes: usize,
    ) -> (Arc<Self>, watch::Sender<()> /* The exit sender */) {
        info!(
            "Starting checkpoint service with {max_transactions_per_checkpoint} max_transactions_per_checkpoint and {max_checkpoint_size_bytes} max_checkpoint_size_bytes"
        );
        let (exit_snd, exit_rcv) = watch::channel(());
        let service = Arc::new(Self {});
        (service, exit_snd)
    }
}
impl CheckpointServiceNotify for CheckpointService {
    fn notify_checkpoint_signature(
        &self,
        epoch_store: &AuthorityPerEpochStore,
        info: &CheckpointSignatureMessage,
    ) -> SuiResult {
        Ok(())
    }

    fn notify_checkpoint(&self) -> SuiResult {
        Ok(())
    }
}

#[derive(DBMapUtils)]
pub struct CheckpointStore {
    /// Maps checkpoint contents digest to checkpoint contents
    pub(crate) checkpoint_content: DBMap<CheckpointContentsDigest, CheckpointContents>,
    /// Stores certified checkpoints
    pub(crate) certified_checkpoints: DBMap<CheckpointSequenceNumber, TrustedCheckpoint>,
    /// Map from checkpoint digest to certified checkpoint
    pub(crate) checkpoint_by_digest: DBMap<CheckpointDigest, TrustedCheckpoint>,
    /// A map from epoch ID to the sequence number of the last checkpoint in that epoch.
    epoch_last_checkpoint_map: DBMap<EpochId, CheckpointSequenceNumber>,
}

impl CheckpointStore {
    pub fn new(path: &Path) -> Arc<Self> {
        Arc::new(Self::open_tables_read_write(
            path.to_path_buf(),
            MetricConf::new("checkpoint"),
            None,
            None,
        ))
    }
    pub fn checkpoint_db(&self, path: &Path) -> SuiResult {
        // This checkpoints the entire db and not one column family
        self.checkpoint_content
            .checkpoint_db(path)
            .map_err(Into::into)
    }
    pub fn get_checkpoint_contents(
        &self,
        digest: &CheckpointContentsDigest,
    ) -> Result<Option<CheckpointContents>, TypedStoreError> {
        self.checkpoint_content.get(digest)
    }

    pub fn multi_get_checkpoint_content(
        &self,
        contents_digest: &[CheckpointContentsDigest],
    ) -> Result<Vec<Option<CheckpointContents>>, TypedStoreError> {
        self.checkpoint_content.multi_get(contents_digest)
    }
    pub fn get_checkpoint_by_digest(
        &self,
        digest: &CheckpointDigest,
    ) -> Result<Option<VerifiedCheckpoint>, TypedStoreError> {
        self.checkpoint_by_digest
            .get(digest)
            .map(|maybe_checkpoint| maybe_checkpoint.map(|c| c.into()))
    }
    pub fn get_checkpoint_by_sequence_number(
        &self,
        sequence_number: CheckpointSequenceNumber,
    ) -> Result<Option<VerifiedCheckpoint>, TypedStoreError> {
        self.certified_checkpoints
            .get(&sequence_number)
            .map(|maybe_checkpoint| maybe_checkpoint.map(|c| c.into()))
    }
    pub fn multi_get_checkpoint_by_sequence_number(
        &self,
        sequence_numbers: &[CheckpointSequenceNumber],
    ) -> Result<Vec<Option<VerifiedCheckpoint>>, TypedStoreError> {
        let checkpoints = self
            .certified_checkpoints
            .multi_get(sequence_numbers)?
            .into_iter()
            .map(|maybe_checkpoint| maybe_checkpoint.map(|c| c.into()))
            .collect();

        Ok(checkpoints)
    }

    /// Re-executes all transactions from all local, uncertified checkpoints for crash recovery.
    /// All transactions thus re-executed are guaranteed to not have any missing dependencies,
    /// because we start from the highest executed checkpoint, and proceed through checkpoints in
    /// order.
    #[instrument(level = "debug", skip_all)]
    pub async fn reexecute_local_checkpoints(
        &self,
        state: &AuthorityState,
        epoch_store: &AuthorityPerEpochStore,
    ) {
        info!("rexecuting locally computed checkpoints for crash recovery");
        let epoch = epoch_store.epoch();
    }
}
