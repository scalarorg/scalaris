use std::sync::Arc;

use sui_types::messages_checkpoint::{
    CertifiedCheckpointSummary, CheckpointContents, CheckpointSummary,
};
use tokio::sync::mpsc;

use crate::{
    authority::AuthorityState,
    checkpoints::{CheckpointMetrics, CheckpointService},
};

pub fn checkpoint_service_for_testing(state: Arc<AuthorityState>) -> Arc<CheckpointService> {
    let (output, _result) = mpsc::channel::<(CheckpointContents, CheckpointSummary)>(10);
    //let accumulator = StateAccumulator::new(state.get_accumulator_store().clone());
    let (certified_output, _certified_result) = mpsc::channel::<CertifiedCheckpointSummary>(10);

    let epoch_store = state.epoch_store_for_testing();

    let (checkpoint_service, _) = CheckpointService::spawn(
        // state.clone(),
        // state.get_checkpoint_store().clone(),
        // epoch_store.clone(),
        // state.get_transaction_cache_reader().clone(),
        // Arc::new(accumulator),
        // Box::new(output),
        // Box::new(certified_output),
        CheckpointMetrics::new_for_tests(),
        3,
        100_000,
    );
    checkpoint_service
}
