use crate::{
    messages_consensus::{ConsensusTransaction, ConsensusTransactionKind, UserTransaction},
    transaction::{RawData, RawTransaction},
};
use arc_swap::{ArcSwapOption, Guard};
use consensus_core::TransactionClient;
pub use narwhal_worker::LazyNarwhalClient;
use std::{
    hash::{DefaultHasher, Hasher},
    sync::Arc,
    time::Duration,
};
use sui_types::error::{SuiError, SuiResult};
use tap::prelude::*;
use tokio::time::{sleep, timeout};
use tracing::{info, warn};

#[mockall::automock]
#[async_trait::async_trait]
pub trait SubmitToConsensus: Sync + Send + 'static {
    async fn submit_to_consensus(&self, transactions: &[ConsensusTransaction]) -> SuiResult;
    async fn submit_raw_transactions(&self, transactions: Vec<RawData>) -> SuiResult;
}

/// Basically a wrapper struct that reads from the LOCAL_MYSTICETI_CLIENT variable where the latest
/// MysticetiClient is stored in order to communicate with Mysticeti. The LazyMysticetiClient is considered
/// "lazy" only in the sense that we can't use it directly to submit to consensus unless the underlying
/// local client is set first.
#[derive(Default, Clone)]
pub struct LazyMysticetiClient {
    client: Arc<ArcSwapOption<TransactionClient>>,
}

impl LazyMysticetiClient {
    pub fn new() -> Self {
        Self {
            client: Arc::new(ArcSwapOption::empty()),
        }
    }

    async fn get(&self) -> Guard<Option<Arc<TransactionClient>>> {
        let client = self.client.load();
        if client.is_some() {
            return client;
        }

        // We expect this to get called during the SUI process start. After that at least one
        // object will have initialised and won't need to call again.
        const MYSTICETI_START_TIMEOUT: Duration = Duration::from_secs(30);
        const LOAD_RETRY_TIMEOUT: Duration = Duration::from_millis(100);
        if let Ok(client) = timeout(MYSTICETI_START_TIMEOUT, async {
            loop {
                let client = self.client.load();
                if client.is_some() {
                    return client;
                } else {
                    sleep(LOAD_RETRY_TIMEOUT).await;
                }
            }
        })
        .await
        {
            return client;
        }

        panic!(
            "Timed out after {:?} waiting for Mysticeti to start!",
            MYSTICETI_START_TIMEOUT,
        );
    }

    pub fn set(&self, client: Arc<TransactionClient>) {
        self.client.store(Some(client));
    }
}

#[async_trait::async_trait]
impl SubmitToConsensus for LazyMysticetiClient {
    async fn submit_to_consensus(&self, transactions: &[ConsensusTransaction]) -> SuiResult {
        // TODO(mysticeti): confirm comment is still true
        // The retrieved TransactionClient can be from the past epoch. Submit would fail after
        // Mysticeti shuts down, so there should be no correctness issue.
        let transactions_bytes = transactions
            .iter()
            .map(|t| bcs::to_bytes(t).expect("Serializing consensus transaction cannot fail"))
            .collect::<Vec<_>>();
        let client = self.get().await;
        client
            .as_ref()
            .expect("Client should always be returned")
            .submit(transactions_bytes)
            .await
            .tap_err(|r| {
                // Will be logged by caller as well.
                warn!("Submit transactions failed with: {:?}", r);
            })
            .map_err(|err| SuiError::FailedToSubmitToConsensus(err.to_string()))
    }
    async fn submit_raw_transactions(&self, transactions: Vec<RawData>) -> SuiResult {
        let transactions = transactions
            .into_iter()
            .map(|raw_data| {
                let mut hasher = DefaultHasher::new();
                hasher.write(raw_data.as_slice());
                let tracking_id = hasher.finish().to_le_bytes();
                let raw_tx = RawTransaction::new_from_data_and_sig(
                    raw_data,
                    sui_types::crypto::EmptySignInfo {},
                );
                let kind = ConsensusTransactionKind::UserTransaction(Box::new(
                    UserTransaction::RawTransaction(raw_tx),
                ));
                ConsensusTransaction { tracking_id, kind }
            })
            .collect::<Vec<ConsensusTransaction>>();
        let res = self.submit_to_consensus(transactions.as_slice()).await;
        info!(
            "LazyMysticetiClient::submit_raw_transaction result {:?}",
            &res
        );
        return res;
    }
}

#[async_trait::async_trait]
impl SubmitToConsensus for LazyNarwhalClient {
    async fn submit_to_consensus(&self, transactions: &[ConsensusTransaction]) -> SuiResult {
        let transactions = transactions
            .iter()
            .map(|t| bcs::to_bytes(t).expect("Serializing consensus transaction cannot fail"))
            .collect::<Vec<_>>();
        // The retrieved LocalNarwhalClient can be from the past epoch. Submit would fail after
        // Narwhal shuts down, so there should be no correctness issue.
        let client = {
            let c = self.client.load();
            if c.is_some() {
                c
            } else {
                self.client.store(Some(self.get().await));
                self.client.load()
            }
        };
        let client = client.as_ref().unwrap().load();
        client
            .submit_transactions(transactions)
            .await
            .map_err(|e| SuiError::FailedToSubmitToConsensus(format!("{:?}", e)))
            .tap_err(|r| {
                // Will be logged by caller as well.
                warn!("Submit transaction failed with: {:?}", r);
            })?;
        Ok(())
    }
    async fn submit_raw_transactions(&self, transactions: Vec<RawData>) -> SuiResult {
        let transactions = transactions
            .into_iter()
            .map(|raw_data| {
                let mut hasher = DefaultHasher::new();
                hasher.write(raw_data.as_slice());
                let tracking_id = hasher.finish().to_le_bytes();
                let raw_tx = RawTransaction::new_from_data_and_sig(
                    raw_data,
                    sui_types::crypto::EmptySignInfo {},
                );
                let kind = ConsensusTransactionKind::UserTransaction(Box::new(
                    UserTransaction::RawTransaction(raw_tx),
                ));
                ConsensusTransaction { tracking_id, kind }
            })
            .collect::<Vec<ConsensusTransaction>>();
        self.submit_to_consensus(transactions.as_slice()).await
    }
}
