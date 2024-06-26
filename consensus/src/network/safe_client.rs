// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::authority_client::AuthorityAPI;
use crate::consensus_types::HandleVerifyMessageResponse;
use crate::epoch::committee_store::CommitteeStore;
use crate::transaction::RawTransaction;
use mysten_metrics::histogram::{Histogram, HistogramVec};
use prometheus::core::GenericCounter;
use prometheus::{register_int_counter_vec_with_registry, IntCounterVec, Registry};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use sui_types::crypto::AuthorityPublicKeyBytes;
use sui_types::effects::{SignedTransactionEffects, TransactionEffectsAPI};
use sui_types::error::{SuiError, SuiResult};
use sui_types::{base_types::*, committee::*, fp_ensure};

macro_rules! check_error {
    ($address:expr, $cond:expr, $msg:expr) => {
        $cond.tap_err(|err| {
            if err.individual_error_indicates_epoch_change() {
                debug!(?err, authority=?$address, "Not a real client error");
            } else {
                error!(?err, authority=?$address, $msg);
            }
        })
    }
}

#[derive(Clone)]
pub struct SafeClientMetricsBase {
    total_requests_by_address_method: IntCounterVec,
    total_responses_by_address_method: IntCounterVec,
    latency: HistogramVec,
}

impl SafeClientMetricsBase {
    pub fn new(registry: &Registry) -> Self {
        Self {
            total_requests_by_address_method: register_int_counter_vec_with_registry!(
                "safe_client_total_requests_by_address_method",
                "Total requests to validators group by address and method",
                &["address", "method"],
                registry,
            )
            .unwrap(),
            total_responses_by_address_method: register_int_counter_vec_with_registry!(
                "safe_client_total_responses_by_address_method",
                "Total good (OK) responses from validators group by address and method",
                &["address", "method"],
                registry,
            )
            .unwrap(),
            latency: HistogramVec::new_in_registry(
                "safe_client_latency",
                "RPC latency observed by safe client aggregator, group by address and method",
                &["address", "method"],
                registry,
            ),
        }
    }
}

/// Prometheus metrics which can be displayed in Grafana, queried and alerted on
#[derive(Clone)]
pub struct SafeClientMetrics {
    total_requests_handle_transaction_info_request: GenericCounter<prometheus::core::AtomicU64>,
    total_ok_responses_handle_transaction_info_request: GenericCounter<prometheus::core::AtomicU64>,
    total_requests_handle_object_info_request: GenericCounter<prometheus::core::AtomicU64>,
    total_ok_responses_handle_object_info_request: GenericCounter<prometheus::core::AtomicU64>,
    handle_transaction_latency: Histogram,
    handle_certificate_latency: Histogram,
    handle_obj_info_latency: Histogram,
    handle_tx_info_latency: Histogram,
}

impl SafeClientMetrics {
    pub fn new(metrics_base: &SafeClientMetricsBase, validator_address: AuthorityName) -> Self {
        let validator_address = validator_address.to_string();

        let total_requests_handle_transaction_info_request = metrics_base
            .total_requests_by_address_method
            .with_label_values(&[&validator_address, "handle_transaction_info_request"]);
        let total_ok_responses_handle_transaction_info_request = metrics_base
            .total_responses_by_address_method
            .with_label_values(&[&validator_address, "handle_transaction_info_request"]);

        let total_requests_handle_object_info_request = metrics_base
            .total_requests_by_address_method
            .with_label_values(&[&validator_address, "handle_object_info_request"]);
        let total_ok_responses_handle_object_info_request = metrics_base
            .total_responses_by_address_method
            .with_label_values(&[&validator_address, "handle_object_info_request"]);

        let handle_transaction_latency = metrics_base
            .latency
            .with_label_values(&[&validator_address, "handle_transaction"]);
        let handle_certificate_latency = metrics_base
            .latency
            .with_label_values(&[&validator_address, "handle_certificate"]);
        let handle_obj_info_latency = metrics_base
            .latency
            .with_label_values(&[&validator_address, "handle_object_info_request"]);
        let handle_tx_info_latency = metrics_base
            .latency
            .with_label_values(&[&validator_address, "handle_transaction_info_request"]);

        Self {
            total_requests_handle_transaction_info_request,
            total_ok_responses_handle_transaction_info_request,
            total_requests_handle_object_info_request,
            total_ok_responses_handle_object_info_request,
            handle_transaction_latency,
            handle_certificate_latency,
            handle_obj_info_latency,
            handle_tx_info_latency,
        }
    }

    pub fn new_for_tests(validator_address: AuthorityName) -> Self {
        let registry = Registry::new();
        let metrics_base = SafeClientMetricsBase::new(&registry);
        Self::new(&metrics_base, validator_address)
    }
}

/// See `SafeClientMetrics::new` for description of each metrics.
/// The metrics are per validator client.
#[derive(Clone)]
pub struct SafeClient<C>
where
    C: Clone,
{
    authority_client: C,
    committee_store: Arc<CommitteeStore>,
    address: AuthorityPublicKeyBytes,
    metrics: SafeClientMetrics,
}

impl<C: Clone> SafeClient<C> {
    pub fn new(
        authority_client: C,
        committee_store: Arc<CommitteeStore>,
        address: AuthorityPublicKeyBytes,
        metrics: SafeClientMetrics,
    ) -> Self {
        Self {
            authority_client,
            committee_store,
            address,
            metrics,
        }
    }
}

impl<C: Clone> SafeClient<C> {
    pub fn authority_client(&self) -> &C {
        &self.authority_client
    }

    #[cfg(test)]
    pub fn authority_client_mut(&mut self) -> &mut C {
        &mut self.authority_client
    }

    fn get_committee(&self, epoch_id: &EpochId) -> SuiResult<Arc<Committee>> {
        self.committee_store
            .get_committee(epoch_id)?
            .ok_or(SuiError::MissingCommitteeAtEpoch(*epoch_id))
    }

    fn check_signed_effects_plain(
        &self,
        digest: &TransactionDigest,
        signed_effects: SignedTransactionEffects,
        expected_effects_digest: Option<&TransactionEffectsDigest>,
    ) -> SuiResult<SignedTransactionEffects> {
        // Check it has the right signer
        fp_ensure!(
            signed_effects.auth_sig().authority == self.address,
            SuiError::ByzantineAuthoritySuspicion {
                authority: self.address,
                reason: format!(
                    "Unexpected validator address in the signed effects signature: {:?}",
                    signed_effects.auth_sig().authority
                ),
            }
        );
        // Checks it concerns the right tx
        fp_ensure!(
            signed_effects.data().transaction_digest() == digest,
            SuiError::ByzantineAuthoritySuspicion {
                authority: self.address,
                reason: "Unexpected tx digest in the signed effects".to_string()
            }
        );
        // check that the effects digest is correct.
        if let Some(effects_digest) = expected_effects_digest {
            fp_ensure!(
                signed_effects.digest() == effects_digest,
                SuiError::ByzantineAuthoritySuspicion {
                    authority: self.address,
                    reason: "Effects digest does not match with expected digest".to_string()
                }
            );
        }
        self.get_committee(&signed_effects.epoch())?;
        Ok(signed_effects)
    }

    pub fn address(&self) -> &AuthorityPublicKeyBytes {
        &self.address
    }
}

impl<C> SafeClient<C>
where
    C: AuthorityAPI + Send + Sync + Clone + 'static,
{
    /// Initiate a new transfer to a Sui or Primary account.
    pub async fn handle_verify_message(
        &self,
        transaction: RawTransaction,
        client_addr: Option<SocketAddr>,
    ) -> Result<HandleVerifyMessageResponse, SuiError> {
        let _timer = self.metrics.handle_transaction_latency.start_timer();
        let digest = *transaction.digest();
        let response = self
            .authority_client
            .handle_verify_message(transaction.clone(), client_addr)
            .await?;
        // let response = check_error!(
        //     self.address,
        //     self.check_transaction_info(&digest, transaction, response.status),
        //     "Client error in handle_transaction"
        // )?;
        Ok(response)
    }
}
