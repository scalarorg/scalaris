// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::messages_consensus::{ConsensusTransaction, ConsensusTransactionKind, UserTransaction};
use consensus_core::{TransactionVerifier, ValidationError};
use eyre::WrapErr;
use fastcrypto_tbls::dkg;
use mysten_metrics::monitored_scope;
use narwhal_types::{validate_batch_version, BatchAPI};
use narwhal_worker::TransactionValidator;
use prometheus::{register_int_counter_with_registry, IntCounter, Registry};
use std::sync::Arc;
use sui_protocol_config::ProtocolConfig;
use sui_types::error::SuiError;
use tap::TapFallible;
use tracing::{info, warn};

use crate::{authority::AuthorityPerEpochStore, checkpoints::CheckpointServiceNotify};

/// Allows verifying the validity of transactions
#[derive(Clone)]
pub struct SuiTxValidator {
    epoch_store: Arc<AuthorityPerEpochStore>,
    // checkpoint_service: Arc<dyn CheckpointServiceNotify + Send + Sync>,
    metrics: Arc<TxValidatorMetrics>,
}

impl SuiTxValidator {
    pub fn new(
        epoch_store: Arc<AuthorityPerEpochStore>,
        // checkpoint_service: Arc<dyn CheckpointServiceNotify + Send + Sync>,
        metrics: Arc<TxValidatorMetrics>,
    ) -> Self {
        info!(
            "SuiTxValidator constructed for epoch {}",
            epoch_store.epoch()
        );
        Self {
            epoch_store,
            //checkpoint_service,
            metrics,
        }
    }

    fn validate_transactions(
        &self,
        txs: Vec<ConsensusTransactionKind>,
    ) -> Result<(), eyre::Report> {
        let mut cert_batch = Vec::new();
        let mut ckpt_messages = Vec::new();
        let mut ckpt_batch = Vec::new();
        for tx in txs.into_iter() {
            match tx {
                ConsensusTransactionKind::UserTransaction(certificate) => {
                    if let UserTransaction::CertifiedTransaction(certificate) = *certificate {
                        cert_batch.push(certificate);
                    }

                    // if !certificate.contains_shared_object() {
                    //     // new_unchecked safety: we do not use the certs in this list until all
                    //     // have had their signatures verified.
                    //     owned_tx_certs.push(VerifiedCertificate::new_unchecked(*certificate));
                    // }
                }
                ConsensusTransactionKind::CheckpointSignature(signature) => {
                    ckpt_messages.push(signature.clone());
                    ckpt_batch.push(signature.summary);
                }
                ConsensusTransactionKind::RandomnessDkgMessage(_, bytes) => {
                    if bytes.len() > dkg::DKG_MESSAGES_MAX_SIZE {
                        warn!("batch verification error: DKG Message too large");
                        return Err(SuiError::InvalidDkgMessageSize.into());
                    }
                }
                ConsensusTransactionKind::RandomnessDkgConfirmation(_, bytes) => {
                    if bytes.len() > dkg::DKG_MESSAGES_MAX_SIZE {
                        warn!("batch verification error: DKG Confirmation too large");
                        return Err(SuiError::InvalidDkgMessageSize.into());
                    }
                }
                ConsensusTransactionKind::EndOfPublish(_)
                | ConsensusTransactionKind::CapabilityNotification(_)
                | ConsensusTransactionKind::NewJWKFetched(_, _, _)
                | ConsensusTransactionKind::RandomnessStateUpdate(_, _) => {}
            }
        }

        // verify the certificate signatures as a batch
        let cert_count = cert_batch.len();
        let ckpt_count = ckpt_batch.len();

        // self.epoch_store
        //     .signature_verifier
        //     .verify_certs_and_checkpoints(cert_batch, ckpt_batch)
        //     .tap_err(|e| warn!("batch verification error: {}", e))
        //     .wrap_err("Malformed batch (failed to verify)")?;

        // All checkpoint sigs have been verified, forward them to the checkpoint service
        // for ckpt in ckpt_messages {
        //     self.checkpoint_service
        //         .notify_checkpoint_signature(&self.epoch_store, &ckpt)?;
        // }

        self.metrics
            .certificate_signatures_verified
            .inc_by(cert_count as u64);
        self.metrics
            .checkpoint_signatures_verified
            .inc_by(ckpt_count as u64);
        Ok(())

        // todo - we should un-comment line below once we have a way to revert those transactions at the end of epoch
        // all certificates had valid signatures, schedule them for execution prior to sequencing
        // which is unnecessary for owned object transactions.
        // It is unnecessary to write to pending_certificates table because the certs will be written
        // via consensus output.
        // self.transaction_manager
        //     .enqueue_certificates(owned_tx_certs, &self.epoch_store)
        //     .wrap_err("Failed to schedule certificates for execution")
    }
}

fn tx_from_bytes(tx: &[u8]) -> Result<ConsensusTransaction, eyre::Report> {
    bcs::from_bytes::<ConsensusTransaction>(tx)
        .wrap_err("Malformed transaction (failed to deserialize)")
}

impl TransactionValidator for SuiTxValidator {
    type Error = eyre::Report;

    fn validate(&self, _tx: &[u8]) -> Result<(), Self::Error> {
        // We only accept transactions from local sui instance so no need to re-verify it
        Ok(())
    }

    fn validate_batch(
        &self,
        b: &narwhal_types::Batch,
        protocol_config: &ProtocolConfig,
    ) -> Result<(), Self::Error> {
        let _scope = monitored_scope("ValidateBatch");

        // TODO: Remove once we have removed BatchV1 from the codebase.
        validate_batch_version(b, protocol_config)
            .map_err(|err| eyre::eyre!(format!("Invalid Batch: {err}")))?;

        let txs = b
            .transactions()
            .iter()
            .map(|tx| tx_from_bytes(tx).map(|tx| tx.kind))
            .collect::<Result<Vec<_>, _>>()?;

        self.validate_transactions(txs)
    }
}

impl TransactionVerifier for SuiTxValidator {
    fn verify_batch(
        &self,
        _protocol_config: &ProtocolConfig,
        batch: &[&[u8]],
    ) -> Result<(), ValidationError> {
        let txs = batch
            .iter()
            .map(|tx| {
                tx_from_bytes(tx)
                    .map(|tx| tx.kind)
                    .map_err(|e| ValidationError::InvalidTransaction(e.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        self.validate_transactions(txs)
            .map_err(|e| ValidationError::InvalidTransaction(e.to_string()))
    }
}

pub struct TxValidatorMetrics {
    certificate_signatures_verified: IntCounter,
    checkpoint_signatures_verified: IntCounter,
}

impl TxValidatorMetrics {
    pub fn new(registry: &Registry) -> Arc<Self> {
        Arc::new(Self {
            certificate_signatures_verified: register_int_counter_with_registry!(
                "certificate_signatures_verified",
                "Number of certificates verified in consensus batch verifier",
                registry
            )
            .unwrap(),
            checkpoint_signatures_verified: register_int_counter_with_registry!(
                "checkpoint_signatures_verified",
                "Number of checkpoint verified in consensus batch verifier",
                registry
            )
            .unwrap(),
        })
    }
}
