use async_trait::async_trait;
use mysten_metrics::histogram::Histogram as MystenHistogram;
use mysten_metrics::spawn_monitored_task;
use mysten_network::Multiaddr;
use prometheus::{
    register_int_counter_vec_with_registry, register_int_counter_with_registry, IntCounter,
    IntCounterVec, Registry,
};
use std::net::SocketAddr;
use std::time::SystemTime;
use std::{io, sync::Arc};
use sui_core::handle_with_decoration;
use sui_core::traffic_controller::metrics::TrafficControllerMetrics;
use sui_core::traffic_controller::policies::TrafficTally;
use sui_core::traffic_controller::TrafficController;
use sui_types::error::SuiError;
use sui_types::traffic_control::{PolicyConfig, RemoteFirewallConfig, Weight};
use tokio::task::JoinHandle;
use tracing::error;

use crate::authority::AuthorityVerifyState;
use crate::{consensus_types::HandleVerifyMessageResponse, transaction::RawTransaction};

use super::Validator;

pub struct AuthorityServer {
    address: Multiaddr,
}
pub struct ValidatorServiceMetrics {
    pub signature_errors: IntCounter,
    pub tx_verification_latency: MystenHistogram,
    pub cert_verification_latency: MystenHistogram,
    pub consensus_latency: MystenHistogram,
    pub handle_transaction_latency: MystenHistogram,
    pub submit_certificate_consensus_latency: MystenHistogram,
    pub handle_certificate_consensus_latency: MystenHistogram,
    pub handle_certificate_non_consensus_latency: MystenHistogram,

    num_rejected_tx_in_epoch_boundary: IntCounter,
    num_rejected_cert_in_epoch_boundary: IntCounter,
    num_rejected_tx_during_overload: IntCounterVec,
    num_rejected_cert_during_overload: IntCounterVec,
    connection_ip_not_found: IntCounter,
    forwarded_header_parse_error: IntCounter,
    forwarded_header_invalid: IntCounter,
}

impl ValidatorServiceMetrics {
    pub fn new(registry: &Registry) -> Self {
        Self {
            signature_errors: register_int_counter_with_registry!(
                "total_signature_errors",
                "Number of transaction signature errors",
                registry,
            )
            .unwrap(),
            tx_verification_latency: MystenHistogram::new_in_registry(
                "validator_service_tx_verification_latency",
                "Latency of verifying a transaction",
                registry,
            ),
            cert_verification_latency: MystenHistogram::new_in_registry(
                "validator_service_cert_verification_latency",
                "Latency of verifying a certificate",
                registry,
            ),
            consensus_latency: MystenHistogram::new_in_registry(
                "validator_service_consensus_latency",
                "Time spent between submitting a shared obj txn to consensus and getting result",
                registry,
            ),
            handle_transaction_latency: MystenHistogram::new_in_registry(
                "validator_service_handle_transaction_latency",
                "Latency of handling a transaction",
                registry,
            ),
            handle_certificate_consensus_latency: MystenHistogram::new_in_registry(
                "validator_service_handle_certificate_consensus_latency",
                "Latency of handling a consensus transaction certificate",
                registry,
            ),
            submit_certificate_consensus_latency: MystenHistogram::new_in_registry(
                "validator_service_submit_certificate_consensus_latency",
                "Latency of submit_certificate RPC handler",
                registry,
            ),
            handle_certificate_non_consensus_latency: MystenHistogram::new_in_registry(
                "validator_service_handle_certificate_non_consensus_latency",
                "Latency of handling a non-consensus transaction certificate",
                registry,
            ),
            num_rejected_tx_in_epoch_boundary: register_int_counter_with_registry!(
                "validator_service_num_rejected_tx_in_epoch_boundary",
                "Number of rejected transaction during epoch transitioning",
                registry,
            )
            .unwrap(),
            num_rejected_cert_in_epoch_boundary: register_int_counter_with_registry!(
                "validator_service_num_rejected_cert_in_epoch_boundary",
                "Number of rejected transaction certificate during epoch transitioning",
                registry,
            )
            .unwrap(),
            num_rejected_tx_during_overload: register_int_counter_vec_with_registry!(
                "validator_service_num_rejected_tx_during_overload",
                "Number of rejected transaction due to system overload",
                &["error_type"],
                registry,
            )
            .unwrap(),
            num_rejected_cert_during_overload: register_int_counter_vec_with_registry!(
                "validator_service_num_rejected_cert_during_overload",
                "Number of rejected transaction certificate due to system overload",
                &["error_type"],
                registry,
            )
            .unwrap(),
            connection_ip_not_found: register_int_counter_with_registry!(
                "validator_service_connection_ip_not_found",
                "Number of times connection IP was not extractable from request",
                registry,
            )
            .unwrap(),
            forwarded_header_parse_error: register_int_counter_with_registry!(
                "validator_service_forwarded_header_parse_error",
                "Number of times x-forwarded-for header could not be parsed",
                registry,
            )
            .unwrap(),
            forwarded_header_invalid: register_int_counter_with_registry!(
                "validator_service_forwarded_header_invalid",
                "Number of times x-forwarded-for header was invalid",
                registry,
            )
            .unwrap(),
        }
    }

    pub fn new_for_tests() -> Self {
        let registry = Registry::new();
        Self::new(&registry)
    }
}

#[derive(Clone)]
pub struct ValidatorService {
    verify_state: Arc<AuthorityVerifyState>,
    metrics: Arc<ValidatorServiceMetrics>,
    traffic_controller: Option<Arc<TrafficController>>,
}

impl ValidatorService {
    pub fn new(
        verify_state: Arc<AuthorityVerifyState>,
        validator_metrics: Arc<ValidatorServiceMetrics>,
        traffic_controller_metrics: TrafficControllerMetrics,
        policy_config: Option<PolicyConfig>,
        firewall_config: Option<RemoteFirewallConfig>,
    ) -> Self {
        Self {
            verify_state,
            metrics: validator_metrics,
            traffic_controller: policy_config.map(|policy| {
                Arc::new(TrafficController::spawn(
                    policy,
                    traffic_controller_metrics,
                    firewall_config,
                ))
            }),
        }
    }
    async fn handle_verify_message(
        &self,
        request: tonic::Request<RawTransaction>,
    ) -> Result<tonic::Response<HandleVerifyMessageResponse>, tonic::Status> {
        todo!("Implement handle verify message")
    }
}
//impl
impl ValidatorService {
    async fn verify_message_impl(
        &self,
        request: tonic::Request<RawTransaction>,
    ) -> Result<tonic::Response<HandleVerifyMessageResponse>, tonic::Status> {
        self.handle_verify_message(request).await
    }
    async fn handle_traffic_req(
        &self,
        connection_ip: Option<SocketAddr>,
        proxy_ip: Option<SocketAddr>,
    ) -> Result<(), tonic::Status> {
        if let Some(traffic_controller) = &self.traffic_controller {
            let connection = connection_ip.map(|ip| ip.ip());
            let proxy = proxy_ip.map(|ip| ip.ip());
            if !traffic_controller.check(connection, proxy).await {
                // Entity in blocklist
                Err(tonic::Status::from_error(SuiError::TooManyRequests.into()))
            } else {
                Ok(())
            }
        } else {
            Ok(())
        }
    }

    fn handle_traffic_resp<T>(
        &self,
        connection_ip: Option<SocketAddr>,
        proxy_ip: Option<SocketAddr>,
        response: &Result<tonic::Response<T>, tonic::Status>,
    ) {
        let error: Option<SuiError> = if let Err(status) = response {
            Some(SuiError::from(status.clone()))
        } else {
            None
        };

        if let Some(traffic_controller) = self.traffic_controller.clone() {
            traffic_controller.tally(TrafficTally {
                connection_ip: connection_ip.map(|ip| ip.ip()),
                proxy_ip: proxy_ip.map(|ip| ip.ip()),
                error_weight: error.map(normalize).unwrap_or(Weight::zero()),
                timestamp: SystemTime::now(),
            })
        }
    }
}

// TODO: refine error matching here
fn normalize(err: SuiError) -> Weight {
    match err {
        SuiError::UserInputError { .. }
        | SuiError::InvalidSignature { .. }
        | SuiError::SignerSignatureAbsent { .. }
        | SuiError::SignerSignatureNumberMismatch { .. }
        | SuiError::IncorrectSigner { .. }
        | SuiError::UnknownSigner { .. }
        | SuiError::WrongEpoch { .. } => Weight::one(),
        _ => Weight::zero(),
    }
}

#[async_trait]
impl Validator for ValidatorService {
    async fn verify_message(
        &self,
        request: tonic::Request<RawTransaction>,
    ) -> Result<tonic::Response<HandleVerifyMessageResponse>, tonic::Status> {
        let validator_service = self.clone();

        // Spawns a task which handles the transaction. The task will unconditionally continue
        // processing in the event that the client connection is dropped.
        spawn_monitored_task!(async move {
            // NB: traffic tally wrapping handled within the task rather than on task exit
            // to prevent an attacker from subverting traffic control by severing the connection
            handle_with_decoration!(validator_service, verify_message_impl, request)
        })
        .await
        .unwrap()
    }
}
