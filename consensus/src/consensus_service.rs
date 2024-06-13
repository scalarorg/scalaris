// Copyright (c) Scalaris, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::proto::{
    Empty, ExternalTransaction, RequestEcho, ResponseEcho, ValidatorInfo, ValidatorState,
};
use anyhow::{anyhow, Result};
use mysten_metrics::histogram::Histogram as MystenHistogram;
use narwhal_types::Transaction;
use prometheus::{
    register_int_counter_vec_with_registry, register_int_counter_with_registry, IntCounter,
    IntCounterVec, Registry,
};
use serde::{Deserialize, Serialize};
use std::{io, net::SocketAddr, sync::Arc};
use sui_core::traffic_controller::{metrics::TrafficControllerMetrics, TrafficController};
use sui_types::error::*;
use sui_types::multiaddr::Multiaddr;
use sui_types::traffic_control::{PolicyConfig, RemoteFirewallConfig, Weight};
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio::task::JoinHandle;
use tokio_stream::{wrappers::UnboundedReceiverStream, StreamExt};
use tonic::Response;
use tracing::{error, info};

use crate::authority::AuthorityState;
use crate::consensus_client::SubmitToConsensus;
use crate::consensus_handler::ConsensusListener;
use crate::consensus_manager::ConsensusClient;
use crate::consensus_types::{ConsensusServiceResult, ConsensusStreamItem, ResponseStream};
use tonic::transport::server::TcpConnectInfo;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainTransaction {
    pub chain_id: String,
    #[serde(with = "serde_bytes")]
    pub transaction: Transaction,
}
impl ChainTransaction {
    pub fn new(chain_id: String, transaction: Transaction) -> ChainTransaction {
        Self {
            chain_id,
            transaction,
        }
    }
}

// impl Into<ExternalTransaction> for ChainTransaction {
//     fn into(self) -> ExternalTransaction {
//         let ChainTransaction {
//             chain_id,
//             transaction,
//         } = self;
//         ExternalTransaction {
//             chain_id,
//             tx_bytes: transaction,
//         }
//     }
// }

impl Into<Vec<ChainTransaction>> for ExternalTransaction {
    fn into(self) -> Vec<ChainTransaction> {
        let ExternalTransaction { chain_id, tx_bytes } = self;
        tx_bytes
            .into_iter()
            .map(|tx| ChainTransaction {
                chain_id: chain_id.clone(),
                transaction: tx,
            })
            .collect::<Vec<ChainTransaction>>()
    }
}
pub struct ConsensusServerHandle {
    tx_cancellation: tokio::sync::oneshot::Sender<()>,
    local_addr: Multiaddr,
    handle: JoinHandle<Result<(), tonic::transport::Error>>,
}

impl ConsensusServerHandle {
    pub async fn join(self) -> Result<(), io::Error> {
        // Note that dropping `self.complete` would terminate the server.
        self.handle
            .await?
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(())
    }

    pub async fn kill(self) -> Result<(), io::Error> {
        self.tx_cancellation.send(()).map_err(|_e| {
            io::Error::new(io::ErrorKind::Other, "could not send cancellation signal!")
        })?;
        self.handle
            .await?
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(())
    }

    pub fn address(&self) -> &Multiaddr {
        &self.local_addr
    }
}
pub struct ConsensusServiceMetrics {
    pub signature_errors: IntCounter,
    pub tx_verification_latency: MystenHistogram,
    pub cert_verification_latency: MystenHistogram,
    pub consensus_latency: MystenHistogram,
    pub handle_transaction_latency: MystenHistogram,
    pub submit_certificate_consensus_latency: MystenHistogram,
    pub handle_certificate_consensus_latency: MystenHistogram,
    pub handle_certificate_non_consensus_latency: MystenHistogram,

    pub num_rejected_tx_in_epoch_boundary: IntCounter,
    pub num_rejected_cert_in_epoch_boundary: IntCounter,
    pub num_rejected_tx_during_overload: IntCounterVec,
    pub num_rejected_cert_during_overload: IntCounterVec,
    pub connection_ip_not_found: IntCounter,
    pub forwarded_header_parse_error: IntCounter,
    pub forwarded_header_invalid: IntCounter,
}

impl ConsensusServiceMetrics {
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

//Service for handling grpc consensus request
#[derive(Clone)]
pub struct ConsensusService {
    state: Arc<AuthorityState>,
    //Client for send transaction into consensus component
    consensus_client: Arc<ConsensusClient>,
    //Listener for consensus output
    consensus_listener: Arc<ConsensusListener>,
    metrics: Arc<ConsensusServiceMetrics>,
    traffic_controller: Option<Arc<TrafficController>>,
}

impl ConsensusService {
    pub fn new(
        state: Arc<AuthorityState>,
        consensus_client: Arc<ConsensusClient>,
        consensus_listener: Arc<ConsensusListener>,
        validator_metrics: Arc<ConsensusServiceMetrics>,
        traffic_controller_metrics: TrafficControllerMetrics,
        policy_config: Option<PolicyConfig>,
        firewall_config: Option<RemoteFirewallConfig>,
    ) -> Self {
        Self {
            state,
            consensus_client,
            consensus_listener,
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
    pub async fn add_consensus_listener(&self, listener: UnboundedSender<ConsensusStreamItem>) {
        self.consensus_listener.add_listener(listener).await;
    }
    fn get_validator_info(&self) -> ValidatorInfo {
        // let keypair = self.validator_keypair.copy();
        // let pub_key = keypair.public().as_bytes().to_vec();
        // let private_key = keypair.private().as_bytes().to_vec();
        // let node_private_key = self.node_keypair.copy().private().as_bytes().to_vec();
        ValidatorInfo {
            chain_id: String::default(),
            pub_key: vec![],
            private_key: vec![],
            node_private_key: vec![],
        }
    }
    pub fn validator_state(&self) -> &Arc<AuthorityState> {
        &self.state
    }
}
#[tonic::async_trait]
impl crate::ConsensusApi for ConsensusService {
    type InitTransactionStream = ResponseStream;
    async fn echo(
        &self,
        request: tonic::Request<RequestEcho>,
    ) -> ConsensusServiceResult<ResponseEcho> {
        info!("ConsensusServiceServer::echo");
        let echo_message = request.into_inner().message;

        Ok(Response::new(ResponseEcho {
            message: echo_message,
        }))
    }

    async fn get_validator_info(
        &self,
        _request: tonic::Request<Empty>,
    ) -> ConsensusServiceResult<ValidatorInfo> {
        info!("ConsensusServiceServer::get_validator_info");
        let info = self.get_validator_info();

        Ok(Response::new(info))
    }

    async fn get_validator_state(
        &self,
        _request: tonic::Request<Empty>,
    ) -> ConsensusServiceResult<ValidatorState> {
        info!("ConsensusServiceServer::get_validator_state");
        let validator_info = self.get_validator_info();
        let state = ValidatorState {
            validator_info: Some(validator_info),
            round: 0,
        };

        Ok(Response::new(state))
    }

    /*
     * Consensus client init a duplex streaming connection to send external transaction
     * and to receives consensus output.
     * External trasaction contains a namespace field and a content in byte array
     */
    async fn init_transaction(
        &self,
        request: tonic::Request<tonic::Streaming<ExternalTransaction>>,
    ) -> ConsensusServiceResult<Self::InitTransactionStream> {
        info!("ConsensusServiceServer::init_transaction_streams");
        let mut in_stream = request.into_inner();
        /*
         * 20240504
         * Mỗi consensus client khi kết nối tới consensus server sẽ được map với 1 sender channel để nhận kết quả trả ra từ consensus layer
         * Todo: optimize listeners collections để chỉ gửi đúng các dữ liệu mà client quan tâm (ví dụ theo namespace)
         */
        let (tx_consensus, rx_consensus) = mpsc::unbounded_channel();
        self.add_consensus_listener(tx_consensus).await;
        let service = self.clone();
        let _handle = tokio::spawn(async move {
            //let service = consensus_service;
            while let Some(client_message) = in_stream.next().await {
                match client_message {
                    Ok(transaction_in) => {
                        let _handle_res =
                            service.handle_consensus_transaction(transaction_in).await;
                    }
                    Err(err) => {
                        error!("{:?}", err);
                    }
                }
            }
        });
        let out_stream = UnboundedReceiverStream::new(rx_consensus);

        Ok(Response::new(
            Box::pin(out_stream) as Self::InitTransactionStream
        ))
    }
}

impl ConsensusService {
    pub async fn handle_consensus_transaction(
        &self,
        transaction_in: ExternalTransaction,
    ) -> Result<()> {
        info!(
            "gRpc service handle consensus_transaction {:?}",
            &transaction_in
        );
        //Send transaction to the consensus's worker
        let chain_txs: Vec<ChainTransaction> = transaction_in.into();
        // let raw_transactions = chain_txs
        //     .into_iter()
        //     .map(|chain_tx| bcs::to_bytes(&chain_tx).expect("Serialization should not fail."))
        //     .collect::<Vec<Vec<u8>>>();
        //Submit to consensus layer raw transaction (without chain_id)
        let raw_transactions = chain_txs
            .into_iter()
            .map(
                |ChainTransaction {
                     chain_id,
                     transaction,
                 }| {
                    //bcs::to_bytes(&chain_tx).expect("Serialization should not fail.")
                    transaction
                },
            )
            .collect::<Vec<Vec<u8>>>();
        self.consensus_client
            .submit_raw_transactions(raw_transactions)
            .await
            .map_err(|err| anyhow!(err.to_string()))
    }
}

fn make_tonic_request_for_testing<T>(message: T) -> tonic::Request<T> {
    // simulate a TCP connection, which would have added extensions to
    // the request object that would be used downstream
    let mut request = tonic::Request::new(message);
    let tcp_connect_info = TcpConnectInfo {
        local_addr: None,
        remote_addr: Some(SocketAddr::new([127, 0, 0, 1].into(), 0)),
    };
    request.extensions_mut().insert(tcp_connect_info);
    request
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

/// Implements generic pre- and post-processing. Since this is on the critical
/// path, any heavy lifting should be done in a separate non-blocking task
/// unless it is necessary to override the return value.
#[macro_export]
macro_rules! handle_with_decoration {
    ($self:ident, $func_name:ident, $request:ident) => {{
        // extract IP info. Note that in addition to extracting the client IP from
        // the request header, we also get the remote address in case we need to
        // throttle a fullnode, or an end user is running a local quorum driver.
        let connection_ip: Option<SocketAddr> = $request.remote_addr();

        // We will hit this case if the IO type used does not
        // implement Connected or when using a unix domain socket.
        // TODO: once we have confirmed that no legitimate traffic
        // is hitting this case, we should reject such requests that
        // hit this case.
        if connection_ip.is_none() {
            if cfg!(msim) {
                // Ignore the error from simtests.
            } else if cfg!(test) {
                panic!("Failed to get remote address from request");
            } else {
                $self.metrics.connection_ip_not_found.inc();
                error!("Failed to get remote address from request");
            }
        }

        let proxy_ip: Option<SocketAddr> =
            if let Some(op) = $request.metadata().get("x-forwarded-for") {
                match op.to_str() {
                    Ok(ip) => match ip.parse() {
                        Ok(ret) => Some(ret),
                        Err(e) => {
                            $self.metrics.forwarded_header_parse_error.inc();
                            error!("Failed to parse x-forwarded-for header value to SocketAddr: {:?}", e);
                            None
                        }
                    },
                    Err(e) => {
                        // TODO: once we have confirmed that no legitimate traffic
                        // is hitting this case, we should reject such requests that
                        // hit this case.
                        $self.metrics.forwarded_header_invalid.inc();
                        error!("Invalid UTF-8 in x-forwarded-for header: {:?}", e);
                        None
                    }
                }
            } else {
                None
            };

        // check if either IP is blocked, in which case return early
        $self.handle_traffic_req(connection_ip, proxy_ip).await?;
        // handle request
        let response = $self.$func_name($request).await;
        // handle response tallying
        $self.handle_traffic_resp(connection_ip, proxy_ip, &response);
        response
    }};
}
