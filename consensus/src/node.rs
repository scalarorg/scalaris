use crate::authority::authority_aggregator::AuthorityAggregator;
use crate::authority::{AuthorityPerEpochStore, AuthorityVerifyState, RandomnessRoundReceiver};
use crate::checkpoints::{CheckpointMetrics, CheckpointService, CheckpointStore};
// use crate::consensus_adapter::ConnectionMonitorStatus;
use crate::epoch::randomness::RandomnessManager;
use crate::messages_consensus::{
    check_total_jwk_size, AuthorityCapabilities, ConsensusTransaction,
};
use crate::network::{
    safe_client::SafeClientMetricsBase, NetworkAuthorityClient, ValidatorServer, ValidatorService,
    ValidatorServiceMetrics,
};
// use crate::signature_verifier::SignatureVerifierMetrics;
// use crate::storage::RocksDbStore;
use anemo::Network;
use anemo_tower::callback::CallbackLayer;
use anemo_tower::trace::{DefaultMakeSpan, DefaultOnFailure, TraceLayer};
use anyhow::anyhow;
use anyhow::Result;
use arc_swap::ArcSwap;
use fastcrypto::traits::KeyPair;
use fastcrypto_zkp::bn254::zk_login::{JwkId, OIDCProvider, JWK};
use futures::TryFutureExt;
use mysten_metrics::spawn_monitored_task;
use mysten_metrics::RegistryService;
use mysten_network::server::ServerBuilder;
use narwhal_network::metrics::{
    MetricsMakeCallbackHandler, NetworkConnectionMetrics, NetworkMetrics,
};
use prometheus::Registry;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use sui_archival::reader::ArchiveReaderBalancer;
use sui_config::node::{DBCheckpointConfig, RunWithRange};
use sui_config::node_config_metrics::NodeConfigMetrics;
use sui_core::authority::authority_store_tables::AuthorityPerpetualTables;
use sui_core::authority::CHAIN_IDENTIFIER;
use sui_core::authority_aggregator::AuthAggMetrics;
use sui_core::consensus_adapter::ConnectionMonitorStatus;
use sui_core::epoch::committee_store::CommitteeStore;
use sui_core::epoch::data_removal::EpochDataRemover;
use sui_core::epoch::epoch_metrics::EpochMetrics;
use sui_core::execution_cache::build_execution_cache;
use sui_core::module_cache_metrics::ResolverMetrics;
use sui_core::state_accumulator::StateAccumulator;
use sui_core::traffic_controller::metrics::TrafficControllerMetrics;
use sui_macros::fail_point;
use sui_macros::replay_log;
use sui_network::discovery::{self, TrustedPeerChangeEvent};
use sui_network::randomness;
use sui_protocol_config::ProtocolConfig;
use sui_types::base_types::AuthorityName;
use sui_types::committee::{Committee, CommitteeWithNetworkMetadata, EpochId};
use sui_types::crypto::RandomnessRound;
use sui_types::digests::ChainIdentifier;
use sui_types::error::{SuiError, SuiResult};
use sui_types::sui_system_state::epoch_start_sui_system_state::{
    EpochStartSystemState, EpochStartSystemStateTrait,
};
use tap::TapFallible;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use tower::ServiceBuilder;
use tracing::{debug, error_span, info, warn, Instrument};
use typed_store::rocks::default_db_options;
use typed_store::DBMetrics;

use crate::authority::AuthorityState;
use crate::authority::AuthorityStore;
// use crate::consensus_adapter::ConsensusAdapter;
// use crate::consensus_adapter::ConsensusAdapterMetrics;
use crate::consensus_client::SubmitToConsensus;
use crate::consensus_handler::ConsensusHandlerInitializer;
use crate::consensus_handler::ConsensusListener;
use crate::consensus_manager::ConsensusClient;
use crate::consensus_manager::ConsensusManager;
use crate::consensus_manager::ConsensusManagerTrait;
use crate::consensus_service::ConsensusService;
use crate::consensus_service::ConsensusServiceMetrics;
use crate::consensus_throughput_calculator::ConsensusThroughputCalculator;
use crate::consensus_throughput_calculator::ConsensusThroughputProfiler;
use crate::consensus_throughput_calculator::ThroughputProfileRanges;
use crate::consensus_validator::SuiTxValidator;
use crate::consensus_validator::TxValidatorMetrics;
use crate::metrics::GrpcMetrics;
use crate::metrics::SuiNodeMetrics;
use crate::NodeConfig;

static MAX_JWK_KEYS_PER_FETCH: usize = 100;

pub struct NodeComponents {
    validator_server_handle: JoinHandle<Result<()>>,
    validator_overload_monitor_handle: Option<JoinHandle<()>>,
    consensus_manager: ConsensusManager,
    consensus_epoch_data_remover: EpochDataRemover,
    consensus_listener: Arc<ConsensusListener>,
    consensus_client: Arc<ConsensusClient>,
    checkpoint_service_exit: watch::Sender<()>,
    checkpoint_metrics: Arc<CheckpointMetrics>,
    tx_validator_metrics: Arc<TxValidatorMetrics>,
}
pub struct ConsensusNode {
    config: NodeConfig,
    components: Mutex<NodeComponents>,
    state: Arc<AuthorityState>,
    verify_state: Arc<AuthorityVerifyState>,
    registry_service: RegistryService,
    metrics: Arc<SuiNodeMetrics>,
    // state_sync_handle: state_sync::Handle,
    checkpoint_store: Arc<CheckpointStore>,
    //connection_monitor_status: Arc<ConnectionMonitorStatus>,
    shutdown_channel_tx: broadcast::Sender<Option<RunWithRange>>,
}

impl ConsensusNode {
    fn start_jwk_updater(
        config: &NodeConfig,
        metrics: Arc<SuiNodeMetrics>,
        authority: AuthorityName,
        epoch_store: Arc<AuthorityPerEpochStore>,
        consensus_client: Arc<ConsensusClient>,
    ) {
        let epoch = epoch_store.epoch();

        let supported_providers = config
            .zklogin_oauth_providers
            .get(&epoch_store.get_chain_identifier().chain())
            .unwrap_or(&BTreeSet::new())
            .iter()
            .map(|s| OIDCProvider::from_str(s).expect("Invalid provider string"))
            .collect::<Vec<_>>();

        let fetch_interval = Duration::from_secs(config.jwk_fetch_interval_seconds);

        info!(
            ?fetch_interval,
            "Starting JWK updater tasks with supported providers: {:?}", supported_providers
        );

        fn validate_jwk(
            metrics: &Arc<SuiNodeMetrics>,
            provider: &OIDCProvider,
            id: &JwkId,
            jwk: &JWK,
        ) -> bool {
            let Ok(iss_provider) = OIDCProvider::from_iss(&id.iss) else {
                warn!(
                    "JWK iss {:?} (retrieved from {:?}) is not a valid provider",
                    id.iss, provider
                );
                metrics
                    .invalid_jwks
                    .with_label_values(&[&provider.to_string()])
                    .inc();
                return false;
            };

            if iss_provider != *provider {
                warn!(
                    "JWK iss {:?} (retrieved from {:?}) does not match provider {:?}",
                    id.iss, provider, iss_provider
                );
                metrics
                    .invalid_jwks
                    .with_label_values(&[&provider.to_string()])
                    .inc();
                return false;
            }

            if !check_total_jwk_size(id, jwk) {
                warn!("JWK {:?} (retrieved from {:?}) is too large", id, provider);
                metrics
                    .invalid_jwks
                    .with_label_values(&[&provider.to_string()])
                    .inc();
                return false;
            }

            true
        }

        // metrics is:
        //  pub struct SuiNodeMetrics {
        //      pub jwk_requests: IntCounterVec,
        //      pub jwk_request_errors: IntCounterVec,
        //      pub total_jwks: IntCounterVec,
        //      pub unique_jwks: IntCounterVec,
        //  }

        for p in supported_providers.into_iter() {
            let provider_str = p.to_string();
            let epoch_store = epoch_store.clone();
            let consensus_client = consensus_client.clone();
            let metrics = metrics.clone();
            spawn_monitored_task!(epoch_store.clone().within_alive_epoch(
                async move {
                    // note: restart-safe de-duplication happens after consensus, this is
                    // just best-effort to reduce unneeded submissions.
                    let mut seen = HashSet::new();
                    loop {
                        info!("fetching JWK for provider {:?}", p);
                        metrics.jwk_requests.with_label_values(&[&provider_str]).inc();
                        match Self::fetch_jwks(authority, &p).await {
                            Err(e) => {
                                metrics.jwk_request_errors.with_label_values(&[&provider_str]).inc();
                                warn!("Error when fetching JWK for provider {:?} {:?}", p, e);
                                // Retry in 30 seconds
                                tokio::time::sleep(Duration::from_secs(30)).await;
                                continue;
                            }
                            Ok(mut keys) => {
                                metrics.total_jwks
                                    .with_label_values(&[&provider_str])
                                    .inc_by(keys.len() as u64);

                                keys.retain(|(id, jwk)| {
                                    validate_jwk(&metrics, &p, id, jwk) &&
                                    !epoch_store.jwk_active_in_current_epoch(id, jwk) &&
                                    seen.insert((id.clone(), jwk.clone()))
                                });

                                metrics.unique_jwks
                                    .with_label_values(&[&provider_str])
                                    .inc_by(keys.len() as u64);

                                // prevent oauth providers from sending too many keys,
                                // inadvertently or otherwise
                                if keys.len() > MAX_JWK_KEYS_PER_FETCH {
                                    warn!("Provider {:?} sent too many JWKs, only the first {} will be used", p, MAX_JWK_KEYS_PER_FETCH);
                                    keys.truncate(MAX_JWK_KEYS_PER_FETCH);
                                }

                                for (id, jwk) in keys.into_iter() {
                                    info!("Submitting JWK to consensus: {:?}", id);

                                    let txn = ConsensusTransaction::new_jwk_fetched(authority, id, jwk);
                                    consensus_client.submit_consensus_transaction(txn).await
                                        .tap_err(|e| warn!("Error when submitting JWKs to consensus {:?}", e))
                                        .ok();
                                }
                            }
                        }
                        tokio::time::sleep(fetch_interval).await;
                    }
                }
                .instrument(error_span!("jwk_updater_task", epoch)),
            ));
        }
    }
    pub async fn start(
        config: NodeConfig,
        registry_service: RegistryService,
    ) -> Result<Arc<ConsensusNode>> {
        NodeConfigMetrics::new(&registry_service.default_registry()).record_metrics(&config);
        let mut config = config.clone();
        debug!("Start consensus node with config {:?}", &config);
        let prometheus_registry = registry_service.default_registry();
        // Initialize metrics to track db usage before creating any stores
        DBMetrics::init(&prometheus_registry);
        mysten_metrics::init_metrics(&prometheus_registry);
        let genesis = config.genesis()?.clone();
        let secret = Arc::pin(config.protocol_key_pair().copy());
        let genesis_committee = genesis.committee()?;
        let committee_store = Arc::new(CommitteeStore::new(
            config.db_path().join("epochs"),
            &genesis_committee,
            None,
        ));
        let perpetual_options = default_db_options().optimize_db_for_write_throughput(4);
        let perpetual_tables = Arc::new(AuthorityPerpetualTables::open(
            &config.db_path().join("store"),
            Some(perpetual_options.options),
        ));
        let is_genesis = perpetual_tables
            .database_is_empty()
            .expect("Database read should not fail at init.");

        let store =
            AuthorityStore::open(perpetual_tables, &genesis, &config, &prometheus_registry).await?;

        let cur_epoch = store.get_recovery_epoch_at_restart()?;
        let committee = committee_store
            .get_committee(&cur_epoch)?
            .expect("Committee of the current epoch must exist");
        let epoch_start_configuration = store
            .get_epoch_start_configuration()?
            .expect("EpochStartConfiguration of the current epoch must exist");
        let cache_metrics = Arc::new(ResolverMetrics::new(&prometheus_registry));
        // let signature_verifier_metrics = SignatureVerifierMetrics::new(&prometheus_registry);
        let cache_traits =
            build_execution_cache(&epoch_start_configuration, &prometheus_registry, &store);

        let epoch_options = default_db_options().optimize_db_for_write_throughput(4);
        let epoch_store = AuthorityPerEpochStore::new(
            config.protocol_public_key(),
            committee.clone(),
            &config.db_path().join("store"),
            Some(epoch_options.options),
            EpochMetrics::new(&registry_service.default_registry()),
            epoch_start_configuration,
            cache_traits.backing_package_store.clone(),
            cache_traits.object_store.clone(),
            cache_metrics,
            // signature_verifier_metrics,
            &config.expensive_safety_check_config,
            ChainIdentifier::from(*genesis.checkpoint().digest()),
        );

        replay_log!(
            "Beginning replay run. Epoch: {:?}, Protocol config: {:?}",
            epoch_store.epoch(),
            epoch_store.protocol_config()
        );
        // the database is empty at genesis time
        if is_genesis {
            // When we are opening the db table, the only time when it's safe to
            // check SUI conservation is at genesis. Otherwise we may be in the middle of
            // an epoch and the SUI conservation check will fail. This also initialize
            // the expected_network_sui_amount table.
            // cache_traits
            //     .reconfig_api
            //     .expensive_check_sui_conservation(&epoch_store)
            //     .expect("SUI conservation check cannot fail at genesis");
        }
        let effective_buffer_stake = epoch_store.get_effective_buffer_stake_bps();
        let default_buffer_stake = epoch_store
            .protocol_config()
            .buffer_stake_for_protocol_upgrade_bps();
        if effective_buffer_stake != default_buffer_stake {
            warn!(
                ?effective_buffer_stake,
                ?default_buffer_stake,
                "buffer_stake_for_protocol_upgrade_bps is currently overridden"
            );
        }

        let checkpoint_store = CheckpointStore::new(&config.db_path().join("checkpoints"));
        // checkpoint_store.insert_genesis_checkpoint(
        //     genesis.checkpoint(),
        //     genesis.checkpoint_contents().clone(),
        //     &epoch_store,
        // );

        // let state_sync_store = RocksDbStore::new(
        //     cache_traits.clone(),
        //     committee_store.clone(),
        //     checkpoint_store.clone(),
        // );
        let chain_identifier = ChainIdentifier::from(*genesis.checkpoint().digest());
        // It's ok if the value is already set due to data races.
        let _ = CHAIN_IDENTIFIER.set(chain_identifier);

        // Create network
        // TODO only configure validators as seed/preferred peers for validators and not for
        // fullnodes once we've had a chance to re-work fullnode configuration generation.
        let archive_readers =
            ArchiveReaderBalancer::new(config.archive_reader_config(), &prometheus_registry)?;
        let (trusted_peer_change_tx, trusted_peer_change_rx) = watch::channel(Default::default());
        let (randomness_tx, randomness_rx) = mpsc::channel(
            config
                .p2p_config
                .randomness
                .clone()
                .unwrap_or_default()
                .mailbox_capacity(),
        );
        let (
            p2p_network,
            discovery_handle,
            //state_sync_handle,
            randomness_handle,
        ) = Self::create_p2p_network(
            &config,
            // state_sync_store.clone(),
            chain_identifier,
            trusted_peer_change_rx,
            archive_readers.clone(),
            randomness_tx,
            &prometheus_registry,
        )?;

        // We must explicitly send this instead of relying on the initial value to trigger
        // watch value change, so that state-sync is able to process it.
        send_trusted_peer_change(
            &config,
            &trusted_peer_change_tx,
            epoch_store.epoch_start_state(),
        )
        .expect("Initial trusted peers must be set");

        // // Start archiving local state to remote store
        // let state_archive_handle =
        //     Self::start_state_archival(&config, &prometheus_registry, state_sync_store.clone())
        //         .await?;

        // // Start uploading state snapshot to remote store
        // let state_snapshot_handle =
        //     Self::start_state_snapshot(&config, &prometheus_registry, checkpoint_store.clone())?;

        // Start uploading db checkpoints to remote store
        // let (db_checkpoint_config, db_checkpoint_handle) = Self::start_db_checkpoint(
        //     &config,
        //     &prometheus_registry,
        //     state_snapshot_handle.is_some(),
        // )?;
        if !epoch_store
            .protocol_config()
            .simplified_unwrap_then_delete()
        {
            // We cannot prune tombstones if simplified_unwrap_then_delete is not enabled.
            config
                .authority_store_pruning_config
                .set_killswitch_tombstone_pruning(true);
        }
        let db_checkpoint_config = DBCheckpointConfig::default();
        let state = AuthorityState::new(
            config.protocol_public_key(),
            secret,
            config.supported_protocol_versions.unwrap(),
            store.clone(),
            cache_traits.clone(),
            epoch_store.clone(),
            committee_store.clone(),
            checkpoint_store.clone(),
            &prometheus_registry,
            genesis.objects(),
            &db_checkpoint_config,
            config.clone(),
            config.indirect_objects_threshold,
            archive_readers,
        )
        .await;
        let verify_state = Arc::new(AuthorityVerifyState::new());
        // ensure genesis txn was executed
        // 20240606 TaiVV Execution layer
        if epoch_store.epoch() == 0 {
            // let txn = &genesis.transaction();
            // let span = error_span!("genesis_txn", tx_digest = ?txn.digest());
            // let transaction =
            //     sui_types::executable_transaction::VerifiedExecutableTransaction::new_unchecked(
            //         sui_types::executable_transaction::ExecutableTransaction::new_from_data_and_sig(
            //             genesis.transaction().data().clone(),
            //             sui_types::executable_transaction::CertificateProof::Checkpoint(0, 0),
            //         ),
            //     );
            // state
            //     .try_execute_immediately(&transaction, None, &epoch_store)
            //     .instrument(span)
            //     .await
            //     .unwrap();
        }

        checkpoint_store
            .reexecute_local_checkpoints(&state, &epoch_store)
            .await;

        // Start the loop that receives new randomness and generates transactions for it.
        RandomnessRoundReceiver::spawn(state.clone(), randomness_rx);
        // let (end_of_epoch_channel, end_of_epoch_receiver) =
        //     broadcast::channel(config.end_of_epoch_broadcast_channel_capacity);
        // let accumulator = Arc::new(StateAccumulator::new(
        //     cache_traits.accumulator_store.clone(),
        // ));

        let authority_names_to_peer_ids = epoch_store
            .epoch_start_state()
            .get_authority_names_to_peer_ids();

        let network_connection_metrics = NetworkConnectionMetrics::new("sui", &prometheus_registry);
        let validator_display_names = Arc::new(authority_names_to_peer_ids);

        //let authority_names_to_peer_ids = ArcSwap::from_pointee(authority_names_to_peer_ids);
        let authority_names_to_peer_ids = ArcSwap::from(validator_display_names.clone());
        let (_connection_monitor_handle, connection_statuses) =
            narwhal_network::connectivity::ConnectionMonitor::spawn(
                p2p_network.downgrade(),
                network_connection_metrics,
                HashMap::new(),
                None,
            );

        let connection_monitor_status = ConnectionMonitorStatus {
            connection_statuses,
            authority_names_to_peer_ids,
        };

        let connection_monitor_status = Arc::new(connection_monitor_status);
        let sui_node_metrics = Arc::new(SuiNodeMetrics::new(&prometheus_registry));

        let safe_client_metrics_base = SafeClientMetricsBase::new(&prometheus_registry);
        let auth_agg_metrics = AuthAggMetrics::new(&prometheus_registry);
        //state.get_sui_system_state_object_unsafe()
        // let committee_network_metadata = CommitteeWithNetworkMetadata {
        //     committee: todo!(),
        //     network_metadata: todo!(),
        // };
        // let validators = AuthorityAggregator::new_from_committee(
        //     committee_network_metadata,
        //     state.committee_store(),
        //     safe_client_metrics_base.clone(),
        //     Arc::new(auth_agg_metrics),
        //     validator_display_names,
        // )?;

        let components = Self::construct_components(
            config.clone(),
            state.clone(),
            verify_state.clone(),
            committee,
            epoch_store.clone(),
            checkpoint_store.clone(),
            // state_sync_handle.clone(),
            randomness_handle.clone(),
            //accumulator.clone(),
            connection_monitor_status.clone(),
            &registry_service,
            sui_node_metrics.clone(),
        )
        .await?;
        let (shutdown_channel, _) = broadcast::channel::<Option<RunWithRange>>(1);
        let node = Self {
            config,
            components: Mutex::new(components),
            state,
            verify_state,
            registry_service,
            metrics: sui_node_metrics,
            // state_sync_handle,
            checkpoint_store,
            //connection_monitor_status,
            shutdown_channel_tx: shutdown_channel,
        };
        info!("ScalarisNode started!");
        let node = Arc::new(node);
        let node_copy = node.clone();
        // spawn_monitored_task!(async move {
        //     let result = Self::monitor_reconfiguration(node_copy).await;
        //     if let Err(error) = result {
        //         warn!("Reconfiguration finished with error {:?}", error);
        //     }
        // });
        Ok(node)
    }

    fn create_p2p_network(
        config: &NodeConfig,
        //state_sync_store: RocksDbStore,
        chain_identifier: ChainIdentifier,
        trusted_peer_change_rx: watch::Receiver<TrustedPeerChangeEvent>,
        archive_readers: ArchiveReaderBalancer,
        randomness_tx: mpsc::Sender<(EpochId, RandomnessRound, Vec<u8>)>,
        prometheus_registry: &Registry,
    ) -> Result<(
        Network,
        discovery::Handle,
        // state_sync::Handle,
        randomness::Handle,
    )> {
        // let (state_sync, state_sync_server) = state_sync::Builder::new()
        //     .config(config.p2p_config.state_sync.clone().unwrap_or_default())
        //     .store(state_sync_store)
        //     .archive_readers(archive_readers)
        //     .with_metrics(prometheus_registry)
        //     .build();

        let (discovery, discovery_server) = discovery::Builder::new(trusted_peer_change_rx)
            .config(config.p2p_config.clone())
            .build();

        let (randomness, randomness_router) =
            randomness::Builder::new(config.protocol_public_key(), randomness_tx)
                .config(config.p2p_config.randomness.clone().unwrap_or_default())
                .with_metrics(prometheus_registry)
                .build();

        let p2p_network = {
            let routes = anemo::Router::new().add_rpc_service(discovery_server);
            //.add_rpc_service(state_sync_server);
            let routes = routes.merge(randomness_router);

            let inbound_network_metrics =
                NetworkMetrics::new("sui", "inbound", prometheus_registry);
            let outbound_network_metrics =
                NetworkMetrics::new("sui", "outbound", prometheus_registry);

            let service = ServiceBuilder::new()
                .layer(
                    TraceLayer::new_for_server_errors()
                        .make_span_with(DefaultMakeSpan::new().level(tracing::Level::INFO))
                        .on_failure(DefaultOnFailure::new().level(tracing::Level::WARN)),
                )
                .layer(CallbackLayer::new(MetricsMakeCallbackHandler::new(
                    Arc::new(inbound_network_metrics),
                    config.p2p_config.excessive_message_size(),
                )))
                .service(routes);

            let outbound_layer = ServiceBuilder::new()
                .layer(
                    TraceLayer::new_for_client_and_server_errors()
                        .make_span_with(DefaultMakeSpan::new().level(tracing::Level::INFO))
                        .on_failure(DefaultOnFailure::new().level(tracing::Level::WARN)),
                )
                .layer(CallbackLayer::new(MetricsMakeCallbackHandler::new(
                    Arc::new(outbound_network_metrics),
                    config.p2p_config.excessive_message_size(),
                )))
                .into_inner();

            let mut anemo_config = config.p2p_config.anemo_config.clone().unwrap_or_default();
            // Set the max_frame_size to be 1 GB to work around the issue of there being too many
            // staking events in the epoch change txn.
            anemo_config.max_frame_size = Some(1 << 30);

            // Set a higher default value for socket send/receive buffers if not already
            // configured.
            let mut quic_config = anemo_config.quic.unwrap_or_default();
            if quic_config.socket_send_buffer_size.is_none() {
                quic_config.socket_send_buffer_size = Some(20 << 20);
            }
            if quic_config.socket_receive_buffer_size.is_none() {
                quic_config.socket_receive_buffer_size = Some(20 << 20);
            }
            quic_config.allow_failed_socket_buffer_size_setting = true;

            // Set high-performance defaults for quinn transport.
            // With 200MiB buffer size and ~500ms RTT, max throughput ~400MiB/s.
            if quic_config.max_concurrent_bidi_streams.is_none() {
                quic_config.max_concurrent_bidi_streams = Some(500);
            }
            if quic_config.max_concurrent_uni_streams.is_none() {
                quic_config.max_concurrent_uni_streams = Some(500);
            }
            if quic_config.stream_receive_window.is_none() {
                quic_config.stream_receive_window = Some(100 << 20);
            }
            if quic_config.receive_window.is_none() {
                quic_config.receive_window = Some(200 << 20);
            }
            if quic_config.send_window.is_none() {
                quic_config.send_window = Some(200 << 20);
            }
            if quic_config.crypto_buffer_size.is_none() {
                quic_config.crypto_buffer_size = Some(1 << 20);
            }
            if quic_config.max_idle_timeout_ms.is_none() {
                quic_config.max_idle_timeout_ms = Some(30_000);
            }
            if quic_config.keep_alive_interval_ms.is_none() {
                quic_config.keep_alive_interval_ms = Some(5_000);
            }
            anemo_config.quic = Some(quic_config);

            let server_name = format!("sui-{}", chain_identifier);
            let network = Network::bind(config.p2p_config.listen_address)
                .server_name(&server_name)
                .private_key(config.network_key_pair().copy().private().0.to_bytes())
                .config(anemo_config)
                .outbound_request_layer(outbound_layer)
                .start(service)?;
            info!(
                server_name = server_name,
                "P2p network started on {}",
                network.local_addr()
            );

            network
        };

        let discovery_handle = discovery.start(p2p_network.clone());
        // let state_sync_handle = state_sync.start(p2p_network.clone());
        let randomness_handle = randomness.start(p2p_network.clone());

        Ok((
            p2p_network,
            discovery_handle,
            // state_sync_handle,
            randomness_handle,
        ))
    }

    async fn construct_components(
        config: NodeConfig,
        state: Arc<AuthorityState>,
        verify_state: Arc<AuthorityVerifyState>,
        committee: Arc<Committee>,
        epoch_store: Arc<AuthorityPerEpochStore>,
        checkpoint_store: Arc<CheckpointStore>,
        // state_sync_handle: state_sync::Handle,
        randomness_handle: randomness::Handle,
        // accumulator: Arc<StateAccumulator>,
        connection_monitor_status: Arc<ConnectionMonitorStatus>,
        registry_service: &RegistryService,
        sui_node_metrics: Arc<SuiNodeMetrics>,
    ) -> Result<NodeComponents> {
        let mut config_clone = config.clone();
        let consensus_config = config_clone
            .consensus_config
            .as_mut()
            .ok_or_else(|| anyhow!("Validator is missing consensus config"))?;

        let client = Arc::new(ConsensusClient::new());
        // let consensus_adapter = Arc::new(Self::construct_consensus_adapter(
        //     &committee,
        //     &consensus_config,
        //     state.name,
        //     connection_monitor_status.clone(),
        //     &registry_service.default_registry(),
        //     epoch_store.protocol_config().clone(),
        //     client.clone(),
        // ));
        let consensus_listener = Arc::new(ConsensusListener::default());
        let consensus_manager =
            ConsensusManager::new(&config, consensus_config, registry_service, client.clone());

        let mut consensus_epoch_data_remover =
            EpochDataRemover::new(consensus_manager.get_storage_base_path());

        // This only gets started up once, not on every epoch. (Make call to remove every epoch.)
        consensus_epoch_data_remover.run().await;

        let prometheus_registry = registry_service.default_registry();
        let checkpoint_metrics = CheckpointMetrics::new(&prometheus_registry);
        let sui_tx_validator_metrics =
            TxValidatorMetrics::new(&registry_service.default_registry());

        let validators = AuthorityAggregator::new_from_local_system_state(
            state.get_object_cache_reader(),
            state.committee_store(),
            SafeClientMetricsBase::new(&prometheus_registry),
            AuthAggMetrics::new(&prometheus_registry),
        )?;
        let validators = Arc::new(validators);
        info!("Start grpc consensus service");
        let validator_server_handle = Self::start_grpc_consensus_service(
            &config,
            state.clone(),
            verify_state.clone(),
            validators,
            client.clone(),
            consensus_listener.clone(),
            &prometheus_registry,
        )
        .await?;

        // Starts an overload monitor that monitors the execution of the authority.
        // Don't start the overload monitor when max_load_shedding_percentage is 0.
        let validator_overload_monitor_handle = if config
            .authority_overload_config
            .max_load_shedding_percentage
            > 0
        {
            let authority_state = Arc::downgrade(&state);
            let overload_config = config.authority_overload_config.clone();
            fail_point!("starting_overload_monitor");
            // Some(spawn_monitored_task!(overload_monitor(
            //     authority_state,
            //     overload_config,
            // )))
            None
        } else {
            None
        };

        Self::start_epoch_specific_components(
            &config,
            state.clone(),
            consensus_listener,
            client,
            checkpoint_store,
            epoch_store,
            // state_sync_handle,
            randomness_handle,
            consensus_manager,
            consensus_epoch_data_remover,
            // accumulator,
            validator_server_handle,
            validator_overload_monitor_handle,
            checkpoint_metrics,
            sui_node_metrics,
            sui_tx_validator_metrics,
        )
        .await
    }

    async fn start_epoch_specific_components(
        config: &NodeConfig,
        state: Arc<AuthorityState>,
        consensus_listener: Arc<ConsensusListener>,
        consensus_client: Arc<ConsensusClient>,
        checkpoint_store: Arc<CheckpointStore>,
        epoch_store: Arc<AuthorityPerEpochStore>,
        // state_sync_handle: state_sync::Handle,
        randomness_handle: randomness::Handle,
        consensus_manager: ConsensusManager,
        consensus_epoch_data_remover: EpochDataRemover,
        // accumulator: Arc<StateAccumulator>,
        validator_server_handle: JoinHandle<Result<()>>,
        validator_overload_monitor_handle: Option<JoinHandle<()>>,
        checkpoint_metrics: Arc<CheckpointMetrics>,
        sui_node_metrics: Arc<SuiNodeMetrics>,
        tx_validator_metrics: Arc<TxValidatorMetrics>,
    ) -> Result<NodeComponents> {
        info!("Start epoch consensus components");
        // CheckpointService in the
        // https://docs.sui.io/concepts/cryptography/system/checkpoint-verification
        let (checkpoint_service, checkpoint_service_exit) =
            Self::start_checkpoint_service(epoch_store.clone(), checkpoint_metrics.clone());

        // create a new map that gets injected into both the consensus handler and the consensus adapter
        // the consensus handler will write values forwarded from consensus, and the consensus adapter
        // will read the values to make decisions about which validator submits a transaction to consensus
        let low_scoring_authorities = Arc::new(ArcSwap::new(Arc::new(HashMap::new())));

        //consensus_adapter.swap_low_scoring_authorities(low_scoring_authorities.clone());

        let throughput_calculator = Arc::new(ConsensusThroughputCalculator::new(
            None,
            state.metrics.clone(),
        ));

        let throughput_profiler = Arc::new(ConsensusThroughputProfiler::new(
            throughput_calculator.clone(),
            None,
            None,
            state.metrics.clone(),
            ThroughputProfileRanges::from_chain(epoch_store.get_chain_identifier()),
        ));

        // consensus_adapter.swap_throughput_profiler(throughput_profiler);

        let consensus_handler_initializer = ConsensusHandlerInitializer::new(
            state.clone(),
            consensus_listener.clone(),
            checkpoint_service.clone(),
            epoch_store.clone(),
            low_scoring_authorities,
            throughput_calculator,
        );
        info!("Start consensus manager");
        consensus_manager
            .start(
                config,
                epoch_store.clone(),
                consensus_handler_initializer,
                SuiTxValidator::new(
                    epoch_store.clone(),
                    // checkpoint_service.clone(),
                    tx_validator_metrics.clone(),
                ),
            )
            .await;

        if epoch_store.randomness_state_enabled() {
            info!("Create randomness manager");
            let randomness_manager = RandomnessManager::try_new(
                Arc::downgrade(&epoch_store),
                consensus_client.clone(),
                randomness_handle,
                config.protocol_key_pair(),
            )
            .await;
            if let Some(randomness_manager) = randomness_manager {
                epoch_store
                    .set_randomness_manager(randomness_manager)
                    .await?;
            }
        }
        if epoch_store.authenticator_state_enabled() {
            Self::start_jwk_updater(
                config,
                sui_node_metrics,
                state.name,
                epoch_store.clone(),
                consensus_client.clone(),
            );
        }

        Ok(NodeComponents {
            validator_server_handle,
            validator_overload_monitor_handle,
            consensus_manager,
            consensus_epoch_data_remover,
            consensus_listener,
            consensus_client,
            checkpoint_service_exit,
            checkpoint_metrics,
            tx_validator_metrics,
        })
    }
    fn start_checkpoint_service(
        epoch_store: Arc<AuthorityPerEpochStore>,
        checkpoint_metrics: Arc<CheckpointMetrics>,
    ) -> (Arc<CheckpointService>, watch::Sender<()>) {
        let epoch_start_timestamp_ms = epoch_store.epoch_start_state().epoch_start_timestamp_ms();
        let epoch_duration_ms = epoch_store.epoch_start_state().epoch_duration_ms();

        debug!(
            "Starting checkpoint service with epoch start timestamp {}
            and epoch duration {}",
            epoch_start_timestamp_ms, epoch_duration_ms
        );

        let max_tx_per_checkpoint = max_tx_per_checkpoint(epoch_store.protocol_config());
        let max_checkpoint_size_bytes =
            epoch_store.protocol_config().max_checkpoint_size_bytes() as usize;

        CheckpointService::spawn(
            checkpoint_metrics,
            max_tx_per_checkpoint,
            max_checkpoint_size_bytes,
        )
    }

    pub fn subscribe_to_shutdown_channel(&self) -> broadcast::Receiver<Option<RunWithRange>> {
        self.shutdown_channel_tx.subscribe()
    }
    // fn construct_consensus_adapter(
    //     committee: &Committee,
    //     consensus_config: &ConsensusConfig,
    //     authority: AuthorityName,
    //     connection_monitor_status: Arc<ConnectionMonitorStatus>,
    //     prometheus_registry: &Registry,
    //     protocol_config: ProtocolConfig,
    //     consensus_client: Arc<dyn SubmitToConsensus>,
    // ) -> ConsensusAdapter {
    //     let ca_metrics = ConsensusAdapterMetrics::new(prometheus_registry);
    //     // The consensus adapter allows the authority to send user certificates through consensus.

    //     ConsensusAdapter::new(
    //         consensus_client,
    //         authority,
    //         connection_monitor_status,
    //         consensus_config.max_pending_transactions(),
    //         consensus_config.max_pending_transactions() * 2 / committee.num_members(),
    //         consensus_config.max_submit_position,
    //         consensus_config.submit_delay_step_override(),
    //         ca_metrics,
    //         protocol_config,
    //     )
    // }
    async fn start_grpc_consensus_service(
        config: &NodeConfig,
        state: Arc<AuthorityState>,
        verify_state: Arc<AuthorityVerifyState>,
        validators: Arc<AuthorityAggregator<NetworkAuthorityClient>>,
        consensus_client: Arc<ConsensusClient>,
        consensus_listener: Arc<ConsensusListener>,
        prometheus_registry: &Registry,
    ) -> Result<tokio::task::JoinHandle<Result<()>>> {
        let consensus_service = ConsensusService::new(
            state.clone(),
            verify_state.clone(),
            validators,
            consensus_client,
            consensus_listener,
            Arc::new(ConsensusServiceMetrics::new(prometheus_registry)),
            TrafficControllerMetrics::new(prometheus_registry),
            config.policy_config.clone(),
            config.firewall_config.clone(),
        );

        let validator_service = ValidatorService::new(
            verify_state,
            Arc::new(ValidatorServiceMetrics::new(prometheus_registry)),
            TrafficControllerMetrics::new(prometheus_registry),
            config.policy_config.clone(),
            config.firewall_config.clone(),
        );
        let mut server_conf = mysten_network::config::Config::new();
        server_conf.global_concurrency_limit = config.grpc_concurrency_limit;
        server_conf.load_shed = config.grpc_load_shed;
        let mut server_builder =
            ServerBuilder::from_config(&server_conf, GrpcMetrics::new(prometheus_registry));

        server_builder = server_builder
            .add_service(crate::ConsensusApiServer::new(consensus_service))
            .add_service(ValidatorServer::new(validator_service));
        let server = server_builder
            .bind(config.network_address())
            .await
            .map_err(|err| anyhow!(err.to_string()))?;
        let local_addr = server.local_addr();
        info!("Listening to traffic on {local_addr}");
        let grpc_server = spawn_monitored_task!(server.serve().map_err(Into::into));

        Ok(grpc_server)
    }
    async fn shutdown(&self) {
        let components = &*self.components.lock().await;
        components.consensus_manager.shutdown().await;
    }
}
impl ConsensusNode {
    // This function awaits the completion of checkpoint execution of the current epoch,
    // after which it iniitiates reconfiguration of the entire system.
    // pub async fn monitor_reconfiguration(self: Arc<Self>) -> Result<()> {
    //     let mut checkpoint_executor = CheckpointExecutor::new(
    //         self.state_sync_handle.subscribe_to_synced_checkpoints(),
    //         self.checkpoint_store.clone(),
    //         self.state.clone(),
    //         self.accumulator.clone(),
    //         self.config.checkpoint_executor_config.clone(),
    //         &self.registry_service.default_registry(),
    //     );

    //     let run_with_range = self.config.run_with_range;
    //     loop {
    //         let cur_epoch_store = self.state.load_epoch_store_one_call_per_task();

    //         // Advertise capabilities to committee, if we are a validator.
    //         if let Some(components) = &*self.components.lock().await {
    //             // TODO: without this sleep, the consensus message is not delivered reliably.
    //             tokio::time::sleep(Duration::from_millis(1)).await;

    //             let config = cur_epoch_store.protocol_config();
    //             let binary_config = to_binary_config(config);
    //             let transaction =
    //                 ConsensusTransaction::new_capability_notification(AuthorityCapabilities::new(
    //                     self.state.name,
    //                     self.config
    //                         .supported_protocol_versions
    //                         .expect("Supported versions should be populated"),
    //                     self.state
    //                         .get_available_system_packages(&binary_config)
    //                         .await,
    //                 ));
    //             info!(?transaction, "submitting capabilities to consensus");
    //             components
    //                 .consensus_adapter
    //                 .submit(transaction, None, &cur_epoch_store)?;
    //         }

    //         let stop_condition = checkpoint_executor
    //             .run_epoch(cur_epoch_store.clone(), run_with_range)
    //             .await;

    //         if stop_condition == StopReason::RunWithRangeCondition {
    //             ConsensusNode::shutdown(&self).await;
    //             self.shutdown_channel_tx
    //                 .send(run_with_range)
    //                 .expect("RunWithRangeCondition met but failed to send shutdown message");
    //             return Ok(());
    //         }

    //         // Safe to call because we are in the middle of reconfiguration.
    //         let latest_system_state = self
    //             .state
    //             .get_object_cache_reader()
    //             .get_sui_system_state_object_unsafe()
    //             .expect("Read Sui System State object cannot fail");

    //         #[cfg(msim)]
    //         if !self
    //             .sim_state
    //             .sim_safe_mode_expected
    //             .load(Ordering::Relaxed)
    //         {
    //             debug_assert!(!latest_system_state.safe_mode());
    //         }

    //         #[cfg(not(msim))]
    //         debug_assert!(!latest_system_state.safe_mode());

    //         if let Err(err) = self.end_of_epoch_channel.send(latest_system_state.clone()) {
    //             if self.state.is_fullnode(&cur_epoch_store) {
    //                 warn!(
    //                     "Failed to send end of epoch notification to subscriber: {:?}",
    //                     err
    //                 );
    //             }
    //         }

    //         cur_epoch_store.record_is_safe_mode_metric(latest_system_state.safe_mode());
    //         let new_epoch_start_state = latest_system_state.into_epoch_start_state();
    //         let next_epoch_committee = new_epoch_start_state.get_sui_committee();
    //         let next_epoch = next_epoch_committee.epoch();
    //         assert_eq!(cur_epoch_store.epoch() + 1, next_epoch);

    //         info!(
    //             next_epoch,
    //             "Finished executing all checkpoints in epoch. About to reconfigure the system."
    //         );

    //         fail_point_async!("reconfig_delay");

    //         // We save the connection monitor status map regardless of validator / fullnode status
    //         // so that we don't need to restart the connection monitor every epoch.
    //         // Update the mappings that will be used by the consensus adapter if it exists or is
    //         // about to be created.
    //         let authority_names_to_peer_ids =
    //             new_epoch_start_state.get_authority_names_to_peer_ids();
    //         self.connection_monitor_status
    //             .update_mapping_for_epoch(authority_names_to_peer_ids);

    //         cur_epoch_store.record_epoch_reconfig_start_time_metric();

    //         let _ = send_trusted_peer_change(
    //             &self.config,
    //             &self.trusted_peer_change_tx,
    //             &new_epoch_start_state,
    //         );

    //         // The following code handles 4 different cases, depending on whether the node
    //         // was a validator in the previous epoch, and whether the node is a validator
    //         // in the new epoch.
    //         let new_validator_components = if let Some(NodeComponents {
    //             validator_server_handle,
    //             validator_overload_monitor_handle,
    //             consensus_manager,
    //             consensus_epoch_data_remover,
    //             consensus_listener,
    //             consensus_adapter,
    //             checkpoint_service_exit,
    //             checkpoint_metrics,
    //             tx_validator_metrics,
    //         }) = self.components.lock().await.take()
    //         {
    //             info!("Reconfiguring the validator.");
    //             // Stop the old checkpoint service.
    //             drop(checkpoint_service_exit);

    //             consensus_manager.shutdown().await;

    //             let new_epoch_store = self
    //                 .reconfigure_state(
    //                     &self.state,
    //                     &cur_epoch_store,
    //                     next_epoch_committee.clone(),
    //                     new_epoch_start_state,
    //                     &checkpoint_executor,
    //                 )
    //                 .await;

    //             consensus_epoch_data_remover
    //                 .remove_old_data(next_epoch - 1)
    //                 .await;

    //             if self.state.is_validator(&new_epoch_store) {
    //                 // Only restart Narwhal if this node is still a validator in the new epoch.
    //                 Some(
    //                     Self::start_epoch_specific_components(
    //                         &self.config,
    //                         self.state.clone(),
    //                         consensus_listener,
    //                         consensus_adapter,
    //                         self.checkpoint_store.clone(),
    //                         new_epoch_store.clone(),
    //                         self.state_sync_handle.clone(),
    //                         self.randomness_handle.clone(),
    //                         consensus_manager,
    //                         consensus_epoch_data_remover,
    //                         self.accumulator.clone(),
    //                         validator_server_handle,
    //                         validator_overload_monitor_handle,
    //                         checkpoint_metrics,
    //                         self.metrics.clone(),
    //                         tx_validator_metrics,
    //                     )
    //                     .await?,
    //                 )
    //             } else {
    //                 info!("This node is no longer a validator after reconfiguration");
    //                 None
    //             }
    //         } else {
    //             let new_epoch_store = self
    //                 .reconfigure_state(
    //                     &self.state,
    //                     &cur_epoch_store,
    //                     next_epoch_committee.clone(),
    //                     new_epoch_start_state,
    //                     &checkpoint_executor,
    //                 )
    //                 .await;

    //             info!("Promoting the node from fullnode to validator, starting grpc server");

    //             Some(
    //                 Self::construct_validator_components(
    //                     self.config.clone(),
    //                     self.state.clone(),
    //                     Arc::new(next_epoch_committee.clone()),
    //                     new_epoch_store.clone(),
    //                     self.checkpoint_store.clone(),
    //                     self.state_sync_handle.clone(),
    //                     self.randomness_handle.clone(),
    //                     self.accumulator.clone(),
    //                     self.connection_monitor_status.clone(),
    //                     &self.registry_service,
    //                     self.metrics.clone(),
    //                 )
    //                 .await?,
    //             )
    //         };
    //         *self.components.lock().await = new_validator_components;

    //         // Force releasing current epoch store DB handle, because the
    //         // Arc<AuthorityPerEpochStore> may linger.
    //         cur_epoch_store.release_db_handles();

    //         if cfg!(msim)
    //             && !matches!(
    //                 self.config
    //                     .authority_store_pruning_config
    //                     .num_epochs_to_retain_for_checkpoints(),
    //                 None | Some(u64::MAX) | Some(0)
    //             )
    //         {
    //             self.state
    //             .prune_checkpoints_for_eligible_epochs_for_testing(
    //                 self.config.clone(),
    //                 sui_core::authority::authority_store_pruner::AuthorityStorePruningMetrics::new_for_test(),
    //             )
    //             .await?;
    //         }

    //         info!("Reconfiguration finished");
    //     }
    // }
}

#[cfg(not(msim))]
impl ConsensusNode {
    async fn fetch_jwks(
        _authority: AuthorityName,
        provider: &OIDCProvider,
    ) -> SuiResult<Vec<(JwkId, JWK)>> {
        use fastcrypto_zkp::bn254::zk_login::fetch_jwks;
        let client = reqwest::Client::new();
        fetch_jwks(provider, &client)
            .await
            .map_err(|_| SuiError::JWKRetrievalError)
    }
}

#[cfg(msim)]
impl ConsensusNode {
    pub fn get_sim_node_id(&self) -> sui_simulator::task::NodeId {
        self.sim_state.sim_node.id()
    }

    pub fn set_safe_mode_expected(&self, new_value: bool) {
        info!("Setting safe mode expected to {}", new_value);
        self.sim_state
            .sim_safe_mode_expected
            .store(new_value, Ordering::Relaxed);
    }

    #[allow(unused_variables)]
    async fn fetch_jwks(
        authority: AuthorityName,
        provider: &OIDCProvider,
    ) -> SuiResult<Vec<(JwkId, JWK)>> {
        get_jwk_injector()(authority, provider)
    }
}

/// Notify state-sync that a new list of trusted peers are now available.
fn send_trusted_peer_change(
    config: &NodeConfig,
    sender: &watch::Sender<TrustedPeerChangeEvent>,
    epoch_state_state: &EpochStartSystemState,
) -> Result<(), watch::error::SendError<TrustedPeerChangeEvent>> {
    sender
        .send(TrustedPeerChangeEvent {
            new_peers: epoch_state_state.get_validator_as_p2p_peers(config.protocol_public_key()),
        })
        .tap_err(|err| {
            warn!(
                "Failed to send validator peer information to state sync: {:?}",
                err
            );
        })
}

#[cfg(not(test))]
fn max_tx_per_checkpoint(protocol_config: &ProtocolConfig) -> usize {
    protocol_config.max_transactions_per_checkpoint() as usize
}

#[cfg(test)]
fn max_tx_per_checkpoint(_: &ProtocolConfig) -> usize {
    2
}
