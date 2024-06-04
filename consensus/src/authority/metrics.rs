use std::{sync::Arc, time::Duration};

use mysten_metrics::{TX_TYPE_SHARED_OBJ_TX, TX_TYPE_SINGLE_WRITER_TX};
use parking_lot::Mutex;
use prometheus::{
    register_histogram_vec_with_registry, register_histogram_with_registry,
    register_int_counter_vec_with_registry, register_int_counter_with_registry,
    register_int_gauge_vec_with_registry, register_int_gauge_with_registry, Histogram,
    HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec,
};
use sui_core::metrics::{LatencyObserver, RateTracker};
use sui_types::metrics::{BytecodeVerifierMetrics, LimitsMetrics};

/// Prometheus metrics which can be displayed in Grafana, queried and alerted on
pub struct AuthorityMetrics {
    pub(crate) tx_orders: IntCounter,
    pub(crate) total_certs: IntCounter,
    pub(crate) total_cert_attempts: IntCounter,
    pub(crate) total_effects: IntCounter,
    pub shared_obj_tx: IntCounter,
    pub(crate) sponsored_tx: IntCounter,
    pub(crate) tx_already_processed: IntCounter,
    pub(crate) num_input_objs: Histogram,
    pub(crate) num_shared_objects: Histogram,
    pub(crate) batch_size: Histogram,

    pub(crate) authority_state_handle_transaction_latency: Histogram,

    pub(crate) execute_certificate_latency_single_writer: Histogram,
    pub(crate) execute_certificate_latency_shared_object: Histogram,

    pub(crate) execute_certificate_with_effects_latency: Histogram,
    pub(crate) internal_execution_latency: Histogram,
    pub(crate) execution_load_input_objects_latency: Histogram,
    pub(crate) prepare_certificate_latency: Histogram,
    pub(crate) commit_certificate_latency: Histogram,
    pub(crate) db_checkpoint_latency: Histogram,

    pub(crate) transaction_manager_num_enqueued_certificates: IntCounterVec,
    pub(crate) transaction_manager_num_missing_objects: IntGauge,
    pub(crate) transaction_manager_num_pending_certificates: IntGauge,
    pub(crate) transaction_manager_num_executing_certificates: IntGauge,
    pub(crate) transaction_manager_num_ready: IntGauge,
    pub(crate) transaction_manager_object_cache_size: IntGauge,
    pub(crate) transaction_manager_object_cache_hits: IntCounter,
    pub(crate) transaction_manager_object_cache_misses: IntCounter,
    pub(crate) transaction_manager_object_cache_evictions: IntCounter,
    pub(crate) transaction_manager_package_cache_size: IntGauge,
    pub(crate) transaction_manager_package_cache_hits: IntCounter,
    pub(crate) transaction_manager_package_cache_misses: IntCounter,
    pub(crate) transaction_manager_package_cache_evictions: IntCounter,
    pub(crate) transaction_manager_transaction_queue_age_s: Histogram,

    pub(crate) execution_driver_executed_transactions: IntCounter,
    pub(crate) execution_driver_dispatch_queue: IntGauge,
    pub(crate) execution_queueing_delay_s: Histogram,
    pub(crate) prepare_cert_gas_latency_ratio: Histogram,
    pub(crate) execution_gas_latency_ratio: Histogram,

    pub(crate) skipped_consensus_txns: IntCounter,
    pub(crate) skipped_consensus_txns_cache_hit: IntCounter,

    pub(crate) authority_overload_status: IntGauge,
    pub(crate) authority_load_shedding_percentage: IntGauge,

    /// Post processing metrics
    pub(crate) post_processing_total_events_emitted: IntCounter,
    pub(crate) post_processing_total_tx_indexed: IntCounter,
    pub(crate) post_processing_total_tx_had_event_processed: IntCounter,
    pub(crate) post_processing_total_failures: IntCounter,

    /// Consensus handler metrics
    pub consensus_handler_processed: IntCounterVec,
    pub consensus_handler_transaction_sizes: HistogramVec,
    pub consensus_handler_num_low_scoring_authorities: IntGauge,
    pub consensus_handler_scores: IntGaugeVec,
    pub consensus_handler_deferred_transactions: IntCounter,
    pub consensus_handler_congested_transactions: IntCounter,
    pub consensus_handler_cancelled_transactions: IntCounter,
    pub consensus_committed_subdags: IntCounterVec,
    pub consensus_committed_messages: IntGaugeVec,
    pub consensus_committed_user_transactions: IntGaugeVec,
    pub consensus_calculated_throughput: IntGauge,
    pub consensus_calculated_throughput_profile: IntGauge,

    pub limits_metrics: Arc<LimitsMetrics>,

    /// bytecode verifier metrics for tracking timeouts
    pub bytecode_verifier_metrics: Arc<BytecodeVerifierMetrics>,

    pub authenticator_state_update_failed: IntCounter,

    /// Count of zklogin signatures
    pub zklogin_sig_count: IntCounter,
    /// Count of multisig signatures
    pub multisig_sig_count: IntCounter,

    // Tracks recent average txn queueing delay between when it is ready for execution
    // until it starts executing.
    pub execution_queueing_latency: LatencyObserver,

    // Tracks the rate of transactions become ready for execution in transaction manager.
    // The need for the Mutex is that the tracker is updated in transaction manager and read
    // in the overload_monitor. There should be low mutex contention because
    // transaction manager is single threaded and the read rate in overload_monitor is
    // low. In the case where transaction manager becomes multi-threaded, we can
    // create one rate tracker per thread.
    pub txn_ready_rate_tracker: Arc<Mutex<RateTracker>>,

    // Tracks the rate of transactions starts execution in execution driver.
    // Similar reason for using a Mutex here as to `txn_ready_rate_tracker`.
    pub execution_rate_tracker: Arc<Mutex<RateTracker>>,
}

// Override default Prom buckets for positive numbers in 0-10M range
const POSITIVE_INT_BUCKETS: &[f64] = &[
    1., 2., 5., 7., 10., 20., 50., 70., 100., 200., 500., 700., 1000., 2000., 5000., 7000., 10000.,
    20000., 50000., 70000., 100000., 200000., 500000., 700000., 1000000., 2000000., 5000000.,
    7000000., 10000000.,
];

const LATENCY_SEC_BUCKETS: &[f64] = &[
    0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1., 2., 3., 4., 5., 6., 7., 8., 9.,
    10., 20., 30., 60., 90.,
];

// Buckets for low latency samples. Starts from 10us.
const LOW_LATENCY_SEC_BUCKETS: &[f64] = &[
    0.00001, 0.00002, 0.00005, 0.0001, 0.0002, 0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1,
    0.2, 0.5, 1., 2., 5., 10., 20., 50., 100.,
];

const GAS_LATENCY_RATIO_BUCKETS: &[f64] = &[
    10.0, 50.0, 100.0, 200.0, 300.0, 400.0, 500.0, 600.0, 700.0, 800.0, 900.0, 1000.0, 2000.0,
    3000.0, 4000.0, 5000.0, 6000.0, 7000.0, 8000.0, 9000.0, 10000.0, 50000.0, 100000.0, 1000000.0,
];

pub const DEV_INSPECT_GAS_COIN_VALUE: u64 = 1_000_000_000_000;

impl AuthorityMetrics {
    pub fn new(registry: &prometheus::Registry) -> AuthorityMetrics {
        let execute_certificate_latency = register_histogram_vec_with_registry!(
            "authority_state_execute_certificate_latency",
            "Latency of executing certificates, including waiting for inputs",
            &["tx_type"],
            LATENCY_SEC_BUCKETS.to_vec(),
            registry,
        )
        .unwrap();

        let execute_certificate_latency_single_writer =
            execute_certificate_latency.with_label_values(&[TX_TYPE_SINGLE_WRITER_TX]);
        let execute_certificate_latency_shared_object =
            execute_certificate_latency.with_label_values(&[TX_TYPE_SHARED_OBJ_TX]);

        Self {
            tx_orders: register_int_counter_with_registry!(
                "total_transaction_orders",
                "Total number of transaction orders",
                registry,
            )
            .unwrap(),
            total_certs: register_int_counter_with_registry!(
                "total_transaction_certificates",
                "Total number of transaction certificates handled",
                registry,
            )
            .unwrap(),
            total_cert_attempts: register_int_counter_with_registry!(
                "total_handle_certificate_attempts",
                "Number of calls to handle_certificate",
                registry,
            )
            .unwrap(),
            // total_effects == total transactions finished
            total_effects: register_int_counter_with_registry!(
                "total_transaction_effects",
                "Total number of transaction effects produced",
                registry,
            )
            .unwrap(),

            shared_obj_tx: register_int_counter_with_registry!(
                "num_shared_obj_tx",
                "Number of transactions involving shared objects",
                registry,
            )
            .unwrap(),

            sponsored_tx: register_int_counter_with_registry!(
                "num_sponsored_tx",
                "Number of sponsored transactions",
                registry,
            )
            .unwrap(),

            tx_already_processed: register_int_counter_with_registry!(
                "num_tx_already_processed",
                "Number of transaction orders already processed previously",
                registry,
            )
            .unwrap(),
            num_input_objs: register_histogram_with_registry!(
                "num_input_objects",
                "Distribution of number of input TX objects per TX",
                POSITIVE_INT_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            num_shared_objects: register_histogram_with_registry!(
                "num_shared_objects",
                "Number of shared input objects per TX",
                POSITIVE_INT_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            batch_size: register_histogram_with_registry!(
                "batch_size",
                "Distribution of size of transaction batch",
                POSITIVE_INT_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            authority_state_handle_transaction_latency: register_histogram_with_registry!(
                "authority_state_handle_transaction_latency",
                "Latency of handling transactions",
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            execute_certificate_latency_single_writer,
            execute_certificate_latency_shared_object,
            execute_certificate_with_effects_latency: register_histogram_with_registry!(
                "authority_state_execute_certificate_with_effects_latency",
                "Latency of executing certificates with effects, including waiting for inputs",
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            internal_execution_latency: register_histogram_with_registry!(
                "authority_state_internal_execution_latency",
                "Latency of actual certificate executions",
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            execution_load_input_objects_latency: register_histogram_with_registry!(
                "authority_state_execution_load_input_objects_latency",
                "Latency of loading input objects for execution",
                LOW_LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            prepare_certificate_latency: register_histogram_with_registry!(
                "authority_state_prepare_certificate_latency",
                "Latency of executing certificates, before committing the results",
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            commit_certificate_latency: register_histogram_with_registry!(
                "authority_state_commit_certificate_latency",
                "Latency of committing certificate execution results",
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            db_checkpoint_latency: register_histogram_with_registry!(
                "db_checkpoint_latency",
                "Latency of checkpointing dbs",
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            ).unwrap(),
            transaction_manager_num_enqueued_certificates: register_int_counter_vec_with_registry!(
                "transaction_manager_num_enqueued_certificates",
                "Current number of certificates enqueued to TransactionManager",
                &["result"],
                registry,
            )
            .unwrap(),
            transaction_manager_num_missing_objects: register_int_gauge_with_registry!(
                "transaction_manager_num_missing_objects",
                "Current number of missing objects in TransactionManager",
                registry,
            )
            .unwrap(),
            transaction_manager_num_pending_certificates: register_int_gauge_with_registry!(
                "transaction_manager_num_pending_certificates",
                "Number of certificates pending in TransactionManager, with at least 1 missing input object",
                registry,
            )
            .unwrap(),
            transaction_manager_num_executing_certificates: register_int_gauge_with_registry!(
                "transaction_manager_num_executing_certificates",
                "Number of executing certificates, including queued and actually running certificates",
                registry,
            )
            .unwrap(),
            transaction_manager_num_ready: register_int_gauge_with_registry!(
                "transaction_manager_num_ready",
                "Number of ready transactions in TransactionManager",
                registry,
            )
            .unwrap(),
            transaction_manager_object_cache_size: register_int_gauge_with_registry!(
                "transaction_manager_object_cache_size",
                "Current size of object-availability cache in TransactionManager",
                registry,
            )
            .unwrap(),
            transaction_manager_object_cache_hits: register_int_counter_with_registry!(
                "transaction_manager_object_cache_hits",
                "Number of object-availability cache hits in TransactionManager",
                registry,
            )
            .unwrap(),
            authority_overload_status: register_int_gauge_with_registry!(
                "authority_overload_status",
                "Whether authority is current experiencing overload and enters load shedding mode.",
                registry)
            .unwrap(),
            authority_load_shedding_percentage: register_int_gauge_with_registry!(
                "authority_load_shedding_percentage",
                "The percentage of transactions is shed when the authority is in load shedding mode.",
                registry)
            .unwrap(),
            transaction_manager_object_cache_misses: register_int_counter_with_registry!(
                "transaction_manager_object_cache_misses",
                "Number of object-availability cache misses in TransactionManager",
                registry,
            )
            .unwrap(),
            transaction_manager_object_cache_evictions: register_int_counter_with_registry!(
                "transaction_manager_object_cache_evictions",
                "Number of object-availability cache evictions in TransactionManager",
                registry,
            )
            .unwrap(),
            transaction_manager_package_cache_size: register_int_gauge_with_registry!(
                "transaction_manager_package_cache_size",
                "Current size of package-availability cache in TransactionManager",
                registry,
            )
            .unwrap(),
            transaction_manager_package_cache_hits: register_int_counter_with_registry!(
                "transaction_manager_package_cache_hits",
                "Number of package-availability cache hits in TransactionManager",
                registry,
            )
            .unwrap(),
            transaction_manager_package_cache_misses: register_int_counter_with_registry!(
                "transaction_manager_package_cache_misses",
                "Number of package-availability cache misses in TransactionManager",
                registry,
            )
            .unwrap(),
            transaction_manager_package_cache_evictions: register_int_counter_with_registry!(
                "transaction_manager_package_cache_evictions",
                "Number of package-availability cache evictions in TransactionManager",
                registry,
            )
            .unwrap(),
            transaction_manager_transaction_queue_age_s: register_histogram_with_registry!(
                "transaction_manager_transaction_queue_age_s",
                "Time spent in waiting for transaction in the queue",
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            execution_driver_executed_transactions: register_int_counter_with_registry!(
                "execution_driver_executed_transactions",
                "Cumulative number of transaction executed by execution driver",
                registry,
            )
            .unwrap(),
            execution_driver_dispatch_queue: register_int_gauge_with_registry!(
                "execution_driver_dispatch_queue",
                "Number of transaction pending in execution driver dispatch queue",
                registry,
            )
            .unwrap(),
            execution_queueing_delay_s: register_histogram_with_registry!(
                "execution_queueing_delay_s",
                "Queueing delay between a transaction is ready for execution until it starts executing.",
                LATENCY_SEC_BUCKETS.to_vec(),
                registry
            )
            .unwrap(),
            prepare_cert_gas_latency_ratio: register_histogram_with_registry!(
                "prepare_cert_gas_latency_ratio",
                "The ratio of computation gas divided by VM execution latency.",
                GAS_LATENCY_RATIO_BUCKETS.to_vec(),
                registry
            )
            .unwrap(),
            execution_gas_latency_ratio: register_histogram_with_registry!(
                "execution_gas_latency_ratio",
                "The ratio of computation gas divided by certificate execution latency, include committing certificate.",
                GAS_LATENCY_RATIO_BUCKETS.to_vec(),
                registry
            )
            .unwrap(),
            skipped_consensus_txns: register_int_counter_with_registry!(
                "skipped_consensus_txns",
                "Total number of consensus transactions skipped",
                registry,
            )
            .unwrap(),
            skipped_consensus_txns_cache_hit: register_int_counter_with_registry!(
                "skipped_consensus_txns_cache_hit",
                "Total number of consensus transactions skipped because of local cache hit",
                registry,
            )
            .unwrap(),
            post_processing_total_events_emitted: register_int_counter_with_registry!(
                "post_processing_total_events_emitted",
                "Total number of events emitted in post processing",
                registry,
            )
            .unwrap(),
            post_processing_total_tx_indexed: register_int_counter_with_registry!(
                "post_processing_total_tx_indexed",
                "Total number of txes indexed in post processing",
                registry,
            )
            .unwrap(),
            post_processing_total_tx_had_event_processed: register_int_counter_with_registry!(
                "post_processing_total_tx_had_event_processed",
                "Total number of txes finished event processing in post processing",
                registry,
            )
            .unwrap(),
            post_processing_total_failures: register_int_counter_with_registry!(
                "post_processing_total_failures",
                "Total number of failure in post processing",
                registry,
            )
            .unwrap(),
            consensus_handler_processed: register_int_counter_vec_with_registry!(
                "consensus_handler_processed",
                "Number of transactions processed by consensus handler",
                &["class"],
                registry
            ).unwrap(),
            consensus_handler_transaction_sizes: register_histogram_vec_with_registry!(
                "consensus_handler_transaction_sizes",
                "Sizes of each type of transactions processed by consensus handler",
                &["class"],
                POSITIVE_INT_BUCKETS.to_vec(),
                registry
            ).unwrap(),
            consensus_handler_num_low_scoring_authorities: register_int_gauge_with_registry!(
                "consensus_handler_num_low_scoring_authorities",
                "Number of low scoring authorities based on reputation scores from consensus",
                registry
            ).unwrap(),
            consensus_handler_scores: register_int_gauge_vec_with_registry!(
                "consensus_handler_scores",
                "scores from consensus for each authority",
                &["authority"],
                registry,
            ).unwrap(),
            consensus_handler_deferred_transactions: register_int_counter_with_registry!(
                "consensus_handler_deferred_transactions",
                "Number of transactions deferred by consensus handler",
                registry,
            ).unwrap(),
            consensus_handler_congested_transactions: register_int_counter_with_registry!(
                "consensus_handler_congested_transactions",
                "Number of transactions deferred by consensus handler due to congestion",
                registry,
            ).unwrap(),
            consensus_handler_cancelled_transactions: register_int_counter_with_registry!(
                "consensus_handler_cancelled_transactions",
                "Number of transactions cancelled by consensus handler",
                registry,
            ).unwrap(),
            consensus_committed_subdags: register_int_counter_vec_with_registry!(
                "consensus_committed_subdags",
                "Number of committed subdags, sliced by author",
                &["authority"],
                registry,
            ).unwrap(),
            consensus_committed_messages: register_int_gauge_vec_with_registry!(
                "consensus_committed_messages",
                "Total number of committed consensus messages, sliced by author",
                &["authority"],
                registry,
            ).unwrap(),
            consensus_committed_user_transactions: register_int_gauge_vec_with_registry!(
                "consensus_committed_user_transactions",
                "Number of committed user transactions, sliced by submitter",
                &["authority"],
                registry,
            ).unwrap(),
            limits_metrics: Arc::new(LimitsMetrics::new(registry)),
            bytecode_verifier_metrics: Arc::new(BytecodeVerifierMetrics::new(registry)),
            authenticator_state_update_failed: register_int_counter_with_registry!(
                "authenticator_state_update_failed",
                "Number of failed authenticator state updates",
                registry,
            )
            .unwrap(),
            zklogin_sig_count: register_int_counter_with_registry!(
                "zklogin_sig_count",
                "Count of zkLogin signatures",
                registry,
            )
            .unwrap(),
            multisig_sig_count: register_int_counter_with_registry!(
                "multisig_sig_count",
                "Count of zkLogin signatures",
                registry,
            )
            .unwrap(),
            consensus_calculated_throughput: register_int_gauge_with_registry!(
                "consensus_calculated_throughput",
                "The calculated throughput from consensus output. Result is calculated based on unique transactions.",
                registry,
            ).unwrap(),
            consensus_calculated_throughput_profile: register_int_gauge_with_registry!(
                "consensus_calculated_throughput_profile",
                "The current active calculated throughput profile",
                registry
            ).unwrap(),
            execution_queueing_latency: LatencyObserver::new(),
            txn_ready_rate_tracker: Arc::new(Mutex::new(RateTracker::new(Duration::from_secs(10)))),
            execution_rate_tracker: Arc::new(Mutex::new(RateTracker::new(Duration::from_secs(10)))),
        }
    }
}
