use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use crate::{
    consensus_types::{messages_grpc::MessageCerificateResponse, HandleVerifyMessageResponse},
    message_envelope::Envelope,
    network::{
        make_network_authority_clients_with_network_config,
        safe_client::{SafeClient, SafeClientMetrics, SafeClientMetricsBase},
        AuthorityAPI, NetworkAuthorityClient,
    },
    stake_aggregator::{InsertResult, MultiStakeAggregator, StakeAggregator},
    to_digest,
    transaction::{RawData, RawTransaction},
};
use futures::{future::BoxFuture, stream::FuturesUnordered, Future, StreamExt};
use mysten_metrics::{monitored_future, spawn_monitored_task, GaugeGuard};
use mysten_network::config::Config;
use prometheus::Registry;
use sui_core::{
    authority_aggregator::{
        group_errors, AggregatorProcessCertificateError, AuthAggMetrics, TimeoutConfig,
    },
    epoch::committee_store::CommitteeStore,
    execution_cache::ObjectCacheRead,
};
use sui_network::default_mysten_network_config;
use sui_types::{
    base_types::{AuthorityName, ConciseableName},
    committee::{Committee, CommitteeTrait, CommitteeWithNetworkMetadata, EpochId, StakeUnit},
    crypto::{AuthorityPublicKeyBytes, AuthorityStrongQuorumSignInfo, ToFromBytes},
    digests::TransactionDigest,
    error::{SuiError, SuiResult},
    fp_ensure,
    sui_system_state::SuiSystemStateTrait,
};
use tokio::time::{sleep, timeout};
use tracing::{debug, error, info, trace, Instrument};

pub struct Tracer {}
struct ProcessCertificateState {
    // Different authorities could return different effects.  We want at least one effect to come
    // from 2f+1 authorities, which meets quorum and can be considered the approved effect.
    // The map here allows us to count the stake for each unique effect.
    effects_map: MultiStakeAggregator<(EpochId, TransactionDigest), RawData, true>,
    non_retryable_stake: StakeUnit,
    non_retryable_errors: Vec<(SuiError, Vec<AuthorityName>, StakeUnit)>,
    retryable_errors: Vec<(SuiError, Vec<AuthorityName>, StakeUnit)>,
    // As long as none of the exit criteria are met we consider the state retryable
    // 1) >= 2f+1 signatures
    // 2) >= f+1 non-retryable errors
    retryable: bool,

    // collection of extended data returned from the validators.
    // Not all validators will be asked to return this data so we need to hold onto it when one
    // validator has provided it
    // events: Option<TransactionEvents>,
    // input_objects: Option<Vec<Object>>,
    // output_objects: Option<Vec<Object>>,
    auxiliary_data: Option<Vec<u8>>,
}
pub type CertifiedMessage = Envelope<RawTransaction, AuthorityStrongQuorumSignInfo>;

#[derive(Clone)]
pub struct AuthorityAggregator<A: Clone> {
    /// Our Sui committee.
    pub committee: Arc<Committee>,
    /// For more human readable metrics reporting.
    /// It's OK for this map to be empty or missing validators, it then defaults
    /// to use concise validator public keys.
    pub validator_display_names: Arc<HashMap<AuthorityName, String>>,
    /// How to talk to this committee.
    pub authority_clients: Arc<BTreeMap<AuthorityName, Arc<SafeClient<A>>>>,
    /// Metrics
    pub metrics: Arc<AuthAggMetrics>,
    /// Metric base for the purpose of creating new safe clients during reconfiguration.
    pub safe_client_metrics_base: SafeClientMetricsBase,
    pub timeouts: TimeoutConfig,
    /// Store here for clone during re-config.
    pub committee_store: Arc<CommitteeStore>,
}

impl<A: Clone> AuthorityAggregator<A> {
    pub fn new(
        committee: Committee,
        committee_store: Arc<CommitteeStore>,
        authority_clients: BTreeMap<AuthorityName, A>,
        registry: &Registry,
        validator_display_names: Arc<HashMap<AuthorityName, String>>,
    ) -> Self {
        Self::new_with_timeouts(
            committee,
            committee_store,
            authority_clients,
            registry,
            validator_display_names,
            Default::default(),
        )
    }

    pub fn new_with_timeouts(
        committee: Committee,
        committee_store: Arc<CommitteeStore>,
        authority_clients: BTreeMap<AuthorityName, A>,
        registry: &Registry,
        validator_display_names: Arc<HashMap<AuthorityName, String>>,
        timeouts: TimeoutConfig,
    ) -> Self {
        let safe_client_metrics_base = SafeClientMetricsBase::new(registry);
        Self {
            committee: Arc::new(committee),
            validator_display_names,
            authority_clients: create_safe_clients(
                authority_clients,
                &committee_store,
                &safe_client_metrics_base,
            ),
            metrics: Arc::new(AuthAggMetrics::new(registry)),
            safe_client_metrics_base,
            timeouts,
            committee_store,
        }
    }

    pub fn new_with_metrics(
        committee: Committee,
        committee_store: Arc<CommitteeStore>,
        authority_clients: BTreeMap<AuthorityName, A>,
        safe_client_metrics_base: SafeClientMetricsBase,
        auth_agg_metrics: Arc<AuthAggMetrics>,
        validator_display_names: Arc<HashMap<AuthorityName, String>>,
    ) -> Self {
        Self {
            committee: Arc::new(committee),
            authority_clients: create_safe_clients(
                authority_clients,
                &committee_store,
                &safe_client_metrics_base,
            ),
            metrics: auth_agg_metrics,
            safe_client_metrics_base,
            timeouts: Default::default(),
            committee_store,
            validator_display_names,
        }
    }
    /// This function recreates AuthorityAggregator with the given committee.
    /// It also updates committee store which impacts other of its references.
    /// When disallow_missing_intermediate_committees is true, it requires the
    /// new committee needs to be current epoch + 1.
    /// The function could be used along with `reconfig_from_genesis` to fill in
    /// all previous epoch's committee info.
    pub fn recreate_with_net_addresses(
        &self,
        committee: CommitteeWithNetworkMetadata,
        network_config: &Config,
        disallow_missing_intermediate_committees: bool,
    ) -> SuiResult<AuthorityAggregator<NetworkAuthorityClient>> {
        let network_clients =
            make_network_authority_clients_with_network_config(&committee, network_config)
                .map_err(|err| SuiError::GenericAuthorityError {
                    error: format!(
                        "Failed to make authority clients from committee {committee}, err: {:?}",
                        err
                    ),
                })?;

        let safe_clients = network_clients
            .into_iter()
            .map(|(name, api)| {
                (
                    name,
                    Arc::new(SafeClient::new(
                        api,
                        self.committee_store.clone(),
                        name,
                        SafeClientMetrics::new(&self.safe_client_metrics_base, name),
                    )),
                )
            })
            .collect::<BTreeMap<_, _>>();

        // TODO: It's likely safer to do the following operations atomically, in case this function
        // gets called from different threads. It cannot happen today, but worth the caution.
        let new_committee = committee.committee;
        if disallow_missing_intermediate_committees {
            fp_ensure!(
                self.committee.epoch + 1 == new_committee.epoch,
                SuiError::AdvanceEpochError {
                    error: format!(
                        "Trying to advance from epoch {} to epoch {}",
                        self.committee.epoch, new_committee.epoch
                    )
                }
            );
        }
        // This call may return error if this committee is already inserted,
        // which is fine. We should continue to construct the new aggregator.
        // This is because there may be multiple AuthorityAggregators
        // or its containers (e.g. Quorum Drivers)  share the same committee
        // store and all of them need to reconfigure.
        let _ = self.committee_store.insert_new_committee(&new_committee);
        Ok(AuthorityAggregator {
            committee: Arc::new(new_committee),
            authority_clients: Arc::new(safe_clients),
            metrics: self.metrics.clone(),
            timeouts: self.timeouts.clone(),
            safe_client_metrics_base: self.safe_client_metrics_base.clone(),
            committee_store: self.committee_store.clone(),
            validator_display_names: Arc::new(HashMap::new()),
        })
    }

    pub fn get_client(&self, name: &AuthorityName) -> Option<&Arc<SafeClient<A>>> {
        self.authority_clients.get(name)
    }

    pub fn clone_client_test_only(&self, name: &AuthorityName) -> Arc<SafeClient<A>>
    where
        A: Clone,
    {
        self.authority_clients[name].clone()
    }

    pub fn clone_committee_store(&self) -> Arc<CommitteeStore> {
        self.committee_store.clone()
    }

    pub fn clone_inner_committee_test_only(&self) -> Committee {
        (*self.committee).clone()
    }

    pub fn clone_inner_clients_test_only(&self) -> BTreeMap<AuthorityName, SafeClient<A>> {
        (*self.authority_clients)
            .clone()
            .into_iter()
            .map(|(k, v)| (k, (*v).clone()))
            .collect()
    }
}

impl AuthorityAggregator<NetworkAuthorityClient> {
    /// Create a new network authority aggregator by reading the committee and
    /// network address information from the system state object on-chain.
    /// This function needs metrics parameters because registry will panic
    /// if we attempt to register already-registered metrics again.
    pub fn new_from_local_system_state(
        store: &Arc<dyn ObjectCacheRead>,
        committee_store: &Arc<CommitteeStore>,
        safe_client_metrics_base: SafeClientMetricsBase,
        auth_agg_metrics: AuthAggMetrics,
    ) -> anyhow::Result<Self> {
        // TODO: We should get the committee from the epoch store instead to ensure consistency.
        // Instead of this function use AuthorityEpochStore::epoch_start_configuration() to access this object everywhere
        // besides when we are reading fields for the current epoch
        let sui_system_state = store.get_sui_system_state_object_unsafe()?;
        let committee = sui_system_state.get_current_epoch_committee();
        let validator_display_names = sui_system_state
            .into_sui_system_state_summary()
            .active_validators
            .into_iter()
            .filter_map(|s| {
                let authority_name =
                    AuthorityPublicKeyBytes::from_bytes(s.protocol_pubkey_bytes.as_slice());
                if authority_name.is_err() {
                    return None;
                }
                let human_readable_name = s.name;
                Some((authority_name.unwrap(), human_readable_name))
            })
            .collect();
        Self::new_from_committee(
            committee,
            committee_store,
            safe_client_metrics_base,
            Arc::new(auth_agg_metrics),
            Arc::new(validator_display_names),
        )
    }

    pub fn new_from_committee(
        committee: CommitteeWithNetworkMetadata,
        committee_store: &Arc<CommitteeStore>,
        safe_client_metrics_base: SafeClientMetricsBase,
        auth_agg_metrics: Arc<AuthAggMetrics>,
        validator_display_names: Arc<HashMap<AuthorityName, String>>,
    ) -> anyhow::Result<Self> {
        let net_config = default_mysten_network_config();
        let authority_clients =
            make_network_authority_clients_with_network_config(&committee, &net_config)?;
        Ok(Self::new_with_metrics(
            committee.committee,
            committee_store.clone(),
            authority_clients,
            safe_client_metrics_base,
            auth_agg_metrics,
            validator_display_names,
        ))
    }
}

impl<A> AuthorityAggregator<A>
where
    A: AuthorityAPI + Send + Sync + 'static + Clone,
{
    // Repeatedly calls the provided closure on a randomly selected validator until it succeeds.
    // Once all validators have been attempted, starts over at the beginning. Intended for cases
    // that must eventually succeed as long as the network is up (or comes back up) eventually.
    async fn quorum_once_inner<'a, S, FMap>(
        &'a self,
        // try these authorities first
        preferences: Option<&BTreeSet<AuthorityName>>,
        // only attempt from these authorities.
        restrict_to: Option<&BTreeSet<AuthorityName>>,
        // The async function used to apply to each authority. It takes an authority name,
        // and authority client parameter and returns a Result<V>.
        map_each_authority: FMap,
        timeout_each_authority: Duration,
        authority_errors: &mut HashMap<AuthorityName, SuiError>,
    ) -> Result<S, SuiError>
    where
        FMap: Fn(AuthorityName, Arc<SafeClient<A>>) -> AsyncResult<'a, S, SuiError>
            + Send
            + Clone
            + 'a,
        S: Send,
    {
        let start = tokio::time::Instant::now();
        let mut delay = Duration::from_secs(1);
        loop {
            let authorities_shuffled = self.committee.shuffle_by_stake(preferences, restrict_to);
            let mut authorities_shuffled = authorities_shuffled.iter();

            type RequestResult<S> = Result<Result<S, SuiError>, tokio::time::error::Elapsed>;

            enum Event<S> {
                StartNext,
                Request(AuthorityName, RequestResult<S>),
            }

            let mut futures = FuturesUnordered::<BoxFuture<'a, Event<S>>>::new();

            let start_req = |name: AuthorityName, client: Arc<SafeClient<A>>| {
                let map_each_authority = map_each_authority.clone();
                Box::pin(monitored_future!(async move {
                    trace!(name=?name.concise(), now = ?tokio::time::Instant::now() - start, "new request");
                    let map = map_each_authority(name, client);
                    Event::Request(name, timeout(timeout_each_authority, map).await)
                }))
            };

            let schedule_next = || {
                let delay = self.timeouts.serial_authority_request_interval;
                Box::pin(monitored_future!(async move {
                    sleep(delay).await;
                    Event::StartNext
                }))
            };

            // This process is intended to minimize latency in the face of unreliable authorities,
            // without creating undue load on authorities.
            //
            // The fastest possible process from the
            // client's point of view would simply be to issue a concurrent request to every
            // authority and then take the winner - this would create unnecessary load on
            // authorities.
            //
            // The most efficient process from the network's point of view is to do one request at
            // a time, however if the first validator that the client contacts is unavailable or
            // slow, the client must wait for the serial_authority_request_interval period to elapse
            // before starting its next request.
            //
            // So, this process is designed as a compromise between these two extremes.
            // - We start one request, and schedule another request to begin after
            //   serial_authority_request_interval.
            // - Whenever a request finishes, if it succeeded, we return. if it failed, we start a
            //   new request.
            // - If serial_authority_request_interval elapses, we begin a new request even if the
            //   previous one is not finished, and schedule another future request.

            let name = authorities_shuffled.next().ok_or_else(|| {
                error!(
                    ?preferences,
                    ?restrict_to,
                    "Available authorities list is empty."
                );
                SuiError::from("Available authorities list is empty")
            })?;
            futures.push(start_req(*name, self.authority_clients[name].clone()));
            futures.push(schedule_next());

            while let Some(res) = futures.next().await {
                match res {
                    Event::StartNext => {
                        trace!(now = ?tokio::time::Instant::now() - start, "eagerly beginning next request");
                        futures.push(schedule_next());
                    }
                    Event::Request(name, res) => {
                        match res {
                            // timeout
                            Err(_) => {
                                debug!(name=?name.concise(), "authority request timed out");
                                authority_errors.insert(name, SuiError::TimeoutError);
                            }
                            // request completed
                            Ok(inner_res) => {
                                trace!(name=?name.concise(), now = ?tokio::time::Instant::now() - start,
                                       "request completed successfully");
                                match inner_res {
                                    Err(e) => authority_errors.insert(name, e),
                                    Ok(res) => return Ok(res),
                                };
                            }
                        };
                    }
                }

                if let Some(next_authority) = authorities_shuffled.next() {
                    futures.push(start_req(
                        *next_authority,
                        self.authority_clients[next_authority].clone(),
                    ));
                } else {
                    break;
                }
            }

            info!(
                ?authority_errors,
                "quorum_once_with_timeout failed on all authorities, retrying in {:?}", delay
            );
            sleep(delay).await;
            delay = std::cmp::min(delay * 2, Duration::from_secs(5 * 60));
        }
    }

    /// Like quorum_map_then_reduce_with_timeout, but for things that need only a single
    /// successful response, such as fetching a Transaction from some authority.
    /// This is intended for cases in which byzantine authorities can time out or slow-loris, but
    /// can't give a false answer, because e.g. the digest of the response is known, or a
    /// quorum-signed object such as a checkpoint has been requested.
    pub(crate) async fn quorum_once_with_timeout<'a, S, FMap>(
        &'a self,
        // try these authorities first
        preferences: Option<&BTreeSet<AuthorityName>>,
        // only attempt from these authorities.
        restrict_to: Option<&BTreeSet<AuthorityName>>,
        // The async function used to apply to each authority. It takes an authority name,
        // and authority client parameter and returns a Result<V>.
        map_each_authority: FMap,
        timeout_each_authority: Duration,
        // When to give up on the attempt entirely.
        timeout_total: Option<Duration>,
        // The behavior that authorities expect to perform, used for logging and error
        description: String,
    ) -> Result<S, SuiError>
    where
        FMap: Fn(AuthorityName, Arc<SafeClient<A>>) -> AsyncResult<'a, S, SuiError>
            + Send
            + Clone
            + 'a,
        S: Send,
    {
        let mut authority_errors = HashMap::new();

        let fut = self.quorum_once_inner(
            preferences,
            restrict_to,
            map_each_authority,
            timeout_each_authority,
            &mut authority_errors,
        );

        if let Some(t) = timeout_total {
            timeout(t, fut).await.map_err(|_timeout_error| {
                if authority_errors.is_empty() {
                    SuiError::TimeoutError
                } else {
                    SuiError::TooManyIncorrectAuthorities {
                        errors: authority_errors
                            .iter()
                            .map(|(a, b)| (*a, b.clone()))
                            .collect(),
                        action: description,
                    }
                }
            })?
        } else {
            fut.await
        }
    }

    pub async fn process_certificate(
        &self,
        request: RawTransaction,
        client_addr: Option<SocketAddr>,
    ) -> Result<MessageCerificateResponse, AggregatorProcessCertificateError> {
        let state = ProcessCertificateState {
            effects_map: MultiStakeAggregator::new(self.committee.clone()),
            non_retryable_stake: 0,
            non_retryable_errors: vec![],
            retryable_errors: vec![],
            retryable: true,
            auxiliary_data: None,
        };

        // create a set of validators that we should sample to request input/output objects from
        // let validators_to_sample = HashSet::new();

        let tx_digest = *request.digest();
        let timeout_after_quorum = self.timeouts.post_quorum_timeout;

        let request_ref = request;
        let threshold = self.committee.quorum_threshold();
        let validity = self.committee.validity_threshold();

        debug!(
            ?tx_digest,
            quorum_threshold = threshold,
            validity_threshold = validity,
            ?timeout_after_quorum,
            "Broadcasting certificate to authorities"
        );
        let committee: Arc<Committee> = self.committee.clone();
        let authority_clients = self.authority_clients.clone();
        let metrics = self.metrics.clone();
        let metrics_clone = metrics.clone();
        let validator_display_names = self.validator_display_names.clone();
        let (result, mut remaining_tasks) = quorum_map_then_reduce_with_timeout(
            committee.clone(),
            authority_clients.clone(),
            state,
            move |name, client| {
                Box::pin(async move {
                    let _guard = GaugeGuard::acquire(&metrics_clone.inflight_certificate_requests);
                    client
                            .handle_verify_message(request_ref, client_addr)
                            .instrument(
                                tracing::trace_span!("handle_certificate", authority =? name.concise()),
                            )
                            .await
                })
            },
            move |mut state, name, weight, response| {
                let committee_clone = committee.clone();
                let metrics = metrics.clone();
                let display_name = validator_display_names.get(&name).unwrap_or(&name.concise().to_string()).clone();
                Box::pin(async move {
                    // We aggregate the effects response, until we have more than 2f
                    // and return.
                    match AuthorityAggregator::<A>::handle_process_certificate_response(
                        committee_clone,
                        &tx_digest, &mut state, response, name)
                    {
                        Ok(Some(effects)) => ReduceOutput::Success(effects),
                        Ok(None) => {
                            // When the result is none, it is possible that the
                            // non_retryable_stake had been incremented due to
                            // failed individual signature verification.
                            if state.non_retryable_stake >= validity {
                                state.retryable = false;
                                ReduceOutput::Failed(state)
                            } else {
                                ReduceOutput::Continue(state)
                            }
                        },
                        Err(err) => {
                            let concise_name = name.concise();
                            debug!(?tx_digest, name=?concise_name, "Error processing certificate from validator: {:?}", err);
                            metrics
                                .process_cert_errors
                                .with_label_values(&[&display_name, err.as_ref()])
                                .inc();
                            let (retryable, categorized) = err.is_retryable();
                            if !categorized {
                                // TODO: Should minimize possible uncategorized errors here
                                // use ERROR for now to make them easier to spot.
                                error!(?tx_digest, "[WATCHOUT] uncategorized tx error: {err}");
                            }
                            if !retryable {
                                state.non_retryable_stake += weight;
                                state.non_retryable_errors.push((err, vec![name], weight));
                            } else {
                                state.retryable_errors.push((err, vec![name], weight));
                            }
                            if state.non_retryable_stake >= validity {
                                state.retryable = false;
                                ReduceOutput::Failed(state)
                            } else {
                                ReduceOutput::Continue(state)
                            }
                        }
                    }
                })
            },
            // A long timeout before we hear back from a quorum
            self.timeouts.pre_quorum_timeout,
        )
        .await
        .map_err(|state| {
            debug!(
                ?tx_digest,
                num_unique_effects = state.effects_map.unique_key_count(),
                non_retryable_stake = state.non_retryable_stake,
                "Received effects responses from validators"
            );

            // record errors and tx retryable state
            for (sui_err, _, _) in state.retryable_errors.iter().chain(state.non_retryable_errors.iter()) {
                self
                    .metrics
                    .total_aggregated_err
                    .with_label_values(&[
                        sui_err.as_ref(),
                        if state.retryable {
                            "recoverable"
                        } else {
                            "non-recoverable"
                        },
                    ])
                    .inc();
            }
            if state.retryable {
                AggregatorProcessCertificateError::RetryableExecuteCertificate {
                    retryable_errors: group_errors(state.retryable_errors),
                }
            } else {
                AggregatorProcessCertificateError::FatalExecuteCertificate {
                    non_retryable_errors: group_errors(state.non_retryable_errors),
                }
            }
        })?;

        let metrics = self.metrics.clone();
        metrics
            .remaining_tasks_when_reaching_cert_quorum
            .report(remaining_tasks.len() as u64);
        if !remaining_tasks.is_empty() {
            // Use best efforts to send the cert to remaining validators.
            spawn_monitored_task!(async move {
                let mut timeout = Box::pin(sleep(timeout_after_quorum));
                loop {
                    tokio::select! {
                        _ = &mut timeout => {
                            debug!(?tx_digest, "Timed out in post quorum cert broadcasting: {:?}. Remaining tasks: {:?}", timeout_after_quorum, remaining_tasks.len());
                            metrics.cert_broadcasting_post_quorum_timeout.inc();
                            metrics.remaining_tasks_when_cert_broadcasting_post_quorum_timeout.report(remaining_tasks.len() as u64);
                            break;
                        }
                        res = remaining_tasks.next() => {
                            if res.is_none() {
                                break;
                            }
                        }
                    }
                }
            });
        }
        Ok(result)
    }

    fn handle_process_certificate_response(
        committee: Arc<Committee>,
        tx_digest: &TransactionDigest,
        state: &mut ProcessCertificateState,
        response: SuiResult<HandleVerifyMessageResponse>,
        name: AuthorityName,
    ) -> SuiResult<Option<MessageCerificateResponse>> {
        match response {
            Ok(HandleVerifyMessageResponse {
                epoch,
                data,
                signature,
                auxiliary_data,
            }) => {
                debug!(
                    ?tx_digest,
                    name = ?name.concise(),
                    "Validator handled certificate successfully",
                );

                // if events.is_some() && state.events.is_none() {
                //     state.events = events;
                // }

                // if input_objects.is_some() && state.input_objects.is_none() {
                //     state.input_objects = input_objects;
                // }

                // if output_objects.is_some() && state.output_objects.is_none() {
                //     state.output_objects = output_objects;
                // }

                if auxiliary_data.is_some() && state.auxiliary_data.is_none() {
                    state.auxiliary_data = auxiliary_data;
                }

                let digest = TransactionDigest::new(to_digest(data.as_slice()));
                // Note: here we aggregate votes by the hash of the effects structure
                match state.effects_map.insert(
                    (epoch, digest),
                    Envelope::new_from_data_and_sig(data.clone(), signature),
                ) {
                    InsertResult::NotEnoughVotes {
                        bad_votes,
                        bad_authorities,
                    } => {
                        state.non_retryable_stake += bad_votes;
                        if bad_votes > 0 {
                            state.non_retryable_errors.push((
                                SuiError::InvalidSignature {
                                    error: "Individual signature verification failed".to_string(),
                                },
                                bad_authorities,
                                bad_votes,
                            ));
                        }
                        Ok(None)
                    }
                    InsertResult::Failed { error } => Err(error),
                    InsertResult::QuorumReached(cert_sig) => {
                        //Verify signature of the quorum
                        // let ct = CertifiedTransactionEffects::new_from_data_and_sig(
                        //     signed_effects.into_data(),
                        //     cert_sig,
                        // );
                        //Then send certificate message to the client
                        debug!(?tx_digest, "Got quorum for validators handle_certificate.");
                        Ok(Some(MessageCerificateResponse {
                            data,
                            certificate: cert_sig,
                        }))
                    }
                }
            }
            Err(err) => Err(err),
        }
    }
}
fn create_safe_clients<A: Clone>(
    authority_clients: BTreeMap<AuthorityName, A>,
    committee_store: &Arc<CommitteeStore>,
    safe_client_metrics_base: &SafeClientMetricsBase,
) -> Arc<BTreeMap<AuthorityName, Arc<SafeClient<A>>>> {
    Arc::new(
        authority_clients
            .into_iter()
            .map(|(name, api)| {
                (
                    name,
                    Arc::new(SafeClient::new(
                        api,
                        committee_store.clone(),
                        name,
                        SafeClientMetrics::new(safe_client_metrics_base, name),
                    )),
                )
            })
            .collect(),
    )
}

pub type AsyncResult<'a, T, E> = BoxFuture<'a, Result<T, E>>;

pub enum ReduceOutput<R, S> {
    Continue(S),
    ContinueWithTimeout(S, Duration),
    Failed(S),
    Success(R),
}

pub async fn quorum_map_then_reduce_with_timeout_and_prefs<
    'a,
    C,
    K,
    Client: 'a,
    S,
    V,
    R,
    E,
    FMap,
    FReduce,
>(
    committee: Arc<C>,
    authority_clients: Arc<BTreeMap<K, Arc<Client>>>,
    authority_preferences: Option<&BTreeSet<K>>,
    initial_state: S,
    map_each_authority: FMap,
    reduce_result: FReduce,
    initial_timeout: Duration,
) -> Result<
    (
        R,
        FuturesUnordered<impl Future<Output = (K, Result<V, E>)> + 'a>,
    ),
    S,
>
where
    K: Ord + ConciseableName<'a> + Copy + 'a,
    C: CommitteeTrait<K>,
    FMap: FnOnce(K, Arc<Client>) -> AsyncResult<'a, V, E> + Clone + 'a,
    FReduce: Fn(S, K, StakeUnit, Result<V, E>) -> BoxFuture<'a, ReduceOutput<R, S>>,
{
    let authorities_shuffled = committee.shuffle_by_stake(authority_preferences, None);

    // First, execute in parallel for each authority FMap.
    let mut responses: futures::stream::FuturesUnordered<_> = authorities_shuffled
        .into_iter()
        .map(|name| {
            let client = authority_clients[&name].clone();
            let execute = map_each_authority.clone();
            let concise_name = name.concise_owned();
            monitored_future!(async move {
                (
                    name,
                    execute(name, client)
                        .instrument(
                            tracing::trace_span!("quorum_map_auth", authority =? concise_name),
                        )
                        .await,
                )
            })
        })
        .collect();

    let mut current_timeout = initial_timeout;
    let mut accumulated_state = initial_state;
    // Then, as results become available fold them into the state using FReduce.
    while let Ok(Some((authority_name, result))) = timeout(current_timeout, responses.next()).await
    {
        let authority_weight = committee.weight(&authority_name);
        accumulated_state =
            match reduce_result(accumulated_state, authority_name, authority_weight, result).await {
                // In the first two cases we are told to continue the iteration.
                ReduceOutput::Continue(state) => state,
                ReduceOutput::ContinueWithTimeout(state, duration) => {
                    // Adjust the waiting timeout.
                    current_timeout = duration;
                    state
                }
                ReduceOutput::Failed(state) => {
                    return Err(state);
                }
                ReduceOutput::Success(result) => {
                    // The reducer tells us that we have the result needed. Just return it.
                    return Ok((result, responses));
                }
            }
    }
    // If we have exhausted all authorities and still have not returned a result, return
    // error with the accumulated state.
    Err(accumulated_state)
}

/// This function takes an initial state, than executes an asynchronous function (FMap) for each
/// authority, and folds the results as they become available into the state using an async function (FReduce).
///
/// FMap can do io, and returns a result V. An error there may not be fatal, and could be consumed by the
/// MReduce function to overall recover from it. This is necessary to ensure byzantine authorities cannot
/// interrupt the logic of this function.
///
/// FReduce returns a result to a ReduceOutput. If the result is Err the function
/// shortcuts and the Err is returned. An Ok ReduceOutput result can be used to shortcut and return
/// the resulting state (ReduceOutput::End), continue the folding as new states arrive (ReduceOutput::Continue),
/// or continue with a timeout maximum waiting time (ReduceOutput::ContinueWithTimeout).
///
/// This function provides a flexible way to communicate with a quorum of authorities, processing and
/// processing their results into a safe overall result, and also safely allowing operations to continue
/// past the quorum to ensure all authorities are up to date (up to a timeout).
pub async fn quorum_map_then_reduce_with_timeout<
    'a,
    C,
    K,
    Client: 'a,
    S: 'a,
    V: 'a,
    R: 'a,
    E,
    FMap,
    FReduce,
>(
    committee: Arc<C>,
    authority_clients: Arc<BTreeMap<K, Arc<Client>>>,
    // The initial state that will be used to fold in values from authorities.
    initial_state: S,
    // The async function used to apply to each authority. It takes an authority name,
    // and authority client parameter and returns a Result<V>.
    map_each_authority: FMap,
    // The async function that takes an accumulated state, and a new result for V from an
    // authority and returns a result to a ReduceOutput state.
    reduce_result: FReduce,
    // The initial timeout applied to all
    initial_timeout: Duration,
) -> Result<
    (
        R,
        FuturesUnordered<impl Future<Output = (K, Result<V, E>)> + 'a>,
    ),
    S,
>
where
    K: Ord + ConciseableName<'a> + Copy + 'a,
    C: CommitteeTrait<K>,
    FMap: FnOnce(K, Arc<Client>) -> AsyncResult<'a, V, E> + Clone + 'a,
    FReduce: Fn(S, K, StakeUnit, Result<V, E>) -> BoxFuture<'a, ReduceOutput<R, S>> + 'a,
{
    quorum_map_then_reduce_with_timeout_and_prefs(
        committee,
        authority_clients,
        None,
        initial_state,
        map_each_authority,
        reduce_result,
        initial_timeout,
    )
    .await
}
