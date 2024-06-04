use anyhow::Result;
use narwhal_config::Parameters as ConsensusParameters;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use sui_config::genesis;
use sui_config::node::{
    AuthorityKeyPairWithPath, AuthorityOverloadConfig, Genesis, KeyPairWithPath, RunWithRange,
};
use sui_types::crypto::{
    get_key_pair_from_rng, AccountKeyPair, AuthorityKeyPair, AuthorityPublicKeyBytes,
    NetworkKeyPair, SuiKeyPair,
};
use sui_types::multiaddr::Multiaddr;
use sui_types::traffic_control::{PolicyConfig, RemoteFirewallConfig};
use tracing::info;

// Default max number of concurrent requests served
pub const DEFAULT_GRPC_CONCURRENCY_LIMIT: usize = 20000000000;

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct NodeConfig {
    #[serde(default = "default_authority_key_pair")]
    pub protocol_key_pair: AuthorityKeyPairWithPath,
    #[serde(default = "default_key_pair")]
    pub worker_key_pair: KeyPairWithPath,
    #[serde(default = "default_key_pair")]
    pub account_key_pair: KeyPairWithPath,
    #[serde(default = "default_key_pair")]
    pub network_key_pair: KeyPairWithPath,
    #[serde(default = "default_metrics_address")]
    pub metrics_address: SocketAddr,
    #[serde(default = "default_grpc_address")]
    pub network_address: Multiaddr,
    #[serde(default)]
    pub indirect_objects_threshold: usize,
    #[serde(default)]
    pub grpc_load_shed: Option<bool>,

    #[serde(default = "default_concurrency_limit")]
    pub grpc_concurrency_limit: Option<usize>,
    #[serde(default = "default_authority_overload_config")]
    pub authority_overload_config: AuthorityOverloadConfig,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_with_range: Option<RunWithRange>,
    // For killswitch use None
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_config: Option<PolicyConfig>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub firewall_config: Option<RemoteFirewallConfig>,
    pub genesis: Genesis,
    pub address: Multiaddr,
    pub db_path: PathBuf,
    /// Maximum number of pending transactions to submit to consensus, including those
    /// in submission wait.
    /// Assuming 10_000 txn tps * 10 sec consensus latency = 100_000 inflight consensus txns,
    /// Default to 100_000.
    pub max_pending_transactions: Option<usize>,
    /// When defined caps the calculated submission position to the max_submit_position. Even if the
    /// is elected to submit from a higher position than this, it will "reset" to the max_submit_position.
    pub max_submit_position: Option<usize>,
    /// The submit delay step to consensus defined in milliseconds. When provided it will
    /// override the current back off logic otherwise the default backoff logic will be applied based
    /// on consensus latency estimates.
    pub submit_delay_step_override_millis: Option<u64>,
    pub narwhal_config: ConsensusParameters,
}

impl NodeConfig {
    pub fn address(&self) -> &Multiaddr {
        &self.address
    }
    pub fn network_address(&self) -> &Multiaddr {
        &self.network_address
    }
    pub fn db_path(&self) -> PathBuf {
        self.db_path.join("live")
    }
    pub fn narwhal_config(&self) -> &ConsensusParameters {
        &self.narwhal_config
    }
    pub fn protocol_key_pair(&self) -> &AuthorityKeyPair {
        self.protocol_key_pair.authority_keypair()
    }
    pub fn worker_key_pair(&self) -> &NetworkKeyPair {
        match self.worker_key_pair.keypair() {
            SuiKeyPair::Ed25519(kp) => kp,
            other => panic!(
                "Invalid keypair type: {:?}, only Ed25519 is allowed for worker key",
                other
            ),
        }
    }
    pub fn network_key_pair(&self) -> &NetworkKeyPair {
        match self.network_key_pair.keypair() {
            SuiKeyPair::Ed25519(kp) => kp,
            other => panic!(
                "Invalid keypair type: {:?}, only Ed25519 is allowed for network key",
                other
            ),
        }
    }
    pub fn genesis(&self) -> Result<&genesis::Genesis> {
        self.genesis.genesis()
    }
    pub fn protocol_public_key(&self) -> AuthorityPublicKeyBytes {
        self.protocol_key_pair().public().into()
    }
    pub fn max_pending_transactions(&self) -> usize {
        self.max_pending_transactions.unwrap_or(100_000)
    }
    pub fn submit_delay_step_override(&self) -> Option<Duration> {
        self.submit_delay_step_override_millis
            .map(Duration::from_millis)
    }
}

fn default_grpc_address() -> Multiaddr {
    "/ip4/0.0.0.0/tcp/8080".parse().unwrap()
}
fn default_authority_key_pair() -> AuthorityKeyPairWithPath {
    AuthorityKeyPairWithPath::new(get_key_pair_from_rng::<AuthorityKeyPair, _>(&mut OsRng).1)
}

pub fn default_concurrency_limit() -> Option<usize> {
    Some(DEFAULT_GRPC_CONCURRENCY_LIMIT)
}

fn default_authority_overload_config() -> AuthorityOverloadConfig {
    AuthorityOverloadConfig::default()
}

fn default_key_pair() -> KeyPairWithPath {
    KeyPairWithPath::new(
        get_key_pair_from_rng::<AccountKeyPair, _>(&mut OsRng)
            .1
            .into(),
    )
}

fn default_metrics_address() -> SocketAddr {
    use std::net::{IpAddr, Ipv4Addr};
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 9184)
}
