use crate::{consensus_types::HandleVerifyMessageResponse, transaction::RawTransaction};
use anyhow::anyhow;
use async_trait::async_trait;
use mysten_network::{config::Config, Multiaddr};
use std::{collections::BTreeMap, net::SocketAddr, time::Duration};
use sui_types::{
    base_types::AuthorityName, committee::CommitteeWithNetworkMetadata, error::SuiError,
};
use tonic::{metadata::KeyAndValueRef, transport::Channel, IntoRequest};

use super::ValidatorClient;

#[async_trait]
pub trait AuthorityAPI {
    /// Initiate a new transaction to a Sui or Primary account.
    async fn handle_verify_message(
        &self,
        transaction: RawTransaction,
        client_addr: Option<SocketAddr>,
    ) -> Result<HandleVerifyMessageResponse, SuiError>;
}

#[derive(Clone)]
pub struct NetworkAuthorityClient {
    client: ValidatorClient<Channel>,
}

impl NetworkAuthorityClient {
    pub async fn connect(address: &Multiaddr) -> anyhow::Result<Self> {
        let channel = mysten_network::client::connect(address)
            .await
            .map_err(|err| anyhow!(err.to_string()))?;
        Ok(Self::new(channel))
    }

    pub fn connect_lazy(address: &Multiaddr) -> anyhow::Result<Self> {
        let channel = mysten_network::client::connect_lazy(address)
            .map_err(|err| anyhow!(err.to_string()))?;
        Ok(Self::new(channel))
    }

    pub fn new(channel: Channel) -> Self {
        Self {
            client: ValidatorClient::new(channel),
        }
    }

    fn client(&self) -> ValidatorClient<Channel> {
        self.client.clone()
    }
}

#[async_trait]
impl AuthorityAPI for NetworkAuthorityClient {
    /// Initiate a new transfer to a Sui or Primary account.
    async fn handle_verify_message(
        &self,
        transaction: RawTransaction,
        client_addr: Option<SocketAddr>,
    ) -> Result<HandleVerifyMessageResponse, SuiError> {
        let mut request = transaction.into_request();
        insert_metadata(&mut request, client_addr);

        self.client()
            .verify_message(request)
            .await
            .map(tonic::Response::into_inner)
            .map_err(Into::into)
    }
}

pub fn make_network_authority_clients_with_network_config(
    committee: &CommitteeWithNetworkMetadata,
    network_config: &Config,
) -> anyhow::Result<BTreeMap<AuthorityName, NetworkAuthorityClient>> {
    let mut authority_clients = BTreeMap::new();
    for (name, _stakes) in &committee.committee.voting_rights {
        let address = &committee
            .network_metadata
            .get(name)
            .ok_or_else(|| {
                SuiError::from("Missing network metadata in CommitteeWithNetworkMetadata")
            })?
            .network_address;
        let channel = network_config
            .connect_lazy(address)
            .map_err(|err| anyhow!(err.to_string()))?;
        let client = NetworkAuthorityClient::new(channel);
        authority_clients.insert(*name, client);
    }
    Ok(authority_clients)
}

pub fn make_authority_clients_with_timeout_config(
    committee: &CommitteeWithNetworkMetadata,
    connect_timeout: Duration,
    request_timeout: Duration,
) -> anyhow::Result<BTreeMap<AuthorityName, NetworkAuthorityClient>> {
    let mut network_config = mysten_network::config::Config::new();
    network_config.connect_timeout = Some(connect_timeout);
    network_config.request_timeout = Some(request_timeout);
    make_network_authority_clients_with_network_config(committee, &network_config)
}

fn insert_metadata<T>(request: &mut tonic::Request<T>, client_addr: Option<SocketAddr>) {
    if let Some(client_addr) = client_addr {
        let mut metadata = tonic::metadata::MetadataMap::new();
        metadata.insert("x-forwarded-for", client_addr.to_string().parse().unwrap());
        metadata
            .iter()
            .for_each(|key_and_value| match key_and_value {
                KeyAndValueRef::Ascii(key, value) => {
                    request.metadata_mut().insert(key, value.clone());
                }
                KeyAndValueRef::Binary(key, value) => {
                    request.metadata_mut().insert_bin(key, value.clone());
                }
            });
    }
}
