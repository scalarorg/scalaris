mod validator {
    include!(concat!(env!("OUT_DIR"), "/scalaris.validator.Validator.rs"));
}
mod authoriry_server;
mod authority_client;
pub mod safe_client;
pub use authoriry_server::{AuthorityServer, ValidatorService, ValidatorServiceMetrics};
pub use authority_client::{
    make_network_authority_clients_with_network_config, AuthorityAPI, NetworkAuthorityClient,
};
pub use validator::{
    validator_client::ValidatorClient,
    validator_server::{Validator, ValidatorServer},
};
