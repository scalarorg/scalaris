use serde::{Deserialize, Serialize};
use sui_types::{
    committee::EpochId,
    crypto::{AuthoritySignInfo, AuthorityStrongQuorumSignInfo},
};

use crate::transaction::RawData;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandleVerifyMessageResponse {
    pub epoch: EpochId,
    pub data: RawData,
    pub signature: AuthoritySignInfo,
    pub auxiliary_data: Option<Vec<u8>>,
}

pub struct MessageCerificateResponse {
    pub data: RawData,
    pub certificate: AuthorityStrongQuorumSignInfo,
}
