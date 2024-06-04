use std::sync::Arc;

use crate::authority::AuthorityPerEpochStore;
pub mod randomness;
pub mod epoch_metrics {
    pub use sui_core::epoch::epoch_metrics::*;
}
pub mod reconfiguration {
    pub use sui_core::epoch::reconfiguration::{ReconfigCertStatus, ReconfigState};
}
pub mod committee_store {
    pub use sui_core::epoch::committee_store::*;
}
pub trait ReconfigurationInitiator {
    fn close_epoch(&self, epoch_store: &Arc<AuthorityPerEpochStore>);
}
