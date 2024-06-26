use crate::transaction::RawData;

/*
* Store verify state independently with transaction state
*/
pub struct AuthorityVerifyState {}

impl AuthorityVerifyState {
    pub fn new() -> Self {
        Self {}
    }
    pub async fn add_verify_message(&self, message: RawData) {}
}
