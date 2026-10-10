//! Keep this guard in the product control worker, not in a shared Router service.
use crate::{DynamicRuntime, ZResult};
use zenss_contracts::route_authorization::{
    CloseConnectionAuthorityOwner, ConnectionAuthorityOwner, OpenConnectionAuthorityOwner,
};
pub struct ConnectionAuthorityGuard {
    runtime: DynamicRuntime,
    issuer: String,
    owner: ConnectionAuthorityOwner,
    closed: bool,
}
impl ConnectionAuthorityGuard {
    pub fn open(runtime: DynamicRuntime, issuer: &str, control_key: &str) -> ZResult<Self> {
        let response =
            runtime.route_gate_credential(&serde_json::to_vec(&OpenConnectionAuthorityOwner {
                operation: "open_connection_authority_owner".into(),
                issuer: issuer.into(),
                control_key: control_key.into(),
            })?)?;
        let owner: ConnectionAuthorityOwner = serde_json::from_slice(&response)?;
        zenss_contracts::validate_segment(&owner.owner_id)?;
        zenss_contracts::validate_segment(&owner.host_boot)?;
        Ok(Self {
            runtime,
            issuer: issuer.into(),
            owner,
            closed: false,
        })
    }
    pub fn identity(&self) -> &ConnectionAuthorityOwner {
        &self.owner
    }
    pub fn close(&mut self) -> ZResult<()> {
        if self.closed {
            return Ok(());
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Ack {
            closed: bool,
        }
        let response = self.runtime.route_gate_credential(&serde_json::to_vec(
            &CloseConnectionAuthorityOwner {
                operation: "close_connection_authority_owner".into(),
                issuer: self.issuer.clone(),
                owner_id: self.owner.owner_id.clone(),
            },
        )?)?;
        let ack: Ack = serde_json::from_slice(&response)?;
        let _ = ack.closed; // False means this exact owner was already removed.
        self.closed = true;
        Ok(())
    }
}
impl Drop for ConnectionAuthorityGuard {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
