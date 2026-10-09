//! Public transport boundary. No native plugin or private host types cross it.
use crate::ServiceIdentity;
use anyhow::Result;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientMode {
    Outbound,
    Hosted,
}

/// Implementations own their resource policy. Host adapters must never close
/// a borrowed Session or use shared network identity as product authorization.
#[async_trait::async_trait]
pub trait ClientTransport: Send + Sync {
    type Announcement: Send;
    fn mode(&self) -> ClientMode;
    fn timeout(&self) -> Duration;
    fn identity(&self) -> Option<&ServiceIdentity> {
        None
    }
    fn ensure_open(&self) -> Result<()>;
    async fn query(&self, key: &str, payload: Vec<u8>) -> Result<Vec<u8>>;
    async fn announce(&self, identity: &ServiceIdentity) -> Result<Self::Announcement>;
    async fn close(self) -> Result<()>;
}

/// Marker for explicit host adapters. Implemented by the separately selected
/// native integration crate, never discovered implicitly from process context.
pub trait HostedTransport: ClientTransport {}

pub struct OutboundTransport {
    pub(crate) session: zenoh::Session,
    pub(crate) timeout: Duration,
}
#[async_trait::async_trait]
impl ClientTransport for OutboundTransport {
    type Announcement = zenoh::liveliness::LivelinessToken;
    fn mode(&self) -> ClientMode {
        ClientMode::Outbound
    }
    fn timeout(&self) -> Duration {
        self.timeout
    }
    fn ensure_open(&self) -> Result<()> {
        anyhow::ensure!(!self.session.is_closed(), "client session is closed");
        Ok(())
    }
    async fn query(&self, key: &str, payload: Vec<u8>) -> Result<Vec<u8>> {
        let replies = self
            .session
            .get(key.to_owned())
            .payload(payload)
            .timeout(self.timeout)
            .await
            .map_err(|e| anyhow::anyhow!("query failed: {e}"))?;
        let reply = replies
            .recv_async()
            .await
            .map_err(|e| anyhow::anyhow!("query closed without a reply; outcome unknown: {e}"))?;
        let sample = reply.result().map_err(|e| {
            anyhow::anyhow!(
                "remote error: {}",
                e.payload().try_to_string().unwrap_or_default()
            )
        })?;
        anyhow::ensure!(
            sample.payload().len() <= crate::MAX_MESSAGE_BYTES,
            "reply exceeds platform limit"
        );
        Ok(sample.payload().to_bytes().into_owned())
    }
    async fn announce(&self, identity: &ServiceIdentity) -> Result<Self::Announcement> {
        self.session
            .liveliness()
            .declare_token(identity.liveliness_key()?)
            .await
            .map_err(|e| anyhow::anyhow!("announce failed: {e}"))
    }
    async fn close(self) -> Result<()> {
        self.session
            .close()
            .await
            .map_err(|e| anyhow::anyhow!("session close failed: {e}"))
    }
}
