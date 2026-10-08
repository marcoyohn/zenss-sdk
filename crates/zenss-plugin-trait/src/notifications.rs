//! Advisory, platform-only notifications on the managed Router session.
//! Delivery is intentionally lossy: products reconcile authoritative state.
use crate::{zerror, DynamicRuntime, PluginContext, ZResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{broadcast, mpsc},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
use zenoh::{
    query::{ConsolidationMode, QueryTarget},
    sample::{Locality, SampleKind},
    Session,
};

pub const MAX_PAYLOAD: usize = 8192;
const MAX_WIRE: usize = 40 * 1024;
const CAPACITY: usize = 256;
const MAX_PEERS: usize = 128;
const CONCURRENCY: usize = 8;
const TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Notification {
    pub topic: String,
    pub payload: Vec<u8>,
}
impl Notification {
    fn valid(&self) -> bool {
        !self.topic.is_empty()
            && self.topic.len() <= 64
            && self
                .topic
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            && self.payload.len() <= MAX_PAYLOAD
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    notification: Notification,
    deadline_ms: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    source_router: String,
    issuer: String,
    expires_unix_ms: u64,
}
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
fn exact(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 1024
        && key.split('/').all(|s| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
}
fn peer_endpoint(token: &str, scope: &str) -> Option<String> {
    let key = token.strip_suffix("/presence")?;
    let rest = key.strip_prefix(&format!("{scope}/"))?;
    let parts: Vec<_> = rest.split('/').collect();
    (exact(key) && parts.len() == 3 && parts[2] == "notifications").then(|| key.to_owned())
}
fn validate(envelope: &Envelope, receipt: &Receipt, issuer: &str, now: u64) -> bool {
    envelope.notification.valid()
        && receipt.issuer == issuer
        && !receipt.source_router.is_empty()
        && envelope.deadline_ms > now
        && envelope.deadline_ms <= now.saturating_add(2000)
        && envelope.deadline_ms <= receipt.expires_unix_ms
}

/// One bounded notification endpoint per product node/boot. Drop cancels tasks.
/// `scope` must be a platform-only scope covered by the Host issuer policy;
/// SDK grants must never include this scope. Peer presence is only a routing hint.
#[derive(Debug)]
pub struct PlatformNotifications {
    outgoing: mpsc::Sender<Notification>,
    incoming: broadcast::Sender<Notification>,
    stop: CancellationToken,
}
impl PlatformNotifications {
    pub async fn bind(
        session: Session,
        context: PluginContext,
        issuer: String,
        scope: String,
        node: String,
        boot: String,
    ) -> ZResult<Arc<Self>> {
        if !exact(&scope)
            || !exact(&node)
            || node.contains('/')
            || !exact(&boot)
            || boot.contains('/')
            || issuer.is_empty()
        {
            return Err(zerror!("invalid notification scope/identity").into());
        }
        let endpoint = format!("{scope}/{node}/{boot}/notifications");
        let peers = Arc::new(Mutex::new(BTreeSet::<String>::new()));
        let (queries, mut query_rx) = mpsc::channel(CAPACITY);
        let queryable = session
            .declare_queryable(endpoint.clone())
            .allowed_origin(Locality::Remote)
            .callback(move |query: zenoh::query::Query| {
                if query.payload().is_some_and(|p| p.len() <= MAX_WIRE) {
                    if queries.try_send(query).is_err() {
                        tracing::debug!("notification receive queue full");
                    }
                }
            })
            .await?;
        let view = peers.clone();
        let own = endpoint.clone();
        let prefix = scope.clone();
        let subscription = session
            .liveliness()
            .declare_subscriber(format!("{scope}/*/*/notifications/presence"))
            .history(true)
            .callback(move |sample| {
                let Some(peer) = peer_endpoint(sample.key_expr().as_str(), &prefix) else {
                    return;
                };
                if peer == own {
                    return;
                }
                let mut peers = view.lock().unwrap_or_else(|e| e.into_inner());
                if sample.kind() == SampleKind::Delete {
                    peers.remove(&peer);
                } else if peers.len() < MAX_PEERS {
                    peers.insert(peer);
                }
            })
            .await?;
        let token = session
            .liveliness()
            .declare_token(format!("{endpoint}/presence"))
            .await?;
        let (outgoing, mut output_rx) = mpsc::channel::<Notification>(CAPACITY);
        let (incoming, _) = broadcast::channel(CAPACITY);
        let stop = CancellationToken::new();
        let service = Arc::new(Self {
            outgoing,
            incoming: incoming.clone(),
            stop: stop.clone(),
        });
        let runtime = context.runtime.clone();
        context.clone().spawn(async move {
            let mut fanout = JoinSet::new();
            loop {
                tokio::select! { biased;
                    _ = stop.cancelled() => break,
                    _ = context.stopping() => break,
                    _ = fanout.join_next(), if !fanout.is_empty() => {},
                    query = query_rx.recv() => {
                        let Some(query) = query else { break };
                        if let Err(error) = receive(&runtime, &issuer, &endpoint, &incoming, query).await {
                            tracing::debug!(%error, "platform notification rejected");
                        }
                    },
                    notification = output_rx.recv(), if fanout.len() < CONCURRENCY => {
                        let Some(notification) = notification else { break };
                        let destinations: Vec<_> = peers.lock().unwrap_or_else(|e| e.into_inner()).iter().cloned().collect();
                        let session = session.clone();
                        fanout.spawn(async move {
                            // One notification's peers run concurrently, with a fixed global
                            // bound of CONCURRENCY * CONCURRENCY queries across fanout tasks.
                            let notification = notification;
                            use futures_util::{stream, StreamExt};
                            stream::iter(destinations).for_each_concurrent(CONCURRENCY, |key| {
                                let session = session.clone(); let notification = notification.clone();
                                async move {
                                    let operation = async {
                                        let Ok(payload) = serde_json::to_vec(&Envelope {notification, deadline_ms: now_ms()+2000}) else { return };
                                        let (finished, complete) = tokio::sync::oneshot::channel();
                                        struct Finished(Option<tokio::sync::oneshot::Sender<()>>);
                                        impl Drop for Finished { fn drop(&mut self) { if let Some(sender) = self.0.take() { let _ = sender.send(()); } } }
                                        let finished = Finished(Some(finished));
                                        let replies = session.get(key).allowed_destination(Locality::Remote)
                                            .target(QueryTarget::All).consolidation(ConsolidationMode::None)
                                            .timeout(TIMEOUT).payload(payload).callback(move |_| { let _ = &finished; }).await;
                                        if let Err(error) = replies { tracing::debug!(%error, "notification send failed"); }
                                        // Callback destruction means the finite Query completed.
                                        // Ignore ACK bodies: this API promises no durable custody.
                                        let _ = complete.await;
                                    };
                                    let _ = tokio::time::timeout(TIMEOUT, operation).await;
                                }
                            }).await;
                            Ok::<(), zenoh_result::Error>(())
                        });
                    }
                }
            }
            fanout.abort_all();
            while fanout.join_next().await.is_some() {}
            token.undeclare().await?;
            subscription.undeclare().await?;
            queryable.undeclare().await?;
            Ok(())
        });
        Ok(service)
    }
    /// Returns false on invalid input or overload. Never blocks business work.
    pub fn publish(&self, notification: Notification) -> bool {
        notification.valid() && self.outgoing.try_send(notification).is_ok()
    }
    pub fn subscribe(&self) -> broadcast::Receiver<Notification> {
        self.incoming.subscribe()
    }
}
impl Drop for PlatformNotifications {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}
async fn receive(
    runtime: &DynamicRuntime,
    issuer: &str,
    endpoint: &str,
    incoming: &broadcast::Sender<Notification>,
    query: zenoh::query::Query,
) -> ZResult<()> {
    if query.key_expr().as_str() != endpoint {
        return Err(zerror!("notification key mismatch").into());
    }
    let payload = query
        .payload()
        .ok_or_else(|| zerror!("missing notification"))?
        .to_bytes();
    if payload.len() > MAX_WIRE {
        return Err(zerror!("notification too large").into());
    }
    let digest: [u8; 32] = Sha256::digest(&payload).into();
    let receipt: Receipt =
        serde_json::from_slice(&runtime.route_gate_principal(&digest, endpoint)?)?;
    let envelope: Envelope = serde_json::from_slice(&payload)?;
    if !validate(&envelope, &receipt, issuer, now_ms()) {
        return Err(zerror!("invalid notification authority").into());
    }
    let _ = incoming.send(envelope.notification);
    let _ = tokio::time::timeout(
        Duration::from_millis(100),
        query.reply(endpoint.to_owned(), Vec::<u8>::new()),
    )
    .await;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hints_require_finite_platform_authority_and_bounded_data() {
        let mut envelope = Envelope {
            notification: Notification {
                topic: "watch".into(),
                payload: vec![],
            },
            deadline_ms: 2000,
        };
        let mut receipt = Receipt {
            source_router: "a".into(),
            issuer: "product".into(),
            expires_unix_ms: 2000,
        };
        assert!(validate(&envelope, &receipt, "product", 1000));
        assert!(!validate(&envelope, &receipt, "foreign", 1000));
        assert!(!validate(&envelope, &receipt, "product", 2000));
        receipt.expires_unix_ms = 1999;
        assert!(!validate(&envelope, &receipt, "product", 1000));
        receipt.expires_unix_ms = 4000;
        envelope.deadline_ms = 3001;
        assert!(!validate(&envelope, &receipt, "product", 1000));
        envelope.deadline_ms = 2000;
        envelope.notification.payload = vec![0; MAX_PAYLOAD + 1];
        assert!(!validate(&envelope, &receipt, "product", 1000));
        assert!(serde_json::from_str::<Receipt>(r#"{"application_id":"client"}"#).is_err());
    }
    #[test]
    fn discovery_is_exact_and_scoped() {
        assert_eq!(
            peer_endpoint("p/n/b/notifications/presence", "p"),
            Some("p/n/b/notifications".into())
        );
        for key in [
            "foreign/n/b/notifications/presence",
            "p/n/*/notifications/presence",
            "p/n/b/other/presence",
            "p/n/b/c/notifications/presence",
        ] {
            assert!(peer_endpoint(key, "p").is_none());
        }
    }
    #[tokio::test]
    async fn publication_is_bounded_and_drop_cancels() {
        let (outgoing, _rx) = mpsc::channel(1);
        let (incoming, _) = broadcast::channel(1);
        let stop = CancellationToken::new();
        let service = PlatformNotifications {
            outgoing,
            incoming,
            stop: stop.clone(),
        };
        let n = Notification {
            topic: "watch".into(),
            payload: vec![],
        };
        assert!(service.publish(n.clone()));
        assert!(!service.publish(n));
        drop(service);
        assert!(stop.is_cancelled());
    }
}
