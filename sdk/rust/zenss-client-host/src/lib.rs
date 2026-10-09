//! Native-only adapter. Plugins are trusted process code; access bindings are
//! supplied by their composition root, not proof of a remote application's identity.
use anyhow::{ensure, Result};
use std::{
    sync::{Arc, Mutex, Weak},
    time::Duration,
};
use tokio::{sync::Semaphore, task::JoinHandle, time::Instant};
use tokio_util::sync::CancellationToken;
use zenss_client_sdk::{
    ClientMode, ClientTransport, HostedTransport, ServiceIdentity, MAX_MESSAGE_BYTES,
};
use zenss_plugin_trait::{zenss_contracts::PluginPhase, PluginContext};

/// An explicit finite platform binding. Product protocols still validate their
/// own signatures and leases; this does not issue a Lingshu business principal.
#[derive(Debug, Clone)]
pub struct HostBinding {
    pub identity: ServiceIdentity,
    pub query_prefixes: Vec<String>,
    pub expires_at: Instant,
    pub timeout: Duration,
    pub max_inflight: usize,
}
impl HostBinding {
    fn validate(&self) -> Result<()> {
        self.identity.validate()?;
        ensure!(self.expires_at > Instant::now(), "host binding expired");
        ensure!(
            (Duration::from_millis(1)..=Duration::from_secs(300)).contains(&self.timeout),
            "invalid timeout"
        );
        ensure!(
            (1..=1024).contains(&self.max_inflight),
            "invalid host client capacity"
        );
        ensure!(self.query_prefixes.len() <= 64, "too many query scopes");
        let products = format!("zenss/v1/{}/products/", self.identity.deployment);
        let discovery = format!("zenss/v1/{}/discovery/query", self.identity.deployment);
        for prefix in &self.query_prefixes {
            ensure!(
                prefix.len() <= 1024 && !prefix.contains(['*', '?', '#']) && !prefix.ends_with('/'),
                "invalid query scope"
            );
            ensure!(
                prefix == &discovery
                    || prefix
                        .strip_prefix(&products)
                        .is_some_and(|tail| !tail.is_empty()),
                "scope must name products or discovery in the bound deployment"
            );
            for part in prefix.split('/') {
                zenss_plugin_trait::zenss_contracts::validate_segment(part)?;
            }
        }
        Ok(())
    }
    fn allows(&self, key: &str) -> bool {
        let discovery = format!("zenss/v1/{}/discovery/query", self.identity.deployment);
        self.query_prefixes.iter().any(|prefix| {
            key == prefix
                || (prefix != &discovery
                    && key
                        .strip_prefix(prefix)
                        .is_some_and(|tail| tail.starts_with('/')))
        })
    }
}

type TokenSlot = Mutex<Option<zenoh::liveliness::LivelinessToken>>;
struct Lifetime {
    closed: CancellationToken,
    declarations: Mutex<Vec<Weak<TokenSlot>>>,
}
impl Lifetime {
    fn close(&self) {
        self.closed.cancel();
        let mut declarations = self.declarations.lock().unwrap();
        for weak in declarations.drain(..) {
            if let Some(slot) = weak.upgrade() {
                slot.lock().unwrap().take();
            }
        }
    }
    fn track(&self, token: zenoh::liveliness::LivelinessToken) -> Result<HostAnnouncement> {
        let mut declarations = self.declarations.lock().unwrap();
        ensure!(!self.closed.is_cancelled(), "host client closed");
        declarations.retain(|weak| {
            weak.upgrade()
                .is_some_and(|slot| slot.lock().unwrap().is_some())
        });
        ensure!(
            declarations.len() < 128,
            "host client declaration capacity exhausted"
        );
        let slot = Arc::new(Mutex::new(Some(token)));
        declarations.push(Arc::downgrade(&slot));
        Ok(HostAnnouncement(slot))
    }
}
/// Independent declaration handle; dropping/closing Client also removes it.
pub struct HostAnnouncement(Arc<TokenSlot>);
impl HostAnnouncement {
    pub async fn undeclare(self) -> Result<()> {
        let token = self.0.lock().unwrap().take();
        if let Some(token) = token {
            token
                .undeclare()
                .await
                .map_err(|e| anyhow::anyhow!("undeclare failed: {e}"))?;
        }
        Ok(())
    }
    pub fn is_closed(&self) -> bool {
        self.0.lock().unwrap().is_none()
    }
}
impl Drop for HostAnnouncement {
    fn drop(&mut self) {
        self.0.lock().unwrap().take();
    }
}
#[derive(Clone)]
pub struct HostRevocation(Arc<Lifetime>);
impl HostRevocation {
    pub fn revoke(&self) {
        self.0.close();
    }
}

/// Owns only scoped client work and declarations. The supplied Session is borrowed
/// by cloning its handle; it is NEVER closed by this adapter, including failures.
pub struct HostClientContext {
    context: PluginContext,
    session: zenoh::Session,
    binding: HostBinding,
    lifetime: Arc<Lifetime>,
    capacity: Arc<Semaphore>,
    task: Option<JoinHandle<()>>,
}
impl HostClientContext {
    pub fn bind(
        context: PluginContext,
        session: &zenoh::Session,
        binding: HostBinding,
    ) -> Result<Self> {
        binding.validate()?;
        ensure!(!session.is_closed(), "host session closed");
        ensure!(
            session.zid() == context.runtime.zid(),
            "session belongs to another host node"
        );
        ensure!(
            !terminal(context.snapshot().phase),
            "plugin is shutting down"
        );
        let lifetime = Arc::new(Lifetime {
            closed: CancellationToken::new(),
            declarations: Mutex::new(Vec::new()),
        });
        let observer = lifetime.clone();
        let parent = context.clone();
        let shared = session.clone();
        let deadline = binding.expires_at;
        let task = context.spawn_scoped(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(100));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    biased;
                    _ = observer.closed.cancelled() => break,
                    _ = parent.draining() => break,
                    _ = tokio::time::sleep_until(deadline) => break,
                    _ = tick.tick() => if shared.is_closed() || terminal(parent.snapshot().phase) { break; },
                }
            }
            observer.close();
            Ok(())
        }).map_err(|e| anyhow::anyhow!("host cleanup registration rejected: {e}"))?;
        Ok(Self {
            context,
            session: session.clone(),
            capacity: Arc::new(Semaphore::new(binding.max_inflight)),
            binding,
            lifetime,
            task: Some(task),
        })
    }
    pub fn revocation(&self) -> HostRevocation {
        HostRevocation(self.lifetime.clone())
    }
    pub fn runtime_id(&self) -> String {
        self.session.zid().to_string()
    }
    fn check(&self) -> Result<()> {
        if self.lifetime.closed.is_cancelled()
            || self.session.is_closed()
            || Instant::now() >= self.binding.expires_at
            || terminal(self.context.snapshot().phase)
        {
            self.lifetime.close();
            anyhow::bail!("host client expired, revoked or closed");
        }
        Ok(())
    }
}
fn terminal(phase: PluginPhase) -> bool {
    matches!(
        phase,
        PluginPhase::Draining | PluginPhase::Stopping | PluginPhase::Stopped | PluginPhase::Failed
    )
}
impl HostedTransport for HostClientContext {}
#[async_trait::async_trait]
impl ClientTransport for HostClientContext {
    type Announcement = HostAnnouncement;
    fn mode(&self) -> ClientMode {
        ClientMode::Hosted
    }
    fn timeout(&self) -> Duration {
        self.binding.timeout
    }
    fn identity(&self) -> Option<&ServiceIdentity> {
        Some(&self.binding.identity)
    }
    fn ensure_open(&self) -> Result<()> {
        self.check()
    }
    async fn query(&self, key: &str, payload: Vec<u8>) -> Result<Vec<u8>> {
        self.check()?;
        ensure!(
            self.binding.allows(key),
            "query is outside host client scope"
        );
        ensure!(
            payload.len() <= MAX_MESSAGE_BYTES,
            "payload exceeds platform limit"
        );
        let _capacity = self
            .capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow::anyhow!("host client is at capacity"))?;
        let _admission = self
            .context
            .admit()
            .map_err(|e| anyhow::anyhow!("plugin admission rejected: {e}"))?;
        let work = async {
            let replies = self
                .session
                .get(key.to_owned())
                .payload(payload)
                .timeout(self.binding.timeout)
                .await
                .map_err(|e| anyhow::anyhow!("query failed: {e}"))?;
            let reply = replies
                .recv_async()
                .await
                .map_err(|e| anyhow::anyhow!("query closed; outcome unknown: {e}"))?;
            let sample = reply
                .result()
                .map_err(|_| anyhow::anyhow!("remote query rejected"))?;
            ensure!(
                sample.payload().len() <= MAX_MESSAGE_BYTES,
                "reply exceeds platform limit"
            );
            Ok(sample.payload().to_bytes().into_owned())
        };
        tokio::select! {
            biased;
            _ = self.lifetime.closed.cancelled() => anyhow::bail!("host client revoked; outcome unknown"),
            _ = self.context.draining() => anyhow::bail!("plugin draining; outcome unknown"),
            _ = tokio::time::sleep_until(self.binding.expires_at) => anyhow::bail!("host binding expired; outcome unknown"),
            result = work => result,
        }
    }
    async fn announce(&self, identity: &ServiceIdentity) -> Result<Self::Announcement> {
        self.check()?;
        ensure!(
            identity == &self.binding.identity,
            "announcement identity differs from host binding"
        );
        let token = self
            .session
            .liveliness()
            .declare_token(identity.liveliness_key()?)
            .await
            .map_err(|e| anyhow::anyhow!("announce failed: {e}"))?;
        self.check()?;
        self.lifetime.track(token)
    }
    async fn close(mut self) -> Result<()> {
        self.lifetime.close();
        if let Some(task) = self.task.take() {
            task.await
                .map_err(|e| anyhow::anyhow!("host client cleanup failed: {e}"))?;
        }
        Ok(())
    }
}
impl Drop for HostClientContext {
    fn drop(&mut self) {
        self.lifetime.close();
    }
}
