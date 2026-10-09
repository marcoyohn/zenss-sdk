//! Product-neutral ownership of bounded outbound sessions. No enrollment or business retries.
use crate::connectivity::{routers, ConnectivityStatus, ConnectivityTracker};
use crate::transport::TransportOptions;
use std::{future::Future, sync::Arc, time::Duration};
use tokio::{
    sync::{watch, Semaphore},
    task::JoinHandle,
    time::Instant,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(12);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    #[error("invalid channel session configuration")]
    InvalidConfig,
    #[error("channel sessions require a Tokio multi-thread runtime")]
    UnsupportedRuntime,
    #[error("logical service connection channel capacity exhausted")]
    CapacityExceeded,
    #[error("channel authority expired")]
    AuthorityExpired,
    #[error("logical service connection closed")]
    Closed,
    #[error("channel connection failed")]
    Transport,
    #[error("invalid channel control response")]
    InvalidResponse,
    #[error("managed certificate rotation failed")]
    RotationFailed,
    #[error("channel cleanup failed")]
    CleanupFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    Explicit,
    ConnectionClosed,
    RotationFailed,
    AuthorityExpired,
    CleanupFailed,
}

/// One independent Session per lane; cloning a Session never increases this count.
#[derive(Debug, Clone, Copy)]
pub struct PoolLayout {
    lanes: usize,
    dedicated_control: bool,
}
impl Default for PoolLayout {
    fn default() -> Self {
        Self {
            lanes: 1,
            dedicated_control: false,
        }
    }
}
impl PoolLayout {
    pub fn new(lanes: usize) -> Result<Self, TransportError> {
        if !(1..=4).contains(&lanes) {
            return Err(TransportError::InvalidConfig);
        }
        Ok(Self {
            lanes,
            dedicated_control: false,
        })
    }
    /// Reserve a separate physical Session for control queries. It shares the
    /// same finite identity and four-Session connection cap; four data lanes
    /// therefore cannot also request a dedicated control Session.
    pub fn with_control_lane(mut self) -> Result<Self, TransportError> {
        if self.lanes >= 4 {
            return Err(TransportError::InvalidConfig);
        }
        self.dedicated_control = true;
        Ok(self)
    }
    pub fn has_control_lane(self) -> bool {
        self.dedicated_control
    }
    pub fn session_count(self) -> usize {
        self.lanes + usize::from(self.dedicated_control)
    }
    pub fn lanes(self) -> usize {
        self.lanes
    }
}

#[derive(Clone, Copy)]
pub struct PoolMetrics {
    pub pools: &'static str,
    pub connected_lanes: &'static str,
    pub topology_changes: &'static str,
    pub terminations: &'static str,
}
impl Default for PoolMetrics {
    fn default() -> Self {
        Self {
            pools: "zenss_client_channel_managed_pools",
            connected_lanes: "zenss_client_channel_connected_lanes",
            topology_changes: "zenss_client_channel_topology_changes_total",
            terminations: "zenss_client_channel_terminations_total",
        }
    }
}
struct SessionPermit(Option<tokio::sync::OwnedSemaphorePermit>);
impl SessionPermit {
    fn release(&mut self) {
        self.0.take();
    }
}
impl Drop for SessionPermit {
    fn drop(&mut self) {
        if let Some(permit) = self.0.take() {
            permit.forget();
        }
    }
}

pub struct ManagedPool {
    sessions: Vec<zenoh::Session>,
    stop: watch::Sender<bool>,
    closed: watch::Receiver<Option<CloseReason>>,
    authority: watch::Sender<Instant>,
    connectivity: watch::Receiver<ConnectivityStatus>,
    task: Option<JoinHandle<Result<(), TransportError>>>,
    cleanup_failed: bool,
    open_guard: Option<tokio::sync::oneshot::Sender<()>>,
}
impl ManagedPool {
    /// `root_closed` completes on revocation or loss of its owner. Authority is
    /// supplied only after product verification, not inferred from link state.
    pub async fn open(
        options: TransportOptions,
        layout: PoolLayout,
        budget: Arc<Semaphore>,
        deadline: Instant,
        root_closed: impl Future<Output = ()> + Send + 'static,
        metrics: PoolMetrics,
    ) -> Result<Self, TransportError> {
        if !tokio::runtime::Handle::try_current()
            .is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
        {
            return Err(TransportError::UnsupportedRuntime);
        }
        // The opener continues cleanup even if its caller cancels. Dropping
        // the guard revokes the opening attempt, never abandons native lanes.
        let (guard, cancelled) = tokio::sync::oneshot::channel::<()>();
        let (result, received) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let revoked = async move {
                tokio::select! { _ = root_closed => {}, _ = cancelled => {} }
            };
            let pool = Self::open_inner(options, layout, budget, deadline, revoked, metrics).await;
            let _ = result.send(pool); // An unreceived pool drops and requests cleanup.
        });
        let mut pool = received
            .await
            .map_err(|_| TransportError::CleanupFailed)??;
        pool.open_guard = Some(guard);
        Ok(pool)
    }
    async fn open_inner(
        options: TransportOptions,
        layout: PoolLayout,
        budget: Arc<Semaphore>,
        deadline: Instant,
        root_closed: impl Future<Output = ()> + Send + 'static,
        metrics: PoolMetrics,
    ) -> Result<Self, TransportError> {
        if !tokio::runtime::Handle::try_current()
            .is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
        {
            return Err(TransportError::UnsupportedRuntime);
        }
        if Instant::now() >= deadline {
            return Err(TransportError::AuthorityExpired);
        }
        // Validate every lane before reserving capacity or starting I/O.
        let configs = (0..layout.session_count())
            .map(|i| options.configuration(i))
            .collect::<Result<Vec<_>, _>>()?;
        let permit = budget
            .try_acquire_many_owned(layout.session_count() as u32)
            .map_err(|_| TransportError::CapacityExceeded)?;
        let mut permit = SessionPermit(Some(permit));
        let mut root_closed = Box::pin(root_closed);
        let mut sessions = Vec::with_capacity(configs.len());
        let open_deadline = (Instant::now() + CONNECT_TIMEOUT).min(deadline);
        for config in configs {
            let result = tokio::select! {
                biased;
                _ = &mut root_closed => Err(TransportError::Closed),
                _ = tokio::time::sleep_until(open_deadline) => Err(if Instant::now() >= deadline { TransportError::AuthorityExpired } else { TransportError::Transport }),
                result = zenoh::open(config) => result.map_err(|_| TransportError::Transport),
            };
            match result {
                Ok(session) => sessions.push(session),
                Err(error) => {
                    cleanup_pool(&sessions, &mut permit).await?;
                    return Err(error);
                }
            }
        }
        // A ready revocation or expiry takes priority over returning a pool.
        let terminal = tokio::select! {
            biased;
            _ = &mut root_closed => Some(TransportError::Closed),
            _ = tokio::time::sleep_until(deadline) => Some(TransportError::AuthorityExpired),
            _ = std::future::ready(()) => None,
        };
        if let Some(error) = terminal {
            cleanup_pool(&sessions, &mut permit).await?;
            return Err(error);
        }
        let observed = routers(&sessions).await;
        Ok(Self::start(
            sessions,
            layout,
            deadline,
            root_closed,
            permit,
            observed,
            metrics,
            true,
        ))
    }
    fn start(
        sessions: Vec<zenoh::Session>,
        layout: PoolLayout,
        deadline: Instant,
        root_closed: impl Future<Output = ()> + Send + 'static,
        mut permit: SessionPermit,
        observed: Vec<Option<String>>,
        metrics: PoolMetrics,
        observe_topology: bool,
    ) -> Self {
        let (stop, mut stopped) = watch::channel(false);
        let (closed, close_status) = watch::channel(None);
        let (authority, mut authorization) = watch::channel(deadline);
        let mut connectivity = ConnectivityTracker::with_metrics(observed, layout.lanes(), metrics);
        let connectivity_status = connectivity.sender.subscribe();
        let active = sessions.clone();
        let task = tokio::spawn(async move {
            let mut root_closed = Box::pin(root_closed);
            let mut observation = tokio::time::interval_at(
                Instant::now() + Duration::from_secs(1),
                Duration::from_secs(1),
            );
            observation.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let reason = loop {
                let deadline = *authorization.borrow_and_update();
                tokio::select! {
                    biased;
                    _ = &mut root_closed => break CloseReason::ConnectionClosed,
                    _ = tokio::time::sleep_until(deadline) => { if Instant::now() >= *authorization.borrow() { break CloseReason::AuthorityExpired; } },
                    _ = stopped.changed() => break CloseReason::Explicit,
                    result = authorization.changed() => { if result.is_err() { break CloseReason::Explicit; } },
                    _ = observation.tick(), if observe_topology => connectivity.update(routers(&active).await),
                }
            };
            connectivity.close();
            closed.send_replace(Some(reason));
            let result = cleanup_pool(&active, &mut permit).await;
            if result.is_err() {
                closed.send_replace(Some(CloseReason::CleanupFailed));
            }
            let outcome = if result.is_err() {
                "cleanup_failed"
            } else {
                match reason {
                    CloseReason::Explicit => "explicit",
                    CloseReason::ConnectionClosed => "connection_closed",
                    CloseReason::RotationFailed => "rotation_failed",
                    CloseReason::AuthorityExpired => "authority_expired",
                    CloseReason::CleanupFailed => "cleanup_failed",
                }
            };
            metrics::counter!(metrics.terminations, "outcome" => outcome).increment(1);
            result
        });
        Self {
            sessions,
            stop,
            closed: close_status,
            authority,
            connectivity: connectivity_status,
            task: Some(task),
            cleanup_failed: false,
            open_guard: None,
        }
    }
    pub fn sessions(&self) -> &[zenoh::Session] {
        &self.sessions
    }
    pub fn subscribe_closed(&self) -> watch::Receiver<Option<CloseReason>> {
        self.closed.clone()
    }
    pub fn subscribe_deadline(&self) -> watch::Receiver<Instant> {
        self.authority.subscribe()
    }
    pub fn subscribe_connectivity(&self) -> watch::Receiver<ConnectivityStatus> {
        self.connectivity.clone()
    }
    pub fn is_running(&self) -> bool {
        !self.cleanup_failed
            && self.closed.borrow().is_none()
            && self.task.as_ref().is_some_and(|t| !t.is_finished())
    }
    /// Called only after the product verifies a fresh scoped authorization.
    pub fn update_deadline(&self, next: Instant) -> Result<(), TransportError> {
        if !self.is_running() {
            return Err(TransportError::Closed);
        }
        if Instant::now() >= *self.authority.borrow() || next <= Instant::now() {
            return Err(TransportError::AuthorityExpired);
        }
        self.authority.send_replace(next);
        Ok(())
    }
    pub fn request_close(&self) {
        self.stop.send_replace(true);
    }
    pub async fn close(&mut self) -> Result<(), TransportError> {
        self.request_close();
        if let Some(task) = self.task.as_mut() {
            let result = task.await;
            self.task.take();
            match result {
                Ok(result) => self.cleanup_failed = result.is_err(),
                Err(_) => {
                    self.cleanup_failed = true;
                    let _ = close_sessions(&self.sessions).await;
                }
            }
        }
        if self.cleanup_failed {
            Err(TransportError::CleanupFailed)
        } else {
            Ok(())
        }
    }
    #[cfg(feature = "test-support")]
    pub fn abort_driver_for_test(&self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
    /// Fixture-only adoption with a fixed connected topology, including peer-only
    /// test sessions. Never accepts credentials or changes server policy. Use
    /// `open` for real Router observation and topology-change tests.
    #[cfg(feature = "test-support")]
    pub fn fixture(
        sessions: Vec<zenoh::Session>,
        layout: PoolLayout,
        deadline: Instant,
        root_closed: impl Future<Output = ()> + Send + 'static,
        metrics: PoolMetrics,
    ) -> Self {
        assert_eq!(sessions.len(), layout.session_count());
        let observed = vec![Some("fixture-router".into()); sessions.len()];
        Self::start(
            sessions,
            layout,
            deadline,
            root_closed,
            SessionPermit(None),
            observed,
            metrics,
            false,
        )
    }
}
impl Drop for ManagedPool {
    fn drop(&mut self) {
        self.request_close();
    }
}
async fn close_sessions(sessions: &[zenoh::Session]) -> Result<(), TransportError> {
    tokio::time::timeout(
        CLOSE_TIMEOUT,
        futures_util::future::join_all(sessions.iter().map(|s| async move { s.close().await })),
    )
    .await
    .map_err(|_| TransportError::CleanupFailed)?
    .into_iter()
    .try_for_each(|r| r.map_err(|_| TransportError::CleanupFailed))
}
async fn cleanup_pool(
    sessions: &[zenoh::Session],
    permit: &mut SessionPermit,
) -> Result<(), TransportError> {
    close_sessions(sessions).await?;
    permit.release();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn unproven_cleanup_never_releases_physical_capacity() {
        let budget = std::sync::Arc::new(tokio::sync::Semaphore::new(2));
        let permit = SessionPermit(Some(budget.clone().try_acquire_owned().unwrap()));
        let task = tokio::spawn(async move {
            let _permit = permit;
            panic!("simulated lifecycle failure");
        });
        assert!(task.await.unwrap_err().is_panic());
        assert_eq!(budget.available_permits(), 1);

        let mut permit = SessionPermit(Some(budget.clone().try_acquire_owned().unwrap()));
        assert_eq!(budget.available_permits(), 0);
        cleanup_pool(&[], &mut permit).await.unwrap();
        drop(permit);
        assert_eq!(budget.available_permits(), 1);
    }
}
