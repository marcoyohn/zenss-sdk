//! Bounded physical observations; link activity never grants authority.
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use tokio::{sync::watch, time::Instant};

/// Coalesced transport diagnostics. A connected lane is not a ready role.
/// Observations use the stable Zenoh info API at most once per second; short
/// interruptions may coalesce. No endpoint, Router ID or credential is exposed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectivityStatus {
    pub connected_data_lanes: Vec<bool>,
    pub control_connected: Option<bool>,
    pub data_revision: u64,
    pub changed_at: Instant,
    pub closed: bool,
}
impl ConnectivityStatus {
    pub fn connected(&self, lanes: usize) -> bool {
        !self.closed
            && lanes > 0
            && lanes <= self.connected_data_lanes.len()
            && self.connected_data_lanes[..lanes].iter().all(|v| *v)
    }
}
pub struct ConnectivityTracker {
    routers: Vec<Option<String>>,
    data_lanes: usize,
    pub sender: watch::Sender<ConnectivityStatus>,
    metrics: super::PoolMetrics,
}
impl ConnectivityTracker {
    pub fn new(routers: Vec<Option<String>>, data_lanes: usize) -> Self {
        Self::with_metrics(routers, data_lanes, super::PoolMetrics::default())
    }
    pub fn with_metrics(
        routers: Vec<Option<String>>,
        data_lanes: usize,
        metrics: super::PoolMetrics,
    ) -> Self {
        assert!((1..=4).contains(&data_lanes) && routers.len() >= data_lanes && routers.len() <= 4);
        let (sender, _) = watch::channel(ConnectivityStatus {
            connected_data_lanes: routers[..data_lanes].iter().map(Option::is_some).collect(),
            control_connected: routers.get(data_lanes).map(Option::is_some),
            data_revision: 0,
            changed_at: Instant::now(),
            closed: false,
        });
        metrics::gauge!(metrics.pools).increment(1.0);
        record_connected(&routers, data_lanes, 1.0, metrics);
        Self {
            routers,
            data_lanes,
            metrics,
            sender,
        }
    }
    pub fn update(&mut self, routers: Vec<Option<String>>) {
        if routers.len() != self.routers.len() {
            self.close();
            return;
        }
        if routers == self.routers {
            return;
        }
        let mut next = self.sender.borrow().clone();
        if routers[..self.data_lanes] != self.routers[..self.data_lanes] {
            // Exhaustion fails closed rather than making old confirmations current.
            match next.data_revision.checked_add(1) {
                Some(revision) => next.data_revision = revision,
                None => next.closed = true,
            }
        }
        next.connected_data_lanes = routers[..self.data_lanes]
            .iter()
            .map(Option::is_some)
            .collect();
        next.control_connected = routers.get(self.data_lanes).map(Option::is_some);
        next.changed_at = Instant::now();
        record_connected(&self.routers, self.data_lanes, -1.0, self.metrics);
        record_connected(&routers, self.data_lanes, 1.0, self.metrics);
        metrics::counter!(self.metrics.topology_changes).increment(1);
        self.routers = routers;
        self.sender.send_replace(next);
    }
    pub fn close(&mut self) {
        self.update(vec![None; self.routers.len()]);
        self.sender.send_modify(|status| status.closed = true);
    }
}
// Sum live trackers; never use `set`, which would overwrite a sibling pool.
fn record_connected(
    routers: &[Option<String>],
    data_lanes: usize,
    sign: f64,
    metrics: super::PoolMetrics,
) {
    for (plane, range) in [
        ("data", 0..data_lanes),
        ("control", data_lanes..routers.len()),
    ] {
        let count = routers[range].iter().filter(|id| id.is_some()).count();
        metrics::gauge!(metrics.connected_lanes, "plane" => plane).increment(sign * count as f64);
    }
}
impl Drop for ConnectivityTracker {
    fn drop(&mut self) {
        record_connected(&self.routers, self.data_lanes, -1.0, self.metrics);
        metrics::gauge!(self.metrics.pools).decrement(1.0);
    }
}
pub async fn routers(sessions: &[zenoh::Session]) -> Vec<Option<String>> {
    let mut routers = Vec::with_capacity(sessions.len());
    for session in sessions {
        routers.push(if session.is_closed() {
            None
        } else {
            session
                .info()
                .routers_zid()
                .await
                .next()
                .map(|id| id.to_string())
        });
    }
    routers
}

/// One local confirmation tied to an observed data topology. BindLane probes
/// remain admissible while this gate is withdrawn; business admission does not.
#[derive(Clone)]
pub struct TopologyGate {
    confirmed: Arc<AtomicU64>,
    connectivity: watch::Receiver<ConnectivityStatus>,
    lanes: usize,
}
impl TopologyGate {
    pub fn new(connectivity: watch::Receiver<ConnectivityStatus>, lanes: usize) -> Self {
        Self {
            confirmed: Arc::new(AtomicU64::new(u64::MAX)),
            connectivity,
            lanes,
        }
    }
    pub fn withdraw(&self) {
        self.confirmed.store(u64::MAX, Ordering::Release);
    }
    pub fn revision(&self) -> Option<u64> {
        let status = self.connectivity.borrow();
        (status.connected(self.lanes) && status.data_revision != u64::MAX)
            .then_some(status.data_revision)
    }
    pub fn confirm(&self, revision: u64) -> bool {
        if self.revision() != Some(revision) {
            return false;
        }
        self.confirmed.store(revision, Ordering::Release);
        self.ready()
    }
    pub fn ready(&self) -> bool {
        self.revision() == Some(self.confirmed.load(Ordering::Acquire))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn multiple_pool_metrics_are_additive_and_cleanup_does_not_claim_authority() {
        use metrics::{
            Counter, Gauge, Histogram, Key, KeyName, Metadata, Recorder, SharedString, Unit,
        };
        use std::sync::Mutex;
        #[derive(Default)]
        struct Capture(Arc<Mutex<std::collections::HashMap<Key, f64>>>);
        struct Handle(Key, Arc<Mutex<std::collections::HashMap<Key, f64>>>);
        impl metrics::GaugeFn for Handle {
            fn increment(&self, v: f64) {
                *self.1.lock().unwrap().entry(self.0.clone()).or_default() += v;
            }
            fn decrement(&self, v: f64) {
                self.increment(-v);
            }
            fn set(&self, v: f64) {
                self.1.lock().unwrap().insert(self.0.clone(), v);
            }
        }
        impl Recorder for Capture {
            fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
            fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
            fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
            fn register_counter(&self, _: &Key, _: &Metadata<'_>) -> Counter {
                Counter::noop()
            }
            fn register_histogram(&self, _: &Key, _: &Metadata<'_>) -> Histogram {
                Histogram::noop()
            }
            fn register_gauge(&self, key: &Key, _: &Metadata<'_>) -> Gauge {
                Gauge::from_arc(Arc::new(Handle(key.clone(), self.0.clone())))
            }
        }
        let capture = Capture::default();
        let read = |name: &str, plane: Option<&str>| {
            capture
                .0
                .lock()
                .unwrap()
                .iter()
                .filter(|(key, _)| {
                    key.name() == name
                        && plane.map_or(true, |p| key.labels().any(|l| l.value() == p))
                })
                .map(|(_, value)| value)
                .sum::<f64>()
        };
        metrics::with_local_recorder(&capture, || {
            let mut first = ConnectivityTracker::new(
                vec![
                    Some("secret-router-a".into()),
                    Some("secret-control".into()),
                ],
                1,
            );
            let second = ConnectivityTracker::new(vec![Some("secret-router-b".into()); 4], 4);
            assert_eq!(read("zenss_client_channel_managed_pools", None), 2.0);
            assert_eq!(
                read("zenss_client_channel_connected_lanes", Some("data")),
                5.0
            );
            assert_eq!(
                read("zenss_client_channel_connected_lanes", Some("control")),
                1.0
            );
            let gate = TopologyGate::new(first.sender.subscribe(), 1);
            assert!(!gate.ready()); // Successful link observations are not proofs.
            first.close();
            assert_eq!(
                read("zenss_client_channel_connected_lanes", Some("data")),
                4.0
            );
            drop(first);
            assert_eq!(read("zenss_client_channel_managed_pools", None), 1.0);
            drop(second); // Panicking/cancelled task ownership also balances gauges.
            assert_eq!(read("zenss_client_channel_managed_pools", None), 0.0);
            assert_eq!(read("zenss_client_channel_connected_lanes", None), 0.0);
        });
        for key in capture.0.lock().unwrap().keys() {
            assert!(key
                .labels()
                .all(|l| l.key() == "plane" && matches!(l.value(), "data" | "control")));
            assert!(!key.name().contains("secret"));
        }
    }
    #[test]
    fn disconnected_and_replaced_routers_require_fresh_proof_without_control_interference() {
        let mut tracker = ConnectivityTracker::new(
            vec![Some("a".into()), Some("b".into()), Some("control".into())],
            2,
        );
        let gate = TopologyGate::new(tracker.sender.subscribe(), 2);
        assert!(!gate.ready());
        assert!(gate.confirm(0));
        tracker.update(vec![Some("a".into()), Some("b".into()), None]);
        assert!(gate.ready());
        assert_eq!(tracker.sender.borrow().data_revision, 0);
        tracker.update(vec![None, Some("b".into()), None]);
        assert!(!gate.ready());
        tracker.update(vec![Some("a".into()), Some("b".into()), None]);
        assert!(!gate.confirm(0));
        assert!(!gate.ready());
        assert!(gate.confirm(2));
        tracker.update(vec![Some("replacement".into()), Some("b".into()), None]);
        assert!(!gate.ready());
        assert!(!gate.confirm(2));
        assert!(gate.confirm(3));
        tracker.close();
        assert!(!gate.ready());
        assert!(!gate.confirm(4));
    }
    #[test]
    fn coalesced_observations_preserve_revision_and_exhaustion_fails_closed() {
        let mut tracker = ConnectivityTracker::new(vec![Some("a".into())], 1);
        let notifications = tracker.sender.subscribe();
        tracker.update(vec![Some("a".into())]);
        assert!(!notifications.has_changed().unwrap());
        tracker
            .sender
            .send_modify(|s| s.data_revision = u64::MAX - 1);
        let gate = TopologyGate::new(tracker.sender.subscribe(), 1);
        assert!(gate.confirm(u64::MAX - 1));
        tracker.update(vec![Some("b".into())]);
        assert!(!gate.ready());
        assert!(!gate.confirm(u64::MAX));
        tracker.update(vec![Some("c".into())]);
        assert!(tracker.sender.borrow().closed);
    }
}
