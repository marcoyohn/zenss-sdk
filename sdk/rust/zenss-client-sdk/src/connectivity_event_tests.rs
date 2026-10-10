use super::*;

#[test]
fn same_router_reconnect_cannot_hide_behind_a_coalesced_watch_snapshot() {
    let mut tracker = ConnectivityTracker::new(vec![None, None], 1);
    tracker.transport_event(0, "router".into(), true);
    tracker.transport_event(1, "control".into(), true);
    let status = tracker.sender.subscribe();
    let gate = TopologyGate::new(status.clone(), 1);
    let confirmed = status.borrow().data_revision;
    assert!(gate.confirm(confirmed));
    tracker.transport_event(0, "router".into(), false);
    tracker.transport_event(0, "router".into(), true);
    assert!(status.borrow().connected(1));
    assert_eq!(status.borrow().data_revision, confirmed + 2);
    assert!(!gate.ready());
    assert!(!gate.confirm(confirmed));
    assert!(gate.confirm(confirmed + 2));
    let connection_revision = status.borrow().connection_revision;
    tracker.transport_event(1, "control".into(), false);
    tracker.transport_event(1, "control".into(), true);
    assert_eq!(status.borrow().connection_revision, connection_revision + 2);
    assert_eq!(status.borrow().data_revision, confirmed + 2);
    assert!(gate.ready()); // Data-only proof stays distinct from control authority.
}

#[test]
fn duplicate_history_and_multiple_routers_do_not_miss_changed_transport() {
    let mut tracker = ConnectivityTracker::new(vec![None], 1);
    tracker.transport_event(0, "a".into(), true);
    let before = tracker.sender.borrow().clone();
    tracker.transport_event(0, "a".into(), true);
    assert_eq!(*tracker.sender.borrow(), before);
    tracker.transport_event(0, "b".into(), true);
    let gate = TopologyGate::new(tracker.sender.subscribe(), 1);
    assert!(gate.confirm(tracker.sender.borrow().data_revision));
    tracker.transport_event(0, "b".into(), false);
    assert!(tracker.sender.borrow().connected(1));
    assert!(!gate.ready());
    tracker.transport_event(0, "a".into(), false);
    assert!(!tracker.sender.borrow().connected(1));
}

#[test]
fn event_overflow_and_close_never_reopen_admission() {
    let mut tracker = ConnectivityTracker::new(vec![None], 1);
    tracker
        .sender
        .send_modify(|s| s.data_revision = u64::MAX - 1);
    tracker.transport_event(0, "a".into(), true);
    assert!(tracker.sender.borrow().closed);
    tracker.transport_event(0, "a".into(), true);
    assert!(!tracker.sender.borrow().connected(1));
    let mut tracker = ConnectivityTracker::new(vec![None], 1);
    for index in 0..17 {
        tracker.transport_event(0, index.to_string(), true);
    }
    assert!(tracker.sender.borrow().closed);
    assert!(!tracker.sender.borrow().connected(1));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listener_history_and_close_drive_the_actual_router_session() {
    let mut router_config = zenoh::Config::default();
    router_config.insert_json5("mode", "\"router\"").unwrap();
    router_config
        .insert_json5("listen/endpoints", "[\"tcp/127.0.0.1:0\"]")
        .unwrap();
    router_config
        .insert_json5("scouting/multicast/enabled", "false")
        .unwrap();
    let router = zenoh::open(router_config).await.unwrap();
    let endpoints: Vec<String> = router
        .info()
        .locators()
        .await
        .into_iter()
        .map(|v| v.to_string())
        .collect();
    let mut config = zenoh::Config::default();
    config.insert_json5("mode", "\"client\"").unwrap();
    config
        .insert_json5(
            "connect/endpoints",
            &serde_json::to_string(&endpoints).unwrap(),
        )
        .unwrap();
    config
        .insert_json5("scouting/multicast/enabled", "false")
        .unwrap();
    let client = zenoh::open(config).await.unwrap();
    let observer = ConnectivityObserver::bind(
        std::slice::from_ref(&client),
        1,
        super::super::PoolMetrics::default(),
    )
    .await
    .unwrap();
    let mut status = observer.subscribe();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        status.wait_for(|s| s.connected(1)),
    )
    .await
    .unwrap()
    .unwrap();
    let revision = status.borrow().data_revision;
    router.close().await.unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        status.wait_for(|s| !s.connected(1)),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(status.borrow().data_revision > revision);
    observer.close();
    assert!(status.borrow().closed);
    client.close().await.unwrap();
}
