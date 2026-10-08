// SPDX-License-Identifier: Apache-2.0
use super::*;

#[test]
fn declaration_caps_remap_cleanup_and_byte_budget() {
    let budget = Arc::new(AtomicUsize::new(0));
    let mut ids = Declarations::default();
    for kind in [
        IdKind::Resource,
        IdKind::Queryable,
        IdKind::Subscriber,
        IdKind::Token,
    ] {
        for id in 0..kind.business_limit() as u32 {
            assert!(ids.admit(kind, id, "a", &budget));
        }
        assert!(!ids.admit(kind, kind.business_limit() as u32, "a", &budget));
        let before = budget.load(Ordering::Acquire);
        assert!(ids.admit(kind, 0, "a", &budget));
        assert!(!ids.admit(kind, 0, "b", &budget));
        assert_eq!(budget.load(Ordering::Acquire), before);
        ids.remove(kind, 0);
        assert!(ids.admit(kind, kind.business_limit() as u32, "a", &budget));
    }
    drop(ids);
    assert_eq!(budget.load(Ordering::Acquire), 0);
    let mut ids = Declarations::default();
    for id in 0..2048 {
        if !ids.admit(IdKind::Resource, id, &"x".repeat(KEY_BYTES), &budget) {
            assert!(id > 0);
            assert!(ids.bytes <= FLOW_BYTES);
            break;
        }
    }
    assert!(!ids.admit(IdKind::Resource, 9999, &"x".repeat(KEY_BYTES + 1), &budget));
    drop(ids);
    assert_eq!(budget.load(Ordering::Acquire), 0);
}

#[test]
fn current_and_future_interests_share_capacity_and_cannot_change_mode() {
    let budget = Arc::default();
    let mut ids = Declarations::default();
    for id in 0..IdKind::Interest.business_limit() as u32 {
        assert!(ids.admit(
            if id % 2 == 0 {
                IdKind::Interest
            } else {
                IdKind::CurrentInterest
            },
            id,
            "",
            &budget
        ));
    }
    assert!(!ids.admit(IdKind::Interest, 129, "", &budget));
    assert!(!ids.admit(IdKind::CurrentInterest, 129, "", &budget));
    assert!(!ids.admit(IdKind::CurrentInterest, 0, "", &budget));
    ids.remove(IdKind::CurrentInterest, 1);
    assert!(ids.admit(IdKind::CurrentInterest, 129, "", &budget));
    ids.remove(IdKind::CurrentInterest, 0); // DeclareFinal never removes a future interest.
    assert!(ids.ids.contains_key(&(IdKind::Interest, 0)));
    drop(ids);
    assert_eq!(budget.load(Ordering::Acquire), 0);
}

#[test]
fn shared_budget_is_atomic_and_owner_drop_returns_queries_and_declarations() {
    let budget = Arc::new(AtomicUsize::new(0));
    let mut threads = vec![];
    for _ in 0..16 {
        let budget = budget.clone();
        threads.push(std::thread::spawn(move || {
            Reservation::for_query(&budget, STATE_BYTES / 8, QueryCapacity::Control)
        }));
    }
    let reservations: Vec<_> = threads
        .into_iter()
        .filter_map(|t| t.join().unwrap())
        .collect();
    assert_eq!(reservations.len(), 8);
    assert_eq!(budget.load(Ordering::Acquire), STATE_BYTES);
    drop(reservations);
    let owner = Arc::new(FaceResources::default());
    owner
        .incoming
        .lock()
        .unwrap()
        .admit(IdKind::Queryable, 1, "a", &budget);
    owner.pending.lock().unwrap().incoming.insert(
        1,
        Pending {
            capacity: QueryCapacity::Business,
            key: "a".into(),
            until: Instant::now(),
            _reservation: Reservation::new(&budget, 129).unwrap(),
        },
    );
    let replacement = owner.clone();
    drop(owner);
    assert_eq!(budget.load(Ordering::Acquire), 258);
    replacement
        .pending
        .lock()
        .unwrap()
        .incoming
        .retain(|_, p| p.until > Instant::now());
    assert_eq!(budget.load(Ordering::Acquire), 129);
    drop(replacement);
    assert_eq!(budget.load(Ordering::Acquire), 0);
}

#[test]
fn router_sourced_declarations_use_native_node_and_key_identity() {
    let budget = Arc::default();
    let mut ids = Declarations::default();
    for id in 0..IdKind::Queryable.business_limit() {
        assert!(ids.admit_sourced(IdKind::Queryable, 1, &format!("key/{id}"), &budget));
    }
    assert!(ids.admit_sourced(IdKind::Queryable, 1, "key/0", &budget));
    assert!(!ids.admit_sourced(IdKind::Queryable, 2, "key/0", &budget));
    ids.remove_sourced(IdKind::Queryable, 2, "key/0");
    assert!(!ids.admit_sourced(IdKind::Queryable, 2, "key/0", &budget));
    ids.remove_sourced(IdKind::Queryable, 1, "key/0");
    assert!(ids.admit_sourced(IdKind::Queryable, 2, "key/0", &budget));
    drop(ids);
    assert_eq!(budget.load(Ordering::Acquire), 0);
}

struct Allow;
impl RouteGate for Allow {
    fn query_capacity(&self, request: &RouteRequest<'_>, _: QueryCapacitySource) -> QueryCapacity {
        if request.key == Some("budget/1")
            && request
                .payload
                .is_some_and(|p| p == b"control" || p.first() == Some(&b'C'))
        {
            QueryCapacity::Control
        } else {
            QueryCapacity::Business
        }
    }
    fn authorize(&self, _: &RouteSubject, request: &RouteRequest<'_>) -> bool {
        !(request.flow == RouteFlow::Egress
            && request.action == RouteAction::Query
            && request.key == Some("budget/2"))
    }
    #[cfg(feature = "zenss-router-origin")]
    fn query_origin(
        &self,
        subject: &RouteSubject,
        request: &RouteRequest<'_>,
        attachment: Option<&[u8]>,
    ) -> ZResult<Option<Vec<u8>>> {
        // Trusted TCP fixture only; production uses signed, current grant receipts.
        if !self.authorize(subject, request)
            || attachment.is_some_and(|a| a != b"fixture-provenance")
        {
            return Err(zenoh_result::zerror!("fixture origin denied").into());
        }
        Ok(attachment.map(|a| a.to_vec()))
    }
}

// Real native face, declarations and reconfiguration. TCP is a local test fixture only.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_face_reconfiguration_preserves_claims_and_declaration_caps() {
    use crate::net::runtime::RuntimeBuilder;
    let config = crate::Config::from_json5(
        r#"{
        mode: "router", listen: {endpoints:["tcp/127.0.0.1:0"]},
        scouting: {multicast:{enabled:false}}
    }"#,
    )
    .unwrap();
    let mut router = RuntimeBuilder::new(config).build().await.unwrap();
    router.install_route_gate(Arc::new(Allow)).unwrap();
    router.start().await.unwrap();
    let mut config = crate::Config::default();
    config.insert_json5("mode", r#""client""#).unwrap();
    config
        .insert_json5("scouting/multicast/enabled", "false")
        .unwrap();
    config
        .insert_json5(
            "connect/endpoints",
            &format!(r#"["{}"]"#, router.get_locators()[0]),
        )
        .unwrap();
    let client = crate::open(config).await.unwrap();
    let mut queryables = vec![];
    for id in 0..IdKind::Queryable.business_limit() {
        queryables.push(
            client
                .declare_queryable(format!("budget/{id}"))
                .await
                .unwrap(),
        );
    }
    let gateway = router.router();
    let tables = &gateway.tables;
    // Wait for native ingress to populate the remote client face.
    for _ in 0..300 {
        let count = tables
            .tables
            .read()
            .unwrap()
            .data
            .faces
            .values()
            .filter(|f| !f.is_local)
            .map(|f| f.remote_mappings.len())
            .sum::<usize>();
        if count >= IdKind::Queryable.business_limit() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // A reconfiguration actually rebuilds every face's interceptor chains.
    let config = router.config().lock().clone();
    for _ in 0..3 {
        tables.update_config(&config).unwrap();
    }
    // The factory recreates wrappers but returns the same live metadata Owner.
    // A duplicate key from a different physical client must remain rejected after reload.
    let mut config = crate::Config::default();
    config.insert_json5("mode", r#""client""#).unwrap();
    config
        .insert_json5("scouting/multicast/enabled", "false")
        .unwrap();
    config
        .insert_json5(
            "connect/endpoints",
            &format!(r#"["{}"]"#, router.get_locators()[0]),
        )
        .unwrap();
    let second = crate::open(config).await.unwrap();
    let _duplicate = second.declare_queryable("budget/0").await.unwrap();
    let _excess = client.declare_queryable("budget/excess").await.unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    let queries_lock = tables.queries_lock.read().unwrap();
    let state = tables.tables.read().unwrap();
    assert_eq!(
        state
            .data
            .faces
            .values()
            .filter(|f| !f.is_local)
            .map(|f| f.pending_queries.len())
            .sum::<usize>(),
        0
    );
    drop(state);
    drop(queries_lock);
    // Verify quota through native routing, not the client's local declaration return.
    let platform = crate::session::init(router.clone().into()).await.unwrap();
    // A local EPrimitives return value is a network-statistics flag, not callback admission.
    let local = platform.declare_queryable("center/control").await.unwrap();
    let replies = client
        .get("center/control")
        .consolidation(crate::query::ConsolidationMode::None)
        .timeout(Duration::from_secs(1))
        .await
        .unwrap();
    let inbound = tokio::time::timeout(Duration::from_millis(500), local.recv_async())
        .await
        .unwrap()
        .unwrap();
    inbound.reply("center/control", "accepted").await.unwrap();
    drop(inbound);
    assert!(replies.recv_async().await.unwrap().result().is_ok());
    drop(local);
    let requests = platform
        .get("budget/excess")
        .timeout(Duration::from_millis(100))
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(200), _excess.recv_async())
            .await
            .is_err()
    );
    let request = platform
        .get("budget/0")
        .consolidation(crate::query::ConsolidationMode::None)
        .timeout(Duration::from_millis(500))
        .await
        .unwrap();
    let query = tokio::time::timeout(Duration::from_millis(300), queryables[0].recv_async())
        .await
        .unwrap()
        .unwrap();
    query.reply("budget/0", "ok").await.unwrap();
    drop(query);
    assert!(request.recv_async().await.unwrap().result().is_ok());
    assert!(
        tokio::time::timeout(Duration::from_millis(100), _duplicate.recv_async())
            .await
            .is_err()
    );
    drop(requests);
    // Egress denial must release native pending state immediately (not after an hour).
    let denied = platform
        .get("budget/2")
        .timeout(Duration::from_secs(3600))
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(300), denied.recv_async())
            .await
            .unwrap()
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), queryables[2].recv_async())
            .await
            .is_err()
    );
    {
        let state = tables.tables.read().unwrap();
        let _queries = tables.queries_lock.read().unwrap();
        assert_eq!(
            state
                .data
                .faces
                .values()
                .map(|f| f.pending_queries.len())
                .sum::<usize>(),
            0
        );
    }
    // Native pending capacity also covers trusted local senders; inspect the real maps.
    let mut requests = Vec::new();
    let mut held = Vec::new();
    for _ in 0..1024 {
        requests.push(
            platform
                .get("budget/1")
                .timeout(Duration::from_secs(3600))
                .await
                .unwrap(),
        );
        held.push(
            tokio::time::timeout(Duration::from_secs(1), queryables[1].recv_async())
                .await
                .unwrap()
                .unwrap(),
        );
    }
    {
        let state = tables.tables.read().unwrap();
        let _queries = tables.queries_lock.read().unwrap();
        assert_eq!(
            state
                .data
                .faces
                .values()
                .filter(|f| !f.is_local)
                .map(|f| f.pending_queries.len())
                .sum::<usize>(),
            1024
        );
    }
    let excess = platform
        .get("budget/1")
        .timeout(Duration::from_secs(3600))
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(300), excess.recv_async())
            .await
            .unwrap()
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), queryables[1].recv_async())
            .await
            .is_err()
    );
    // Business pressure must leave both native pending state and egress correlations
    // available for the Host-classified control class on this same target face.
    // The body cap excludes the separately bounded reserved origin attachment.
    let boundary = platform
        .get("budget/1")
        .payload(vec![b'C'; 4 * 1024 * 1024 + 32 * 1024])
        .attachment("fixture-provenance")
        .timeout(Duration::from_secs(60))
        .await
        .unwrap();
    let query = tokio::time::timeout(Duration::from_secs(3), queryables[1].recv_async())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(query.payload().unwrap().len(), 4 * 1024 * 1024 + 32 * 1024);
    query
        .reply("budget/1", "attached boundary accepted")
        .await
        .unwrap();
    drop(query);
    assert!(boundary.recv_async().await.unwrap().result().is_ok());
    assert!(boundary.recv_async().await.is_err());
    let oversized = platform
        .get("budget/1")
        .payload(vec![b'C'; 4 * 1024 * 1024 + 32 * 1024 + 1])
        .attachment("fixture-provenance")
        .timeout(Duration::from_secs(60))
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(3), oversized.recv_async())
            .await
            .unwrap()
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), queryables[1].recv_async())
            .await
            .is_err()
    );
    let mut control_requests = Vec::new();
    let mut control_held = Vec::new();
    for _ in 0..CONTROL_QUERY_LIMIT {
        control_requests.push(
            platform
                .get("budget/1")
                .payload("control")
                .timeout(Duration::from_secs(60))
                .await
                .unwrap(),
        );
        control_held.push(
            tokio::time::timeout(Duration::from_secs(1), queryables[1].recv_async())
                .await
                .unwrap()
                .unwrap(),
        );
    }
    {
        let state = tables.tables.read().unwrap();
        let _queries = tables.queries_lock.read().unwrap();
        assert_eq!(
            state
                .data
                .faces
                .values()
                .filter(|f| !f.is_local)
                .map(|f| f.pending_queries.len())
                .sum::<usize>(),
            QUERY_LIMIT + CONTROL_QUERY_LIMIT
        );
    }
    let control_excess = platform
        .get("budget/1")
        .payload("control")
        .timeout(Duration::from_secs(60))
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(300), control_excess.recv_async())
            .await
            .unwrap()
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), queryables[1].recv_async())
            .await
            .is_err()
    );
    let first = control_held.pop().unwrap();
    first
        .reply("budget/1", "control survived business pressure")
        .await
        .unwrap();
    drop(first);
    assert!(tokio::time::timeout(
        Duration::from_secs(1),
        control_requests.last().unwrap().recv_async()
    )
    .await
    .unwrap()
    .unwrap()
    .result()
    .is_ok());
    drop(control_held);
    drop(control_requests);
    drop(held);
    for _ in 0..300 {
        let state = tables.tables.read().unwrap();
        let _queries = tables.queries_lock.read().unwrap();
        let count = state
            .data
            .faces
            .values()
            .map(|f| f.pending_queries.len())
            .sum::<usize>();
        drop(_queries);
        drop(state);
        if count == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    {
        let state = tables.tables.read().unwrap();
        let _queries = tables.queries_lock.read().unwrap();
        assert_eq!(
            state
                .data
                .faces
                .values()
                .map(|f| f.pending_queries.len())
                .sum::<usize>(),
            0
        );
    }
    // Exercise the dispatcher wire normalization itself, rather than a separate estimator.
    let state = tables
        .tables
        .read()
        .unwrap()
        .data
        .faces
        .values()
        .find(|f| f.is_local)
        .unwrap()
        .clone();
    let face = crate::net::routing::dispatcher::face::Face {
        tables: tables.clone(),
        state,
    };
    let mut message = zenoh_protocol::network::Request::rand();
    message.wire_expr = zenoh_protocol::core::WireExpr::empty()
        .with_suffix("budget/absent")
        .to_owned();
    message.ext_nodeid.node_id = 0;
    message.ext_timeout = Some(Duration::from_secs(3600));
    face.route_query(&mut message);
    assert_eq!(message.ext_timeout, Some(Duration::from_secs(60)));
    drop(requests);
    drop(queryables);
    second.close().await.unwrap();
    client.close().await.unwrap();
    platform.close().await.unwrap();
    router.close().await.unwrap();
}

#[cfg(feature = "plugins")]
#[test]
fn official_native_check_rejects_earlier_same_profile_layout() {
    let current = zenoh_plugin_trait::Compatibility::new(crate::GIT_VERSION, crate::FEATURES);
    let same = zenoh_plugin_trait::Compatibility::new(crate::GIT_VERSION, crate::FEATURES);
    assert!(current.check(&same).is_ok());
    // Upstream extracts only the first hyphen-delimited commit segment. Our
    // revision must be a single segment, or a suffix would silently be ignored.
    assert_eq!(crate::GIT_VERSION.split('-').count(), 2);
    #[cfg(feature = "zenss-router-origin")]
    let old_version = "v1.10.1-zenss-route-gate-2";
    #[cfg(not(feature = "zenss-router-origin"))]
    let old_version = "v1.10.1-zenss-route-gate-1";
    let old = zenoh_plugin_trait::Compatibility::new(old_version, crate::FEATURES);
    assert!(current.check(&old).is_err());
    #[cfg(feature = "zenss-router-origin")]
    let previous = "v1.10.1-zenssroutegate2_resourcebudget3";
    #[cfg(not(feature = "zenss-router-origin"))]
    let previous = "v1.10.1-zenssroutegate1_resourcebudget3";
    assert!(current
        .check(&zenoh_plugin_trait::Compatibility::new(
            previous,
            crate::FEATURES
        ))
        .is_err());
}

#[test]
fn declaration_pressure_cannot_spend_control_metadata_reserve() {
    let budget = Arc::new(AtomicUsize::new(0));
    let business = Reservation::new(&budget, STATE_BYTES - CONTROL_STATE_BYTES).unwrap();
    assert!(Reservation::new(&budget, 1).is_none());
    let control =
        Reservation::for_query(&budget, CONTROL_STATE_BYTES, QueryCapacity::Control).unwrap();
    assert!(Reservation::for_query(&budget, 1, QueryCapacity::Control).is_none());
    drop(control);
    assert!(Reservation::new(&budget, 1).is_none());
    drop(business);
    assert_eq!(budget.load(Ordering::Acquire), 0);
}

#[test]
fn declaration_id_reserves_preserve_absolute_limits_duplicate_updates_and_release() {
    for kind in [
        IdKind::Resource,
        IdKind::Queryable,
        IdKind::Subscriber,
        IdKind::Token,
    ] {
        let budget = Arc::default();
        let mut ids = Declarations::default();
        for id in 0..kind.business_limit() as u32 {
            assert!(ids.admit(kind, id, "key", &budget));
        }
        let next = kind.business_limit() as u32;
        assert!(!ids.admit(kind, next, "key", &budget));
        for id in next..kind.limit() as u32 {
            assert!(ids.admit_with_capacity(kind, id, "key", &budget, QueryCapacity::Control));
        }
        assert!(!ids.admit_with_capacity(
            kind,
            kind.limit() as u32,
            "key",
            &budget,
            QueryCapacity::Control
        ));
        let before = budget.load(Ordering::Acquire);
        assert!(ids.admit_with_capacity(kind, 0, "key", &budget, QueryCapacity::Control));
        assert!(!ids.admit_with_capacity(kind, 0, "other", &budget, QueryCapacity::Control));
        assert_eq!(budget.load(Ordering::Acquire), before);
        ids.remove(kind, next);
        assert!(ids.admit_with_capacity(kind, next, "key", &budget, QueryCapacity::Control));
        drop(ids);
        assert_eq!(budget.load(Ordering::Acquire), 0);
    }
}

#[test]
fn declaration_global_and_flow_pressure_preserve_query_metadata_and_atomic_refusal() {
    let budget = Arc::default();
    let business = Reservation::new(&budget, STATE_BYTES - CONTROL_STATE_BYTES).unwrap();
    assert!(Reservation::new(&budget, 1).is_none());
    let declaration = Reservation::for_declaration(
        &budget,
        CONTROL_STATE_BYTES - 512 * 1024,
        QueryCapacity::Control,
    )
    .unwrap();
    assert!(Reservation::for_declaration(&budget, 1, QueryCapacity::Control).is_none());
    let query = Reservation::for_query(&budget, 512 * 1024, QueryCapacity::Control).unwrap();
    assert_eq!(budget.load(Ordering::Acquire), STATE_BYTES);
    drop((business, declaration, query));
    assert_eq!(budget.load(Ordering::Acquire), 0);
    let mut ids = Declarations::default();
    // Long exact keys reach the per-flow byte ceiling before the Resource ID cap.
    let key = "x".repeat(KEY_BYTES);
    let mut id = 0;
    while ids.admit(IdKind::Resource, id, &key, &budget) {
        id += 1;
    }
    let before = budget.load(Ordering::Acquire);
    assert!(ids.admit_with_capacity(IdKind::Resource, id, &key, &budget, QueryCapacity::Control));
    assert!(budget.load(Ordering::Acquire) > before);
    while ids.admit_with_capacity(
        IdKind::Resource,
        id + 1,
        &key,
        &budget,
        QueryCapacity::Control,
    ) {
        id += 1;
    }
    let before = (ids.ids.len(), ids.bytes, budget.load(Ordering::Acquire));
    assert!(!ids.admit_with_capacity(
        IdKind::Resource,
        id + 100,
        &key,
        &budget,
        QueryCapacity::Control
    ));
    assert_eq!(
        (ids.ids.len(), ids.bytes, budget.load(Ordering::Acquire)),
        before
    );
    drop(ids);
    assert_eq!(budget.load(Ordering::Acquire), 0);
}

// Exercise Request admission itself: a Reservation-only test cannot detect a
// declaration allocator accidentally used by the production Query branch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interceptor_query_uses_metadata_floor_after_declaration_pressure() {
    struct ControlQuery;
    impl RouteGate for ControlQuery {
        fn authorize(&self, _: &RouteSubject, _: &RouteRequest<'_>) -> bool {
            true
        }
        fn query_capacity(
            &self,
            request: &RouteRequest<'_>,
            _: QueryCapacitySource,
        ) -> QueryCapacity {
            if request.key == Some("control/query") {
                QueryCapacity::Control
            } else {
                QueryCapacity::Business
            }
        }
    }
    struct Context(&'static str);
    impl InterceptorContext for Context {
        fn face(&self) -> Option<crate::net::routing::dispatcher::face::Face> {
            None
        }
        fn full_expr(&self, _: &NetworkMessageMut) -> Option<&str> {
            Some(self.0)
        }
        fn get_cache(&self, _: &NetworkMessageMut) -> Option<&Box<dyn Any + Send + Sync>> {
            None
        }
    }
    let config = crate::Config::from_json5(
        r#"{mode:"router",listen:{endpoints:["tcp/127.0.0.1:0"]},scouting:{multicast:{enabled:false}}}"#,
    ).unwrap();
    let mut router = crate::net::runtime::RuntimeBuilder::new(config)
        .build()
        .await
        .unwrap();
    router.start().await.unwrap();
    let config = crate::Config::from_json5(&format!(
        r#"{{mode:"client",connect:{{endpoints:["{}"]}},scouting:{{multicast:{{enabled:false}}}}}}"#,
        router.get_locators()[0]
    )).unwrap();
    let client = crate::open(config).await.unwrap();
    let transport = router
        .manager()
        .get_transports_unicast()
        .await
        .into_iter()
        .next()
        .unwrap();
    for flow in [RouteFlow::Ingress, RouteFlow::Egress] {
        let budget = Arc::default();
        let held =
            Reservation::for_declaration(&budget, STATE_BYTES - 512 * 1024, QueryCapacity::Control)
                .unwrap();
        let owner = Arc::new(FaceResources::default());
        let interceptor = GateInterceptor {
            gate: Arc::new(ControlQuery),
            transport: Some(transport.clone()),
            flow,
            claims: Arc::default(),
            owner: owner.clone(),
            budget: budget.clone(),
            tx_budget: Arc::default(),
        };
        let mut request = zenoh_protocol::network::Request::rand();
        request.id = 1;
        request.payload = zenoh_protocol::zenoh::RequestBody::Query(Default::default());
        let mut message = NetworkMessageMut {
            body: NetworkBodyMut::Request(&mut request),
            reliability: zenoh_protocol::core::Reliability::Reliable,
        };
        assert!(!interceptor.intercept(&mut message, &mut Context("business/query")));
        assert_eq!(budget.load(Ordering::Acquire), held.bytes);
        assert!(interceptor.intercept(&mut message, &mut Context("control/query")));
        let used = budget.load(Ordering::Acquire);
        assert_eq!(used, held.bytes + "control/query".len() + 128);
        // Duplicate ID and absolute exhaustion refuse without changing ownership.
        assert!(!interceptor.intercept(&mut message, &mut Context("control/query")));
        let rest =
            Reservation::for_query(&budget, STATE_BYTES - used, QueryCapacity::Control).unwrap();
        request.id = 2;
        let mut message = NetworkMessageMut {
            body: NetworkBodyMut::Request(&mut request),
            reliability: zenoh_protocol::core::Reliability::Reliable,
        };
        assert!(!interceptor.intercept(&mut message, &mut Context("control/query")));
        assert_eq!(budget.load(Ordering::Acquire), STATE_BYTES);
        drop(rest);
        drop(interceptor);
        drop(owner);
        assert_eq!(budget.load(Ordering::Acquire), held.bytes);
        drop(held);
        assert_eq!(budget.load(Ordering::Acquire), 0);
    }
    client.close().await.unwrap();
    router.close().await.unwrap();
}

#[test]
fn interest_control_classification_requires_all_reverse_permissions() {
    use zenoh_protocol::network::interest::InterestOptions as O;
    struct Scoped {
        mixed: bool,
        panic: bool,
    }
    impl RouteGate for Scoped {
        fn resource_capacity(&self, key: &str) -> QueryCapacity {
            if key == "control/exact" {
                QueryCapacity::Control
            } else {
                QueryCapacity::Business
            }
        }
        fn authorize(&self, subject: &RouteSubject, request: &RouteRequest<'_>) -> bool {
            if self.panic {
                panic!("unavailable authority");
            }
            subject.tls_common_name.is_some()
                && (request.action == RouteAction::Interest
                    || (request.flow == RouteFlow::Egress
                        && request.action == RouteAction::DeclareQueryable)
                    || (self.mixed
                        && request.flow == RouteFlow::Egress
                        && request.action == RouteAction::Resource))
        }
    }
    let mut subject = RouteSubject {
        public_key_der: None,
        tls_common_name: Some("authenticated".into()),
        role: WhatAmI::Client,
    };
    let capacity = |g: &Scoped, s: &RouteSubject, k, o, f| subject_interest_capacity(g, s, k, o, f);
    let g = Scoped {
        mixed: false,
        panic: false,
    };
    assert_eq!(
        capacity(
            &g,
            &subject,
            "control/exact",
            O::QUERYABLES,
            RouteFlow::Ingress
        ),
        QueryCapacity::Control
    );
    for (key, options, flow) in [
        (
            "control/exact",
            O::QUERYABLES + O::KEYEXPRS,
            RouteFlow::Ingress,
        ),
        (
            "control/exact",
            O::QUERYABLES + O::SUBSCRIBERS,
            RouteFlow::Ingress,
        ),
        ("control/exact", O::TOKENS, RouteFlow::Ingress),
        ("control/exact", O::QUERYABLES, RouteFlow::Egress),
        ("control/*", O::QUERYABLES, RouteFlow::Ingress),
        ("", O::QUERYABLES, RouteFlow::Ingress),
    ] {
        assert_eq!(
            capacity(&g, &subject, key, options, flow),
            QueryCapacity::Business
        );
    }
    assert_eq!(
        capacity(
            &Scoped {
                mixed: true,
                panic: false
            },
            &subject,
            "control/exact",
            O::QUERYABLES + O::KEYEXPRS,
            RouteFlow::Ingress
        ),
        QueryCapacity::Control
    );
    assert_eq!(
        capacity(
            &Scoped {
                mixed: true,
                panic: true
            },
            &subject,
            "control/exact",
            O::QUERYABLES,
            RouteFlow::Ingress
        ),
        QueryCapacity::Business
    );
    subject.tls_common_name = None;
    assert_eq!(
        capacity(
            &g,
            &subject,
            "control/exact",
            O::QUERYABLES,
            RouteFlow::Ingress
        ),
        QueryCapacity::Business
    );
}

#[test]
fn current_and_future_wire_interests_share_control_reserve_and_reclaim() {
    let budget = Arc::default();
    let mut ids = Declarations::default();
    let business = IdKind::Interest.business_limit() as u32;
    for id in 0..business {
        assert!(ids.admit(IdKind::Interest, id, "business", &budget));
    }
    assert!(!ids.admit(IdKind::CurrentInterest, business, "control/exact", &budget));
    for id in business..IdKind::Interest.limit() as u32 {
        let kind = if id % 2 == 0 {
            IdKind::CurrentInterest
        } else {
            IdKind::Interest
        };
        assert!(ids.admit_with_capacity(
            kind,
            id,
            "control/exact",
            &budget,
            QueryCapacity::Control
        ));
        let used = budget.load(Ordering::Acquire);
        assert!(ids.admit_with_capacity(
            kind,
            id,
            "control/exact",
            &budget,
            QueryCapacity::Business
        ));
        assert_eq!(budget.load(Ordering::Acquire), used);
        assert!(!ids.admit_with_capacity(
            if kind == IdKind::Interest {
                IdKind::CurrentInterest
            } else {
                IdKind::Interest
            },
            id,
            "control/exact",
            &budget,
            QueryCapacity::Control
        ));
    }
    assert!(!ids.admit_with_capacity(
        IdKind::Interest,
        500,
        "control/exact",
        &budget,
        QueryCapacity::Control
    ));
    ids.remove(IdKind::CurrentInterest, business);
    assert!(ids.admit_with_capacity(
        IdKind::CurrentInterest,
        business,
        "control/exact",
        &budget,
        QueryCapacity::Control
    ));
    drop(ids);
    assert_eq!(budget.load(Ordering::Acquire), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_interest_pressure_requires_reverse_declaration_before_reserve() {
    use std::sync::atomic::AtomicBool;
    use zenoh_protocol::network::interest::InterestOptions;
    struct Policy(AtomicBool);
    impl RouteGate for Policy {
        fn resource_capacity(&self, key: &str) -> QueryCapacity {
            if key == "control/exact" {
                QueryCapacity::Control
            } else {
                QueryCapacity::Business
            }
        }
        fn authorize(&self, _: &RouteSubject, request: &RouteRequest<'_>) -> bool {
            request.action == RouteAction::Interest || self.0.load(Ordering::Acquire)
        }
    }
    struct Context;
    impl InterceptorContext for Context {
        fn face(&self) -> Option<crate::net::routing::dispatcher::face::Face> {
            None
        }
        fn full_expr(&self, _: &NetworkMessageMut) -> Option<&str> {
            Some("control/exact")
        }
        fn get_cache(&self, _: &NetworkMessageMut) -> Option<&Box<dyn Any + Send + Sync>> {
            None
        }
    }
    let config=crate::Config::from_json5(r#"{mode:"router",listen:{endpoints:["tcp/127.0.0.1:0"]},scouting:{multicast:{enabled:false}}}"#).unwrap();
    let mut router = crate::net::runtime::RuntimeBuilder::new(config)
        .build()
        .await
        .unwrap();
    router.start().await.unwrap();
    let config=crate::Config::from_json5(&format!(r#"{{mode:"client",connect:{{endpoints:["{}"]}},scouting:{{multicast:{{enabled:false}}}}}}"#,router.get_locators()[0])).unwrap();
    let client = crate::open(config).await.unwrap();
    let transport = router
        .manager()
        .get_transports_unicast()
        .await
        .into_iter()
        .next()
        .unwrap();
    for flow in [RouteFlow::Ingress, RouteFlow::Egress] {
        let gate = Arc::new(Policy(AtomicBool::new(false)));
        let factory = GateFactory::new(gate.clone());
        let owner = factory.resources(&transport).unwrap();
        let ids = if flow == RouteFlow::Ingress {
            &owner.incoming
        } else {
            &owner.outgoing
        };
        for id in 0..IdKind::Interest.business_limit() as u32 {
            assert!(ids
                .lock()
                .unwrap()
                .admit(IdKind::Interest, id, "business", &factory.budget));
        }
        let interceptor = GateInterceptor {
            gate: gate.clone(),
            transport: Some(transport.clone()),
            flow,
            claims: factory.claims.clone(),
            owner: owner.clone(),
            budget: factory.budget.clone(),
            tx_budget: Arc::default(),
        };
        let mut interest = zenoh_protocol::network::Interest {
            id: 500,
            mode: InterestMode::CurrentFuture,
            options: InterestOptions::QUERYABLES,
            wire_expr: Some("control/exact".into()),
            ext_qos: Default::default(),
            ext_tstamp: None,
            ext_nodeid: Default::default(),
        };
        let before = factory.budget.load(Ordering::Acquire);
        let mut msg = NetworkMessageMut {
            body: NetworkBodyMut::Interest(&mut interest),
            reliability: zenoh_protocol::core::Reliability::Reliable,
        };
        assert!(!interceptor.intercept(&mut msg, &mut Context));
        assert_eq!(factory.budget.load(Ordering::Acquire), before);
        gate.0.store(true, Ordering::Release);
        assert!(interceptor.intercept(&mut msg, &mut Context));
        let used = factory.budget.load(Ordering::Acquire);
        assert!(used > before);
        assert!(interceptor.intercept(&mut msg, &mut Context));
        assert_eq!(factory.budget.load(Ordering::Acquire), used);
        interest.mode = InterestMode::Final;
        gate.0.store(false, Ordering::Release);
        let mut msg = NetworkMessageMut {
            body: NetworkBodyMut::Interest(&mut interest),
            reliability: zenoh_protocol::core::Reliability::Reliable,
        };
        assert!(interceptor.intercept(&mut msg, &mut Context));
        assert_eq!(factory.budget.load(Ordering::Acquire), before);
        drop(interceptor);
        drop(owner);
        assert_eq!(factory.budget.load(Ordering::Acquire), 0);
    }
    client.close().await.unwrap();
    router.close().await.unwrap();
}

#[test]
fn complete_encoding_counter_matches_official_codec_and_exact_boundaries() {
    use zenoh_buffers::writer::HasWriter;
    for _ in 0..128 {
        let mut owned = zenoh_protocol::network::NetworkMessage::rand();
        let mut bytes = Vec::new();
        Zenoh080::new().write(&mut bytes.writer(), &owned).unwrap();
        let msg = owned.as_mut();
        assert_eq!(encoded_message_len(&msg, bytes.len()), Some(bytes.len()));
        assert_eq!(encoded_message_len(&msg, bytes.len() - 1), None);
        assert_eq!(encoded_message_len(&msg, usize::MAX), Some(bytes.len()));
    }
    let mut counter = EncodedCounter { used: 0, limit: 1 };
    assert!(counter.write(&[]).is_err());
    counter.write_exact(&[]).unwrap();
    // Maximum VLE scratch does not consume nine bytes for a one-byte integer.
    Zenoh080::new().write(&mut counter, 1u64).unwrap();
    assert_eq!(counter.used, 1);
    assert!(counter.charge(usize::MAX).is_err());
    assert_eq!(counter.used, 1);
    // No heap scratch or truncation if a future codec asks for a larger slot.
    assert!(unsafe { counter.with_slot(10, |_| panic!("unexpected codec scratch")) }.is_err());
}

#[test]
fn complete_encoding_counts_parameters_unknown_extensions_and_error_bodies() {
    use zenoh_protocol::{
        common::{ZExtBody, ZExtUnknown},
        network::Request,
    };
    let large: zenoh_buffers::ZBuf = vec![0u8; ENCODED_MESSAGE_BYTES].into();
    let mut request = Request::rand();
    request.payload = zenoh_protocol::zenoh::RequestBody::Query(Default::default());
    let zenoh_protocol::zenoh::RequestBody::Query(query) = &mut request.payload;
    query.parameters = "p".repeat(ENCODED_MESSAGE_BYTES);
    assert!(request.payload_size() < ENCODED_MESSAGE_BYTES);
    assert!(encoded_message_len(&request_message(&mut request), ENCODED_MESSAGE_BYTES).is_none());
    let zenoh_protocol::zenoh::RequestBody::Query(query) = &mut request.payload;
    query.parameters.clear();
    query.ext_unknown.push(ZExtUnknown {
        id: 0x4f,
        body: ZExtBody::ZBuf(large.clone()),
    });
    assert!(request.payload_size() < ENCODED_MESSAGE_BYTES);
    assert!(encoded_message_len(&request_message(&mut request), ENCODED_MESSAGE_BYTES).is_none());
    let mut response = zenoh_protocol::network::Response::rand();
    let mut error = zenoh_protocol::zenoh::Err::rand();
    error.payload = large.clone();
    response.payload = ResponseBody::Err(error);
    assert!(encoded_message_len(
        &NetworkMessageMut {
            body: NetworkBodyMut::Response(&mut response),
            reliability: zenoh_protocol::core::Reliability::Reliable
        },
        ENCODED_MESSAGE_BYTES
    )
    .is_none());
    let mut push = zenoh_protocol::network::Push::rand();
    let mut put = zenoh_protocol::zenoh::Put::rand();
    put.payload = vec![0u8; 1].into();
    put.ext_attachment = Some(zenoh_protocol::zenoh::put::ext::AttachmentType { buffer: large });
    push.payload = PushBody::Put(put);
    assert!(encoded_message_len(
        &NetworkMessageMut {
            body: NetworkBodyMut::Push(&mut push),
            reliability: zenoh_protocol::core::Reliability::Reliable
        },
        ENCODED_MESSAGE_BYTES
    )
    .is_none());
}
fn request_message(request: &mut zenoh_protocol::network::Request) -> NetworkMessageMut<'_> {
    NetworkMessageMut {
        body: NetworkBodyMut::Request(request),
        reliability: zenoh_protocol::core::Reliability::Reliable,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_encoding_preflight_refuses_before_authority_and_preserves_reply_owner() {
    struct Gate(Arc<AtomicUsize>);
    impl RouteGate for Gate {
        fn authorize(&self, _: &RouteSubject, _: &RouteRequest<'_>) -> bool {
            self.0.fetch_add(1, Ordering::SeqCst);
            true
        }
        #[cfg(feature = "zenss-router-origin")]
        fn query_origin(
            &self,
            _: &RouteSubject,
            _: &RouteRequest<'_>,
            _: Option<&[u8]>,
        ) -> ZResult<Option<Vec<u8>>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(Some(vec![0; 8192]))
        }
    }
    struct Context;
    impl InterceptorContext for Context {
        fn face(&self) -> Option<crate::net::routing::dispatcher::face::Face> {
            None
        }
        fn full_expr(&self, _: &NetworkMessageMut) -> Option<&str> {
            Some("control/query")
        }
        fn get_cache(&self, _: &NetworkMessageMut) -> Option<&Box<dyn Any + Send + Sync>> {
            None
        }
    }
    let config=crate::Config::from_json5(r#"{mode:"router",listen:{endpoints:["tcp/127.0.0.1:0"]},scouting:{multicast:{enabled:false}}}"#).unwrap();
    let mut router = crate::net::runtime::RuntimeBuilder::new(config)
        .build()
        .await
        .unwrap();
    router.start().await.unwrap();
    let config=crate::Config::from_json5(&format!(r#"{{mode:"client",connect:{{endpoints:["{}"]}},scouting:{{multicast:{{enabled:false}}}}}}"#,router.get_locators()[0])).unwrap();
    let client = crate::open(config).await.unwrap();
    let transport = router
        .manager()
        .get_transports_unicast()
        .await
        .into_iter()
        .next()
        .unwrap();
    for flow in [RouteFlow::Ingress, RouteFlow::Egress] {
        let checks = Arc::new(AtomicUsize::new(0));
        let owner = Arc::new(FaceResources::default());
        let budget = Arc::new(AtomicUsize::new(0));
        let interceptor = GateInterceptor {
            gate: Arc::new(Gate(checks.clone())),
            transport: Some(transport.clone()),
            flow,
            claims: Arc::default(),
            owner: owner.clone(),
            budget: budget.clone(),
            tx_budget: Arc::default(),
        };
        let mut request = zenoh_protocol::network::Request::rand();
        request.id = 99;
        request.payload = zenoh_protocol::zenoh::RequestBody::Query(Default::default());
        let zenoh_protocol::zenoh::RequestBody::Query(query) = &mut request.payload;
        query.parameters = "x".repeat(ENCODED_MESSAGE_BYTES);
        assert!(!interceptor.intercept(&mut request_message(&mut request), &mut Context));
        assert_eq!(checks.load(Ordering::SeqCst), 0);
        assert_eq!(budget.load(Ordering::Acquire), 0);
        assert!(owner.pending.lock().unwrap().incoming.is_empty());
        assert!(owner.pending.lock().unwrap().outgoing.is_empty());
        #[cfg(feature = "zenss-router-origin")]
        {
            let zenoh_protocol::zenoh::RequestBody::Query(query) = &mut request.payload;
            query.parameters.clear();
            let base = encoded_message_len(&request_message(&mut request), usize::MAX).unwrap();
            let zenoh_protocol::zenoh::RequestBody::Query(query) = &mut request.payload;
            query.parameters = "x".repeat(ENCODED_MESSAGE_BYTES - base - 32);
            assert!(
                encoded_message_len(&request_message(&mut request), ENCODED_MESSAGE_BYTES)
                    .is_some()
            );
            assert!(!interceptor.intercept(&mut request_message(&mut request), &mut Context));
            assert_eq!(checks.load(Ordering::SeqCst), 1);
            assert_eq!(budget.load(Ordering::Acquire), 0);
        }
        // A too-large Err has the right RID and no key, but cannot consume or
        // alter a live response correlation. A later bounded reply still works.
        let pending = Pending {
            capacity: QueryCapacity::Business,
            key: "control/query".into(),
            until: Instant::now() + Duration::from_secs(10),
            _reservation: Reservation::new(&budget, 141).unwrap(),
        };
        let mut state = owner.pending.lock().unwrap();
        let map = match flow {
            RouteFlow::Ingress => &mut state.outgoing,
            RouteFlow::Egress => &mut state.incoming,
        };
        map.insert(99, pending);
        drop(state);
        let mut response = zenoh_protocol::network::Response::rand();
        response.rid = 99;
        let mut error = zenoh_protocol::zenoh::Err::rand();
        error.payload = vec![0; ENCODED_MESSAGE_BYTES].into();
        response.payload = ResponseBody::Err(error);
        let before = checks.load(Ordering::SeqCst);
        let mut message = NetworkMessageMut {
            body: NetworkBodyMut::Response(&mut response),
            reliability: zenoh_protocol::core::Reliability::Reliable,
        };
        assert!(!interceptor.intercept(&mut message, &mut Context));
        assert_eq!(checks.load(Ordering::SeqCst), before);
        assert_eq!(budget.load(Ordering::Acquire), 141);
        let ResponseBody::Err(error) = &mut response.payload else {
            unreachable!()
        };
        error.payload = vec![0; 1].into();
        let mut message = NetworkMessageMut {
            body: NetworkBodyMut::Response(&mut response),
            reliability: zenoh_protocol::core::Reliability::Reliable,
        };
        assert!(interceptor.intercept(&mut message, &mut Context));
        let mut final_ = zenoh_protocol::network::ResponseFinal {
            rid: 99,
            ext_qos: Default::default(),
            ext_tstamp: None,
        };
        let mut message = NetworkMessageMut {
            body: NetworkBodyMut::ResponseFinal(&mut final_),
            reliability: zenoh_protocol::core::Reliability::Reliable,
        };
        assert!(interceptor.intercept(&mut message, &mut Context));
        assert_eq!(budget.load(Ordering::Acquire), 0);
    }
    client.close().await.unwrap();
    router.close().await.unwrap();
}

#[test]
fn gated_chain_bounds_post_admission_growth_and_async_fragment_handoffs() {
    struct Boundary;
    impl InterceptorTrait for Boundary {
        fn encoded_message_limit(&self) -> Option<usize> {
            Some(64)
        }
        fn compute_keyexpr_cache(&self, _: &keyexpr) -> Option<Box<dyn Any + Send + Sync>> {
            None
        }
        fn intercept(&self, _: &mut NetworkMessageMut, _: &mut dyn InterceptorContext) -> bool {
            true
        }
    }
    struct Grow;
    impl InterceptorTrait for Grow {
        fn compute_keyexpr_cache(&self, _: &keyexpr) -> Option<Box<dyn Any + Send + Sync>> {
            None
        }
        fn intercept(&self, msg: &mut NetworkMessageMut, _: &mut dyn InterceptorContext) -> bool {
            let NetworkBodyMut::Request(r) = &mut msg.body else {
                return true;
            };
            let zenoh_protocol::zenoh::RequestBody::Query(q) = &mut r.payload;
            q.parameters = "x".repeat(65);
            r.ext_qos
                .set_congestion_control(CongestionControl::BlockFirst);
            true
        }
    }
    let mut context = crate::net::routing::RoutingContext {
        msg: (),
        full_expr: Default::default(),
    };
    let mut request = zenoh_protocol::network::Request::rand();
    request.payload = zenoh_protocol::zenoh::RequestBody::Query(Default::default());
    let gated = super::super::InterceptorsChain::new(vec![Box::new(Boundary), Box::new(Grow)], 0);
    assert!(!gated.intercept(&mut request_message(&mut request), &mut context));
    assert_eq!(
        request.ext_qos.get_congestion_control(),
        CongestionControl::Block
    );
    let ungated = super::super::InterceptorsChain::new(vec![Box::new(Grow)], 0);
    assert!(ungated.intercept(&mut request_message(&mut request), &mut context));
    assert_eq!(
        request.ext_qos.get_congestion_control(),
        CongestionControl::BlockFirst
    );
    // Every message family is normalized using the official QoS setters. The
    // original priority and express bits survive, and ordinary Drop stays Drop.
    for _ in 0..256 {
        let mut owned = zenoh_protocol::network::NetworkMessage::rand();
        let mut msg = owned.as_mut();
        let priority = msg.priority();
        let express = msg.is_express();
        let cc = msg.congestion_control();
        assert!(bound_encoded_message(&mut msg, ENCODED_MESSAGE_BYTES));
        assert_eq!(msg.priority(), priority);
        assert_eq!(msg.is_express(), express);
        assert_eq!(
            msg.congestion_control(),
            if cc == CongestionControl::BlockFirst {
                CongestionControl::Block
            } else {
                cc
            }
        );
    }
}

// Real official wire fragmentation and routing; isolated TCP policy, not mTLS.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_fragmented_tcp_metadata_and_oversized_reply_refuse_then_recover() {
    struct Gate(Arc<AtomicUsize>);
    impl RouteGate for Gate {
        fn authorize(&self, _: &RouteSubject, r: &RouteRequest<'_>) -> bool {
            if r.action == RouteAction::Query {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
            true
        }
    }
    struct Tap(Arc<AtomicUsize>);
    impl InterceptorTrait for Tap {
        fn compute_keyexpr_cache(&self, _: &keyexpr) -> Option<Box<dyn Any + Send + Sync>> {
            None
        }
        fn intercept(&self, msg: &mut NetworkMessageMut, _: &mut dyn InterceptorContext) -> bool {
            if let NetworkBodyMut::Request(r) = &mut msg.body {
                let zenoh_protocol::zenoh::RequestBody::Query(q) = &mut r.payload;
                self.0.fetch_max(q.parameters.len(), Ordering::SeqCst);
            }
            true
        }
    }
    impl InterceptorFactoryTrait for Tap {
        fn new_transport_unicast(
            &self,
            _: &TransportUnicast,
        ) -> (Option<IngressInterceptor>, Option<EgressInterceptor>) {
            (Some(Box::new(Tap(self.0.clone()))), None)
        }
        fn new_transport_multicast(&self, _: &TransportMulticast) -> Option<EgressInterceptor> {
            None
        }
        fn new_peer_multicast(&self, _: &TransportMulticast) -> Option<IngressInterceptor> {
            None
        }
    }
    let decoded = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let config=crate::Config::from_json5(r#"{mode:"router",listen:{endpoints:["tcp/127.0.0.1:0"]},scouting:{multicast:{enabled:false}},transport:{unicast:{qos:{enabled:false}},link:{rx:{max_message_size:33554432}}}}"#).unwrap();
    let mut router = crate::net::runtime::RuntimeBuilder::new(config)
        .build()
        .await
        .unwrap();
    router
        .install_route_gate(Arc::new(Gate(calls.clone())))
        .unwrap();
    // Observe actual post-defragmentation native bytes before gate admission.
    router
        .router()
        .tables
        .tables
        .write()
        .unwrap()
        .data
        .interceptors
        .insert(0, Box::new(Tap(decoded.clone())));
    router.start().await.unwrap();
    let platform = crate::session::init(router.clone().into()).await.unwrap();
    let queryable = platform.declare_queryable("encoded/query").await.unwrap();
    let config=crate::Config::from_json5(&format!(r#"{{mode:"client",connect:{{endpoints:["{}"]}},scouting:{{multicast:{{enabled:false}}}},transport:{{unicast:{{qos:{{enabled:false}}}},link:{{rx:{{max_message_size:33554432}}}}}}}}"#,router.get_locators()[0])).unwrap();
    let client = crate::open(config).await.unwrap();
    // Fully reassemble >21MiB below the fixture's32MiB RX limit, then refuse
    // before Query authority/handler. A payload-only check cannot detect this.
    let replies = client
        .get(format!(
            "encoded/query?p={}",
            "x".repeat(ENCODED_MESSAGE_BYTES)
        ))
        .payload("small")
        .timeout(Duration::from_millis(500))
        .await
        .unwrap();
    while let Ok(reply) = replies.recv_async().await {
        // The stock Query timeout may be an Err reply. It is not a successful
        // Handler result, and it must not contain the refused large body.
        assert!(reply.result().is_err());
        assert!(reply.result().unwrap_err().payload().len() < 1024);
    }
    assert!(decoded.load(Ordering::SeqCst) > ENCODED_MESSAGE_BYTES);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), queryable.recv_async())
            .await
            .is_err()
    );
    for large_reply in [false, true, false] {
        let replies = client
            .get("encoded/query")
            .timeout(Duration::from_millis(500))
            .await
            .unwrap();
        let query = tokio::time::timeout(Duration::from_millis(300), queryable.recv_async())
            .await
            .unwrap()
            .unwrap();
        if large_reply {
            // Local reply builder success is not transport/business acceptance.
            let _ = query.reply_err(vec![0u8; ENCODED_MESSAGE_BYTES]).await;
        } else {
            query.reply("encoded/query", "ok").await.unwrap();
        }
        drop(query);
        if large_reply {
            while let Ok(reply) = replies.recv_async().await {
                assert!(reply.result().is_err());
                assert!(reply.result().unwrap_err().payload().len() < 1024);
            }
        } else {
            assert_eq!(
                replies
                    .recv_async()
                    .await
                    .unwrap()
                    .result()
                    .unwrap()
                    .payload()
                    .to_bytes()
                    .as_ref(),
                b"ok"
            );
        }
    }
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    drop(queryable);
    client.close().await.unwrap();
    platform.close().await.unwrap();
    router.close().await.unwrap();
}
