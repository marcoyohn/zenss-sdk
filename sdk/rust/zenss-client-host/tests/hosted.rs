use std::time::Duration;
use tokio::time::{timeout, Instant};
use zenss_client_host::{HostBinding, HostClientContext};
use zenss_client_sdk::{Client, ClientMode, ClientOptions, ServiceIdentity};
use zenss_plugin_trait::{ManagedPlugin, PluginContext, RunningPlugin};

const KEY: &str = "zenss/v1/dev/products/echo/one/query";
const DISCOVERY: &str = "zenss/v1/dev/discovery/query";
struct Host {
    runtime: zenoh::internal::runtime::Runtime,
    context: PluginContext,
    plugin: RunningPlugin,
    session: zenoh::Session,
}
impl Host {
    async fn new() -> Self {
        let config = zenoh::Config::from_json5(r#"{mode:"router",listen:{endpoints:["tcp/127.0.0.1:0"]},scouting:{multicast:{enabled:false},gossip:{enabled:false}}}"#).unwrap();
        let mut runtime = zenoh::internal::runtime::RuntimeBuilder::new(config)
            .build()
            .await
            .unwrap();
        runtime.start().await.unwrap();
        let (send, receive) = tokio::sync::oneshot::channel();
        let plugin = ManagedPlugin::start(runtime.clone().into(), 8, move |context| async move {
            context.ready()?;
            send.send(context.clone()).ok();
            context.stopping().await;
            Ok(())
        })
        .unwrap();
        let context = receive.await.unwrap();
        let session = context.session().await.unwrap();
        Self {
            runtime,
            context,
            plugin,
            session,
        }
    }
    fn binding(&self, name: &str) -> HostBinding {
        HostBinding {
            identity: ServiceIdentity::new("dev", "example", name).unwrap(),
            query_prefixes: vec!["zenss/v1/dev/products/echo/one".into(), DISCOVERY.into()],
            expires_at: Instant::now() + Duration::from_secs(30),
            timeout: Duration::from_secs(2),
            max_inflight: 2,
        }
    }
    async fn client(&self, name: &str) -> Client<HostClientContext> {
        Client::from_host(self.context.clone(), self.binding(name))
            .await
            .unwrap()
    }
    fn command(&self, action: &str) {
        let map = serde_json::json!({"__zenss__":{"command":{"protocol":1,"action":action}}})
            .as_object()
            .unwrap()
            .clone();
        self.plugin
            .config_checker(
                zenss_plugin_trait::zenss_contracts::LIFECYCLE_CONFIG_PATH,
                &zenoh_util::ffi::JsonKeyValueMap::default(),
                &map.into(),
            )
            .unwrap();
    }
    async fn close(self) {
        self.command("stop");
        timeout(Duration::from_secs(3), async {
            while !self.context.snapshot().cleanup_complete {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        self.session.close().await.unwrap();
        self.runtime.close().await.unwrap();
    }
}
async fn token_count(session: &zenoh::Session, identity: &ServiceIdentity) -> usize {
    let replies = session
        .liveliness()
        .get(identity.liveliness_key().unwrap())
        .timeout(Duration::from_millis(100))
        .await
        .unwrap();
    let mut count = 0;
    while let Ok(reply) = replies.recv_async().await {
        if reply.result().is_ok() {
            count += 1;
        }
    }
    count
}
async fn wait_closed(token: &zenss_client_host::HostAnnouncement) {
    timeout(Duration::from_secs(2), async {
        while !token.is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hosted_and_outbound_share_protocol_but_only_hosted_shares_runtime() {
    let host = Host::new().await;
    let hosted = host.client("one").await;
    assert_eq!(hosted.session().zid(), host.runtime.zid());
    assert_ne!(hosted.session(), &host.session);
    let owned_session = hosted.session().clone();
    let outbound = Client::connect(ClientOptions {
        endpoints: host
            .runtime
            .get_locators()
            .iter()
            .map(ToString::to_string)
            .collect(),
        tls: None,
        timeout_ms: 2000,
    })
    .await
    .unwrap();
    assert_eq!(hosted.mode(), ClientMode::Hosted);
    assert_eq!(outbound.mode(), ClientMode::Outbound);
    assert_ne!(
        outbound.session().zid().to_string(),
        host.session.zid().to_string()
    );
    let queries = host.session.declare_queryable(KEY).await.unwrap();
    for client_payload in [b"host".to_vec(), b"network".to_vec()] {
        let result = async {
            if client_payload == b"host" {
                hosted.query(KEY, client_payload.clone()).await
            } else {
                outbound.query(KEY, client_payload.clone()).await
            }
        };
        let reply = async {
            let q = queries.recv_async().await.unwrap();
            q.reply(KEY, q.payload().unwrap().clone()).await.unwrap();
        };
        let (result, ()) = tokio::join!(result, reply);
        assert_eq!(result.unwrap(), client_payload);
    }
    let discovery = host.session.declare_queryable(DISCOVERY).await.unwrap();
    let identity = hosted.identity().unwrap().clone();
    let reply = async {
        let q = discovery.recv_async().await.unwrap();
        q.reply(
            DISCOVERY,
            serde_json::to_vec(&vec![identity.clone()]).unwrap(),
        )
        .await
        .unwrap();
    };
    let (result, ()) = tokio::join!(hosted.discover("dev"), reply);
    assert_eq!(result.unwrap(), vec![identity.clone()]);
    let token = hosted.announce(&identity).await.unwrap();
    assert_eq!(token_count(&host.session, &identity).await, 1);
    hosted.close().await.unwrap();
    assert!(owned_session.is_closed());
    assert!(token.is_closed());
    assert_eq!(token_count(&host.session, &identity).await, 0);
    assert!(!host.session.is_closed());
    assert!(!outbound.session().is_closed());
    outbound.close().await.unwrap();
    drop((queries, discovery));
    host.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_drop_and_revoke_remove_only_owned_declarations_and_cancel_work() {
    let host = Host::new().await;
    let first = host.client("first").await;
    let second = host.client("second").await;
    let a = first.announce(first.identity().unwrap()).await.unwrap();
    let b = second.announce(second.identity().unwrap()).await.unwrap();
    first.close().await.unwrap();
    assert!(a.is_closed());
    assert!(!b.is_closed());
    assert_eq!(
        token_count(&host.session, second.identity().unwrap()).await,
        1
    );
    let third = host.client("third").await;
    let revoke = third.revocation();
    let queries = host.session.declare_queryable(KEY).await.unwrap();
    let query = third.query(KEY, b"pending".to_vec());
    let cancellation = async {
        let q = queries.recv_async().await.unwrap();
        revoke.revoke();
        q
    };
    let (result, held_query) = tokio::join!(query, cancellation);
    assert!(result.unwrap_err().to_string().contains("revoked"));
    assert_eq!(host.context.snapshot().active_requests, 0);
    assert!(third.query(KEY, Vec::new()).await.is_err());
    drop(second);
    assert!(b.is_closed());
    assert!(!host.session.is_closed());
    third.close().await.unwrap();
    drop((held_query, queries));
    host.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expiry_and_parent_drain_revoke_presence_and_pending_queries() {
    let host = Host::new().await;
    let mut binding = host.binding("expiring");
    binding.expires_at = Instant::now() + Duration::from_millis(200);
    let client = Client::from_host(host.context.clone(), binding)
        .await
        .unwrap();
    let token = client.announce(client.identity().unwrap()).await.unwrap();
    wait_closed(&token).await;
    assert!(client.query(KEY, Vec::new()).await.is_err());
    client.close().await.unwrap();
    let client = host.client("draining").await;
    let token = client.announce(client.identity().unwrap()).await.unwrap();
    let queries = host.session.declare_queryable(KEY).await.unwrap();
    let action = async {
        let q = queries.recv_async().await.unwrap();
        host.command("drain");
        assert!(host.context.spawn_scoped(async { Ok(()) }).is_err());
        q
    };
    let (result, held_query) = tokio::join!(client.query(KEY, Vec::new()), action);
    let error = result.unwrap_err().to_string();
    assert!(
        error.contains("draining") || error.contains("revoked"),
        "{error}"
    );
    wait_closed(&token).await;
    assert_eq!(host.context.snapshot().active_requests, 0);
    assert!(
        Client::from_host(host.context.clone(), host.binding("late"))
            .await
            .is_err()
    );
    client.close().await.unwrap();
    assert!(!host.session.is_closed());
    drop((held_query, queries));
    host.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scope_identity_capacity_and_timeout_are_enforced_without_replay() {
    let host = Host::new().await;
    let mut binding = host.binding("limited");
    binding.max_inflight = 1;
    binding.timeout = Duration::from_millis(100);
    let client = Client::from_host(host.context.clone(), binding)
        .await
        .unwrap();
    for key in [
        "zenss/v1/other/products/echo/one/query",
        "zenss/v1/dev/products/echo/one-other/query",
        "zenss/v1/dev/discovery/query/extra",
        "zenss/v1/dev/products/echo/*",
    ] {
        assert!(client.query(key, Vec::new()).await.is_err());
    }
    assert!(client
        .announce(&ServiceIdentity::new("dev", "example", "impostor").unwrap())
        .await
        .is_err());
    let queries = host.session.declare_queryable(KEY).await.unwrap();
    let concurrent = async {
        let held = queries.recv_async().await.unwrap();
        assert!(client
            .query(KEY, Vec::new())
            .await
            .unwrap_err()
            .to_string()
            .contains("capacity"));
        held
    };
    let (result, held) = tokio::join!(client.query(KEY, Vec::new()), concurrent);
    assert!(result.is_err());
    assert_eq!(host.context.snapshot().active_requests, 0);
    assert!(queries.try_recv().unwrap().is_none());
    let reply = async {
        let q = queries.recv_async().await.unwrap();
        q.reply(KEY, b"ok".to_vec()).await.unwrap();
    };
    let (result, ()) = tokio::join!(client.query(KEY, Vec::new()), reply);
    assert_eq!(result.unwrap(), b"ok");
    client.close().await.unwrap();
    let mut binding = host.binding("presence-only");
    binding.query_prefixes.clear();
    let presence = Client::from_host(host.context.clone(), binding)
        .await
        .unwrap();
    assert!(presence.query(KEY, Vec::new()).await.is_err());
    presence.close().await.unwrap();
    drop((held, queries));
    host.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_invalid_bindings_and_raw_session_closure_is_terminal() {
    let host = Host::new().await;
    for scope in [
        "zenss/v1/dev",
        "zenss/v1/other/products/echo",
        "zenss/v1/dev/products/*",
        "zenss/v1/dev/products/echo/",
    ] {
        let mut binding = host.binding("invalid");
        binding.query_prefixes = vec![scope.into()];
        assert!(Client::from_host(host.context.clone(), binding)
            .await
            .is_err());
    }
    let client = host.client("closed").await;
    let token = client.announce(client.identity().unwrap()).await.unwrap();
    client.session().close().await.unwrap();
    wait_closed(&token).await;
    assert!(client.query(KEY, Vec::new()).await.is_err());
    assert!(!host.session.is_closed());
    let sibling = host.client("after-raw-close").await;
    assert!(!sibling.session().is_closed());
    sibling.close().await.unwrap();
    client.close().await.unwrap();
    host.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plugin_failure_revokes_client_and_scoped_cleanup_is_acknowledged() {
    let host = Host::new().await;
    let client = host.client("failure").await;
    let token = client.announce(client.identity().unwrap()).await.unwrap();
    host.context
        .spawn_scoped(async {
            panic!("injected finite child failure");
        })
        .unwrap();
    wait_closed(&token).await;
    assert!(client.query(KEY, Vec::new()).await.is_err());
    client.close().await.unwrap();
    timeout(Duration::from_secs(2), async {
        while !host.context.snapshot().cleanup_complete {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        host.context.snapshot().phase,
        zenss_plugin_trait::zenss_contracts::PluginPhase::Failed
    );
    host.close().await;
}

async fn wait_session_closed(session: &zenoh::Session) {
    timeout(Duration::from_secs(2), async {
        while !session.is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_entities_and_clones_close_while_sibling_and_host_keep_communicating() {
    let host = Host::new().await;
    let first = host.client("raw-owner").await;
    let sibling = host.client("raw-sibling").await;
    let own = first.session().clone();
    assert_ne!(&own, sibling.session());
    assert_ne!(&own, &host.session);
    assert_eq!(own.zid(), sibling.session().zid());
    let raw_key = "zenss/v1/dev/products/raw/one/query";
    // Deliberate raw escape hatch outside the facade's echo scope.
    let queryable = own.declare_queryable(raw_key).await.unwrap();
    let subscriber = own.declare_subscriber("raw/events").await.unwrap();
    let publisher = own.declare_publisher("raw/events").await.unwrap();
    publisher.put("before close").await.unwrap();
    let sample = timeout(Duration::from_secs(1), subscriber.recv_async())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sample.payload().to_bytes().as_ref(), b"before close");
    own.declare_queryable("raw/background")
        .callback(|_| {})
        .background()
        .await
        .unwrap();
    let (reply, ()) = tokio::join!(
        async {
            let replies = host.session.get(raw_key).await.unwrap();
            replies
                .recv_async()
                .await
                .unwrap()
                .into_result()
                .unwrap()
                .payload()
                .to_bytes()
                .into_owned()
        },
        async {
            let q = queryable.recv_async().await.unwrap();
            q.reply(raw_key, "before close").await.unwrap();
        }
    );
    assert_eq!(reply, b"before close");
    first.close().await.unwrap();
    assert!(own.is_closed()); // even though an application still holds a clone
    assert!(publisher.put("must fail").await.is_err());
    assert!(timeout(Duration::from_secs(1), queryable.recv_async())
        .await
        .unwrap()
        .is_err());
    assert!(timeout(Duration::from_secs(1), subscriber.recv_async())
        .await
        .unwrap()
        .is_err());
    let queries = host.session.declare_queryable(KEY).await.unwrap();
    let (result, ()) = tokio::join!(sibling.query(KEY, Vec::new()), async {
        let q = queries.recv_async().await.unwrap();
        q.reply(KEY, "still alive").await.unwrap();
    });
    assert_eq!(result.unwrap(), b"still alive");
    assert!(!host.runtime.is_closed());
    assert!(!host.session.is_closed());
    drop(queries);
    // Closing the plugin's own Session must not revoke the independently owned Client.
    host.session.close().await.unwrap();
    let responder = host.context.session().await.unwrap();
    let queries = responder.declare_queryable(KEY).await.unwrap();
    let (result, ()) = tokio::join!(sibling.query(KEY, Vec::new()), async {
        let q = queries.recv_async().await.unwrap();
        q.reply(KEY, "independent of plugin Session").await.unwrap();
    });
    assert_eq!(result.unwrap(), b"independent of plugin Session");
    assert!(!sibling.session().is_closed());
    responder.close().await.unwrap();
    sibling.close().await.unwrap();
    host.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn cancelled_close_waiter_and_unpolled_close_still_reclaim_owned_sessions() {
    use std::{future::Future, task::Poll};
    let host = Host::new().await;
    let client = host.client("cancelled-close").await;
    let session = client.session().clone();
    tokio::spawn(async move {
        let mut closing = Box::pin(client.close());
        // Occupy this runtime's single worker while polling once: the tracked
        // supervisor cannot finish until this task yields after dropping close.
        let pending =
            std::future::poll_fn(|cx| Poll::Ready(closing.as_mut().poll(cx).is_pending())).await;
        assert!(pending);
        drop(closing);
    })
    .await
    .unwrap();
    wait_session_closed(&session).await;
    let client = host.client("never-polled").await;
    let session = client.session().clone();
    drop(client.close());
    wait_session_closed(&session).await;
    assert!(host.context.accepting());
    assert!(!host.session.is_closed());
    host.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expiry_revocation_drop_and_stop_close_raw_sessions_before_cleanup_ack() {
    let host = Host::new().await;
    let mut binding = host.binding("expire-raw");
    binding.expires_at = Instant::now() + Duration::from_millis(150);
    let expires = Client::from_host(host.context.clone(), binding)
        .await
        .unwrap();
    wait_session_closed(expires.session()).await;
    expires.close().await.unwrap();
    let revoked = host.client("revoke-raw").await;
    revoked.revocation().revoke();
    wait_session_closed(revoked.session()).await;
    revoked.close().await.unwrap();
    let dropped = host.client("drop-raw").await;
    let session = dropped.session().clone();
    drop(dropped);
    wait_session_closed(&session).await;
    let stopped = host.client("stop-raw").await;
    host.command("stop");
    timeout(Duration::from_secs(2), async {
        while !host.context.snapshot().cleanup_complete {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(stopped.session().is_closed());
    assert!(!host.runtime.is_closed());
    assert!(!host.session.is_closed());
    stopped.close().await.unwrap();
    host.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_runtime_shutdown_closes_clients_and_rejects_new_construction() {
    let host = Host::new().await;
    let client = host.client("runtime-stop").await;
    host.runtime.close().await.unwrap();
    wait_session_closed(client.session()).await;
    assert!(
        Client::from_host(host.context.clone(), host.binding("late"))
            .await
            .is_err()
    );
    client.close().await.unwrap();
    host.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn current_thread_host_factory_is_rejected_before_native_session_creation() {
    let host = Host::new().await;
    let context = host.context.clone();
    let binding = host.binding("unsupported-runtime");
    let error = tokio::task::spawn_blocking(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            match Client::from_host(context, binding).await {
                Ok(_) => panic!("single-thread construction must be rejected"),
                Err(error) => error.to_string(),
            }
        })
    })
    .await
    .unwrap();
    assert!(error.contains("multithread Tokio"));
    assert!(host.context.accepting());
    assert!(!host.session.is_closed());
    host.close().await;
}
