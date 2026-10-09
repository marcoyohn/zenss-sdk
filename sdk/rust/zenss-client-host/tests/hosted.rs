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
    fn adapter(&self, name: &str) -> HostClientContext {
        HostClientContext::bind(self.context.clone(), &self.session, self.binding(name)).unwrap()
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
    let adapter = host.adapter("one");
    assert_eq!(adapter.runtime_id(), host.runtime.zid().to_string());
    let hosted = Client::from_host(adapter).await.unwrap();
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
    let first = Client::from_host(host.adapter("first")).await.unwrap();
    let second = Client::from_host(host.adapter("second")).await.unwrap();
    let a = first.announce(first.identity().unwrap()).await.unwrap();
    let b = second.announce(second.identity().unwrap()).await.unwrap();
    first.close().await.unwrap();
    assert!(a.is_closed());
    assert!(!b.is_closed());
    assert_eq!(
        token_count(&host.session, second.identity().unwrap()).await,
        1
    );
    let third_adapter = host.adapter("third");
    let revoke = third_adapter.revocation();
    let third = Client::from_host(third_adapter).await.unwrap();
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
    let client = Client::from_host(
        HostClientContext::bind(host.context.clone(), &host.session, binding).unwrap(),
    )
    .await
    .unwrap();
    let token = client.announce(client.identity().unwrap()).await.unwrap();
    wait_closed(&token).await;
    assert!(client.query(KEY, Vec::new()).await.is_err());
    client.close().await.unwrap();
    let client = Client::from_host(host.adapter("draining")).await.unwrap();
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
        HostClientContext::bind(host.context.clone(), &host.session, host.binding("late")).is_err()
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
    let client = Client::from_host(
        HostClientContext::bind(host.context.clone(), &host.session, binding).unwrap(),
    )
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
    let presence = Client::from_host(
        HostClientContext::bind(host.context.clone(), &host.session, binding).unwrap(),
    )
    .await
    .unwrap();
    assert!(presence.query(KEY, Vec::new()).await.is_err());
    presence.close().await.unwrap();
    drop((held, queries));
    host.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_foreign_or_closed_sessions_and_invalid_bindings() {
    let host = Host::new().await;
    let other = Host::new().await;
    assert!(HostClientContext::bind(
        host.context.clone(),
        &other.session,
        host.binding("foreign")
    )
    .is_err());
    for scope in [
        "zenss/v1/dev",
        "zenss/v1/other/products/echo",
        "zenss/v1/dev/products/*",
        "zenss/v1/dev/products/echo/",
    ] {
        let mut binding = host.binding("invalid");
        binding.query_prefixes = vec![scope.into()];
        assert!(HostClientContext::bind(host.context.clone(), &host.session, binding).is_err());
    }
    let client = Client::from_host(host.adapter("closed")).await.unwrap();
    let token = client.announce(client.identity().unwrap()).await.unwrap();
    host.session.close().await.unwrap();
    wait_closed(&token).await;
    assert!(client.query(KEY, Vec::new()).await.is_err());
    assert!(
        HostClientContext::bind(host.context.clone(), &host.session, host.binding("late")).is_err()
    );
    client.close().await.unwrap();
    other.close().await;
    host.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plugin_failure_revokes_client_and_scoped_cleanup_is_acknowledged() {
    let host = Host::new().await;
    let client = Client::from_host(host.adapter("failure")).await.unwrap();
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
