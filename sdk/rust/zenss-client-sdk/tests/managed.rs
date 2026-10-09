use zenss_client_sdk::{PoolLayout, TransportError};
#[test]
fn bounded_independent_lanes_include_control() {
    for n in 1..=4 {
        assert_eq!(PoolLayout::new(n).unwrap().session_count(), n);
    }
    for n in [0, 5, usize::MAX] {
        assert!(matches!(
            PoolLayout::new(n),
            Err(TransportError::InvalidConfig)
        ));
    }
    assert!(PoolLayout::new(4).unwrap().with_control_lane().is_err());
    assert_eq!(
        PoolLayout::new(3)
            .unwrap()
            .with_control_lane()
            .unwrap()
            .session_count(),
        4
    );
}

use base64::{engine::general_purpose::STANDARD, Engine};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ED25519,
};
use std::{sync::Arc, time::Duration};
use tokio::{sync::Semaphore, time::Instant};
use zenss_client_sdk::{
    transport::{TransportCredentials, TransportOptions},
    CloseReason, ManagedPool, PoolMetrics,
};

struct Fixture {
    router: zenoh::Session,
    endpoint: String,
    root: String,
    certificate: String,
    key: String,
}
impl Fixture {
    fn options(&self) -> TransportOptions {
        TransportOptions {
            endpoints: vec![self.endpoint.clone()],
            credentials: TransportCredentials::Mtls {
                root_ca: self.root.clone(),
                certificate: self.certificate.clone(),
                private_key: self.key.clone(),
            },
            max_message_bytes: 20 * 1024 * 1024 + 64 * 1024,
        }
    }
    async fn new() -> Self {
        let mut ca = CertificateParams::new(vec![]).unwrap();
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let ca_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let root = ca.self_signed(&ca_key).unwrap().pem();
        let issuer = Issuer::new(ca, ca_key);
        let mut leaf =
            CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
        leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let certificate = leaf.signed_by(&key, &issuer).unwrap().pem();
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let endpoint = format!("tls/127.0.0.1:{port}");
        let config=zenoh::Config::from_json5(&serde_json::json!({
            "mode":"router","listen":{"endpoints":[endpoint]},"scouting":{"multicast":{"enabled":false},"gossip":{"enabled":false}},
            "transport":{"link":{"tls":{"root_ca_certificate_base64":STANDARD.encode(&root),"listen_certificate_base64":STANDARD.encode(&certificate),"listen_private_key_base64":STANDARD.encode(key.serialize_pem()),"enable_mtls":true}}}
        }).to_string()).unwrap();
        Self {
            router: zenoh::open(config).await.unwrap(),
            endpoint,
            root,
            certificate,
            key: key.serialize_pem(),
        }
    }
}
async fn wait_capacity(budget: &Semaphore, expected: usize) {
    tokio::time::timeout(Duration::from_secs(15), async {
        while budget.available_permits() != expected {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_pools_reuse_sessions_and_share_replacement_budget() {
    let f = Fixture::new().await;
    let queryable = f.router.declare_queryable("test/echo").await.unwrap();
    let reply = tokio::spawn(async move {
        while let Ok(q) = queryable.recv_async().await {
            q.reply("test/echo", q.payload().unwrap().to_bytes().into_owned())
                .await
                .unwrap();
        }
    });
    for count in [1, 2, 4] {
        let budget = Arc::new(Semaphore::new(4));
        let mut pool = ManagedPool::open(
            f.options(),
            PoolLayout::new(count).unwrap(),
            budget.clone(),
            Instant::now() + Duration::from_secs(30),
            std::future::pending(),
            PoolMetrics::default(),
        )
        .await
        .unwrap();
        let ids = pool
            .sessions()
            .iter()
            .map(|s| s.zid().to_string())
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(ids.len(), count);
        for s in pool.sessions() {
            for _ in 0..2 {
                let r = s
                    .get("test/echo")
                    .payload("hello")
                    .await
                    .unwrap()
                    .recv_async()
                    .await
                    .unwrap();
                assert_eq!(r.result().unwrap().payload().to_bytes().as_ref(), b"hello");
            }
        }
        assert_eq!(budget.available_permits(), 4 - count);
        let replacement = ManagedPool::open(
            f.options(),
            PoolLayout::new(4).unwrap(),
            budget.clone(),
            Instant::now() + Duration::from_secs(30),
            std::future::pending(),
            PoolMetrics::default(),
        )
        .await;
        assert!(matches!(replacement, Err(TransportError::CapacityExceeded)));
        pool.close().await.unwrap();
        pool.close().await.unwrap();
        assert_eq!(budget.available_permits(), 4);
        assert!(pool.sessions().iter().all(zenoh::Session::is_closed));
    }
    reply.abort();
    f.router.close().await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expiry_revocation_drop_and_cancelled_close_cleanup_without_revival() {
    let f = Fixture::new().await;
    for reason in [
        CloseReason::AuthorityExpired,
        CloseReason::ConnectionClosed,
        CloseReason::Explicit,
    ] {
        let budget = Arc::new(Semaphore::new(4));
        let (revoke, revoked) = tokio::sync::oneshot::channel::<()>();
        let mut pool = ManagedPool::open(
            f.options(),
            PoolLayout::default(),
            budget.clone(),
            Instant::now() + Duration::from_secs(30),
            async move {
                let _ = revoked.await;
            },
            PoolMetrics::default(),
        )
        .await
        .unwrap();
        let mut closed = pool.subscribe_closed();
        let sessions = pool.sessions().to_vec();
        match reason {
            CloseReason::AuthorityExpired => pool
                .update_deadline(Instant::now() + Duration::from_millis(30))
                .unwrap(),
            CloseReason::ConnectionClosed => {
                drop(revoke);
            }
            _ => {
                pool.request_close();
            }
        }
        tokio::time::timeout(Duration::from_secs(3), closed.wait_for(|s| s.is_some()))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(*closed.borrow(), Some(reason));
        assert!(pool
            .update_deadline(Instant::now() + Duration::from_secs(30))
            .is_err());
        // Cancelling a join is safe; a subsequent close still joins its driver.
        {
            let closing = pool.close();
            tokio::pin!(closing);
            tokio::select! {biased;_ = &mut closing=>{},_ = tokio::task::yield_now()=>{}}
        }
        pool.close().await.unwrap();
        wait_capacity(&budget, 4).await;
        assert!(sessions.iter().all(zenoh::Session::is_closed));
    }
    let budget = Arc::new(Semaphore::new(4));
    let pool = ManagedPool::open(
        f.options(),
        PoolLayout::new(2).unwrap(),
        budget.clone(),
        Instant::now() + Duration::from_secs(30),
        std::future::pending(),
        PoolMetrics::default(),
    )
    .await
    .unwrap();
    let sessions = pool.sessions().to_vec();
    drop(pool);
    wait_capacity(&budget, 4).await;
    assert!(sessions.iter().all(zenoh::Session::is_closed));
    f.router.close().await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_open_and_bad_trust_return_capacity() {
    let f = Fixture::new().await;
    let budget = Arc::new(Semaphore::new(4));
    // A TCP listener accepts no TLS handshake, forcing a cancellable open.
    let stalled = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut options = f.options();
    options.endpoints = vec![format!("tls/{}", stalled.local_addr().unwrap())];
    let b = budget.clone();
    let opening = tokio::spawn(async move {
        ManagedPool::open(
            options,
            PoolLayout::new(2).unwrap(),
            b,
            Instant::now() + Duration::from_secs(30),
            std::future::pending(),
            PoolMetrics::default(),
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(3), async {
        while budget.available_permits() == 4 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    opening.abort();
    let _ = opening.await;
    wait_capacity(&budget, 4).await;
    let other = Fixture::new().await;
    let mut wrong = f.options();
    if let TransportCredentials::Mtls { root_ca, .. } = &mut wrong.credentials {
        *root_ca = other.root.clone();
    }
    assert!(ManagedPool::open(
        wrong,
        PoolLayout::default(),
        budget.clone(),
        Instant::now() + Duration::from_secs(30),
        std::future::pending(),
        PoolMetrics::default()
    )
    .await
    .is_err());
    wait_capacity(&budget, 4).await;
    other.router.close().await.unwrap();
    f.router.close().await.unwrap();
}
#[tokio::test]
async fn current_thread_rejected_before_io() {
    let options = TransportOptions {
        endpoints: vec!["tls/localhost:1".into()],
        credentials: TransportCredentials::Mtls {
            root_ca: "invalid".into(),
            certificate: "invalid".into(),
            private_key: "invalid".into(),
        },
        max_message_bytes: 1024,
    };
    assert!(matches!(
        ManagedPool::open(
            options,
            PoolLayout::default(),
            Arc::new(Semaphore::new(4)),
            Instant::now() + Duration::from_secs(5),
            std::future::pending(),
            PoolMetrics::default()
        )
        .await,
        Err(TransportError::UnsupportedRuntime)
    ));
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn profile_rejects_overrides_mixed_transport_and_preserves_resource_budget() {
    let f = Fixture::new().await;
    let mut options = f.options();
    for endpoint in [
        "tcp/host:7447",
        "tls/host:7447#verify_name_on_connect=false",
        "tls/host:7447?x=y",
        "tls/host:0",
    ] {
        options.endpoints = vec![endpoint.into()];
        assert!(options.configuration(0).is_err());
    }
    options = f.options();
    let config = options.configuration(0).unwrap();
    assert_eq!(
        config
            .get_json("transport/link/tx/queue/size/data")
            .unwrap(),
        "16"
    );
    assert_eq!(
        config
            .get_json("transport/link/tx/queue/congestion_control/block/wait_before_close")
            .unwrap(),
        "250000"
    );
    assert_eq!(
        config
            .get_json("transport/link/tls/verify_name_on_connect")
            .unwrap(),
        "true"
    );
    assert!(!format!("{:?}", options.credentials).contains("PRIVATE"));
    f.router.close().await.unwrap();
}
#[cfg(feature = "plaintext")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_tcp_rejects_unknown_keys_without_fallback_and_reclaims_capacity() {
    if std::env::var_os("ZENSS_TRANSPORT_TEST_TRACE").is_some() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("zenoh_transport=debug,zenoh=warn")
            .try_init();
    }
    use zenss_client_sdk::credentials::PossessionKey;
    let key = PossessionKey::generate().unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let router=zenoh::open(zenoh::Config::from_json5(&serde_json::json!({"mode":"router","listen":{"endpoints":[endpoint]},"scouting":{"multicast":{"enabled":false},"gossip":{"enabled":false}},"transport":{"auth":key.native_config().unwrap()}}).to_string()).unwrap()).await.unwrap();
    let client_key = PossessionKey::generate().unwrap();
    assert_ne!(
        key.fingerprint().unwrap(),
        client_key.fingerprint().unwrap()
    );
    let budget = Arc::new(Semaphore::new(4));
    let options = TransportOptions {
        endpoints: vec![endpoint],
        credentials: TransportCredentials::IntranetPlaintext(client_key),
        max_message_bytes: 1024,
    };
    let config = options.configuration(0).unwrap();
    assert_eq!(
        config.get_json("transport/link/protocols").unwrap(),
        "[\"tcp\"]"
    );
    // Stock routers have no dynamic issuer allowlist: unknown public keys must
    // fail closed. Positive issuer admission is tested by the licensed Host.
    assert!(matches!(
        ManagedPool::open(
            options,
            PoolLayout::default(),
            budget.clone(),
            Instant::now() + Duration::from_secs(30),
            std::future::pending(),
            PoolMetrics::default()
        )
        .await,
        Err(TransportError::Transport)
    ));
    assert_eq!(budget.available_permits(), 4);
    router.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_after_first_lane_closes_partial_pool() {
    let f = Fixture::new().await;
    let stalled = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut options = f.options();
    options
        .endpoints
        .push(format!("tls/{}", stalled.local_addr().unwrap()));
    let budget = Arc::new(Semaphore::new(4));
    let shared = budget.clone();
    let opening = tokio::spawn(async move {
        ManagedPool::open(
            options,
            PoolLayout::new(2).unwrap(),
            shared,
            Instant::now() + Duration::from_secs(30),
            std::future::pending(),
            PoolMetrics::default(),
        )
        .await
    });
    // Reaching the second listener proves lane zero already completed.
    let (_socket, _) = tokio::time::timeout(Duration::from_secs(3), stalled.accept())
        .await
        .unwrap()
        .unwrap();
    opening.abort();
    let _ = opening.await;
    wait_capacity(&budget, 4).await;
    f.router.close().await.unwrap();
}
