//! Run with: cargo run --locked -p zenss-client-host --example host_client
//! This composition fixture stands in for zenssd providing a PluginContext.
use anyhow::Result;
use std::time::Duration;
use tokio::time::Instant;
use zenss_client_host::{HostBinding, HostClientContext};
use zenss_client_sdk::{Client, ServiceIdentity};
use zenss_plugin_trait::ManagedPlugin;

#[tokio::main]
async fn main() -> Result<()> {
    let config = zenoh::Config::from_json5(r#"{mode:"router",listen:{endpoints:[]},scouting:{multicast:{enabled:false},gossip:{enabled:false}}}"#).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut runtime = zenoh::internal::runtime::RuntimeBuilder::new(config)
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    runtime.start().await.map_err(|e| anyhow::anyhow!("{e}"))?;
    let (send, receive) = tokio::sync::oneshot::channel();
    let plugin = ManagedPlugin::start(runtime.clone().into(), 8, move |context| async move {
        context.ready()?;
        send.send(context.clone()).ok();
        context.stopping().await;
        Ok(())
    })
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    let context = receive.await?;
    let session = context
        .session()
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let key = "zenss/v1/dev/products/echo/one/query";
    let queries = session
        .declare_queryable(key)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let identity = ServiceIdentity::new("dev", "example", "one")?;
    let binding = HostBinding {
        identity: identity.clone(),
        query_prefixes: vec![key.into()],
        expires_at: Instant::now() + Duration::from_secs(60),
        timeout: Duration::from_secs(2),
        max_inflight: 8,
    };
    let adapter = HostClientContext::bind(context.clone(), &session, binding)?;
    let client = Client::from_host(adapter).await?;
    let announcement = client.announce(&identity).await?;
    let answer = async {
        let query = queries
            .recv_async()
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        query
            .reply(key, "hello from the shared Router")
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))
    };
    let (response, answered) = tokio::join!(client.query(key, Vec::new()), answer);
    answered?;
    println!("{}", String::from_utf8(response?)?);
    client.close().await?;
    assert!(announcement.is_closed());
    assert!(!session.is_closed());
    println!(
        "client closed; host Session remains open ({})",
        session.zid()
    );
    drop(queries);
    let command = serde_json::json!({"__zenss__":{"command":{"protocol":1,"action":"stop"}}})
        .as_object()
        .unwrap()
        .clone();
    plugin
        .config_checker(
            zenss_plugin_trait::zenss_contracts::LIFECYCLE_CONFIG_PATH,
            &zenoh_util::ffi::JsonKeyValueMap::default(),
            &command.into(),
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    tokio::time::timeout(Duration::from_secs(3), async {
        while !context.snapshot().cleanup_complete {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    session.close().await.map_err(|e| anyhow::anyhow!("{e}"))?;
    runtime.close().await.map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}
