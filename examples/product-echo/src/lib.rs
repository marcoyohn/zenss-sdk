//! A product compiled from public SDK only; receives the existing host Runtime.
use zenss_client_host::HostBinding;
use zenss_client_sdk::Client;
use zenss_plugin_trait::zenss_contracts::{ServiceIdentity, MAX_MESSAGE_BYTES};
use zenss_plugin_trait::{
    plugin_config, plugin_version, DynamicRuntime, ManagedPlugin, Plugin, PluginSettings,
    RunningPlugin, ZResult,
};
pub struct EchoPlugin;
zenss_plugin_trait::declare_zenss_plugin!(EchoPlugin);
impl Plugin for EchoPlugin {
    type StartArgs = DynamicRuntime;
    type Instance = RunningPlugin;
    const DEFAULT_NAME: &'static str = "echo";
    const PLUGIN_VERSION: &'static str = plugin_version!();
    const PLUGIN_LONG_VERSION: &'static str = env!("CARGO_PKG_VERSION");
    fn start(name: &str, runtime: &DynamicRuntime) -> ZResult<RunningPlugin> {
        let config = plugin_config(runtime, name)?;
        let settings = PluginSettings::read(&config)?;
        let instance = config
            .get("instance")
            .and_then(|v| v.as_str())
            .unwrap_or("one");
        let identity = ServiceIdentity::new(settings.deployment, "echo", instance)?;
        let fail_init = config
            .get("fail_init")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let hang_stop = config
            .get("hang_stop")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let delay = config
            .get("init_delay_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
            .min(300_000);
        ManagedPlugin::start(
            runtime.clone(),
            settings.max_inflight,
            move |context| async move {
                let session = context.session().await?;
                tokio::select! {
                    _=context.stopping()=>{session.close().await?;return Ok(());},
                    _=tokio::time::sleep(std::time::Duration::from_millis(delay))=>{}
                }
                if fail_init {
                    return Err(zenss_plugin_trait::zerror!(
                        "injected asynchronous product initialization failure"
                    )
                    .into());
                }
                let key = format!(
                    "zenss/v1/{}/products/echo/{}/query",
                    identity.deployment, identity.instance
                );
                let queries = session
                    .declare_queryable(key)
                    .with(zenoh::handlers::FifoChannel::new(64))
                    .await?;
                let token = session
                    .liveliness()
                    .declare_token(identity.liveliness_key()?)
                    .await?;
                // Exercise the public hosted factory across the actual dynamic
                // plugin boundary before readiness. This temporary client has
                // its own Session but does not create another Router or socket.
                let probe = Client::from_host(
                    context.clone(),
                    HostBinding {
                        identity: ServiceIdentity::new(
                            &identity.deployment,
                            "echo-probe",
                            &identity.instance,
                        )?,
                        query_prefixes: vec![],
                        expires_at: tokio::time::Instant::now()
                            + std::time::Duration::from_secs(30),
                        timeout: std::time::Duration::from_secs(2),
                        max_inflight: 1,
                    },
                )
                .await?;
                let probe_session = probe.session().clone();
                let probe_presence = probe.announce(probe.identity().unwrap()).await?;
                let shared_runtime =
                    probe_session.zid() == session.zid() && probe_session != session;
                probe.close().await?;
                let hosted_session_closed = shared_runtime
                    && probe_session.is_closed()
                    && probe_presence.is_closed()
                    && !session.is_closed();
                if !hosted_session_closed {
                    return Err(zenss_plugin_trait::zerror!(
                        "hosted client ownership check failed"
                    )
                    .into());
                }
                context.ready()?;
                loop {
                    tokio::select! {
                        biased;
                        _=context.draining()=>break,
                        query=queries.recv_async()=>{
                            let query=query?;
                            let Ok(_admission)=context.admit() else {query.reply_err("echo busy or draining").await?;continue;};
                            let payload=query.payload().map(|p|p.to_bytes().into_owned()).unwrap_or_default();
                            if payload.len()>MAX_MESSAGE_BYTES {query.reply_err("payload too large").await?;continue;}
                            query.reply(query.key_expr().clone(),serde_json::to_vec(&serde_json::json!({"echo":String::from_utf8_lossy(&payload),"runtime_id":session.zid().to_string(),"hosted_session_closed":hosted_session_closed}))?).await?;
                        }
                    }
                }
                token.undeclare().await?;
                drop(queries);
                context.stopping().await;
                if hang_stop {
                    std::future::pending::<()>().await;
                }
                session.close().await?;
                Ok(())
            },
        )
    }
}
