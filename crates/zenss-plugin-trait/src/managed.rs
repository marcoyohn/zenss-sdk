//! Lifecycle over official config_checker/adminspace_getter, without another loader ABI.

use crate::{
    spawn_runtime, zerror, DynamicRuntime, PluginControl, PluginReport, RunningPlugin,
    RunningPluginTrait, ZResult,
};
use futures_util::FutureExt;
use std::{
    future::Future,
    panic::AssertUnwindSafe,
    sync::{Arc, Mutex},
};
use tokio::task::JoinHandle;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use zenoh::internal::plugins::Response;
use zenoh_util::ffi::JsonKeyValueMap;
use zenss_contracts::{
    LifecycleAction, LifecycleCommand, PluginPhase, PluginSnapshot, LIFECYCLE_CONFIG_PATH,
    PROTOCOL_VERSION,
};

struct State {
    snapshot: Mutex<PluginSnapshot>,
    drain: CancellationToken,
    stop: CancellationToken,
    tasks: TaskTracker,
    max_inflight: usize,
}

impl State {
    fn command(&self, action: LifecycleAction) {
        let mut snapshot = self.snapshot.lock().unwrap();
        if snapshot.cleanup_complete {
            return;
        }
        if snapshot.phase != PluginPhase::Failed {
            snapshot.phase = match action {
                LifecycleAction::Drain if !self.stop.is_cancelled() => PluginPhase::Draining,
                _ => PluginPhase::Stopping,
            };
        }
        self.drain.cancel();
        if action == LifecycleAction::Stop {
            self.stop.cancel();
        }
    }

    fn failed(&self, message: String) {
        let mut snapshot = self.snapshot.lock().unwrap();
        snapshot.phase = PluginPhase::Failed;
        snapshot.error = Some(message.chars().take(1024).collect());
        self.drain.cancel();
        self.stop.cancel();
    }
}

#[derive(Clone)]
pub struct PluginContext {
    pub runtime: DynamicRuntime,
    state: Arc<State>,
}

impl PluginContext {
    pub async fn session(&self) -> ZResult<zenoh::Session> {
        zenoh::session::init(self.runtime.clone()).await
    }

    pub fn ready(&self) -> ZResult<()> {
        let mut snapshot = self.state.snapshot.lock().unwrap();
        if self.state.drain.is_cancelled() || snapshot.phase == PluginPhase::Failed {
            return Err(zerror!("plugin cannot become ready after drain or failure").into());
        }
        snapshot.phase = PluginPhase::Ready;
        Ok(())
    }

    pub fn snapshot(&self) -> PluginSnapshot {
        self.state.snapshot.lock().unwrap().clone()
    }
    pub async fn draining(&self) {
        self.state.drain.cancelled().await;
    }
    pub async fn stopping(&self) {
        self.state.stop.cancelled().await;
    }
    pub fn accepting(&self) -> bool {
        self.snapshot().phase == PluginPhase::Ready
    }

    /// Hold through the entire admitted operation, including its authorized completion.
    pub fn admit(&self) -> ZResult<AdmissionGuard> {
        let mut snapshot = self.state.snapshot.lock().unwrap();
        if snapshot.phase != PluginPhase::Ready
            || snapshot.active_requests >= self.state.max_inflight
        {
            return Err(zerror!("plugin is not accepting work or is at capacity").into());
        }
        snapshot.active_requests += 1;
        Ok(AdmissionGuard {
            state: self.state.clone(),
        })
    }

    /// Supervised children must observe stopping() and finish their own cleanup.
    /// Failure or panic revokes readiness. Cleanup is acknowledged only after all children exit.
    pub fn spawn<F>(&self, future: F)
    where
        F: Future<Output = ZResult<()>> + Send + 'static,
    {
        let state = self.state.clone();
        self.state.tasks.spawn(async move {
            let result = AssertUnwindSafe(future).catch_unwind().await;
            match result {
                Ok(Ok(())) if state.stop.is_cancelled() => {}
                Ok(Ok(())) => state.failed("required child task exited unexpectedly".into()),
                Ok(Err(error)) => state.failed(format!("required child task failed: {error}")),
                Err(_) => state.failed("required child task panicked".into()),
            }
        });
    }
}

pub struct AdmissionGuard {
    state: Arc<State>,
}
impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        self.state.snapshot.lock().unwrap().active_requests -= 1;
    }
}

pub struct ManagedPlugin {
    state: Arc<State>,
    task: JoinHandle<()>,
}

impl ManagedPlugin {
    pub fn start<F, Fut>(
        runtime: DynamicRuntime,
        max_inflight: usize,
        run: F,
    ) -> ZResult<RunningPlugin>
    where
        F: FnOnce(PluginContext) -> Fut + Send + 'static,
        Fut: Future<Output = ZResult<()>> + Send + 'static,
    {
        if !(1..=100_000).contains(&max_inflight) {
            return Err(zerror!("max_inflight must be 1..100000").into());
        }
        let state = Arc::new(State {
            snapshot: Mutex::new(PluginSnapshot {
                protocol: PROTOCOL_VERSION,
                phase: PluginPhase::Starting,
                active_requests: 0,
                cleanup_complete: false,
                error: None,
            }),
            drain: CancellationToken::new(),
            stop: CancellationToken::new(),
            tasks: TaskTracker::new(),
            max_inflight,
        });
        let context = PluginContext {
            runtime,
            state: state.clone(),
        };
        let worker_state = state.clone();
        let task = spawn_runtime(async move {
            let result = AssertUnwindSafe(run(context)).catch_unwind().await;
            match result {
                Ok(Ok(())) if worker_state.stop.is_cancelled() => {}
                Ok(Ok(())) => worker_state.failed("plugin task exited before shutdown".into()),
                Ok(Err(error)) => worker_state.failed(format!("plugin task failed: {error}")),
                Err(_) => worker_state.failed("plugin task panicked".into()),
            }
            worker_state.stop.cancel();
            worker_state.tasks.close();
            worker_state.tasks.wait().await;
            // An admission guard moved outside tracked work still prevents a false cleanup ACK.
            while worker_state.snapshot.lock().unwrap().active_requests != 0 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            let mut snapshot = worker_state.snapshot.lock().unwrap();
            snapshot.cleanup_complete = true;
            if snapshot.phase != PluginPhase::Failed {
                snapshot.phase = PluginPhase::Stopped;
            }
        });
        Ok(Box::new(Self { state, task }))
    }
}

impl PluginControl for ManagedPlugin {
    fn report(&self) -> PluginReport {
        let mut report = PluginReport::default();
        if let Some(error) = &self.state.snapshot.lock().unwrap().error {
            report.add_error(error.clone());
        }
        report
    }
}

impl RunningPluginTrait for ManagedPlugin {
    fn config_checker(
        &self,
        path: &str,
        _current: &JsonKeyValueMap,
        new: &JsonKeyValueMap,
    ) -> ZResult<Option<JsonKeyValueMap>> {
        if path != LIFECYCLE_CONFIG_PATH {
            return Err(zerror!("only host lifecycle commands are supported; replace the process for configuration changes").into());
        }
        let map = new.into_serde_map();
        let value = map
            .get("__zenss__")
            .and_then(|v| v.get("command"))
            .ok_or_else(|| zerror!("missing lifecycle command"))?;
        let command: LifecycleCommand = serde_json::from_value(value.clone())?;
        if command.protocol != PROTOCOL_VERSION {
            return Err(zerror!("unsupported lifecycle protocol").into());
        }
        self.state.command(command.action);
        Ok(None)
    }

    fn adminspace_getter<'a>(
        &'a self,
        selector: &'a zenoh::key_expr::KeyExpr<'a>,
        base: &str,
    ) -> ZResult<Vec<Response>> {
        let key = format!("{base}/__zenss__/state");
        if selector.intersects(&zenoh::key_expr::KeyExpr::try_from(key.clone())?) {
            Ok(vec![Response::new(
                key,
                serde_json::to_value(&*self.state.snapshot.lock().unwrap())?,
            )])
        } else {
            Ok(Vec::new())
        }
    }
}

impl Drop for ManagedPlugin {
    fn drop(&mut self) {
        self.state.command(LifecycleAction::Stop);
        // The host waits for cleanup first and pins libraries; timeout ends the process.
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn state() -> Arc<State> {
        Arc::new(State {
            snapshot: Mutex::new(PluginSnapshot {
                protocol: PROTOCOL_VERSION,
                phase: PluginPhase::Ready,
                active_requests: 0,
                cleanup_complete: false,
                error: None,
            }),
            drain: CancellationToken::new(),
            stop: CancellationToken::new(),
            tasks: TaskTracker::new(),
            max_inflight: 1,
        })
    }
    async fn runtime() -> zenoh::internal::runtime::Runtime {
        let config=zenoh::Config::from_json5(r#"{mode:"router",listen:{endpoints:["tcp/127.0.0.1:0"]},scouting:{multicast:{enabled:false},gossip:{enabled:false}}}"#).unwrap();
        let mut runtime = zenoh::internal::runtime::RuntimeBuilder::new(config)
            .build()
            .await
            .unwrap();
        runtime.start().await.unwrap();
        runtime
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drain_rejects_new_work_and_preserves_inflight_accounting() {
        let runtime = runtime().await;
        let state = state();
        let context = PluginContext {
            runtime: runtime.clone().into(),
            state: state.clone(),
        };
        let admitted = context.admit().unwrap();
        assert!(context.admit().is_err());
        state.command(LifecycleAction::Drain);
        state.command(LifecycleAction::Drain);
        assert!(context.admit().is_err());
        assert!(context.ready().is_err());
        assert_eq!(context.snapshot().active_requests, 1);
        drop(admitted);
        assert_eq!(context.snapshot().active_requests, 0);
        state.command(LifecycleAction::Stop);
        state.command(LifecycleAction::Drain);
        assert_eq!(context.snapshot().phase, PluginPhase::Stopping);
        runtime.close().await.unwrap();
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn child_panic_revokes_ready_and_waits_for_cleanup() {
        let runtime = runtime().await;
        let state = state();
        let context = PluginContext {
            runtime: runtime.clone().into(),
            state: state.clone(),
        };
        context.spawn(async {
            panic!("injected required child failure");
            #[allow(unreachable_code)]
            Ok(())
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), context.stopping())
            .await
            .unwrap();
        assert_eq!(context.snapshot().phase, PluginPhase::Failed);
        assert!(context.admit().is_err());
        assert!(context.ready().is_err());
        state.tasks.close();
        state.tasks.wait().await;
        runtime.close().await.unwrap();
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn managed_cleanup_waits_for_cooperative_children() {
        let runtime = runtime().await;
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let plugin = ManagedPlugin::start(runtime.clone().into(), 1, move |context| async move {
            let child = context.clone();
            context.spawn(async move {
                child.stopping().await;
                tokio::time::sleep(std::time::Duration::from_millis(80)).await;
                Ok(())
            });
            context.ready()?;
            sender.send(context.clone()).ok();
            context.stopping().await;
            Ok(())
        })
        .unwrap();
        let context = receiver.await.unwrap();
        context.state.command(LifecycleAction::Stop);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(!context.snapshot().cleanup_complete);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !context.snapshot().cleanup_complete {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(context.snapshot().phase, PluginPhase::Stopped);
        drop(plugin);
        runtime.close().await.unwrap();
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cleanup_waits_for_every_retained_admission_guard() {
        let runtime = runtime().await;
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let plugin = ManagedPlugin::start(runtime.clone().into(), 1, move |context| async move {
            context.ready()?;
            sender.send(context.clone()).ok();
            context.stopping().await;
            Ok(())
        })
        .unwrap();
        let context = receiver.await.unwrap();
        let admission = context.admit().unwrap();
        context.state.command(LifecycleAction::Stop);
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert!(!context.snapshot().cleanup_complete);
        drop(admission);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !context.snapshot().cleanup_complete {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        drop(plugin);
        runtime.close().await.unwrap();
    }
}
