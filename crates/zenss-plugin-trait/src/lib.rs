//! ZenSS Plugin System
//!
//! This module provides utilities for ZenSS plugins.
//! ZenSS plugins are standard Zenoh plugins using DynamicRuntime.

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::task::JoinHandle;
mod managed;
pub use managed::{AdmissionGuard, ManagedPlugin, PluginContext};
pub use zenss_contracts;

// Re-export Zenoh plugin traits
#[doc(hidden)]
pub use zenoh_plugin_trait as native_traits;
pub use zenoh_plugin_trait::{
    declare_plugin, plugin_long_version, plugin_version, Plugin, PluginControl, PluginReport,
    PluginStatusRec,
};
pub use zenoh_result::{bail, zerror, ZResult};

// Re-export common types
pub use zenoh::internal::runtime::DynamicRuntime;
pub use zenoh::internal::{plugins::RunningPluginTrait, zlock};
pub type RunningPlugin = Box<dyn RunningPluginTrait + Send + Sync>;

// Global runtime configuration for dynamic plugins
static WORKER_THREAD_NUM: AtomicUsize = AtomicUsize::new(2);
static MAX_BLOCK_THREAD_NUM: AtomicUsize = AtomicUsize::new(50);

fn get_or_create_runtime() -> &'static tokio::runtime::Runtime {
    use std::sync::OnceLock;
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(WORKER_THREAD_NUM.load(Ordering::SeqCst))
            .max_blocking_threads(MAX_BLOCK_THREAD_NUM.load(Ordering::SeqCst))
            .enable_all()
            .build()
            .expect("Unable to create runtime")
    })
}

/// Block on an async task using the appropriate runtime.
///
/// This function automatically detects whether we're in a standalone binary
/// (with access to a current runtime) or in a dynamic plugin (no current runtime).
///
/// - In standalone binaries: uses the current runtime
/// - In dynamic plugins: uses a global runtime created on first use
#[inline(always)]
pub fn blockon_runtime<F: Future>(task: F) -> F::Output {
    // Check whether able to get the current runtime
    match tokio::runtime::Handle::try_current() {
        Ok(rt) => {
            // Able to get the current runtime (standalone binary), use the current runtime
            tokio::task::block_in_place(|| rt.block_on(task))
        }
        Err(_) => {
            // Unable to get the current runtime (dynamic plugins), reuse the global runtime
            get_or_create_runtime().block_on(task)
        }
    }
}

/// Spawn an async task using the appropriate runtime.
///
/// This function automatically detects whether we're in a standalone binary
/// (with access to a current runtime) or in a dynamic plugin (no current runtime).
///
/// - In standalone binaries: spawns on the current runtime
/// - In dynamic plugins: spawns on a global runtime created on first use
pub fn spawn_runtime<F>(task: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    // Check whether able to get the current runtime
    match tokio::runtime::Handle::try_current() {
        Ok(rt) => {
            // Able to get the current runtime (standalone binary), spawn on the current runtime
            rt.spawn(task)
        }
        Err(_) => {
            // Unable to get the current runtime (dynamic plugins), spawn on the global runtime
            get_or_create_runtime().spawn(task)
        }
    }
}

/// Macro to declare a ZenSS plugin for dynamic loading
///
/// This uses Zenoh's plugin declaration mechanism.
#[macro_export]
macro_rules! declare_zenss_plugin {
    ($plugin_type:ty) => {
        #[cfg(feature = "dynamic_plugin")]
        mod __zenss_plugin_entry {
            use super::*;
            use $crate::native_traits as zenoh_plugin_trait;
            $crate::declare_plugin!($plugin_type);
        }
    };
}

/// Snapshot startup configuration; no private host types are exposed.
pub fn plugin_config(runtime: &DynamicRuntime, name: &str) -> ZResult<serde_json::Value> {
    runtime.get_config().get_plugin_config(name)
}

/// Native-only admission control. The host validates issuer scope, revisions,
/// exact permissions and the 30-second hard lease. This is never exposed to clients.
pub fn update_route_authorization(
    runtime: &DynamicRuntime,
    command: &zenss_contracts::route_authorization::RouteAuthorizationCommand,
) -> ZResult<()> {
    let bytes = serde_json::to_vec(command)?;
    if bytes.len() > zenss_contracts::route_authorization::MAX_ROUTE_COMMAND_BYTES {
        return Err(zerror!("route command exceeds native control limit").into());
    }
    runtime.route_gate_command(&bytes)
}

/// Resolve the host's receipt for this received Query. Attachments, ZID, source
/// info and the payload's own identity fields are never accepted as proof.
pub fn authenticated_query_principal(
    runtime: &DynamicRuntime,
    query: &zenoh::query::Query,
) -> ZResult<zenss_contracts::route_authorization::RoutePrincipal> {
    Ok(authenticated_query_context(runtime, query)?.principal)
}

pub fn authenticated_query_context(
    runtime: &DynamicRuntime,
    query: &zenoh::query::Query,
) -> ZResult<zenss_contracts::route_authorization::AuthenticatedQueryContext> {
    use sha2::{Digest, Sha256};
    let payload = query
        .payload()
        .ok_or_else(|| zerror!("query lacks authenticated envelope"))?;
    let digest: [u8; 32] = Sha256::digest(payload.to_bytes()).into();
    Ok(serde_json::from_slice(&runtime.route_gate_principal(
        &digest,
        query.key_expr().as_str(),
    )?)?)
}

/// Sign a CSR after the native product has freshly authenticated its parent key.
/// The host replaces all CSR names/usages and fixes a client-only lifetime.
pub fn issue_channel_credential(
    runtime: &DynamicRuntime,
    request: &zenss_contracts::route_authorization::ChannelCredentialRequest,
) -> ZResult<zenss_contracts::route_authorization::ChannelCredential> {
    let bytes = serde_json::to_vec(request)?;
    if bytes.len() > zenss_contracts::route_authorization::MAX_ROUTE_COMMAND_BYTES {
        return Err(zerror!("credential request exceeds native control limit").into());
    }
    Ok(serde_json::from_slice(
        &runtime.route_gate_credential(&bytes)?,
    )?)
}

/// Validated host metadata injected into every configured plugin.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PluginSettings {
    pub deployment: String,
    pub max_inflight: usize,
}
impl PluginSettings {
    pub fn read(value: &serde_json::Value) -> ZResult<Self> {
        let result: Self = serde_json::from_value(
            value
                .get("__zenss__")
                .cloned()
                .ok_or_else(|| zerror!("missing host metadata"))?,
        )?;
        zenss_contracts::validate_segment(&result.deployment)?;
        if !(1..=100_000).contains(&result.max_inflight) {
            return Err(zerror!("invalid admission limit").into());
        }
        Ok(result)
    }
}
