//! Privileged native product-to-host admission commands, never a network protocol.
use serde::{Deserialize, Serialize};

pub const ROUTE_GATE_ABI: &str = "zenss-route-gate/1";
pub const MAX_ROUTE_LEASE_MS: u64 = 30_000;
pub const MAX_ROUTE_COMMAND_BYTES: usize = 64 * 1024;
pub const MAX_CHANNEL_CERTIFICATE_MS: u64 = 300_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteFlow {
    Ingress,
    Egress,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteAction {
    Query,
    Reply,
    DeclareQueryable,
    DeclareSubscriber,
    Put,
    Delete,
    LivelinessToken,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutePermission {
    pub flow: RouteFlow,
    pub action: RouteAction,
    pub key: String,
    /// Control completions can remain admitted while the product drains.
    #[serde(default)]
    pub during_drain: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteLease {
    /// Opt-in connection authority. Every mapped SDK lane must terminate at the
    /// same edge Host as its control Session. Reconnect requires new Host proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection: Option<RouteConnectionBinding>,
    pub issuer: String,
    pub grant_id: String,
    pub certificate_identity: String,
    /// SHA256 of the authoritative parent credential identity, never its secret.
    pub credential_fingerprint: String,
    pub revision: u64,
    pub expires_unix_ms: u64,
    pub permissions: Vec<RoutePermission>,
    /// Required for a product's shared control endpoints. The adapter resolves
    /// this host-authenticated principal; payload claims alone are not identity.
    pub principal: Option<RoutePrincipal>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutePrincipal {
    pub application_id: String,
    pub instance_id: String,
    pub base_generation: String,
    pub issuer: String,
    pub credential_fingerprint: String,
    pub certificate_identity: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelCredentialRequest {
    pub principal: RoutePrincipal,
    /// Signed by the client's locally generated key. No private key is sent.
    pub csr_pem: String,
    pub expires_unix_ms: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelCredential {
    pub certificate_pem: String,
    pub root_ca_pem: String,
    pub expires_unix_ms: u64,
    /// Lowercase hex Ed25519 public key, extracted from the verified CSR.
    pub message_public_key: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedQueryContext {
    pub principal: RoutePrincipal,
    pub message_public_key: Option<String>,
}
/// An opaque owner boot and physical transport identity, issued only by the
/// native Host. Certificate identity and claimed Zenoh ZID are not connection IDs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedConnectionIdentity {
    pub host_boot: String,
    pub transport_epoch: u64,
}

/// Host-observed physical bindings; never accepted from untrusted SDK payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConnectionBinding {
    /// Dependent roles lose admission when their exact control grant is revoked
    /// or expires, even while both physical Sessions remain live.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_grant_id: Option<String>,
    /// Native product-owner scope, independent of a shared Router's lifetime.
    pub owner_id: String,
    pub control: AuthenticatedConnectionIdentity,
    pub routes: Vec<ConnectionRoute>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionRoute {
    pub key: String,
    pub connection: AuthenticatedConnectionIdentity,
}

/// Opt-in native receipt. The legacy principal ABI remains unchanged. A missing
/// physical observation is an error, never an invented connected identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedConnectionQueryContext {
    pub context: AuthenticatedQueryContext,
    pub connection: AuthenticatedConnectionIdentity,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionQueryContextRequest {
    /// Must be `take_connection_query_context`; privileged native command only.
    pub operation: String,
    pub digest: [u8; 32],
    pub key: String,
}

/// One-use, direct pinned Router provenance. This carries no SDK principal,
/// CSR, business grant or retained-report identity. Product checks remain mandatory.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedPlatformQueryContext {
    pub source_router: String,
    pub issuer: String,
    pub expires_unix_ms: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum RouteAuthorizationCommand {
    Grant {
        lease: Box<RouteLease>,
    },
    RevokeGrant {
        issuer: String,
        grant_id: String,
        revision: u64,
    },
    RevokeCredential {
        issuer: String,
        credential_fingerprint: String,
    },
    Drain {
        issuer: String,
    },
}

/// Privileged native capacity policy. It grants no network route or business permission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryControlRule {
    pub key: String,
    /// Exact top-level JSON `kind` values accepted for reserved capacity.
    pub kinds: Vec<String>,
    pub max_payload_bytes: usize,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryControlPolicyCommand {
    /// Must be `install_query_control_policy`; never a remote Query operation.
    pub operation: String,
    pub issuer: String,
    /// Atomically replaces this issuer's bounded policy; an empty list removes it.
    pub rules: Vec<QueryControlRule>,
    /// Fail closed on Hosts predating atomic grant-bound capacity.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub require_grant_bound_capacity: bool,
}

/// Trusted capacity attached to one actual Grant; keys come from its permissions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryGrantControlPolicy {
    pub flow: RouteFlow,
    pub kinds: Vec<String>,
    pub max_payload_bytes: usize,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlledRouteGrantCommand {
    /// Must be `install_controlled_route_grant`; never a remote Query operation.
    pub operation: String,
    pub lease: Box<RouteLease>,
    pub capacity: QueryGrantControlPolicy,
}

/// Privileged local lifecycle commands. These are never accepted from Router peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenConnectionAuthorityOwner {
    pub operation: String,
    pub issuer: String,
    pub control_key: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionAuthorityOwner {
    pub owner_id: String,
    pub host_boot: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloseConnectionAuthorityOwner {
    pub operation: String,
    pub issuer: String,
    pub owner_id: String,
}
