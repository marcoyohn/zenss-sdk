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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteLease {
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
