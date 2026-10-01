//! Outbound-only clients. A session reuses its transport; operations are never replayed.
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;
pub use zenss_contracts::{ServiceIdentity, MAX_MESSAGE_BYTES};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientOptions {
    pub endpoints: Vec<String>,
    /// Native Zenoh TLS credentials (paths or PEM values as supported by Zenoh).
    #[serde(default)]
    pub tls: Option<Value>,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
}
fn default_timeout() -> u64 {
    5000
}

impl ClientOptions {
    pub fn configuration(&self) -> Result<zenoh::Config> {
        ensure!(
            !self.endpoints.is_empty() && self.endpoints.len() <= 16,
            "1..16 explicit endpoints required"
        );
        ensure!(
            (1..=300_000).contains(&self.timeout_ms),
            "timeout must be 1..300000ms"
        );
        for endpoint in &self.endpoints {
            ensure!(
                !endpoint.contains(['?', '#']),
                "endpoint-local security overrides are forbidden"
            );
            let (protocol, address) = endpoint.split_once('/').context("invalid endpoint")?;
            ensure!(
                matches!(protocol, "tcp" | "tls"),
                "only TCP and TLS transports are supported"
            );
            let address = address.split(['?', '#']).next().unwrap();
            let host = address
                .rsplit_once(':')
                .map(|(h, _)| h.trim_matches(['[', ']']))
                .unwrap_or("");
            let loopback = host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback());
            ensure!(loopback || protocol == "tls", "remote clients require TLS");
            if protocol == "tls" {
                let tls = self.tls.as_ref().context("TLS configuration required")?;
                ensure!(
                    tls.get("enable_mtls") == Some(&json!(true)),
                    "mutual TLS must be enabled for client credentials"
                );
                ensure!(
                    tls.get("verify_name_on_connect") != Some(&json!(false)),
                    "server name verification required"
                );
                ensure!(
                    tls.get("close_link_on_expiration") == Some(&json!(true)),
                    "certificate expiration must close links"
                );
                for field in [
                    "root_ca_certificate",
                    "connect_certificate",
                    "connect_private_key",
                ] {
                    ensure!(
                        tls.get(field)
                            .and_then(Value::as_str)
                            .is_some_and(|s| !s.is_empty()),
                        "missing TLS credential {field}"
                    );
                }
            }
        }
        let mut value = json!({"mode":"client","connect":{"endpoints":self.endpoints,"timeout_ms":self.timeout_ms},"listen":{"endpoints":[]},"scouting":{"multicast":{"enabled":false},"gossip":{"enabled":false}},"transport":{"link":{"rx":{"max_message_size":2*MAX_MESSAGE_BYTES}}}});
        if let Some(tls) = &self.tls {
            value["transport"]["link"]["tls"] = tls.clone();
        }
        zenoh::Config::from_json5(&value.to_string())
            .map_err(|e| anyhow::anyhow!("invalid client configuration: {e}"))
    }
}

pub struct Client {
    session: zenoh::Session,
    timeout: Duration,
}
impl Client {
    pub async fn connect(options: ClientOptions) -> Result<Self> {
        let config = options.configuration()?;
        let timeout = Duration::from_millis(options.timeout_ms);
        let session = tokio::time::timeout(timeout, zenoh::open(config))
            .await
            .context("connection timeout")?
            .map_err(|e| anyhow::anyhow!("connection failed: {e}"))?;
        Ok(Self { session, timeout })
    }
    /// Native session APIs for subscriptions and explicitly addressed product protocols.
    pub fn session(&self) -> &zenoh::Session {
        &self.session
    }
    pub async fn announce(
        &self,
        identity: &ServiceIdentity,
    ) -> Result<zenoh::liveliness::LivelinessToken> {
        self.session
            .liveliness()
            .declare_token(identity.liveliness_key()?)
            .await
            .map_err(|e| anyhow::anyhow!("announce failed: {e}"))
    }
    /// Address a single instance. A timeout is an unknown business outcome; no retry occurs.
    pub async fn query(&self, key: &str, payload: impl Into<Vec<u8>>) -> Result<Vec<u8>> {
        ensure!(
            !key.contains('*') && key.len() <= 1024,
            "queries require a bounded exact instance key"
        );
        let payload = payload.into();
        ensure!(
            payload.len() <= MAX_MESSAGE_BYTES,
            "payload exceeds platform limit"
        );
        let replies = self
            .session
            .get(key.to_owned())
            .payload(payload)
            .timeout(self.timeout)
            .await
            .map_err(|e| anyhow::anyhow!("query failed: {e}"))?;
        let reply = tokio::time::timeout(self.timeout, replies.recv_async())
            .await
            .context("query timeout; outcome unknown")?
            .map_err(|e| anyhow::anyhow!("query closed without a reply; outcome unknown: {e}"))?;
        let sample = reply.result().map_err(|e| {
            anyhow::anyhow!(
                "remote error: {}",
                e.payload().try_to_string().unwrap_or_default()
            )
        })?;
        ensure!(
            sample.payload().len() <= MAX_MESSAGE_BYTES,
            "reply exceeds platform limit"
        );
        Ok(sample.payload().to_bytes().into_owned())
    }
    pub async fn discover(&self, deployment: &str) -> Result<Vec<ServiceIdentity>> {
        zenss_contracts::validate_segment(deployment)?;
        let reply = self
            .query(
                &format!("zenss/v1/{deployment}/discovery/query"),
                Vec::new(),
            )
            .await?;
        let identities: Vec<ServiceIdentity> = serde_json::from_slice(&reply)?;
        for identity in &identities {
            identity.validate()?;
            ensure!(
                identity.deployment == deployment,
                "discovery scope mismatch"
            );
        }
        Ok(identities)
    }
    pub async fn close(self) -> Result<()> {
        self.session
            .close()
            .await
            .map_err(|e| anyhow::anyhow!("session close failed: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_remote_plaintext_and_unverified_tls() {
        let mut options = ClientOptions {
            endpoints: vec!["tcp/10.0.0.1:7447".into()],
            tls: None,
            timeout_ms: 1000,
        };
        assert!(options.configuration().is_err());
        options.endpoints = vec!["tcp/127.0.0.1:7447".into()];
        assert!(options.configuration().is_ok());
        options.endpoints = vec!["tls/server:7447".into()];
        options.tls = Some(json!({"verify_name_on_connect":false}));
        assert!(options.configuration().is_err());
    }
}
