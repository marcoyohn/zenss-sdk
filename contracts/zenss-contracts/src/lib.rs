//! Public platform contracts. No daemon, database or native plugin dependencies.

use serde::{Deserialize, Serialize};
pub mod route_authorization;

pub const PROTOCOL_VERSION: u32 = 1;
pub const LIFECYCLE_CONFIG_PATH: &str = "__zenss__/command";
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginPhase {
    Starting,
    Ready,
    Degraded,
    Draining,
    Stopping,
    Stopped,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginSnapshot {
    pub protocol: u32,
    pub phase: PluginPhase,
    pub active_requests: usize,
    pub cleanup_complete: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleAction {
    Drain,
    Stop,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleCommand {
    pub protocol: u32,
    pub action: LifecycleAction,
}

#[derive(Debug, thiserror::Error)]
#[error("identity segments must contain 1..128 ASCII letters, digits, underscores or hyphens")]
pub struct InvalidIdentity;

pub fn validate_segment(value: &str) -> Result<(), InvalidIdentity> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
    {
        return Err(InvalidIdentity);
    }
    Ok(())
}

/// Network presence, not product authorization, lease or execution readiness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceIdentity {
    pub deployment: String,
    pub product: String,
    pub instance: String,
}

impl ServiceIdentity {
    pub fn new(
        deployment: impl Into<String>,
        product: impl Into<String>,
        instance: impl Into<String>,
    ) -> Result<Self, InvalidIdentity> {
        let result = Self {
            deployment: deployment.into(),
            product: product.into(),
            instance: instance.into(),
        };
        result.validate()?;
        Ok(result)
    }

    pub fn validate(&self) -> Result<(), InvalidIdentity> {
        validate_segment(&self.deployment)?;
        validate_segment(&self.product)?;
        validate_segment(&self.instance)
    }

    pub fn liveliness_key(&self) -> Result<String, InvalidIdentity> {
        self.validate()?;
        Ok(format!(
            "zenss/v1/{}/services/{}/{}",
            self.deployment, self.product, self.instance
        ))
    }

    pub fn parse_key(key: &str) -> Option<Self> {
        let parts: Vec<_> = key.split('/').collect();
        if parts.len() != 6 || parts[0] != "zenss" || parts[1] != "v1" || parts[3] != "services" {
            return None;
        }
        Self::new(parts[2], parts[4], parts[5]).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_key_injection_and_invalid_deserialized_identity() {
        for value in ["", "a/b", "*", "a?b", "a#b", "中文"] {
            assert!(validate_segment(value).is_err());
        }
        let identity = ServiceIdentity {
            deployment: "dev".into(),
            product: "**".into(),
            instance: "one".into(),
        };
        assert!(identity.liveliness_key().is_err());
        assert!(ServiceIdentity::parse_key("zenss/v1/dev/services/app/one/extra").is_none());
    }

    #[test]
    fn identity_round_trips_and_keeps_product_scope() {
        let first = ServiceIdentity::new("dev", "lingshu", "one").unwrap();
        let other = ServiceIdentity::new("dev", "zencollab", "one").unwrap();
        assert_eq!(
            ServiceIdentity::parse_key(&first.liveliness_key().unwrap()),
            Some(first.clone())
        );
        assert_ne!(
            first.liveliness_key().unwrap(),
            other.liveliness_key().unwrap()
        );
    }
}
