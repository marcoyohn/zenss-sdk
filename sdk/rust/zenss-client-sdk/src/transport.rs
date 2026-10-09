//! Typed transport profiles; no arbitrary endpoint-local security overrides.
use crate::TransportError;
use base64::{engine::general_purpose::STANDARD, Engine};

pub enum TransportCredentials {
    Mtls {
        root_ca: String,
        certificate: String,
        private_key: String,
    },
    #[cfg(feature = "plaintext")]
    IntranetPlaintext(crate::credentials::PossessionKey),
}
impl std::fmt::Debug for TransportCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TransportCredentials([REDACTED])")
    }
}
pub struct TransportOptions {
    pub endpoints: Vec<String>,
    pub credentials: TransportCredentials,
    pub max_message_bytes: usize,
}
impl TransportOptions {
    pub fn configuration(&self, lane: usize) -> Result<zenoh::Config, TransportError> {
        if self.endpoints.is_empty()
            || self.endpoints.len() > 16
            || lane >= 4
            || !(1..=32 * 1024 * 1024).contains(&self.max_message_bytes)
        {
            return Err(TransportError::InvalidConfig);
        }
        let (protocol, root_ca, certificate, private_key) = match &self.credentials {
            TransportCredentials::Mtls {
                root_ca,
                certificate,
                private_key,
            } => {
                if [root_ca, certificate, private_key]
                    .iter()
                    .any(|s| s.is_empty())
                {
                    return Err(TransportError::InvalidConfig);
                }
                (
                    "tls",
                    root_ca.as_str(),
                    certificate.as_str(),
                    private_key.as_str(),
                )
            }
            #[cfg(feature = "plaintext")]
            TransportCredentials::IntranetPlaintext(_) => ("tcp", "", "", ""),
        };
        for endpoint in &self.endpoints {
            let Some((scheme, address)) = endpoint.split_once('/') else {
                return Err(TransportError::InvalidConfig);
            };
            if scheme != protocol
                || endpoint.contains(['?', '#', ';'])
                || endpoint.chars().any(char::is_whitespace)
                || address.is_empty()
            {
                return Err(TransportError::InvalidConfig);
            }
            let Some((host, port)) = address.rsplit_once(':') else {
                return Err(TransportError::InvalidConfig);
            };
            if host.is_empty() || !port.parse::<u16>().is_ok_and(|p| p > 0) {
                return Err(TransportError::InvalidConfig);
            }
        }
        #[allow(unused_mut)]
        let mut value = serde_json::json!({
            "mode": "client",
            "listen": {"endpoints": []},
            "connect": {"endpoints": ordered_endpoints(&self.endpoints, lane), "timeout_ms": 0,
                "exit_on_failure": true,
                // Disable only the native initial retry loop; the SDK supplies one
                // five-second whole-pool deadline. Native reconnect still reads
                // this finite backoff and stops after its first successful Router.
                "retry": {"period_init_ms": 250, "period_max_ms": 5000, "period_increase_factor": 2.0}},
            "scouting": {"multicast": {"enabled": false}, "gossip": {"enabled": false}},
            "adminspace": {"enabled": false},
            "transport": {"unicast": {
                // One active Router plus a transient replacement. Endpoint lists
                // are failover choices, not permission for eight live transports.
                "max_sessions": 2, "max_links": 1, "accept_pending": 1,
                "open_timeout": 5000, "accept_timeout": 5000,
                "lowlatency": false, "qos": {"enabled": false}},
                "link": {"protocols": ["tls"],
                // Native framing/keys/receipt need room beyond the product envelope.
                "rx": {"buffer_size": 65535, "max_message_size": self.max_message_bytes},
                // Universal/no-QoS uses data. Sixteen lazy batches absorb bounded
                // bursts; keep the 250ms close and every other priority at two.
                "tx": {"batch_size": 65535, "queue": {
                    "size": {"control": 2, "real_time": 2, "interactive_high": 2,
                        "interactive_low": 2, "data_high": 2, "data": 16, "data_low": 2, "background": 2},
                    "allocation": {"mode": "lazy"},
                    "congestion_control": {"block": {"wait_before_close": 250000}}
                }},
                "tls": {
                    // Kernel receive storage is distinct from native RX batch pools.
                    // Linux requires net.core.rmem_max >= 1MiB for this request.
                    "so_rcvbuf": 1024 * 1024,
                    "root_ca_certificate_base64": STANDARD.encode(root_ca),
                    "connect_certificate_base64": STANDARD.encode(certificate),
                    "connect_private_key_base64": STANDARD.encode(private_key),
                    "enable_mtls": true, "verify_name_on_connect": true, "close_link_on_expiration": true
                }}}
        });
        match &self.credentials {
            TransportCredentials::Mtls { .. } => {}
            #[cfg(feature = "plaintext")]
            TransportCredentials::IntranetPlaintext(key) => {
                value["transport"]["link"]["protocols"] = serde_json::json!(["tcp"]);
                value["transport"]["link"]
                    .as_object_mut()
                    .unwrap()
                    .remove("tls");
                value["transport"]["link"]["tcp"] = serde_json::json!({"so_rcvbuf": 1024 * 1024});
                value["transport"]["auth"] = key.native_config()?;
            }
        }
        zenoh::Config::from_json5(&value.to_string()).map_err(|_| TransportError::InvalidConfig)
    }
}

fn ordered_endpoints(endpoints: &[String], lane: usize) -> Vec<&str> {
    (0..endpoints.len())
        .map(|offset| endpoints[(lane + offset) % endpoints.len()].as_str())
        .collect()
}
