# ZenSS SDK integration

## Contracts

`zenss-contracts` exposes protocol version `1`, lifecycle phase/snapshot/command types, and `ServiceIdentity`. A validated identity contains deployment, product and instance; each segment is 1–128 ASCII letters, digits, underscores or hyphens. Presence uses `zenss/v1/{deployment}/services/{product}/{instance}`. Presence means network membership, not authorization, business readiness or an execution lease. Message payloads are limited to 1 MiB.

```rust
use zenss_contracts::ServiceIdentity;
let identity = ServiceIdentity::new("dev", "lingshu", "one")?;
let key = identity.liveliness_key()?;
# Ok::<(), zenss_contracts::InvalidIdentity>(())
```

## Outbound Client SDK

```rust
use zenss_client_sdk::{Client, ClientOptions};
let client = Client::connect(ClientOptions {
    endpoints: vec!["tcp/127.0.0.1:7447".into()],
    tls: None,
    timeout_ms: 5000,
}).await?;
let reply = client.query("zenss/v1/local/products/echo/one/query", b"hello".to_vec()).await?;
client.close().await?;
# Ok::<(), anyhow::Error>(())
```

The SDK opens explicit outbound sessions in Zenoh client mode. Scouting and listening are disabled. Local TCP is limited to IP loopback. Remote connections use `tls/server.example:7447` with `tls` set to Zenoh credential configuration, including `enable_mtls: true`, `root_ca_certificate`, `connect_certificate`, `connect_private_key`, `verify_name_on_connect: true`, and `close_link_on_expiration: true`. Set paths to files delivered by your deployment; never commit keys or credentials. Endpoint-local security overrides are rejected. The host must independently authenticate certificates and enforce namespace ACLs.

`query` addresses a bounded exact key, rejects wildcard queries and oversized requests/replies, and returns the first result or an error. A timeout is an unknown business outcome; the SDK does not replay business writes. `discover(deployment)` calls the platform discovery capability and validates every returned identity's scope. Keep the token returned by `announce` alive for the desired presence lifetime. Native `session()` APIs are available for subscriptions and product-specific protocols. Endpoint lists are failover/topology inputs, not a promised arbitrary connection pool.

## Native Plugin SDK

See [product-echo](../examples/product-echo/src/lib.rs) for the complete buildable example. Implement official `Plugin` with `DynamicRuntime` and `RunningPlugin`, declare it with `declare_zenss_plugin!`, and use `ManagedPlugin::start` to supervise asynchronous initialization, admission, child tasks, drain and cleanup. Read injected deployment/admission settings through `PluginSettings`; do not depend on private `zenssd` or `zenss-config` crates.

Obtain the product Session from the supplied host Runtime, rather than creating a second Router. Declare business Queryables/subscribers only after initialization succeeds. Retain admission guards while work is active, respect drain/cancellation and track tasks so cleanup is acknowledged only when resources are released. Arbitrary blocking native start code is not forcibly preempted or sandboxed.

```sh
cargo build --locked -p zenss-example-product-echo
# Use an independently supplied, compatible zenssd binary:
zenssd --plugin-dir ./target/debug -P echo:./target/debug/libzenss_plugin_echo.so -c /path/to/product-config.json5
# macOS uses .dylib; host and plugin must target the same platform.
```

Use a host-supported config with an explicit plane, identity, safe listen endpoint and echo plugin entry. The SDK repository intentionally does not include private deployment configuration. Lifecycle commands are host-owned official config/adminspace interactions, not additional arbitrary public control endpoints. The host loads only explicitly configured/trusted library paths. A native plugin runs with host privileges.

## Current delivery scope

These packages provide foundation contracts and lifecycle/network primitives. They do not implement Lingshu/ZenCollab domain APIs, a general capability-negotiation handshake, durable business retries, Kubernetes scheduling or a stable cross-compiler ABI. Product integrations supply their own versioned protocol and authorization checks. Use only host/plugin target combinations verified in your host artifact's support matrix.
