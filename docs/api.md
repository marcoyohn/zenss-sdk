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

## Native route authorization (0.2.0 candidate)

The matching host may enable `zenss-route-gate/1`. Public `zenss_contracts::route_authorization` contains `RouteLease`, `RoutePrincipal`, exact action/flow permissions and revoke/drain commands. The private host validates issuer ownership, increasing revision, bounded capacity and a hard lease of at most 30 seconds. Root revocation affects all roles; grant revocation affects one grant. Client certificates are a separate bound of at most five minutes, not a business grant.

A trusted native product freshly authenticates the application/parent key, then calls `issue_channel_credential(runtime, &request)` with a client-generated signed Ed25519 CSR; the client private key stays local. The host replaces CSR names/usages and signs only client credentials using deployment-owned secrets. `update_route_authorization(runtime, &command)` is native-only control, never an SDK-accessible Queryable. Declare exact routes only after a valid grant and explicit product readiness handshake.

When processing a shared control Query, call `authenticated_query_context(runtime, &query)` before business logic. It consumes the host's admission receipt for the real bytes/target and returns the authenticated principal and message verification public key. Compare business claims to this principal and independently verify signatures, nonce reuse, role/attempt permission and hard deadlines. Do not trust payload identities, attachments, source_info or ZID as authentication.

The native build kit contains stock public Zenoh source plus the reviewed admission hook and upstream licenses. Its deterministic ABI marker/vendor inventory must match the separately delivered host. It excludes private admission/CA implementation. Ordinary Client SDK dependencies continue to use crates.io Zenoh. TLS credentials accept file paths or the matching `*_base64` fields; use exactly one representation per credential, and Debug redacts TLS values.

This is admission infrastructure. It does not finish product bootstrap, trusted multi-router origin propagation, CA rotation, 1/2/4 lane recovery, domain retries or production readiness.

## Optional Router origin native profile (unreleased candidate)

The build kit vendor now exposes `zenoh/zenss-router-origin` in addition to the
existing default route gate. A native product using `zenoh.workspace = true` selects
it with `zenoh = { workspace = true, features = ["zenss-router-origin"] }` in its
manifest, matching a host built with `zenssd/router-origin`. The native marker and
vtable become `zenss-route-gate/2`; default builds stay `/1`. Match the host target,
compiler and entire shared feature graph. Profiles are listed in compatibility and
vendor inventory files. The route command/context DTOs do not change.

This optional hook reserves a bounded Query attachment for private host provenance;
ordinary application clients supply no such attachment and continue using official
registry Zenoh. Peer config/signing/policy and CA keys are not public SDK content.
The candidate is not a release of Lingshu cross-replica business support, and does
not alter immutable 0.2.0 SDK/Host tags. A matched formal release and target validation
are required before downstream selection.


### Platform query context in the /2 candidate

Use `authenticated_platform_query_context(runtime, &query)` for a privileged
product-to-product request whose direct Router origin is Platform. Its strict
`AuthenticatedPlatformQueryContext` exposes only the authenticated source Router,
issuer and original admission deadline. It uses the same single-use digest/key
receipt callback as the Client helper; select the expected context before lookup.
A Platform receipt cannot be decoded by `authenticated_query_context` as a Client,
and a Client receipt cannot be decoded as Platform. Receipt admission never mints
Client credentials, report grants or business permission. Products must recheck
their own application, role, capability and operation deadlines. This helper is an
unreleased matching /2 addition; it does not require ordinary clients to use the
native build kit.

### Candidate finite Router admission transfer (not released in v0.2.0)

The matched Router-origin Host accepts these strict, privileged JSON operations
through `DynamicRuntime::route_gate_credential`, without adding a native trait
method. The ordinary Client SDK never exposes them.

- `{"operation":"probe_route_authorization_transfer","issuer":"<product>"}`
  returns `{source, peers}` for configured pinned ownership. Unsupported Hosts fail.
- `{"operation":"export_route_authorization","audience":"<pinned-router-CN>","command":<existing RouteAuthorizationCommand>}`
  returns a JSON string containing an opaque finite signed capsule. Only current
  locally issued grants or applied local revoke tombstones can be exported.
- `{"operation":"import_route_authorization","source":"<authenticated-router-CN>","capsule":"<opaque-string>"}`
  returns `null` on installation. A product network adapter must first consume a
  one-use direct pinned Platform Query receipt and pass its verified source.

Capsules are audience-bound and have a three-second acceptance window. Imported
CSR provenance is foreign; it cannot issue, independently extend or re-export a
grant. Same-revision retries keep the first monotonic deadline. Source, CSR and
parent ownership remain fixed; revocation fences late imports. Remote product
Drain is unsupported. The receiving lease is shortened by 500ms for the fixed
250ms clock-anchor tolerance at each Router. Network replication and business
route-ready proof remain product responsibilities. These operations require the
candidate matching Host and reviewed topology; they do not enable production.

## Managed outbound transport

- `ManagedPool::open(options, layout, shared_budget, deadline, root_closed, metrics)` opens finite independent sessions, cancelled safely even during partial opening.
- `subscribe_connectivity`, `subscribe_closed`, `subscribe_deadline` provide coalesced observations without granting product readiness.
- `update_deadline` accepts a product-verified monotonic deadline and refuses expired/stopped owners.
- `request_close`/`close` stop and join; failed cleanup retains capacity.
- `credentials::signing_request` creates a local signing key/CSR; `PossessionKey` supports the explicit `plaintext` feature. Private keys are never sent to the platform.
- Existing Client, query/discover and announcement APIs remain available.
