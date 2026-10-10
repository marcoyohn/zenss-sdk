# ZenSS SDK

Public contracts, native Plugin SDK and dual-mode Client SDK for **ZenSS (ZeroNode Serverless Scale)**. This repository is generated from approved committed source files. The private platform host and its history are not distributed here. Edit the source repository, not this generated snapshot.

| Package | Role |
| --- | --- |
| `zenss-contracts` | Versioned keys, lifecycle messages and application identities; no host dependencies |
| `zenss-plugin-trait` | Native Plugin SDK using the official Zenoh plugin interface, managed lifecycle and version-pinned native admission hook |
| `zenss-client-sdk` | Explicit outbound/hosted client facade, managed network pools and service discovery |
| `zenss-client-host` | Optional native adapter creating an owned Session on the supplied host Runtime |

## Build

```sh
cargo build --locked --workspace
cargo test --locked --workspace
```

The repository includes its own public dependency lockfile and Rust toolchain. CI checks Linux and macOS using only this repository and crates.io. See [API and integration guide](docs/api.md), [echo plugin](examples/product-echo/src/lib.rs), and [outbound client](examples/outbound-client/src/main.rs).

## Depend on a release

```toml
[dependencies]
zenss-contracts = { git = "https://github.com/marcoyohn/zenss-sdk", tag = "v0.6.0" }
zenss-client-sdk = { git = "https://github.com/marcoyohn/zenss-sdk", tag = "v0.6.0" }
# Native server plugin only:
# zenss-plugin-trait = { git = "https://github.com/marcoyohn/zenss-sdk", tag = "v0.6.0" }
```

The tag above is an example; use a tag that exists in this repository or pin an actual published `rev`. Contracts, Plugin SDK and Client SDK share the SDK release version. Registry publication is separate; these crates are not claimed to be on crates.io.

## Compatibility and host delivery

`compatibility.json` contains portable toolchain, Zenoh and lock inputs. `sdk-source.json` records the source revision and SHA-256 hashes of the entire exported snapshot. Native plugins must match their **host artifact's** compiler, target, features and shared dependency graph. Matching an SDK version alone does not establish Rust ABI compatibility; rebuild native plugins when upgrading the host. Native plugins are trusted code and share process permissions. Upgrade by draining and replacing the host process.

Network clients depend on application/Zenoh protocol compatibility and do not need the host's Rust compiler. SDK CI verifies independent compilation/tests; binary host/plugin integration and target support are recorded separately with host releases. A host binary/container is supplied separately by the platform owner. This SDK snapshot contains no host binary, platform internals, deployment secrets or automatic business-retry executor.

## License

See [LICENSE](LICENSE). Licensing of the public SDK is separate from licensing of the private platform implementation. Preserve applicable notices for Zenoh and other dependencies in downstream distributions.

The 0.2.0 candidate includes a reviewed, public upstream Zenoh vendor with the `zenss-route-gate/1` native extension. The Client SDK retains its stock registry dependency. Private host policy and CA implementation are excluded. The original 0.1.1 releases remain immutable. See the [native admission API](docs/api.md#native-route-authorization-020-candidate) for exact scope and remaining gates.

## Linux native receive-window prerequisite

The Lingshu native TLS profile requests `transport.link.tls.so_rcvbuf = 1048576`
through official Zenoh configuration; the gated Host applies the same request to
TCP/TLS. This kernel receive buffer is distinct from the 65535-byte native RX
batch pool. Linux normally accounts twice the socket request. Host admission
charges that receive storage within the existing aggregate allocation; it is
not a bound on all TLS, allocator, kernel send or business memory.

Verify `sysctl -n net.core.rmem_max` on **both the Host and Linux SDK machine**.
The deployment prerequisite is at least1048576 bytes. Linux silently clamps
ordinary SO_RCVBUF when this limit is lower; checking configuration alone cannot
prove the requested window was granted. For containers/Kubernetes, configure
and verify the underlying node through its normal provisioning process; this
is not an application-level or portable Pod sysctl.

An operator can provision the required cap with
`sudo sysctl -w net.core.rmem_max=1048576`, retaining a larger existing value.
Persist it using the machine's normal sysctl provisioning only after deployment
review. The SDK and Host never change system limits or use SO_RCVBUFFORCE.
Official configuration and the fixed resource/performance gates must be verified
with the actual deployment cap; diagnostic socket injection is not acceptance.
The accepted Linux fixture uses glibc arena2 and records its node cap separately.
macOS kernel-window behavior has not been accepted by the Linux measurements.

Version 0.4.0 adds proven RSA transport-key metadata for explicit authenticated intranet TCP products. Native layout IDs end in `_resourcebudget12_plaintext1`; rebuild plugins with the exact matching Host/Build Kit. Route protocol versions `/1` and `/2` are unchanged, but the 0.3.0 native layout is incompatible. This does not make the generic `zenss-client-sdk` accept remote plaintext: Lingshu uses its own official-Zenoh client and HTTPS bootstrap.

Development TCP Router peering uses native stamp `_resourcebudget12_plaintext2`. It retains the same public interfaces and wire protocol versions; products still must rebuild against the exact matching Host/Build Kit. Version 0.4.0's immutable plaintext1 artifacts do not provide this opt-in feature. Ordinary network clients continue to use official Zenoh.

### Candidate platform notification API

The next build kit adds `zenss_plugin_trait::notifications::PlatformNotifications`: bounded, advisory platform hints on the shared Host Session, authenticated by issuer-scoped Router receipts. Products retain authoritative reconciliation. This API is not in published v0.4.0; use a new immutable release before updating downstream pins. See `docs/platform-notifications.md` in the source repository.

## Managed client transport (v0.5.1)

`zenss-client-sdk` now provides `ManagedPool`, `PoolLayout`, typed `TransportOptions`,
TLS/explicit intranet RSA credentials, local CSR/key generation, connectivity
notifications and bounded cleanup. Product code owns identity verification,
role handoff and business acknowledgements. Enable `plaintext` explicitly for
the authenticated unencrypted profile; no TLS fallback is attempted.

This release adds client APIs only. Existing native Host/Plugin SDK/build-kit
v0.5.0 combinations stay pinned; no v0.5.1 Host image is implied. Network clients
continue to use official crates.io Zenoh 1.10.1 and never require private source.

### v0.5.2 fixture correction

The test-support managed fixture keeps its declared synthetic topology stable until closure. Real pools continue observing Router topology; no production protocol or Host change is included.

## Explicit Runtime ownership (v0.6.0)

Use `Client::connect(options)` for an independent client Runtime and Session, or
`Client::from_host(context, binding)` for a new client-owned Session sharing the
zenssd Router Runtime. The latter requires the public `zenss-client-host` adapter.
Both expose query, discovery, presence and mode-specific `session()` access.
See [the runnable example](sdk/rust/zenss-client-host/examples/host_client.rs).

Each hosted Client owns a distinct Session; closing, dropping, expiring or revoking
it closes that Session, including raw declarations and retained Session clones.
Host and sibling Sessions remain usable. Cleanup is tracked through plugin shutdown.
Raw Session operations bypass facade scope/capacity checks; shared ZID does not
confer product authorization. Plugins remain trusted native code.

This breaking change replaces 0.5.3's borrowed-Session constructor. Session.clone()
is not an independent Session; create another Client from PluginContext instead.
Ordinary clients retain registry Zenoh and exclude the native adapter/Plugin SDK.
Native consumers rebuild with a matched Host/Plugin SDK/build kit. SDK publication
does not certify a new Host image; Lingshu's authenticated ManagedPool remains
outbound. See [the API guide](docs/api.md) for ownership and migration details.

## Connection lifecycle (0.7.0)

ManagedPool observes official Zenoh transport events with history and independent
physical revisions. Rapid disconnect/reopen fences the old connection even when
watch notifications coalesce. The ordinary Client still uses crates.io Zenoh.

Matched native Host/build kits add product-owner scopes and physical connection
receipts. Connected data grants require their current parent control grant;
owner loss, transport loss and root revocation deny new and queued admission.
The privileged `connection-authority/2` capability reports `disconnect_channel`:
products can retire authenticated local transports after revoking admission.
This does not replace product authorization or accepted business report deadlines.

Native layout IDs now end in `_plaintext2_connection1` because RouteSubject gains
physical evidence. Older binary plugins must be rebuilt with the matching kit;
wire clients negotiate product support. Route protocol `/1` and `/2` are unchanged.
