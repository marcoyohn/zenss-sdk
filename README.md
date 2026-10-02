# ZenSS SDK

Public contracts, native Plugin SDK and outbound Client SDK for **ZenSS (ZeroNode Serverless Scale)**. This repository is generated from approved committed source files. The private platform host and its history are not distributed here. Edit the source repository, not this generated snapshot.

| Package | Role |
| --- | --- |
| `zenss-contracts` | Versioned keys, lifecycle messages and application identities; no host dependencies |
| `zenss-plugin-trait` | Native Plugin SDK using the official Zenoh plugin interface, managed lifecycle and version-pinned native admission hook |
| `zenss-client-sdk` | Outbound TCP/TLS sessions, bounded queries and service discovery |

## Build

```sh
cargo build --locked --workspace
cargo test --locked --workspace
```

The repository includes its own public dependency lockfile and Rust toolchain. CI checks Linux and macOS using only this repository and crates.io. See [API and integration guide](docs/api.md), [echo plugin](examples/product-echo/src/lib.rs), and [outbound client](examples/outbound-client/src/main.rs).

## Depend on a release

```toml
[dependencies]
zenss-contracts = { git = "https://github.com/marcoyohn/zenss-sdk", tag = "v0.1.1" }
zenss-client-sdk = { git = "https://github.com/marcoyohn/zenss-sdk", tag = "v0.1.1" }
# Native server plugin only:
# zenss-plugin-trait = { git = "https://github.com/marcoyohn/zenss-sdk", tag = "v0.1.1" }
```

The tag above is an example; use a tag that exists in this repository or pin an actual published `rev`. Contracts, Plugin SDK and Client SDK share the SDK release version. Registry publication is separate; these crates are not claimed to be on crates.io.

## Compatibility and host delivery

`compatibility.json` contains portable toolchain, Zenoh and lock inputs. `sdk-source.json` records the source revision and SHA-256 hashes of the entire exported snapshot. Native plugins must match their **host artifact's** compiler, target, features and shared dependency graph. Matching an SDK version alone does not establish Rust ABI compatibility; rebuild native plugins when upgrading the host. Native plugins are trusted code and share process permissions. Upgrade by draining and replacing the host process.

Network clients depend on application/Zenoh protocol compatibility and do not need the host's Rust compiler. SDK CI verifies independent compilation/tests; binary host/plugin integration and target support are recorded separately with host releases. A host binary/container is supplied separately by the platform owner. This SDK snapshot contains no host binary, platform internals, deployment secrets or automatic business-retry executor.

## License

See [LICENSE](LICENSE). Licensing of the public SDK is separate from licensing of the private platform implementation. Preserve applicable notices for Zenoh and other dependencies in downstream distributions.

The 0.2.0 candidate includes a reviewed, public upstream Zenoh vendor with the `zenss-route-gate/1` native extension. The Client SDK retains its stock registry dependency. Private host policy and CA implementation are excluded. The original 0.1.1 releases remain immutable. See the [native admission API](docs/api.md#native-route-authorization-020-candidate) for exact scope and remaining gates.
