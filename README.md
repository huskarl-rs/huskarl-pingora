<!-- cargo-reedme: start -->

<!-- cargo-reedme: info-start

    Do not edit this region by hand
    ===============================

    This region was generated from Rust documentation comments by `cargo-reedme` using this command:

        cargo +nightly reedme

    for more info: https://github.com/nik-rev/cargo-reedme

cargo-reedme: info-end -->

Browser login and access-token protection for Pingora reverse proxies.

Wrap an existing Pingora proxy to authenticate requests before forwarding them
upstream. Choose the integration that matches your clients:

| Task | Start with |
|---|---|
| Require browser sign-in and manage sessions | `login::LoginProxy` |
| Protect resources and publish discovery metadata | `resource::assembly::ResourceAssembly` |
| Integrate resources into your own router or publisher | `resource::BoundResource` |
| Validate access tokens without resource discovery | `resource::Guard` + `resource::AuthProxy` |

# Start here

Follow a [first-run tutorial](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/tutorial/) for browser login or token
protection. For an existing application, choose a [how-to guide](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/how_to/).
The [explanations](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/explanation/) cover URL mapping, path ambiguity, and
session lifecycle. The [reference](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/reference/) and API modules describe
configuration, defaults, and observable behavior.

# Cargo features

Defaults enable `resource`, `login`, and `default-jws-verifier-platform`.
For one authentication mode, choose one of these dependency declarations:

```toml
# Access-token protection.
huskarl-pingora = { version = "0.7", default-features = false, features = ["resource", "default-jws-verifier-platform"] }

# Browser login.
huskarl-pingora = { version = "0.7", default-features = false, features = ["login", "default-jws-verifier-platform"] }
```

| Feature | Effect |
|---|---|
| `resource` | Resource policies, token authentication, and discovery publication |
| `login` | Browser login, session context, and login policies |
| `default-jws-verifier-platform` | Native token verification; omit when supplying your own verifier platform |
| `metrics` | Adapter counters; install your own recorder/exporter |
| `upstream_modules` | Support for Pingora upstream modules |

Features compile APIs; your application must still configure and install a
proxy. Cargo features are additive: other dependencies can enable the default
verifier platform. See the [telemetry reference](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/reference/telemetry/)
for counter names and counting boundaries.

# Routing

Use `subtree` to protect a path and its descendants, and `route` for one exact
path. Unmatched policy paths require authentication by default. Policies use
paths as received by Pingora, including any incoming mount prefix.
The path guard checks your declared downstream parsing assumptions; it does
not rewrite requests. See [route policies](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/how_to/) for configuration.

# Before deployment

Use HTTPS, preserve session keys across restarts, and restrict upstream access
to trusted proxy connections. Forward authenticated identity explicitly and
replace client-supplied identity headers. Browser sessions also require a
choice of storage, refresh-concurrency policy, and reliable cookie delivery.
Follow [Deploy a proxy](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/how_to/deployment/) before exposing it beyond localhost.

<!-- cargo-reedme: end -->

For discovery setup and multiple resources, follow
[Publish protected-resource metadata](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/how_to/resource_metadata/) and the
[runnable two-resource example](examples/multi_resource_proxy.rs).

Start with the [example progression](examples/README.md): one resource, multiple
resources, custom publication, then browser login and rewritten deployments.
