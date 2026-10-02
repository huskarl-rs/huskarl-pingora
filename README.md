<!-- cargo-reedme: start -->

<!-- cargo-reedme: info-start

    Do not edit this region by hand
    ===============================

    This region was generated from Rust documentation comments by `cargo-reedme` using this command:

        cargo +nightly reedme

    for more info: https://github.com/nik-rev/cargo-reedme

cargo-reedme: info-end -->

Browser login and bearer-token protection for Pingora reverse proxies.

Choose `login` for browser sessions managed by an OIDC provider, or
`resource` for clients that send access tokens. Both features are enabled
by default. `default-jws-verifier-platform` supplies native token verification;
without it, provide a verifier platform explicitly.

Enable the optional `metrics` feature for named adapter counters. See the
[telemetry reference](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/reference/telemetry/) for counting boundaries,
application diagnostics, and dependency limitations.

# Cargo features

The defaults enable `resource`, `login`, and `default-jws-verifier-platform`.
This suits a gateway serving both token-authenticated APIs and browser sessions.
For a gateway dedicated to one mode, disable defaults and select that mode:

```toml
# Bearer/DPoP/mTLS resource protection only.
huskarl-pingora = { version = "0.6", default-features = false, features = ["resource", "default-jws-verifier-platform"] }

# Browser login only.
huskarl-pingora = { version = "0.6", default-features = false, features = ["login", "default-jws-verifier-platform"] }
```

These are alternative dependency declarations. Add `metrics` for adapter
counters; add `upstream_modules` when using Pingora upstream modules. Neither
feature selects an authentication mode. To use an application-supplied verifier
platform, omit `default-jws-verifier-platform` and supply the platform explicitly
when configuring token validation. Cargo features are additive, so other
dependencies may still enable the underlying default platform. Enabling a
feature compiles its APIs; it does
not install authentication on a proxy automatically.

# Deployment limits

Before deploying browser login beyond localhost:

- Use HTTPS and configure the public HTTPS redirect URI; its scheme controls
  secure cookies, even when TLS terminates before Pingora.
- Persist cookie keys and share compatible key rings across replicas. Shared
  keys let replicas read sessions; they do not coordinate refresh exchanges.
- Check provider rules for simultaneous refresh-token exchanges. The
  engine does not prevent them, even within one replica.
- Cookie sessions cannot prevent an older response from restoring browser
  state after refresh or logout. Local logout does not end provider SSO.
- Restrict upstream access to trusted proxy connections and replace incoming
  identity headers before forwarding authenticated identity.

Follow the [deployment guide](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/how_to/deployment/) for configuration,
session-store choices, cookie delivery, and rollout checks.

# Documentation

- **Learn:** follow a [tutorial](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/tutorial/) from setup to a working proxy.
- **Do a task:** use the [how-to guides](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/how_to/) for routing and identity forwarding.
- **Understand:** read the [explanations](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/explanation/) for path ambiguity and proxy lifecycle.
- **Look up a contract:** use the [configuration reference](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/reference/)
  and feature-specific API modules below.
The [`login`](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/login/) module documents `LoginProxy`, `LoginRule`, and `LoginCtx`.
The [`resource`](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/resource/) module documents `ResourcePolicy`, `BoundResource`, and standalone `AuthProxy`.

# Routing

Use `subtree` to protect a path and its descendants; `route` matches one
exact path. Unmatched paths require authentication by default. The path
guard checks the downstream parsing assumptions you declare; it does not
rewrite paths or infer your upstream’s behavior.

Start with the [how-to guides](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/how_to/) to configure route rules and
the [explanations](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/explanation/) to understand their security boundaries.

<!-- cargo-reedme: end -->

For discovery setup and multiple resources, follow
[Publish protected-resource metadata](docs/how_to/resource_metadata.md) and the
[runnable two-resource example](examples/multi_resource_proxy.rs).

Start with the [example progression](examples/README.md): one resource, multiple
resources, custom publication, then browser login and rewritten deployments.
