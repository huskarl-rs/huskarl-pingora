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

# Documentation

- **Learn:** follow a [tutorial](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/tutorial/) from setup to a working proxy.
- **Do a task:** use the [how-to guides](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/how_to/) for routing and identity forwarding.
- **Understand:** read the [explanations](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/explanation/) for path ambiguity and proxy lifecycle.
- **Look up a contract:** use the [configuration reference](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/reference/)
  and feature-specific API modules below.
The [`login`](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/login/) module documents `LoginProxy`, `LoginRule`, and `LoginCtx`.
The [`resource`](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/resource/) module documents `AuthProxy`, `Guard`, and `Rule`.

# Routing

Use `subtree` to protect a path and its descendants; `route` matches one
exact path. Unmatched paths require authentication by default. The path
guard checks the downstream parsing assumptions you declare; it does not
rewrite paths or infer your upstream’s behavior.

Start with the [how-to guides](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/how_to/) to configure route rules and
the [explanations](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/explanation/) to understand their security boundaries.

<!-- cargo-reedme: end -->
