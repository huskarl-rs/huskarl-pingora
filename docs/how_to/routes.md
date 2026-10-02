# Choose route policies

Use a required rule for protected endpoints, an optional rule for pages that can
personalize anonymous access, and a public rule when authentication should be
skipped entirely. Policies use the path received by Pingora, including its mount
prefix. For gateway deployments, first configure [URL mapping](crate::_docs::how_to::url_mapping).

## 1. Choose authentication behavior

| Policy | No credentials | Supplied credentials |
|---|---|---|
| Resource `required` | 401 challenge | Validate, then apply audience, scope, and custom checks |
| Resource `optional` | Forward anonymously | Validate, then apply the same checks; invalid tokens are rejected |
| Login `required` | Start login for browser navigation; challenge API requests | Load a session, then apply its custom check |
| Login `optional` | Forward anonymously | Load a session and apply any custom check |
| `public` | Forward anonymously | Skip token validation or session loading |

Optional login does not promise that every request proceeds. A custom check can
deny a loaded session; load errors and temporary refresh unavailability can stop
forwarding. For cleared or expired sessions, the shared engine determines whether
a usable session remains. See [refresh behavior](https://docs.rs/huskarl-login/0.5.0/huskarl_login/_docs/explanation/refresh/).

Public rules do not populate identity even when a client supplies credentials.
Use optional authentication for an anonymous page that should display a signed-in
user. Opening an optional login page does not itself start sign-in; link to a
required route.

## 2. Protect a subtree and add an exact exception

`subtree("/api", ...)` covers `/api`, `/api/`, and descendants. `route("/api", ...)`
covers only `/api`. A more-specific exact route can carve out an exception:

```rust
# #[cfg(feature = "resource")]
# {
use huskarl_pingora::resource::{
    CaseSensitivity, DecodeDepth, GuardConfig, ResourcePolicy, Rule,
};
let policy = ResourcePolicy::<()>::builder()
    .path_guard(GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne))
    .subtree("/api", Rule::required().scopes(["api.read"]))
    .route("/api/health", Rule::public())
    .build()?;
# let _ = policy;
# }
# Ok::<(), Box<dyn std::error::Error>>(())
```

The claims type `()` keeps this policy-only example independent of a validator.
When attaching it to a guard, use your validator's claims type, usually inferred
by the surrounding construction. Required scopes use that type's `HasScopes`
implementation. All listed scopes must be present; audience lists accept any
matching audience. Public rules with authorization constraints fail at build time.

For login, apply the equivalent rules to an existing builder:

```rust
# #[cfg(feature = "login")]
# fn configure<P, SD>(inner: P, engine: std::sync::Arc<huskarl_pingora::login::LoginEngine<SD>>)
# -> Result<(), Box<dyn std::error::Error>>
# where P: pingora_proxy::ProxyHttp + Send + Sync,
# P::CTX: huskarl_pingora::login::HasLoginSession<SD::SessionType> + Send + Sync,
# SD: huskarl_pingora::login::SessionDriver + Send + Sync {
use huskarl_pingora::login::{CaseSensitivity, DecodeDepth, GuardConfig, LoginProxy, LoginRule};
let proxy = LoginProxy::builder()
    .inner(inner)
    .engine(engine)
    .path_guard(GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne))
    .subtree("/dashboard", LoginRule::required())
    .route("/health", LoginRule::public())
    .route("/", LoginRule::optional())
    .build()?;
# let _ = proxy;
# Ok(())
# }
```

Unmatched paths require authentication by default. A trailing slash in
`subtree("/api/", ...)` excludes bare `/api`. Use `blob_subtree` when nested
policy overrides should be rejected at build time; it still checks path ambiguity.

## 3. Set method policy deliberately

Register rules for the same path to distinguish reads from writes. An all-method
rule at that path provides the fallback for methods without an explicit override:

```rust
# #[cfg(feature = "resource")]
# {
use http::Method;
use huskarl_pingora::resource::{CaseSensitivity, DecodeDepth, GuardConfig, ResourcePolicy, Rule};
let policy = ResourcePolicy::<()>::builder()
    .path_guard(GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne))
    .route("/items", Rule::required()) // Fallback for other methods at this path.
    .route("/items", Rule::public().method(Method::GET))
    .route("/items", Rule::required().scopes(["items.write"]).method(Method::POST))
    .build()?;
# let _ = policy;
# }
# Ok::<(), Box<dyn std::error::Error>>(())
```

Without that all-method rule, unlisted methods return 403 before authentication,
even if a broader subtree or the default rule is public. HEAD is a separate
request method; add a HEAD rule when it should share GET's access policy.
Strip method-override headers if an upstream honors them. Login's default CORS
preflight pass-through is handled before session policy; the inner proxy still
owns its CORS response.

## 4. Verify the boundaries

Test the bare path, trailing slash, descendants, exact exception, and GET/HEAD/POST
requests. Test missing, invalid, insufficient-scope, and valid credentials. For
optional login, test anonymous access and a loaded session rejected by a custom
check. Verify that public routes see no authenticated context.

Configure the [path guard](crate::_docs::how_to::path_guard) for the full downstream
parsing pipeline. The proxy forwards paths unchanged; access rules must cover the
boundaries the upstream actually enforces.
