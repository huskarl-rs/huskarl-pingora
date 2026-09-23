<!-- cargo-reedme: start -->

<!-- cargo-reedme: info-start

    Do not edit this region by hand
    ===============================

    This region was generated from Rust documentation comments by `cargo-reedme` using this command:

        cargo +nightly reedme

    for more info: https://github.com/nik-rev/cargo-reedme

cargo-reedme: info-end -->

Pingora integration for huskarl.

This crate provides two independent feature-gated modules:
- **`resource`** — OAuth 2.0 resource-server (bearer token) protection via [`resource::AuthProxy`](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/resource/proxy/struct.AuthProxy.html) and [`resource::Guard`](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/resource/guard/struct.Guard.html).
- **`login`** — OAuth 2.0 Authorization Code Grant login layer via [`login::LoginProxy`](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/login/proxy/struct.LoginProxy.html).

Both features are enabled by default.

# Routing

Both proxies map request paths to per-path rules. There are two ways to
register a rule, and **which you pick is a security decision**:

- **`subtree(path, rule)`** applies the rule to `path` *and everything
  beneath it* (`/admin`, `/admin/`, `/admin/users/42`). This is what you
  almost always want when protecting an area of your API, and it is the
  recommended default.
- **`route(pattern, rule)`** matches a single path *exactly*. `route("/admin",
  …)` does **not** cover `/admin/` or `/admin/users` — those fall through to
  the default rule. Reach for `route` only when you genuinely mean one path
  (e.g. a health check), or to carve a more-specific exception out of a
  `subtree`.

Using `route` where you meant `subtree` is a classic authorization gap: the
scope/audience checks you attached to `/admin` silently don’t apply to
`/admin/users`. When in doubt, use `subtree`.

Unmatched paths fall back to the builder’s default rule — `Rule::required()`
/ `LoginRule::required()` — so everything is protected unless you open it up.

# Path confusion

Rules are matched on the request path, but the **raw** path is forwarded
upstream. If the proxy and the upstream disagree about what a path *means* —
a parser differential — a request can be authorized as one path while the
upstream acts on another (`/x/../admin/secret`, `/admin%2fsecret`,
`/admin/..;/secret`, …). Both proxies guard against this automatically, and
it is **on by default**. The guard only ever *detects*: it denies with `400`,
or allows and forwards the **raw** path unchanged — nothing synthesized ever
reaches the upstream.

The default [`GuardMode::RejectAmbiguous`](https://docs.rs/huskarl_route_guard/latest/huskarl_route_guard/config/enum.GuardMode.html#variant.RejectAmbiguous)
checks whether the configured downstream parsing behaviors could select a
different authorization rule. Its guarantees depend on your case sensitivity,
decode depth, and structural-class declarations. See the
[`path_confusion`](https://docs.rs/huskarl_route_guard/latest/huskarl_route_guard/config/) configuration module for the supported parsing model.

Structural forms can pass when analysis proves they stay within the same rule.
For example, `subtree("/files", Rule::public())` permits `/files/a%2Fb.txt`
when no nested rule changes the policy. `/files/../admin/x` is denied when it
could escape into a different rule. NUL truncation is always denied in active modes.

`blob_subtree` registers an exclusive subtree: nested overrides are a build
error. It uses the same ambiguity checks as an ordinary subtree; exclusivity
does not disable checks or by itself establish uniform method coverage.

Method-specific rules deny unlisted methods with `403 Forbidden`, even if
the default rule is public. Register an all-method rule at the same path to
supply an explicit fallback policy.

## Opt-in classes and encodings

The always-on alphabet is encoded slash, dot-segments, `;`-matrix-params, and
`%00`/raw-NUL truncation — the forms whose legitimate-traffic cost is near nil. A
backend that considers *more* paths equivalent needs the matching toggle on
[`StructuralClasses`](https://docs.rs/huskarl_route_guard/latest/huskarl_route_guard/config/struct.StructuralClasses.html), passed via the builder's
`structural_classes`:

- [`with_backslash()`](https://docs.rs/huskarl_route_guard/latest/huskarl_route_guard/config/struct.StructuralClasses.html#method.with_backslash) — `\`/`%5C`
  as a separator (Windows/IIS);
- [`with_overlong([…])`](path_confusion::StructuralClasses::with_overlong) —
  recognise overlong-UTF-8 forms (`%C0%AF`) accepted by legacy decoders;
- [`with_probe(p)`](https://docs.rs/huskarl_route_guard/latest/huskarl_route_guard/config/struct.StructuralClasses.html#method.with_probe) — a custom
  [`StructuralProbe`](https://docs.rs/huskarl_route_guard/latest/huskarl_route_guard/config/trait.StructuralProbe.html) **break-glass** for a structural
  form the built-in alphabet doesn't ship (e.g. a fresh CVE), denied on presence
  anywhere in the path.

Each toggle is a per-deployment security decision: it is how you tell the guard
which paths your backend considers equivalent. Example:
`StructuralClasses::new().with_backslash()`. (Case and decode depth are **not**
here — they are separate, required builder declarations; see below.)

## Decode depth

The builder requires [`DecodeDepth`](https://docs.rs/huskarl_route_guard/latest/huskarl_route_guard/config/enum.DecodeDepth.html), with no default.
Declare `UpToOne` when downstream performs at most one whole-path percent decode,
or `UpToTwo` when it may perform up to two. Count actual decoding passes across
intermediaries and the origin, rather than the number of processes. More than
two passes are outside the supported model.

## Case-insensitive backends

Path matching here is **case-sensitive** (and so is the route matcher), but whether that
matches your upstream is a security fact the library cannot infer — so the builder
**requires** you to declare it with
[`CaseSensitivity`](https://docs.rs/huskarl_route_guard/latest/huskarl_route_guard/config/enum.CaseSensitivity.html); there is no default. A case-folding
upstream — IIS, ASP.NET, servlet containers on Windows, or anything serving files
from a Windows/macOS filesystem — routes `/ADMIN` and `/admin` to the same resource,
so a differently-cased request can reach a route *without that route's checks*
(`/ADMIN` falling through to a weaker rule, then served as `/admin`).

- [`Sensitive`](https://docs.rs/huskarl_route_guard/latest/huskarl_route_guard/config/enum.CaseSensitivity.html#variant.Sensitive) — the upstream distinguishes
  case; routes differing only by case are genuinely distinct and allowed.
- [`Insensitive`](https://docs.rs/huskarl_route_guard/latest/huskarl_route_guard/config/enum.CaseSensitivity.html#variant.Insensitive) — the upstream folds
  case. The guard then runs a **precise case-fold check**: it lowercases the request
  path, re-routes it, and denies only if the folded path lands on a *different* rule
  — mixed-case content that folds within its own rule (`/files/ReadMe.TXT`) keeps
  flowing, while `/ADMIN` folding onto a distinct `/admin` rule is denied. **Route
  patterns must be registered in lowercase** (an uppercase pattern is a build error —
  it is the form the backend resolves to), and two routes differing only by case are
  rejected at build. Only ASCII case is modeled.

## Strict mode, disabled mode, and analysis budget

[`GuardMode::RequireCanonical`](https://docs.rs/huskarl_route_guard/latest/huskarl_route_guard/config/enum.GuardMode.html#variant.RequireCanonical)
rejects recognized structural forms and complete percent escapes even within a
uniform subtree. [`GuardMode::Disabled`](https://docs.rs/huskarl_route_guard/latest/huskarl_route_guard/config/enum.GuardMode.html#variant.Disabled)
disables ambiguity analysis, but still validates path input and denies unlisted
methods. Select the mode with `.guard_mode(...)`.

`.max_analysis_path_len(...)` sets the analysis budget in original path bytes
(default: 8,192). With custom probes it applies to every path; disabled mode
bypasses the budget. This is not an overall request-size limit.

Active modes reject non-canonical route patterns at construction time.

# Resource server example

A minimal JWT-protected reverse proxy using an [RFC 9068] validator. Note
how `subtree` protects the whole API while `route` opens a single exact
health endpoint:

[RFC 9068]: https://datatracker.ietf.org/doc/html/rfc9068

```rust
use std::sync::Arc;

use async_trait::async_trait;
use huskarl_pingora::{
    resource::{AuthCtx, AuthProxy, CaseSensitivity, DecodeDepth, Guard, Rule},
    resource_server::{
        core::{jwk::JwksSource, server_metadata::AuthorizationServerMetadata},
        validator::rfc9068::Rfc9068Validator,
    },
};
use huskarl_reqwest::ReqwestClient;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::Result;
use pingora_proxy::{ProxyHttp, Session};

type Claims = huskarl_pingora::resource_server::validator::rfc9068::Rfc9068AccessTokenClaims;

struct MyProxy;

#[async_trait]
impl ProxyHttp for MyProxy {
    type CTX = AuthCtx<(), Claims>;
    fn new_ctx(&self) -> Self::CTX {
        AuthCtx::new(())
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let peer = HttpPeer::new("127.0.0.1:3000", false, String::new());
        Ok(Box::new(peer))
    }
}

#[tokio::main]
async fn main() {
    // 1. Create an HTTP client for fetching metadata and JWKS.
    let http_client = ReqwestClient::builder()
        .mtls(huskarl_reqwest::mtls::NoMtls)
        .build()
        .await
        .expect("HTTP client");

    // 2. Discover the authorization server's metadata (issuer, jwks_uri, …).
    let metadata = AuthorizationServerMetadata::fetch()
        .http_client(&http_client)
        .issuer("https://auth.example.com")
        .call()
        .await
        .expect("AS metadata");

    // 3. Build an RFC 9068 JWT validator.
    let jwks = Arc::new(JwksSource::builder().http_client(http_client).build());
    let validator = Rfc9068Validator::builder_from_metadata(&metadata)
        .audience("my-api")
        .jws_verifier_factory(jwks)
        .build()
        .await
        .expect("validator");

    // 4. Wrap your proxy with the auth guard.
    //    `subtree` protects a path and everything beneath it; `route`
    //    matches one exact path. Unmatched paths use the default
    //    (`Rule::required()`), so the whole proxy is closed by default.
    let guard = Guard::builder()
        .validator(validator)
        .case_sensitivity(CaseSensitivity::Sensitive) // required: declare backend case behavior
        .decode_depth(DecodeDepth::UpToOne) // required: declare decode depth behind this layer
        .subtree("/api", Rule::required().scopes(["api"])) // /api and below
        .route("/health", Rule::public()) // exactly /health
        .build()
        .expect("guard");

    let proxy = AuthProxy::new(MyProxy, guard);
    // pass `proxy` to pingora — it implements ProxyHttp
}
```

<!-- cargo-reedme: end -->
