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

It combines a *positional* check (which structural bytes can change routing, and
where) with a *content-decode* check (whether percent-decoding the path lands on a
different rule, catching `/%61dmin` → `/admin`). For the complete decision
algorithm — what each check covers, what it does **not**, and how to configure it
for your backend — see the
[`path_confusion`](https://docs.rs/huskarl_route_guard/latest/huskarl_route_guard/path_confusion/) module.

The guard, whose mode is selected with [`PathConfusion`](https://docs.rs/huskarl_route_guard/latest/huskarl_route_guard/path_confusion/enum.PathConfusion.html),
denies a structural byte wherever a wildcard or catch-all captures it. To proxy opaque keys
that legitimately contain encoded separators, opt the tail in explicitly with
`blob_subtree` (see below) — it is never inferred from table shape.

## Positional structural reject (the default)

[`PathConfusion::reject_structural()`](https://docs.rs/huskarl_route_guard/latest/huskarl_route_guard/path_confusion/PathConfusion/fn.reject_structural.html)
models **no backend**. Because route patterns are canonical, any structural
character (`%2F`, `..`, `;`, …) in a request necessarily lands inside a wildcard or
catch-all position — so the default denies it. The route table you already wrote is
the entire input; you never need to know how your backend parses paths.

With `subtree("/files", …)`, `subtree("/admin", …)`, and
`route("/users/{id}", …)`:

| request | verdict | reason |
|---|---|---|
| `/files/a%2Fb.txt` | **deny** | `%2F` could split the captured tail into another segment |
| `/files/../admin/x` | **deny** | `..` can climb out of `/files` into `/admin` |
| `/users/4%2F2` | **deny** | `%2F` could split the `{id}` segment into another route |
| `/users/42` | allow | clean |

## Opaque key spaces (`blob_subtree`)

When a prefix proxies opaque identifiers whose keys legitimately contain encoded
separators (object-store keys, …), register it with `blob_subtree` instead of
`subtree`. Its catch-all tail then **tolerates** the boundary-shifting bytes
(`%2F`, `;`, `\`) inside the key, so `/files/a%2Fb.txt` is allowed — but `..` and
NUL truncation are **still** denied even there, so traversal cannot escape the
blob. Registering a more-specific route *under* a `blob_subtree` is a
build error (a structural byte could then relocate into it), so the opt-in is safe
by construction rather than dependent on table shape.

## Opt-in classes and encodings

The always-on alphabet is encoded slash, dot-segments, `;`-matrix-params, and
`%00`/raw-NUL truncation — the forms whose legitimate-traffic cost is near nil. A
backend that considers *more* paths equivalent needs the matching toggle on
[`StructuralClasses`](https://docs.rs/huskarl_route_guard/latest/huskarl_route_guard/path_confusion/struct.StructuralClasses.html), passed via the builder’s
`structural_classes`:

- [`with_backslash()`](https://docs.rs/huskarl_route_guard/latest/huskarl_route_guard/path_confusion/StructuralClasses/fn.with_backslash.html) — `\`/`%5C`
  as a separator (Windows/IIS);
- [`with_overlong([…])`](https://docs.rs/huskarl_route_guard/latest/huskarl_route_guard/path_confusion/StructuralClasses/fn.with_overlong.html) —
  recognise overlong-UTF-8 forms (`%C0%AF`) accepted by legacy decoders;
- [`with_probe(p)`](https://docs.rs/huskarl_route_guard/latest/huskarl_route_guard/path_confusion/StructuralClasses/fn.with_probe.html) — a custom
  [`StructuralProbe`](https://docs.rs/huskarl_route_guard/latest/huskarl_route_guard/path_confusion/trait.StructuralProbe.html) **break-glass** for a structural
  form the built-in alphabet doesn’t ship (e.g. a fresh CVE), denied on presence
  anywhere in the path.

Each toggle is a per-deployment security decision: it is how you tell the guard
which paths your backend considers equivalent. Example:
`StructuralClasses::new().with_backslash()`. (Case and decode depth are **not**
here — they are separate, required builder declarations; see below.)

## Decoding layers in front of the upstream

The builder **requires** a [`DecodeLayers`](https://docs.rs/huskarl_route_guard/latest/huskarl_route_guard/path_confusion/enum.DecodeLayers.html)
declaration; there is no default. Declare
[`UpToTwo`](https://docs.rs/huskarl_route_guard/latest/huskarl_route_guard/path_confusion/DecodeLayers/#variant.UpToTwo) whenever the path may receive
one or two percent-decode passes before it is finally routed — a CDN or WAF in front
of the origin, or proxy-in-front-of-proxy. That topology is **CVE-2025-0108** (PAN-OS):
nginx decoded `%252e%252e` once and passed it, then Apache decoded again to `..`
and traversed into a protected path. Under `UpToTwo`, double-percent forms
(`%252F`, `%252E`) are treated as structure and the content-decode check applies
two passes. Declare [`Single`](https://docs.rs/huskarl_route_guard/latest/huskarl_route_guard/path_confusion/DecodeLayers/#variant.Single) for a lone
backend with nothing decoding in front; when unsure, `UpToTwo` is the safe,
deny-more direction.

## Case-insensitive backends

Path matching here is **case-sensitive** (and so is the route matcher), but whether that
matches your upstream is a security fact the library cannot infer — so the builder
**requires** you to declare it with
[`CaseSensitivity`](https://docs.rs/huskarl_route_guard/latest/huskarl_route_guard/path_confusion/enum.CaseSensitivity.html); there is no default. A case-folding
upstream — IIS, ASP.NET, servlet containers on Windows, or anything serving files
from a Windows/macOS filesystem — routes `/ADMIN` and `/admin` to the same resource,
so a differently-cased request can reach a route *without that route’s checks*
(`/ADMIN` falling through to a weaker rule, then served as `/admin`).

- [`Sensitive`](https://docs.rs/huskarl_route_guard/latest/huskarl_route_guard/path_confusion/CaseSensitivity/#variant.Sensitive) — the upstream distinguishes
  case; routes differing only by case are genuinely distinct and allowed.
- [`Insensitive`](https://docs.rs/huskarl_route_guard/latest/huskarl_route_guard/path_confusion/CaseSensitivity/#variant.Insensitive) — the upstream folds
  case. The guard then runs a **precise case-fold check**: it lowercases the request
  path, re-routes it, and denies only if the folded path lands on a *different* rule
  — mixed-case content that folds within its own rule (`/files/ReadMe.TXT`) keeps
  flowing, while `/ADMIN` folding onto a distinct `/admin` rule is denied. **Route
  patterns must be registered in lowercase** (an uppercase pattern is a build error —
  it is the form the backend resolves to), and two routes differing only by case are
  rejected at build. Only ASCII case is modeled.

## Strict and off

[`reject_non_canonical()`](https://docs.rs/huskarl_route_guard/latest/huskarl_route_guard/path_confusion/PathConfusion/fn.reject_non_canonical.html)
treats *every* position as live — it denies **any** non-canonical path (`..`,
`//`, encoded separators) outright, strict defense-in-depth that also rejects
legitimate blob keys. [`off()`](https://docs.rs/huskarl_route_guard/latest/huskarl_route_guard/path_confusion/PathConfusion/fn.off.html) disables the
guard.

## Build-time check

Registering a route pattern that is itself non-canonical (e.g. `route("/a//b")`
alongside `route("/a/b")`) is rejected at build time — every request to it
would be denied, so it is a configuration error rather than a silent dead
route.

# Resource server example

A minimal JWT-protected reverse proxy using an [RFC 9068] validator. Note
how `subtree` protects the whole API while `route` opens a single exact
health endpoint:

[RFC 9068]: https://datatracker.ietf.org/doc/html/rfc9068

```rust
use std::sync::Arc;

use async_trait::async_trait;
use huskarl_pingora::{
    resource::{AuthCtx, AuthProxy, CaseSensitivity, DecodeLayers, Guard, Rule},
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
        .decode_layers(DecodeLayers::Single) // required: declare decode depth behind this layer
        .subtree("/api", Rule::required().scopes(["api"])) // /api and below
        .route("/health", Rule::public()) // exactly /health
        .build()
        .expect("guard");

    let proxy = AuthProxy::new(MyProxy, guard);
    // pass `proxy` to pingora — it implements ProxyHttp
}
```

<!-- cargo-reedme: end -->
