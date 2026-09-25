#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![cfg_attr(not(test), deny(clippy::indexing_slicing))]
#![warn(clippy::pedantic)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! Pingora integration for huskarl.
//!
//! This crate provides two independent feature-gated modules:
// Each bullet is gated to its feature so the intra-doc links resolve under any feature
// combination (a shared `//!` line would link a module that isn't compiled). The default
// build enables both, so docs.rs shows both with working links.
#![cfg_attr(
    feature = "resource",
    doc = "- **`resource`** — OAuth 2.0 resource-server (bearer token) protection via [`resource::AuthProxy`] and [`resource::Guard`]."
)]
#![cfg_attr(
    feature = "login",
    doc = "- **`login`** — OAuth 2.0 Authorization Code Grant login layer via [`login::LoginProxy`]."
)]
//!
//! Both features are enabled by default.
//!
//! # Routing
//!
//! Both proxies map request paths to per-path rules. There are two ways to
//! register a rule, and **which you pick is a security decision**:
//!
//! - **`subtree(path, rule)`** applies the rule to `path` *and everything
//!   beneath it* (`/admin`, `/admin/`, `/admin/users/42`). This is what you
//!   almost always want when protecting an area of your API, and it is the
//!   recommended default.
//! - **`route(pattern, rule)`** matches a single path *exactly*. `route("/admin",
//!   …)` does **not** cover `/admin/` or `/admin/users` — those fall through to
//!   the default rule. Reach for `route` only when you genuinely mean one path
//!   (e.g. a health check), or to carve a more-specific exception out of a
//!   `subtree`.
//!
//! Using `route` where you meant `subtree` is a classic authorization gap: the
//! scope/audience checks you attached to `/admin` silently don't apply to
//! `/admin/users`. When in doubt, use `subtree`.
//!
//! Unmatched paths fall back to the builder's default rule — `Rule::required()`
//! / `LoginRule::required()` — so everything is protected unless you open it up.
//!
//! # Path confusion
//!
//! Rules are matched on the request path, which huskarl leaves unchanged.
//! If the proxy and the upstream disagree about what a path *means* —
//! a parser differential — a request can be authorized as one path while the
//! upstream acts on another (`/x/../admin/secret`, `/admin%2fsecret`,
//! `/admin/..;/secret`, …). Both proxies guard against this automatically, and
//! it is **on by default**. The guard only ever *detects*: it denies the request
//! or allows it without rewriting the path. An inner proxy can still rewrite it;
//! see the forwarding and rewrite contract below.
//!
//! The default [`GuardMode::RejectAmbiguous`](path_confusion::GuardMode::RejectAmbiguous)
//! checks whether the configured downstream parsing behaviors could select a
//! different authorization rule. Its guarantees depend on your case sensitivity,
//! decode depth, and structural-class declarations. See the
//! [`path_confusion`] configuration module for the supported parsing model.
//!
//! Structural forms can pass when analysis proves they stay within the same rule.
//! For example, `subtree("/files", Rule::public())` permits `/files/a%2Fb.txt`
//! when no nested rule changes the policy. `/files/../admin/x` is denied when it
//! could escape into a different rule. NUL truncation is always denied in active modes.
//!
//! `blob_subtree` registers an exclusive subtree: nested overrides are a build
//! error. It uses the same ambiguity checks as an ordinary subtree; exclusivity
//! does not disable checks or by itself establish uniform method coverage.
//!
//! Method-specific rules deny unlisted methods with `403 Forbidden`, even if
//! the default rule is public. Register an all-method rule at the same path to
//! supply an explicit fallback policy.
//!
//! ## Authorization across layers
//!
//! The path guard checks ambiguity against this proxy's configured rules only.
//! A `LoginProxy` with only a default rule still enforces that login policy and
//! performs input checks, but its ambiguity analysis cannot distinguish finer
//! permission boundaries enforced by inner handlers. For example, if an inner
//! handler restricts `/downloads/private` more than `/downloads/public`, a
//! single outer login rule does not protect that distinction from path confusion.
//!
//! Represent those boundaries in the guarding layer's rule table, or guard them
//! in the layer that makes the authorization decision, using its own rules and
//! downstream parsing assumptions. Passing the outer guard does not establish
//! that a path is unambiguous for every inner authorization decision.
//!
//! ## Forwarding and rewrite contract
//!
//! The baseline contract is to forward the checked path unchanged. The guard
//! analyzes downstream parsing of that path; it does not model arbitrary rewrites
//! performed by an inner proxy such as `RouterProxy`.
//!
//! A prefix replacement can preserve the guarantee only when every downstream
//! interpretation of the rewritten path remains within the authorization policy
//! checked before the rewrite. The rule table must cover the corresponding
//! boundaries in the original path namespace, and the declared case sensitivity,
//! decode depth, and structural classes must cover the full downstream pipeline,
//! including any parsing performed by the rewrite itself.
//!
//! Applying the same prefix replacement consistently is not sufficient by itself:
//! removing a prefix can change where `..` resolves, and decoding before selecting
//! a prefix can change which rewrite applies. Verify the actual guard, rewrite,
//! and downstream routing together, including encoded separators and traversal
//! at the prefix boundary. If that correspondence cannot be established, resolve
//! and authorize the rewritten path with a guard configured for the destination
//! rules before dispatching it.
//!
//! ## Opt-in classes and encodings
//!
//! The always-on alphabet is encoded slash, dot-segments, `;`-matrix-params, and
//! `%00`/raw-NUL truncation — the forms whose legitimate-traffic cost is near nil. A
//! backend that considers *more* paths equivalent needs the matching toggle on
//! [`StructuralClasses`](path_confusion::StructuralClasses), passed via the builder's
//! `structural_classes`:
//!
//! - [`with_backslash()`](path_confusion::StructuralClasses::with_backslash) — `\`/`%5C`
//!   as a separator (Windows/IIS);
//! - [`with_overlong([…])`](path_confusion::StructuralClasses::with_overlong) —
//!   recognise overlong-UTF-8 forms (`%C0%AF`) accepted by legacy decoders;
//! - [`with_probe(p)`](path_confusion::StructuralClasses::with_probe) — a custom
//!   [`StructuralProbe`](path_confusion::StructuralProbe) **break-glass** for a structural
//!   form the built-in alphabet doesn't ship (e.g. a fresh CVE), denied on presence
//!   anywhere in the path.
//!
//! Each toggle is a per-deployment security decision: it is how you tell the guard
//! which paths your backend considers equivalent. Example:
//! `StructuralClasses::new().with_backslash()`. (Case and decode depth are **not**
//! here — they are separate, required builder declarations; see below.)
//!
//! ## Decode depth
//!
//! The builder requires [`DecodeDepth`](path_confusion::DecodeDepth), with no default.
//! Declare `UpToOne` when downstream performs at most one whole-path percent decode,
//! or `UpToTwo` when it may perform up to two. Count actual decoding passes across
//! intermediaries and the origin, rather than the number of processes. More than
//! two passes are outside the supported model.
//!
//! ## Case-insensitive backends
//!
//! Path matching here is **case-sensitive** (and so is the route matcher), but whether that
//! matches your upstream is a security fact the library cannot infer — so the builder
//! **requires** you to declare it with
//! [`CaseSensitivity`](path_confusion::CaseSensitivity); there is no default. A case-folding
//! upstream — IIS, ASP.NET, servlet containers on Windows, or anything serving files
//! from a Windows/macOS filesystem — routes `/ADMIN` and `/admin` to the same resource,
//! so a differently-cased request can reach a route *without that route's checks*
//! (`/ADMIN` falling through to a weaker rule, then served as `/admin`).
//!
//! - [`Sensitive`](path_confusion::CaseSensitivity::Sensitive) — the upstream distinguishes
//!   case; routes differing only by case are genuinely distinct and allowed.
//! - [`Insensitive`](path_confusion::CaseSensitivity::Insensitive) — the upstream folds
//!   case. The guard then runs a **precise case-fold check**: it lowercases the request
//!   path, re-routes it, and denies only if the folded path lands on a *different* rule
//!   — mixed-case content that folds within its own rule (`/files/ReadMe.TXT`) keeps
//!   flowing, while `/ADMIN` folding onto a distinct `/admin` rule is denied. **Route
//!   patterns must be registered in lowercase** (an uppercase pattern is a build error —
//!   it is the form the backend resolves to), and two routes differing only by case are
//!   rejected at build. Only ASCII case is modeled.
//!
//! ## Strict mode, disabled mode, and analysis budget
//!
//! [`GuardMode::RequireCanonical`](path_confusion::GuardMode::RequireCanonical)
//! rejects recognized structural forms and complete percent escapes even within a
//! uniform subtree. [`GuardMode::Disabled`](path_confusion::GuardMode::Disabled)
//! disables ambiguity analysis, but still validates path input and denies unlisted
//! methods. Select the mode with `.guard_mode(...)`.
//!
//! `.max_analysis_path_len(...)` sets the analysis budget in original path bytes
//! (default: 8,192). With custom probes it applies to every path; disabled mode
//! bypasses the budget. This is not an overall request-size limit.
//!
//! Active modes reject non-canonical route patterns at construction time.
//!
//! # Resource server example
//!
//! A minimal JWT-protected reverse proxy using an [RFC 9068] validator. Note
//! how `subtree` protects the whole API while `route` opens a single exact
//! health endpoint:
//!
//! [RFC 9068]: https://datatracker.ietf.org/doc/html/rfc9068
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use async_trait::async_trait;
//! use huskarl_pingora::{
//!     resource::{AuthCtx, AuthProxy, CaseSensitivity, DecodeDepth, Guard, Rule},
//!     resource_server::{
//!         core::{jwk::JwksSource, server_metadata::AuthorizationServerMetadata},
//!         validator::rfc9068::Rfc9068Validator,
//!     },
//! };
//! use huskarl_reqwest::ReqwestClient;
//! use pingora_core::upstreams::peer::HttpPeer;
//! use pingora_error::Result;
//! use pingora_proxy::{ProxyHttp, Session};
//!
//! type Claims = huskarl_pingora::resource_server::validator::rfc9068::Rfc9068AccessTokenClaims;
//!
//! struct MyProxy;
//!
//! #[async_trait]
//! impl ProxyHttp for MyProxy {
//!     type CTX = AuthCtx<(), Claims>;
//!     fn new_ctx(&self) -> Self::CTX {
//!         AuthCtx::new(())
//!     }
//!
//!     async fn upstream_peer(
//!         &self,
//!         _session: &mut Session,
//!         _ctx: &mut Self::CTX,
//!     ) -> Result<Box<HttpPeer>> {
//!         let peer = HttpPeer::new("127.0.0.1:3000", false, String::new());
//!         Ok(Box::new(peer))
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() {
//!     // 1. Create an HTTP client for fetching metadata and JWKS.
//!     let http_client = ReqwestClient::builder()
//!         .mtls(huskarl_reqwest::mtls::NoMtls)
//!         .build()
//!         .await
//!         .expect("HTTP client");
//!
//!     // 2. Discover the authorization server's metadata (issuer, jwks_uri, …).
//!     let metadata = AuthorizationServerMetadata::fetch()
//!         .http_client(&http_client)
//!         .issuer("https://auth.example.com")
//!         .call()
//!         .await
//!         .expect("AS metadata");
//!
//!     // 3. Build an RFC 9068 JWT validator.
//!     let jwks = Arc::new(JwksSource::builder().http_client(http_client).build());
//!     let validator = Rfc9068Validator::builder_from_metadata(&metadata)
//!         .audience("my-api")
//!         .jws_verifier_factory(jwks)
//!         .build()
//!         .await
//!         .expect("validator");
//!
//!     // 4. Wrap your proxy with the auth guard.
//!     //    `subtree` protects a path and everything beneath it; `route`
//!     //    matches one exact path. Unmatched paths use the default
//!     //    (`Rule::required()`), so the whole proxy is closed by default.
//!     let guard = Guard::builder()
//!         .validator(validator)
//!         .case_sensitivity(CaseSensitivity::Sensitive) // required: declare backend case behavior
//!         .decode_depth(DecodeDepth::UpToOne) // required: declare decode depth behind this layer
//!         .subtree("/api", Rule::required().scopes(["api"])) // /api and below
//!         .route("/health", Rule::public()) // exactly /health
//!         .build()
//!         .expect("guard");
//!
//!     let proxy = AuthProxy::new(MyProxy, guard);
//!     // pass `proxy` to pingora — it implements ProxyHttp
//! }
//! ```

#[cfg(feature = "login")]
pub mod login;
#[cfg(feature = "resource")]
pub(crate) mod metrics;
#[cfg(feature = "resource")]
pub mod resource;

/// Re-export of [`huskarl_resource_server`] for convenience.
#[cfg(feature = "resource")]
pub use huskarl_resource_server as resource_server;
/// Re-export of [`huskarl_route_guard`]'s path-confusion configuration — the
/// routing and path-confusion engine both proxies are built on.
#[cfg(any(feature = "resource", feature = "login"))]
pub use huskarl_route_guard::config as path_confusion;

#[cfg(any(feature = "resource", feature = "login"))]
mod method;
