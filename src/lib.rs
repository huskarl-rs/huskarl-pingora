#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![cfg_attr(not(test), deny(clippy::indexing_slicing))]
#![warn(clippy::pedantic)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! Browser login and access-token protection for Pingora reverse proxies.
//!
//! Wrap an existing Pingora proxy to authenticate requests before forwarding them
//! upstream. Choose the integration that matches your clients:
//!
//! | Task | Start with |
//! |---|---|
//! | Require browser sign-in and manage sessions | `login::LoginProxy` |
//! | Protect resources and publish discovery metadata | `resource::assembly::ResourceAssembly` |
//! | Integrate resources into your own router or publisher | `resource::BoundResource` |
//! | Validate access tokens without resource discovery | `resource::Guard` + `resource::AuthProxy` |
//!
//! # Start here
//!
//! Follow a [first-run tutorial](_docs::tutorial) for browser login or token
//! protection. For an existing application, choose a [how-to guide](_docs::how_to).
//! The [explanations](_docs::explanation) cover URL mapping, path ambiguity, and
//! session lifecycle. The [reference](_docs::reference) and API modules describe
//! configuration, defaults, and observable behavior.
//!
//! # Cargo features
//!
//! Defaults enable `resource`, `login`, and `default-jws-verifier-platform`.
//! For one authentication mode, choose one of these dependency declarations:
//!
//! ```toml
//! # Access-token protection.
//! huskarl-pingora = { version = "0.6", default-features = false, features = ["resource", "default-jws-verifier-platform"] }
//!
//! # Browser login.
//! huskarl-pingora = { version = "0.6", default-features = false, features = ["login", "default-jws-verifier-platform"] }
//! ```
//!
//! | Feature | Effect |
//! |---|---|
//! | `resource` | Resource policies, token authentication, and discovery publication |
//! | `login` | Browser login, session context, and login policies |
//! | `default-jws-verifier-platform` | Native token verification; omit when supplying your own verifier platform |
//! | `metrics` | Adapter counters; install your own recorder/exporter |
//! | `upstream_modules` | Support for Pingora upstream modules |
//!
//! Features compile APIs; your application must still configure and install a
//! proxy. Cargo features are additive: other dependencies can enable the default
//! verifier platform. See the [telemetry reference](_docs::reference::telemetry)
//! for counter names and counting boundaries.
//!
//! # Routing
//!
//! Use `subtree` to protect a path and its descendants, and `route` for one exact
//! path. Unmatched policy paths require authentication by default. Policies use
//! paths as received by Pingora, including any incoming mount prefix.
//! The path guard checks your declared downstream parsing assumptions; it does
//! not rewrite requests. See [route policies](_docs::how_to) for configuration.
//!
//! # Before deployment
//!
//! Use HTTPS, preserve session keys across restarts, and restrict upstream access
//! to trusted proxy connections. Forward authenticated identity explicitly and
//! replace client-supplied identity headers. Browser sessions also require a
//! choice of storage, refresh-concurrency policy, and reliable cookie delivery.
//! Follow [Deploy a proxy](_docs::how_to::deployment) before exposing it beyond localhost.

#[cfg(any(doc, doctest))]
pub mod _docs;

#[cfg(feature = "login")]
pub mod login;
#[cfg(any(feature = "resource", feature = "login"))]
pub(crate) mod metrics;
#[cfg(feature = "resource")]
pub mod resource;

/// Re-export of [`huskarl_resource_server`] for convenience.
#[cfg(feature = "resource")]
pub use huskarl_resource_server as resource_server;
#[cfg(any(feature = "resource", feature = "login"))]
pub mod path_confusion;

#[cfg(any(feature = "resource", feature = "login"))]
mod method;

#[cfg(any(feature = "resource", feature = "login"))]
mod routing;

#[cfg(all(test, any(feature = "resource", feature = "login")))]
mod metrics_test_support;
