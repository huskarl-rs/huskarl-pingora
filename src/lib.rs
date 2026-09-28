#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![cfg_attr(not(test), deny(clippy::indexing_slicing))]
#![warn(clippy::pedantic)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! Browser login and bearer-token protection for Pingora reverse proxies.
//!
//! Choose `login` for browser sessions managed by an OIDC provider, or
//! `resource` for clients that send access tokens. Both features are enabled
//! by default. `default-jws-verifier-platform` supplies native token verification;
//! without it, provide a verifier platform explicitly.
//!
//! # Deployment limits
//!
//! Before deploying browser login beyond localhost:
//!
//! - Use HTTPS and configure the public HTTPS redirect URI; its scheme controls
//!   secure cookies, even when TLS terminates before Pingora.
//! - Persist cookie keys and share compatible key rings across replicas. Shared
//!   keys let replicas read sessions; they do not coordinate refresh exchanges.
//! - Check provider rules for simultaneous refresh-token exchanges. The
//!   engine does not prevent them, even within one replica.
//! - Cookie sessions cannot prevent an older response from restoring browser
//!   state after refresh or logout. Local logout does not end provider SSO.
//! - Restrict upstream access to trusted proxy connections and replace incoming
//!   identity headers before forwarding authenticated identity.
//!
//! Follow the [deployment guide](_docs::how_to::deployment) for configuration,
//! session-store choices, cookie delivery, and rollout checks.
//!
//! # Documentation
//!
//! - **Learn:** follow a [tutorial](_docs::tutorial) from setup to a working proxy.
//! - **Do a task:** use the [how-to guides](_docs::how_to) for routing and identity forwarding.
//! - **Understand:** read the [explanations](_docs::explanation) for path ambiguity and proxy lifecycle.
//! - **Look up a contract:** use the [configuration reference](_docs::reference)
//!   and feature-specific API modules below.
#![cfg_attr(
    feature = "login",
    doc = "The [`login`] module documents `LoginProxy`, `LoginRule`, and `LoginCtx`."
)]
#![cfg_attr(
    feature = "resource",
    doc = "The [`resource`] module documents `AuthProxy`, `Guard`, and `Rule`."
)]
//!
//! # Routing
//!
//! Use `subtree` to protect a path and its descendants; `route` matches one
//! exact path. Unmatched paths require authentication by default. The path
//! guard checks the downstream parsing assumptions you declare; it does not
//! rewrite paths or infer your upstream's behavior.
//!
//! Start with the [how-to guides](_docs::how_to) to configure route rules and
//! the [explanations](_docs::explanation) to understand their security boundaries.

#[cfg(any(doc, doctest))]
pub mod _docs;

#[cfg(feature = "login")]
pub mod login;
#[cfg(feature = "resource")]
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
