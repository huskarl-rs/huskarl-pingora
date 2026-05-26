//! OAuth 2.0 resource server (bearer token) protection for Pingora.
//!
//! Provides [`AuthProxy`], a [`ProxyHttp`](pingora_proxy::ProxyHttp) decorator
//! that validates bearer tokens on incoming requests before forwarding them to
//! the inner proxy.
//!
//! Access control is defined through path-based [`Rule`]s registered on a
//! [`Guard`]. Each rule specifies whether a route is public, optionally
//! authenticated, or requires a valid token — and can additionally enforce
//! audience, scope, and custom checks.
//!
//! # Features
//!
//! - **Path-based routing** — rules are matched using [`matchit`] patterns
//!   (e.g. `/users/{id}`, `/public/*rest`).
//! - **Scope enforcement** — requires tokens to carry specific scopes via the
//!   [`HasScopes`] trait.
//! - **DPoP support** — proof-of-possession tokens are validated and
//!   `DPoP-Nonce` headers are propagated automatically.
//! - **Credential stripping** — `Authorization` and `DPoP` headers are removed
//!   before forwarding to upstream by default.
//! - **[RFC 9728] resource metadata** — optionally serves a
//!   `/.well-known/oauth-protected-resource` JSON endpoint.
//!
//! [RFC 9728]: https://datatracker.ietf.org/doc/html/rfc9728

mod ctx;
pub(crate) mod error;
mod guard;
mod outcome;
mod proxy;
pub(crate) mod response;
pub mod rule;
pub mod scopes;
#[cfg(test)]
pub(crate) mod test_support;
pub(crate) mod uri;

pub use ctx::{AuthCtx, HasAuthState};
pub use error::ConfigError;
pub use guard::{ClientCertDer, Guard, GuardBuilder};
pub use outcome::Outcome;
pub use proxy::AuthProxy;
pub use rule::{CheckError, Rule, TokenRequirement};
pub use scopes::HasScopes;
