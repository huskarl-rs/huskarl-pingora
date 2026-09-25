//! OAuth 2.0 Authorization Code Grant login layer for Pingora.
//!
//! Provides [`LoginProxy`], a [`ProxyHttp`](pingora_proxy::ProxyHttp) decorator
//! that runs each request through the shared
//! [`LoginEngine`]: unauthenticated
//! requests are redirected through an Authorization Code Grant flow before
//! reaching the inner proxy.
//!
//! Per-path policy is registered on [`LoginProxy::builder`]: prefer
//! [`subtree`](LoginProxyBuilder::subtree) to apply a [`LoginRule`] to a path
//! and everything beneath it, and use [`route`](LoginProxyBuilder::route) for a
//! single exact path. See the [crate-level routing notes](crate#routing) for why
//! the choice matters.
//!
//! Session management is built in via two modes:
//!
//! - **Cookie sessions** ([`CookieSessionStore`]) — encrypt the full session
//!   into chunked browser cookies. No external infrastructure needed.
//! - **Store-backed sessions** ([`StoreBackedSessionStore`]) — cookie holds an
//!   encrypted pointer; data lives in an external store (Redis, DB, etc.)
//!   that you provide via the [`ExternalSessionStore`] trait.
//!
//! PAR, JAR, `DPoP`, and PKCE are handled by the
//! [`AuthorizationCodeGrant`](huskarl::grant::authorization_code::AuthorizationCodeGrant)
//! driving the flow, following the grant's own configuration.

mod ctx;
mod proxy;
mod rule;

// ── Pingora-specific public API ─────────────────────────────────────────────
pub use ctx::{HasLoginSession, LoginCtx, LoginState};
// ── Advanced: implementing a custom session type or external store, or driving
// engine primitives directly ─────────────────────────────────────────────────
//
// `PersistedSession` / `PersistedSessionState` are the session types for the
// store-backed (server-side) path: use `PersistedSessionState` directly as your
// `ExternalSessionStore::SessionType`, or embed it in a custom type that
// implements `PersistedSession`. `SessionEnricher` builds that session from a
// completed login (`StoreBackedSessionStore::build_with_enricher`).
pub use huskarl_login::{
    CompletedLogin, ExternalSessionStore, PersistedSession, PersistedSessionState, SessionDriver,
    SessionEnricher, SessionState, engine::LoginResponse,
};
// ── Everyday building blocks ─────────────────────────────────────────────────
//
// Re-exported from `huskarl_login` so a typical `LoginProxy` setup imports from
// a single module. For anything not listed here, depend on `huskarl_login`
// directly.
pub use huskarl_login::{
    ConfigError, CookieSession, CookieSessionStore, DefaultPersistFailurePolicy, LoginConfig,
    LogoutConfig, PersistFailurePolicy, SessionError, SessionLifetime, StoreBackedSessionStore,
    engine::LoginEngine,
};
pub use proxy::{LoginProxy, LoginProxyBuilder, RouteConfigError};
pub use rule::{CheckError, LoginRule};

pub use crate::method::MethodMatch;
#[doc(no_inline)]
pub use crate::path_confusion::{
    CaseSensitivity, DecodeDepth, GuardConfig, GuardMode, ResolveError, ResolveErrorKind,
    StructuralChar, StructuralClass, StructuralClasses, StructuralProbe,
};
