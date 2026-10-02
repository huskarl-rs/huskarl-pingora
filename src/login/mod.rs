//! OAuth 2.0 Authorization Code Grant login layer for Pingora.
//!
//! Provides [`LoginProxy`], a [`ProxyHttp`](pingora_proxy::ProxyHttp) decorator
//! that uses a shared [`LoginEngine`] to load sessions and handle sign-in and
//! logout. Required routes redirect unauthenticated browser navigations to the
//! provider; API requests receive a challenge. Public routes skip session loading,
//! and optional routes allow requests without a session.
//!
//! Your inner proxy's context must implement [`HasLoginSession`]. Use
//! [`LoginCtx`] to wrap an existing context, then read its loaded session in the
//! inner request or forwarding hooks. Use [`LoginState::respond`] for local
//! responses that must deliver session cookies.
//!
//! Per-path policy is registered on [`LoginProxy::builder`]: prefer
//! [`subtree`](LoginProxyBuilder::subtree) to apply a [`LoginRule`] to a path
//! and everything beneath it, and use [`route`](LoginProxyBuilder::route) for a
//! single exact path. See the [crate-level routing notes](crate#routing) for why
//! the choice matters.
//!
//! Follow the [browser login tutorial](crate::_docs::tutorial::browser_login)
//! for a complete proxy and upstream setup. See [identity forwarding](crate::_docs::how_to::identity)
//! for the boundary between the proxy context and an upstream service.
//!
//! # Configure the shared engine
//!
//! Use the `huskarl-login` [engine tutorial](https://docs.rs/huskarl-login/0.5.0/huskarl_login/_docs/tutorial/getting_started/)
//! to construct a grant, session store, and engine for your application. Its
//! [deployment guide](https://docs.rs/huskarl-login/0.5.0/huskarl_login/_docs/how_to/deployment/)
//! covers provider policy, keys, replicas, and storage. This adapter owns Pingora
//! route policies, request context, forwarding, and response finalization.
//!
//! Session management supports two modes:
//!
//! - **Cookie sessions** ([`CookieSessionStore`]) — encrypt the full session
//!   into chunked browser cookies. No external infrastructure needed.
//! - **Store-backed sessions** ([`StoreBackedSessionStore`]) — cookie holds an
//!   encrypted pointer; data lives in an external store (Redis, DB, etc.)
//!   that you provide via the [`ExternalSessionStore`] trait. Follow the shared
//!   [external-store guide](https://docs.rs/huskarl-login/0.5.0/huskarl_login/_docs/how_to/external_store/).
//!
//! To add profile fields or application roles, use the shared
//! [session enrichment guide](https://docs.rs/huskarl-login/0.5.0/huskarl_login/_docs/how_to/enrichment/).
//! For cookie updates on local responses, follow
//! [Return a local response](crate::_docs::how_to::local_responses).
//!
//! PAR, JAR, `DPoP`, and PKCE are handled by the
//! [`AuthorizationCodeGrant`](huskarl::grant::authorization_code::AuthorizationCodeGrant)
//! driving the flow, following the grant's own configuration.

mod ctx;
mod diagnostics;
mod proxy;
mod rule;

// ── Pingora-specific public API ─────────────────────────────────────────────
pub use ctx::{HasLoginSession, LoginCtx, LoginState};
pub use diagnostics::{LoginDiagnostic, LoginPhase, SessionOperation};
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
