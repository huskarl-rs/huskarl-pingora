//! OAuth 2.0 Authorization Code Grant login layer for Pingora.
//!
//! Provides [`LoginProxy`], a [`ProxyHttp`](pingora_proxy::ProxyHttp) decorator
//! that runs each request through the shared
//! [`LoginEngine`](huskarl_login::engine::LoginEngine): unauthenticated
//! requests are redirected through an Authorization Code Grant flow before
//! reaching the inner proxy.
//!
//! Session management is built in via two modes:
//!
//! - **Cookie sessions** ([`CookieSessionStore`]) — encrypt the full session
//!   into chunked browser cookies. No external infrastructure needed.
//! - **Store-backed sessions** ([`StoreBackedSessionStore`]) — cookie holds an
//!   encrypted pointer; data lives in an external store (Redis, DB, etc.)
//!   that you provide via the [`ExternalSessionStore`] trait.
//!
//! PAR, JAR, `DPoP`, and PKCE are handled by the [`LoginGrant`] implementation —
//! the blanket impl for [`AuthorizationCodeGrant`](huskarl::grant::authorization_code::AuthorizationCodeGrant)
//! wires these up automatically via the grant's own configuration.

mod ctx;
mod proxy;
mod rule;

// ── Pingora-specific public API ─────────────────────────────────────────────
pub use ctx::{HasLoginSession, LoginCtx, LoginState};
/// Re-export of [`huskarl::grant::core::TokenResponse`] for use in session
/// store implementations.
pub use huskarl::grant::core::TokenResponse;
/// Re-export of [`huskarl::token::IdToken`] for use in custom session types.
pub use huskarl::token::IdToken;
/// Re-export of [`huskarl::token::RefreshToken`] for use in custom session types.
pub use huskarl::token::RefreshToken;
pub use huskarl_login::{
    CompletedLogin, ConfigError, CookieData, CookieSession, CookieSessionStore, DefaultErrorPage,
    DefaultPersistFailurePolicy, ErrorPage, ErrorPageResponse, ExternalSessionStore, LoginConfig,
    LoginGrant, PersistFailurePolicy, PersistedSession, PersistedSessionState, Session,
    SessionDriver, SessionError, SessionState, StoreBackedSessionStore,
    engine::{LoadedSession, LoginEngine, LoginResponse, SessionPersistence},
};
pub use proxy::{LoginProxy, RouteConfigError};
pub use rule::{CheckError, LoginRule, SessionRequirement};
