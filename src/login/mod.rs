//! OAuth 2.0 Authorization Code Grant login layer for Pingora.
//!
//! Provides [`LoginProxy`], a [`ProxyHttp`](pingora_proxy::ProxyHttp) decorator that redirects
//! unauthenticated requests through an Authorization Code Grant flow before
//! forwarding to the inner proxy.
//!
//! Session management is built in via two modes:
//!
//! - **Cookie sessions** ([`CookieSessionStore`]) — encrypt the full session
//!   into chunked browser cookies. No external infrastructure needed.
//! - **Store-backed sessions** ([`StoreBackedSessionStore`]) — cookie holds an
//!   encrypted pointer; data lives in an external store (Redis, DB, etc.)
//!   that you provide via the [`ExternalSessionStore`] trait.
//!
//! PAR, JAR, DPoP, and PKCE are all handled by the [`LoginGrant`]
//! implementation — the blanket impl for [`AuthorizationCodeGrant`](huskarl::grant::authorization_code::AuthorizationCodeGrant) wires
//! these up automatically via the grant's own configuration.

mod config;
pub(crate) mod cookie;
mod cookie_session;
mod ctx;
mod error_page;
mod grant;
mod proxy;
mod serde_time;
pub(crate) mod session;
mod store_session;
mod token_session;
mod url;

pub use config::{ConfigError, LoginConfig};
pub use cookie::get_cookie;
pub use cookie_session::{CookieSession, CookieSessionStore};
pub use ctx::{HasLoginSession, LoginCtx};
pub use error_page::{DefaultErrorPage, ErrorPage, ErrorPageResponse};
pub use grant::{CompletedLogin, IdClaims, LoginGrant};
/// Re-export of [`huskarl::grant::core::TokenResponse`] for use in
/// [`TokenSession`] and session store implementations.
pub use huskarl::grant::core::TokenResponse;
/// Re-export of [`huskarl::token::IdToken`] for use in [`TokenSession`]
/// implementations.
pub use huskarl::token::IdToken;
/// Re-export of [`huskarl::token::RefreshToken`] for use in [`TokenSession`]
/// implementations.
pub use huskarl::token::RefreshToken;
pub use proxy::LoginProxy;
pub use session::{SessionDriver, SessionError};
pub use store_session::{CoreSessionData, ExternalSessionStore, StoreBackedSessionStore};
pub use token_session::{TokenSession, TokenState};
