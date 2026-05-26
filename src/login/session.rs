//! Sealed session driver trait.
//!
//! [`SessionDriver`] abstracts session persistence so that
//! [`LoginProxy`](super::LoginProxy) can work with any session backend. The
//! trait is **sealed** — pick from the built-in implementations
//! ([`CookieSessionStore`](super::CookieSessionStore) or
//! [`StoreBackedSessionStore`](super::StoreBackedSessionStore)) or provide
//! custom persistence via [`ExternalSessionStore`](super::ExternalSessionStore).

use pingora_http::ResponseHeader;

use super::grant::CompletedLogin;

/// A boxed standard error type used by session store methods.
pub type SessionError = Box<dyn std::error::Error + Send + Sync>;

pub(super) fn to_session_err(e: impl std::error::Error + Send + Sync + 'static) -> SessionError {
    Box::new(e)
}

pub(crate) mod sealed {
    pub trait Sealed {}
}

/// Session driver trait implemented by the built-in session stores.
///
/// This trait is **sealed** — it cannot be implemented outside this crate.
/// Users pick a session mode by constructing either a
/// [`CookieSessionStore`](super::CookieSessionStore) or a
/// [`StoreBackedSessionStore`](super::StoreBackedSessionStore).
///
/// To provide custom session persistence, implement
/// [`ExternalSessionStore`](super::ExternalSessionStore) and wrap it in a
/// [`StoreBackedSessionStore`](super::StoreBackedSessionStore).
pub trait SessionDriver: sealed::Sealed + Send + Sync {
    /// The session type stored and retrieved by this driver.
    type Session: Send + Sync;

    /// The error type returned by [`load`](Self::load).
    type LoadError: std::error::Error + Send + Sync + 'static;

    #[doc(hidden)]
    fn create(
        &self,
        completed: CompletedLogin,
    ) -> impl Future<Output = Result<Self::Session, SessionError>> + Send;

    #[doc(hidden)]
    fn load(
        &self,
        headers: &http::HeaderMap,
    ) -> impl Future<Output = Result<Option<Self::Session>, Self::LoadError>> + Send;

    #[doc(hidden)]
    fn save(
        &self,
        session: &Self::Session,
        response: &mut ResponseHeader,
    ) -> impl Future<Output = Result<(), SessionError>> + Send;

    #[doc(hidden)]
    fn touch(
        &self,
        session: &Self::Session,
        response: &mut ResponseHeader,
    ) -> impl Future<Output = Result<(), SessionError>> + Send;

    #[doc(hidden)]
    fn delete(
        &self,
        session: &Self::Session,
        response: &mut ResponseHeader,
    ) -> impl Future<Output = Result<(), SessionError>> + Send;
}
