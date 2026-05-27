//! Per-request login state context.
//!
//! Defines [`HasLoginSession`], the trait that your proxy context must implement
//! for [`LoginProxy`](super::LoginProxy) to thread session and persistence state
//! through `request_filter` → inner proxy → `upstream_response_filter`, and
//! [`LoginCtx`], a convenience wrapper that implements it automatically.

use http::{HeaderMap, HeaderValue};
use huskarl_login::engine::SessionPersistence;

/// State held on the proxy context across the request lifecycle.
///
/// [`LoginProxy`](super::LoginProxy) populates this in `request_filter` and
/// reads it in `upstream_response_filter` to persist or delete the session
/// after the inner proxy responds.
///
/// User code mostly interacts with `LoginState` via [`HasLoginSession`]'s
/// convenience methods (`login_session`, `request_session_delete`). The
/// `session` and `delete_requested` fields are public for direct access; the
/// remaining fields are proxy-managed bookkeeping.
#[non_exhaustive]
pub struct LoginState<S> {
    /// The loaded session, if one was present and valid.
    pub session: Option<S>,
    /// Set by the inner proxy via [`HasLoginSession::request_session_delete`]
    /// when it wants the session destroyed on this response (e.g. an
    /// inner-proxy-managed account-deletion endpoint).
    pub delete_requested: bool,
    /// How the engine wants the session persisted after the inner proxy responds.
    pub(crate) persistence: SessionPersistence,
    /// The request headers captured at load time. Cookie-backed stores need the
    /// original `Cookie` header to know which chunked slots the browser has so
    /// they can `Max-Age=0` the leftover ones.
    pub(crate) request_headers: HeaderMap,
    /// `Set-Cookie` headers the engine produced during load (typically clears
    /// for an expired or refresh-failed session). Always empty when a session
    /// successfully loaded.
    pub(crate) clear_cookies: Vec<HeaderValue>,
}

impl<S> Default for LoginState<S> {
    fn default() -> Self {
        Self {
            session: None,
            persistence: SessionPersistence::Skip,
            request_headers: HeaderMap::new(),
            clear_cookies: Vec::new(),
            delete_requested: false,
        }
    }
}

/// Per-request login state hook on a proxy context.
///
/// Implement this on your proxy's context type so [`LoginProxy`](super::LoginProxy)
/// can stash the loaded session, the engine's persistence decision, and the
/// original request headers it needs to persist or delete the session after
/// the inner proxy responds.
///
/// See [`LoginCtx`] for a convenience wrapper that implements this trait
/// automatically.
pub trait HasLoginSession<S> {
    /// Shared access to the [`LoginState`] container.
    fn login_state(&self) -> &LoginState<S>;
    /// Mutable access to the [`LoginState`] container.
    fn login_state_mut(&mut self) -> &mut LoginState<S>;

    /// Convenience accessor: the loaded session, if any.
    fn login_session(&self) -> Option<&S> {
        self.login_state().session.as_ref()
    }

    /// Signals that the session should be deleted on the response. Use this in
    /// an inner-proxy handler (e.g. a "delete my account" endpoint) to tear
    /// down the session as part of normal response processing.
    fn request_session_delete(&mut self) {
        self.login_state_mut().delete_requested = true;
    }
}

/// Convenience context wrapper that bundles login state with an inner user
/// context.
///
/// Similar to `AuthCtx` for resource-server proxies. Access inner context
/// fields via `ctx.inner`.
pub struct LoginCtx<T, S> {
    /// The inner user-defined context.
    pub inner: T,
    state: LoginState<S>,
}

impl<T: Default, S> Default for LoginCtx<T, S> {
    fn default() -> Self {
        Self {
            inner: T::default(),
            state: LoginState::default(),
        }
    }
}

impl<T, S> LoginCtx<T, S> {
    /// Creates a new `LoginCtx` wrapping the given inner context.
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            state: LoginState::default(),
        }
    }
}

impl<T: std::fmt::Debug, S> std::fmt::Debug for LoginCtx<T, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginCtx")
            .field("session_loaded", &self.state.session.is_some())
            .field("persistence", &self.state.persistence)
            .field("delete_requested", &self.state.delete_requested)
            .field("inner", &self.inner)
            .finish()
    }
}

impl<T, S> HasLoginSession<S> for LoginCtx<T, S> {
    fn login_state(&self) -> &LoginState<S> {
        &self.state
    }

    fn login_state_mut(&mut self) -> &mut LoginState<S> {
        &mut self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_ctx_new_defaults() {
        let ctx = LoginCtx::<(), String>::new(());
        assert!(ctx.login_session().is_none());
        assert!(!ctx.login_state().delete_requested);
        assert_eq!(ctx.inner, ());
    }

    #[test]
    fn login_ctx_default_defaults() {
        let ctx = LoginCtx::<(), String>::default();
        assert!(ctx.login_session().is_none());
        assert!(!ctx.login_state().delete_requested);
    }

    #[test]
    fn set_session_and_read() {
        let mut ctx = LoginCtx::<(), String>::new(());
        ctx.login_state_mut().session = Some("session-data".into());
        assert_eq!(ctx.login_session(), Some(&"session-data".to_owned()));
    }

    #[test]
    fn request_session_delete_sets_flag() {
        let mut ctx = LoginCtx::<(), String>::new(());
        ctx.request_session_delete();
        assert!(ctx.login_state().delete_requested);
    }

    #[test]
    fn inner_context_accessible() {
        let mut ctx = LoginCtx::<Vec<i32>, String>::new(vec![1, 2, 3]);
        assert_eq!(ctx.inner, vec![1, 2, 3]);
        ctx.inner.push(4);
        assert_eq!(ctx.inner, vec![1, 2, 3, 4]);
    }
}
