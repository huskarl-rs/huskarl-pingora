//! Per-request login state context.
//!
//! Defines [`HasLoginSession`], the trait that your proxy context must implement
//! for [`LoginProxy`](super::LoginProxy) to thread session and persistence state
//! through `request_filter` → inner proxy → `upstream_response_filter`, and
//! [`LoginCtx`], a convenience wrapper that implements it automatically.

use http::{HeaderMap, HeaderValue};
use huskarl_login::engine::PendingPersist;

/// State held on the proxy context across the request lifecycle.
///
/// [`LoginProxy`](super::LoginProxy) populates this in `request_filter` and
/// reads it in `upstream_response_filter` to persist or delete the session
/// after the inner proxy responds.
///
/// User code reads `session` and sets `delete_requested` directly; the
/// remaining fields are proxy-managed bookkeeping.
#[non_exhaustive]
pub struct LoginState<S> {
    /// The loaded session, if one was present and valid.
    pub session: Option<S>,
    /// Set to `true` by the inner proxy when it wants the session destroyed on
    /// this response (e.g. an inner-proxy-managed account-deletion endpoint).
    pub delete_requested: bool,
    /// `Some` when a post-response save is owed to the store: a token refresh
    /// succeeded but the engine's eager save failed, so the owed persist must
    /// be committed (via [`PendingPersist::commit`]) after the inner proxy
    /// responds. `None` when the loaded session was already fully persisted.
    pub(crate) pending: Option<PendingPersist<S>>,
    /// The request headers captured at load time. Cookie-backed stores need the
    /// original `Cookie` header to know which chunked slots the browser has so
    /// they can `Max-Age=0` the leftover ones.
    pub(crate) request_headers: HeaderMap,
    /// `Set-Cookie` headers the engine produced during load: clears for an
    /// expired or refresh-failed session, or the re-sealed session cookies
    /// when a token refresh was persisted eagerly.
    pub(crate) set_cookies: Vec<HeaderValue>,
}

impl<S> Default for LoginState<S> {
    fn default() -> Self {
        Self {
            session: None,
            pending: None,
            request_headers: HeaderMap::new(),
            set_cookies: Vec::new(),
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
/// Inner-proxy code reaches the session and the delete flag through
/// [`login_state`](Self::login_state) / [`login_state_mut`](Self::login_state_mut):
/// read `login_state().session`, and set `login_state_mut().delete_requested = true`
/// to tear the session down on this response (e.g. a "delete my account"
/// endpoint).
///
/// See [`LoginCtx`] for a convenience wrapper that implements this trait
/// automatically.
pub trait HasLoginSession<S> {
    /// Shared access to the [`LoginState`] container.
    fn login_state(&self) -> &LoginState<S>;
    /// Mutable access to the [`LoginState`] container.
    fn login_state_mut(&mut self) -> &mut LoginState<S>;
}

/// Convenience context wrapper that bundles login state with an inner user
/// context.
///
/// Auto-implements [`HasLoginSession`] over the inner context — use it when your
/// proxy needs no context of its own, or to add login to an existing type without
/// implementing the trait yourself. Access the inner context via `ctx.inner`.
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
            .field("pending_save", &self.state.pending.is_some())
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
        assert!(ctx.login_state().session.is_none());
        assert!(!ctx.login_state().delete_requested);
        assert_eq!(ctx.inner, ());
    }

    #[test]
    fn login_ctx_default_defaults() {
        let ctx = LoginCtx::<(), String>::default();
        assert!(ctx.login_state().session.is_none());
        assert!(!ctx.login_state().delete_requested);
    }

    #[test]
    fn set_session_and_read() {
        let mut ctx = LoginCtx::<(), String>::new(());
        ctx.login_state_mut().session = Some("session-data".into());
        assert_eq!(
            ctx.login_state().session.as_ref(),
            Some(&"session-data".to_owned())
        );
    }

    #[test]
    fn delete_requested_flag() {
        let mut ctx = LoginCtx::<(), String>::new(());
        ctx.login_state_mut().delete_requested = true;
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
