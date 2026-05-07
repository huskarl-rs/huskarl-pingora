//! Per-request login session context.
//!
//! Defines [`HasLoginSession`], the trait that your proxy context must implement
//! for [`LoginProxy`](super::LoginProxy) to store and track session state, and
//! [`LoginCtx`], a convenience wrapper that implements it automatically.

/// Per-request login session state.
///
/// Implement this on your proxy's context type so [`LoginProxy`](super::LoginProxy)
/// can store the loaded session during `request_filter` and detect mutations
/// for automatic persistence in `upstream_response_filter`.
///
/// See [`LoginCtx`] for a convenience wrapper that implements this trait
/// automatically.
pub trait HasLoginSession<S> {
    /// Returns a reference to the session, if loaded.
    fn login_session(&self) -> Option<&S>;
    /// Returns a mutable reference to the session.
    ///
    /// Implementations should set a dirty flag when this is called so that
    /// [`LoginProxy`](super::LoginProxy) can persist changes automatically.
    fn login_session_mut(&mut self) -> Option<&mut S>;
    /// Replaces the stored session.
    fn set_login_session(&mut self, session: Option<S>);
    /// Returns `true` if the session has been mutated since the last save.
    fn is_session_dirty(&self) -> bool;
    /// Clears the dirty flag after the session has been persisted.
    fn clear_session_dirty(&mut self);
    /// Requests that the session be deleted during response processing.
    fn request_session_delete(&mut self);
    /// Returns `true` if session deletion has been requested.
    fn is_delete_requested(&self) -> bool;
    /// Removes and returns the session, clearing dirty and delete flags.
    ///
    /// Used when a session needs to be deleted during request processing
    /// (e.g. expired session) before `upstream_response_filter` runs.
    fn take_login_session(&mut self) -> Option<S>;
    /// Mutable access without setting the dirty flag.
    ///
    /// Used for lightweight updates like recording activity that should be
    /// persisted via [`SessionDriver::touch`](super::SessionDriver::touch)
    /// rather than a full save.
    fn login_session_touch_mut(&mut self) -> Option<&mut S>;
}

/// Convenience context wrapper that bundles login session state with an inner
/// user context.
///
/// Similar to `AuthCtx` for resource-server proxies.
/// Mutations via [`login_session_mut`](HasLoginSession::login_session_mut)
/// automatically set the dirty flag so [`LoginProxy`](super::LoginProxy) can
/// persist changes on the response.
///
/// Access inner context fields via `ctx.inner`.
pub struct LoginCtx<T, S> {
    /// The inner user-defined context.
    pub inner: T,
    session: Option<S>,
    session_dirty: bool,
    delete_requested: bool,
}

impl<T: Default, S> Default for LoginCtx<T, S> {
    fn default() -> Self {
        Self {
            inner: T::default(),
            session: None,
            session_dirty: false,
            delete_requested: false,
        }
    }
}

impl<T, S> LoginCtx<T, S> {
    /// Creates a new `LoginCtx` wrapping the given inner context.
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            session: None,
            session_dirty: false,
            delete_requested: false,
        }
    }
}

impl<T: std::fmt::Debug, S: std::fmt::Debug> std::fmt::Debug for LoginCtx<T, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginCtx")
            .field("session", &self.session)
            .field("session_dirty", &self.session_dirty)
            .field("delete_requested", &self.delete_requested)
            .field("inner", &self.inner)
            .finish()
    }
}

impl<T, S> HasLoginSession<S> for LoginCtx<T, S> {
    fn login_session(&self) -> Option<&S> {
        self.session.as_ref()
    }

    fn login_session_mut(&mut self) -> Option<&mut S> {
        if self.session.is_some() {
            self.session_dirty = true;
        }
        self.session.as_mut()
    }

    fn set_login_session(&mut self, session: Option<S>) {
        self.session = session;
        self.session_dirty = false;
    }

    fn is_session_dirty(&self) -> bool {
        self.session_dirty
    }

    fn clear_session_dirty(&mut self) {
        self.session_dirty = false;
    }

    fn request_session_delete(&mut self) {
        self.delete_requested = true;
    }

    fn is_delete_requested(&self) -> bool {
        self.delete_requested
    }

    fn take_login_session(&mut self) -> Option<S> {
        self.session_dirty = false;
        self.delete_requested = false;
        self.session.take()
    }

    fn login_session_touch_mut(&mut self) -> Option<&mut S> {
        self.session.as_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_ctx_new_defaults() {
        let ctx = LoginCtx::<(), String>::new(());
        assert!(ctx.login_session().is_none());
        assert!(!ctx.is_session_dirty());
        assert_eq!(ctx.inner, ());
    }

    #[test]
    fn login_ctx_default_defaults() {
        let ctx = LoginCtx::<(), String>::default();
        assert!(ctx.login_session().is_none());
        assert!(!ctx.is_session_dirty());
    }

    #[test]
    fn set_session_and_read() {
        let mut ctx = LoginCtx::<(), String>::new(());
        ctx.set_login_session(Some("session-data".into()));
        assert_eq!(ctx.login_session(), Some(&"session-data".to_owned()));
        // set_login_session clears dirty flag
        assert!(!ctx.is_session_dirty());
    }

    #[test]
    fn session_mut_sets_dirty() {
        let mut ctx = LoginCtx::<(), String>::new(());
        ctx.set_login_session(Some("data".into()));
        assert!(!ctx.is_session_dirty());

        let s = ctx.login_session_mut().unwrap();
        s.push_str("-modified");
        assert!(ctx.is_session_dirty());
        assert_eq!(ctx.login_session(), Some(&"data-modified".to_owned()));
    }

    #[test]
    fn session_mut_without_session_not_dirty() {
        let mut ctx = LoginCtx::<(), String>::new(());
        assert!(ctx.login_session_mut().is_none());
        assert!(!ctx.is_session_dirty());
    }

    #[test]
    fn clear_dirty_flag() {
        let mut ctx = LoginCtx::<(), String>::new(());
        ctx.set_login_session(Some("data".into()));
        let _ = ctx.login_session_mut(); // sets dirty
        assert!(ctx.is_session_dirty());

        ctx.clear_session_dirty();
        assert!(!ctx.is_session_dirty());
    }

    #[test]
    fn set_session_none_clears() {
        let mut ctx = LoginCtx::<(), String>::new(());
        ctx.set_login_session(Some("data".into()));
        ctx.set_login_session(None);
        assert!(ctx.login_session().is_none());
        assert!(!ctx.is_session_dirty());
    }

    #[test]
    fn delete_not_requested_by_default() {
        let ctx = LoginCtx::<(), String>::new(());
        assert!(!ctx.is_delete_requested());
    }

    #[test]
    fn request_session_delete_sets_flag() {
        let mut ctx = LoginCtx::<(), String>::new(());
        ctx.request_session_delete();
        assert!(ctx.is_delete_requested());
    }

    #[test]
    fn delete_requested_survives_set_session() {
        let mut ctx = LoginCtx::<(), String>::new(());
        ctx.request_session_delete();
        ctx.set_login_session(Some("data".into()));
        assert!(ctx.is_delete_requested());
    }

    #[test]
    fn inner_context_accessible() {
        let mut ctx = LoginCtx::<Vec<i32>, String>::new(vec![1, 2, 3]);
        assert_eq!(ctx.inner, vec![1, 2, 3]);
        ctx.inner.push(4);
        assert_eq!(ctx.inner, vec![1, 2, 3, 4]);
    }

    #[test]
    fn take_login_session_returns_and_clears() {
        let mut ctx = LoginCtx::<(), String>::new(());
        ctx.set_login_session(Some("data".into()));
        let _ = ctx.login_session_mut(); // sets dirty
        ctx.request_session_delete();

        let taken = ctx.take_login_session();
        assert_eq!(taken, Some("data".to_owned()));
        assert!(ctx.login_session().is_none());
        assert!(!ctx.is_session_dirty());
        assert!(!ctx.is_delete_requested());
    }

    #[test]
    fn take_login_session_when_empty() {
        let mut ctx = LoginCtx::<(), String>::new(());
        assert!(ctx.take_login_session().is_none());
        assert!(!ctx.is_session_dirty());
        assert!(!ctx.is_delete_requested());
    }

    #[test]
    fn login_session_touch_mut_does_not_set_dirty() {
        let mut ctx = LoginCtx::<(), String>::new(());
        ctx.set_login_session(Some("data".into()));

        let s = ctx.login_session_touch_mut().unwrap();
        s.push_str("-touched");
        assert!(!ctx.is_session_dirty());
        assert_eq!(ctx.login_session(), Some(&"data-touched".to_owned()));
    }

    #[test]
    fn login_session_touch_mut_when_empty() {
        let mut ctx = LoginCtx::<(), String>::new(());
        assert!(ctx.login_session_touch_mut().is_none());
        assert!(!ctx.is_session_dirty());
    }
}
