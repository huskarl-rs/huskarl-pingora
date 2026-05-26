//! Per-request authentication context for the resource server.
//!
//! Defines [`HasAuthState`], the trait that your proxy context must implement
//! for [`AuthProxy`](super::AuthProxy) to store validated token state, and
//! [`AuthCtx`], a convenience wrapper that implements it automatically.

use std::sync::Arc;

use crate::resource_server::validator::ValidatedRequest;

/// Per-request OAuth 2.0 authentication state.
///
/// Implement this on your proxy's context type so [`AuthProxy`](super::AuthProxy)
/// can write auth state during `request_filter` and act on it in subsequent hooks.
/// Read [`validated_token()`](HasAuthState::validated_token) in your own proxy to inspect claims.
///
/// # Example
///
/// ```
/// use std::sync::Arc;
///
/// use huskarl_pingora::{resource::HasAuthState, resource_server::validator::ValidatedRequest};
///
/// struct MyClaims;
///
/// #[derive(Default)]
/// struct MyCtx {
///     token: Option<Arc<ValidatedRequest<MyClaims>>>,
///     dpop_nonce: Option<String>,
///     strip_credentials: bool,
/// }
///
/// impl HasAuthState<MyClaims> for MyCtx {
///     fn validated_token(&self) -> Option<&Arc<ValidatedRequest<MyClaims>>> {
///         self.token.as_ref()
///     }
///     fn validated_token_mut(&mut self) -> &mut Option<Arc<ValidatedRequest<MyClaims>>> {
///         &mut self.token
///     }
///     fn dpop_nonce_mut(&mut self) -> &mut Option<String> {
///         &mut self.dpop_nonce
///     }
///     fn strip_credentials(&self) -> bool {
///         self.strip_credentials
///     }
///     fn set_strip_credentials(&mut self, strip: bool) {
///         self.strip_credentials = strip;
///     }
/// }
/// ```
pub trait HasAuthState<C> {
    /// Returns the validated token, if present.
    ///
    /// Set by [`AuthProxy`](super::AuthProxy) during `request_filter`. Read
    /// this in your proxy's `upstream_peer` or other hooks to inspect claims.
    fn validated_token(&self) -> Option<&Arc<ValidatedRequest<C>>>;
    /// Mutable reference to the validated token. Used internally by
    /// [`AuthProxy`](super::AuthProxy) to store the validation result.
    fn validated_token_mut(&mut self) -> &mut Option<Arc<ValidatedRequest<C>>>;
    /// Mutable reference to the DPoP nonce to include in the response, if any.
    fn dpop_nonce_mut(&mut self) -> &mut Option<String>;
    /// Whether the `Authorization` and `DPoP` headers should be stripped before
    /// forwarding the request upstream.
    fn strip_credentials(&self) -> bool;
    /// Sets whether credentials should be stripped before forwarding upstream.
    fn set_strip_credentials(&mut self, strip: bool);
}

/// Convenience context wrapper that bundles auth state with an inner user context.
///
/// [`AuthProxy`](super::AuthProxy) no longer requires this type — it works with
/// any context implementing [`HasAuthState`] directly. This wrapper is provided
/// for cases where you want to add auth to an existing context type without
/// modifying it.
///
/// Access inner context fields via `ctx.inner`.
pub struct AuthCtx<T, C = ()> {
    token: Option<Arc<ValidatedRequest<C>>>,
    dpop_nonce: Option<String>,
    strip_credentials: bool,
    /// The inner user-defined context.
    pub inner: T,
}

impl<T: Default, C> Default for AuthCtx<T, C> {
    fn default() -> Self {
        Self {
            token: None,
            dpop_nonce: None,
            strip_credentials: true,
            inner: T::default(),
        }
    }
}

impl<T, C> AuthCtx<T, C> {
    /// Creates a new `AuthCtx` wrapping the given inner context.
    pub fn new(inner: T) -> Self {
        Self {
            token: None,
            dpop_nonce: None,
            strip_credentials: true,
            inner,
        }
    }
}

impl<T: std::fmt::Debug, C> std::fmt::Debug for AuthCtx<T, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthCtx")
            .field("has_token", &self.token.is_some())
            .field("dpop_nonce", &self.dpop_nonce)
            .field("strip_credentials", &self.strip_credentials)
            .field("inner", &self.inner)
            .finish()
    }
}

impl<T, C> HasAuthState<C> for AuthCtx<T, C> {
    fn validated_token(&self) -> Option<&Arc<ValidatedRequest<C>>> {
        self.token.as_ref()
    }

    fn validated_token_mut(&mut self) -> &mut Option<Arc<ValidatedRequest<C>>> {
        &mut self.token
    }

    fn dpop_nonce_mut(&mut self) -> &mut Option<String> {
        &mut self.dpop_nonce
    }

    fn strip_credentials(&self) -> bool {
        self.strip_credentials
    }

    fn set_strip_credentials(&mut self, strip: bool) {
        self.strip_credentials = strip;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_validated_request() -> Arc<ValidatedRequest<()>> {
        Arc::new(ValidatedRequest {
            issuer: None,
            subject: None,
            audience: vec![],
            jti: None,
            issued_at: None,
            expiration: None,
            cnf: None,
            claims: (),
            introspection_jwt: None,
        })
    }

    #[test]
    fn new_defaults() {
        let ctx = AuthCtx::<(), ()>::new(());
        assert!(ctx.validated_token().is_none());
        let _: () = ctx.inner;
        assert!(ctx.strip_credentials);
    }

    #[test]
    fn default_defaults() {
        let ctx = AuthCtx::<(), ()>::default();
        assert!(ctx.validated_token().is_none());
        assert!(ctx.strip_credentials);
    }

    #[test]
    fn validated_token_read_write() {
        let mut ctx = AuthCtx::<(), ()>::new(());
        assert!(ctx.validated_token().is_none());

        let token = make_validated_request();
        *ctx.validated_token_mut() = Some(token.clone());

        assert!(ctx.validated_token().is_some());
        assert!(Arc::ptr_eq(ctx.validated_token().unwrap(), &token));
    }

    #[test]
    fn dpop_nonce_round_trip() {
        let mut ctx = AuthCtx::<(), ()>::new(());
        assert!(ctx.dpop_nonce_mut().is_none());

        *ctx.dpop_nonce_mut() = Some("nonce-123".into());
        assert_eq!(ctx.dpop_nonce_mut().as_deref(), Some("nonce-123"));

        let taken = ctx.dpop_nonce_mut().take();
        assert_eq!(taken.as_deref(), Some("nonce-123"));
        assert!(ctx.dpop_nonce_mut().is_none());
    }

    #[test]
    fn strip_credentials_toggle() {
        let mut ctx = AuthCtx::<(), ()>::new(());
        assert!(ctx.strip_credentials());

        ctx.set_strip_credentials(false);
        assert!(!ctx.strip_credentials());

        ctx.set_strip_credentials(true);
        assert!(ctx.strip_credentials());
    }

    #[test]
    fn inner_context_accessible() {
        let mut ctx = AuthCtx::<String, ()>::new("hello".into());
        assert_eq!(ctx.inner, "hello");
        ctx.inner.push_str(" world");
        assert_eq!(ctx.inner, "hello world");
    }

    #[test]
    fn debug_omits_token_details() {
        let mut ctx = AuthCtx::<(), ()>::new(());
        let debug_none = format!("{ctx:?}");
        assert!(debug_none.contains("has_token: false"));

        *ctx.validated_token_mut() = Some(make_validated_request());
        let debug_some = format!("{ctx:?}");
        assert!(debug_some.contains("has_token: true"));
    }
}
