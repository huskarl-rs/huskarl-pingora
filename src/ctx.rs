use std::sync::Arc;

use crate::resource_server::validator::ValidatedRequest;

/// Per-request OAuth 2.0 authentication state.
///
/// Implement this on your proxy's context type so [`AuthProxy`](crate::AuthProxy)
/// can write auth state during `request_filter` and act on it in subsequent hooks.
/// Read `validated_token_mut()` in your own proxy to inspect claims.
///
/// # Example
///
/// ```
/// use std::sync::Arc;
///
/// use huskarl_pingora::{HasAuthState, resource_server::validator::ValidatedRequest};
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
    /// Mutable reference to the validated token. Written by [`AuthProxy`](crate::AuthProxy)
    /// during `request_filter`; read this in your proxy to inspect claims.
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
/// [`AuthProxy`](crate::AuthProxy) no longer requires this type — it works with
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
