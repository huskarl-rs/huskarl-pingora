use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use huskarl_resource_server::validator::ValidatedRequest;

/// Per-request context that wraps an inner user context with authentication state.
///
/// Through [`Deref`] and [`DerefMut`], fields on the inner `T` are accessible
/// directly (e.g. `ctx.my_field`), while `ctx.token` provides access to the
/// validated request.
pub struct AuthCtx<T, C> {
    /// The validated token for this request, populated by [`AuthProxy`](crate::AuthProxy)
    /// during `request_filter`.
    pub token: Option<Arc<ValidatedRequest<C>>>,
    /// DPoP nonce to include in the response, if any.
    pub(crate) dpop_nonce: Option<String>,
    /// Whether to strip the `Authorization` header before forwarding upstream.
    pub(crate) strip_credentials: bool,
    /// The inner user-defined context.
    pub inner: T,
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

impl<T, C> Deref for AuthCtx<T, C> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T, C> DerefMut for AuthCtx<T, C> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}
