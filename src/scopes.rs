/// A trait for checking OAuth 2.0 scopes on token claims.
///
/// Implement this for your custom claims type so that [`Guard`](crate::Guard)
/// can enforce scope-based access rules.
pub trait HasScopes {
    /// Returns `true` if the token grants the given scope.
    fn has_scope(&self, scope: &str) -> bool;
}

impl<E> HasScopes for crate::resource_server::validator::rfc9068::Rfc9068AccessTokenClaims<E> {
    fn has_scope(&self, scope: &str) -> bool {
        self.scope
            .as_ref()
            .is_some_and(|s| s.split_whitespace().any(|t| t == scope))
    }
}
