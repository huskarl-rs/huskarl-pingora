/// A trait for extracting OAuth 2.0 scopes from token claims.
///
/// Implement this for your custom claims type so that [`Guard`](crate::Guard)
/// can enforce scope-based access rules.
pub trait HasScopes {
    /// Returns the scopes associated with the token, if any.
    fn scopes(&self) -> Option<Vec<String>>;
}

impl<E> HasScopes for huskarl_resource_server::validator::rfc9068::Rfc9068AccessTokenClaims<E> {
    fn scopes(&self) -> Option<Vec<String>> {
        self.scope
            .as_ref()
            .map(|s| s.split_whitespace().map(String::from).collect())
    }
}
