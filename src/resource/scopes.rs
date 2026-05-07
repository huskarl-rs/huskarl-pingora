//! Scope checking for validated token claims.
//!
//! The [`HasScopes`] trait lets [`Guard`](super::Guard) enforce scope-based
//! access rules. A built-in implementation is provided for
//! [`Rfc9068AccessTokenClaims`](crate::resource_server::validator::rfc9068::Rfc9068AccessTokenClaims)
//! which parses space-separated scopes per [RFC 9068].
//!
//! [RFC 9068]: https://datatracker.ietf.org/doc/html/rfc9068

/// A trait for checking OAuth 2.0 scopes on token claims.
///
/// Implement this for your custom claims type so that [`Guard`](super::Guard)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource_server::validator::rfc9068::Rfc9068AccessTokenClaims;

    fn claims(scope: Option<&str>) -> Rfc9068AccessTokenClaims {
        Rfc9068AccessTokenClaims {
            client_id: "test".into(),
            auth_time: None,
            acr: None,
            amr: vec![],
            scope: scope.map(String::from),
            extra_claims: (),
        }
    }

    #[test]
    fn no_scope_has_nothing() {
        let c = claims(None);
        assert!(!c.has_scope("read"));
    }

    #[test]
    fn empty_scope_has_nothing() {
        let c = claims(Some(""));
        assert!(!c.has_scope("read"));
    }

    #[test]
    fn single_scope_matches() {
        let c = claims(Some("read"));
        assert!(c.has_scope("read"));
        assert!(!c.has_scope("write"));
    }

    #[test]
    fn multiple_scopes_space_separated() {
        let c = claims(Some("read write admin"));
        assert!(c.has_scope("read"));
        assert!(c.has_scope("write"));
        assert!(c.has_scope("admin"));
        assert!(!c.has_scope("delete"));
    }

    #[test]
    fn partial_match_does_not_count() {
        let c = claims(Some("readonly"));
        assert!(!c.has_scope("read"));
        assert!(c.has_scope("readonly"));
    }

    #[test]
    fn extra_whitespace_handled() {
        let c = claims(Some("read  write"));
        assert!(c.has_scope("read"));
        assert!(c.has_scope("write"));
    }
}
