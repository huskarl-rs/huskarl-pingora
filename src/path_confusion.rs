//! Path-confusion configuration and HTTP status mapping shared by both proxies.
//!
//! Configuration types are re-exported from [`huskarl_route_guard`]. Integrators
//! using its router directly can use [`resolve_error_status`] to return the same
//! denial statuses as `LoginProxy` and `Guard`.

pub use huskarl_route_guard::config::*;

/// Maps a route-resolution denial to its HTTP status.
///
/// Invalid or ambiguous input maps to 400, a missing method policy to 403, and
/// an internal routing invariant violation to 500. Response bodies, authentication
/// challenges, and logging remain the caller's responsibility.
#[must_use]
pub const fn resolve_error_status(error: &ResolveError) -> http::StatusCode {
    match error.kind() {
        ResolveErrorKind::InvalidInput => http::StatusCode::BAD_REQUEST,
        ResolveErrorKind::PolicyDenied => http::StatusCode::FORBIDDEN,
        ResolveErrorKind::Internal => http::StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denial_categories_map_to_http_statuses() {
        for (error, status) in [
            (
                ResolveError::InvalidPathInput,
                http::StatusCode::BAD_REQUEST,
            ),
            (ResolveError::TooLong, http::StatusCode::BAD_REQUEST),
            (
                ResolveError::MethodNotConfigured,
                http::StatusCode::FORBIDDEN,
            ),
            (
                ResolveError::InvalidRuleId,
                http::StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ] {
            assert_eq!(resolve_error_status(&error), status);
        }
    }
}
