use std::sync::Arc;

use huskarl_resource_server::validator::ValidatedRequest;

/// The low-level result of [`Guard::check`](crate::Guard::check).
pub enum Outcome<C> {
    /// The request should proceed. Contains the validated token (if any) and
    /// an optional DPoP nonce to include in the response.
    Forward {
        /// The validated token, or `None` for unauthenticated/public requests.
        token: Option<Arc<ValidatedRequest<C>>>,
        /// A DPoP nonce to set in the `DPoP-Nonce` response header, if any.
        dpop_nonce: Option<String>,
        /// Whether to strip the `Authorization` header before forwarding upstream.
        strip_credentials: bool,
    },
    /// The request should be denied. The caller must write the challenge
    /// response to the session.
    Deny {
        /// The HTTP status code (401, 403, etc.).
        status: http::StatusCode,
        /// `WWW-Authenticate` challenge header values.
        challenges: Vec<String>,
        /// A DPoP nonce to set in the `DPoP-Nonce` response header, if any.
        dpop_nonce: Option<String>,
    },
}

