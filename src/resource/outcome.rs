//! Guard check outcome.
//!
//! [`Outcome`] is the result of [`Guard::check`](super::Guard::check),
//! indicating whether a request should be forwarded upstream (with optional
//! validated token) or denied with HTTP challenge headers.

use std::sync::Arc;

use crate::resource_server::validator::ValidatedRequest;

/// The low-level result of [`Guard::check`](super::Guard::check).
///
/// The `Debug` impl intentionally omits token internals.
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

impl<C> std::fmt::Debug for Outcome<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Outcome::Forward {
                token,
                dpop_nonce,
                strip_credentials,
            } => f
                .debug_struct("Forward")
                .field("has_token", &token.is_some())
                .field("dpop_nonce", &dpop_nonce.is_some())
                .field("strip_credentials", strip_credentials)
                .finish(),
            Outcome::Deny {
                status,
                challenges,
                dpop_nonce,
            } => f
                .debug_struct("Deny")
                .field("status", status)
                .field("challenges", challenges)
                .field("dpop_nonce", &dpop_nonce.is_some())
                .finish(),
        }
    }
}
