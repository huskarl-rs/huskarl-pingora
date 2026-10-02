//! Guard check outcome.
//!
//! [`Outcome`] is the result of [`Guard::check`](super::Guard::check),
//! indicating whether a request should be forwarded upstream (with optional
//! validated token) or denied with HTTP challenge headers.

use std::sync::Arc;

use crate::resource_server::{core::platform::Duration, validator::ValidatedRequest};

/// The low-level result of [`Guard::check`](super::Guard::check): forward the
/// request, or deny it (the caller writes the deny response).
///
/// The `Debug` impl intentionally omits token internals.
///
/// Both the enum and its variants are `#[non_exhaustive]`: response metadata
/// grows as the specs do (`Retry-After` arrived after `DPoP-Nonce`), and a new
/// field should not be a breaking change. Match with a trailing `..`.
#[non_exhaustive]
pub enum Outcome<C> {
    /// The request should proceed. Contains the validated token (if any) and
    /// an optional `DPoP` nonce to include in the response.
    #[non_exhaustive]
    Forward {
        /// The validated token, or `None` for unauthenticated/public requests.
        token: Option<Arc<ValidatedRequest<C>>>,
        /// A `DPoP` nonce to set in the `DPoP-Nonce` response header, if any.
        dpop_nonce: Option<String>,
        /// Whether to strip `Authorization` and `DPoP` before forwarding upstream.
        strip_credentials: bool,
    },
    /// The request should be denied. The caller must write the challenge
    /// response to the session.
    #[non_exhaustive]
    Deny {
        /// Structured client-facing details for a custom response body.
        details: super::FailureDetails,
        /// The HTTP status code (401, 403, etc.).
        status: http::StatusCode,
        /// `WWW-Authenticate` challenge header values.
        challenges: Vec<String>,
        /// A `DPoP` nonce to set in the `DPoP-Nonce` response header, if any.
        dpop_nonce: Option<String>,
        /// How long the client should wait before retrying, for the
        /// `Retry-After` response header (RFC 9110 §10.2.3).
        ///
        /// Only ever set for server-side validation failures, which is exactly
        /// when it matters: dropping an authorization server's backoff interval
        /// invites a retry storm against a service that is already failing.
        /// Client errors carry no interval — waiting does not fix a bad token.
        retry_after: Option<Duration>,
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
                retry_after,
                ..
            } => f
                .debug_struct("Deny")
                .field("status", status)
                .field("challenges", challenges)
                .field("dpop_nonce", &dpop_nonce.is_some())
                .field("retry_after", retry_after)
                .finish(),
        }
    }
}
