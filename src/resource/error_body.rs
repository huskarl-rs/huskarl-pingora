//! Customize resource-server rejection bodies without changing protocol headers.
//!
//! Follow [Customize authentication error responses](crate::_docs::how_to::error_responses)
//! for JSON and browser-login examples.

use bytes::Bytes;
use http::{HeaderValue, StatusCode};

pub use crate::resource_server::error::TokenErrorCode;
use crate::resource_server::error::{Challenge, TokenValidationError};

/// Structured failure information passed to [`ErrorBody`].
///
/// Descriptions are application or validator text, not HTML. Escape them when
/// rendering HTML. Server-side failures deliberately expose no error details.
#[derive(Debug, Clone, bon::Builder)]
#[non_exhaustive]
pub struct ErrorDetails<'a> {
    /// The library-selected HTTP status.
    pub status: StatusCode,
    /// Client error code; absent for missing credentials and server failures.
    pub error_code: Option<TokenErrorCode>,
    /// Client-facing description, when supplied by the rejecting check.
    pub error_description: Option<&'a str>,
    /// Required scopes, when supplied by the rejecting check.
    pub required_scopes: Option<&'a [String]>,
    /// The complete authentication challenges accompanying this response.
    pub challenges: &'a [String],
}

/// A rejection body and its media type.
///
/// Status, challenges, nonce, retry interval, caching, and content length remain
/// library-controlled. The default is an empty body with no content type.
#[derive(Debug, Clone, Default)]
pub struct ErrorBodyResponse {
    /// Body bytes. Never sent for HEAD requests.
    pub body: Bytes,
    /// Media type of the representation, for example `application/json`.
    pub content_type: Option<HeaderValue>,
}

impl ErrorBodyResponse {
    /// Creates a body with a validated content-type header value.
    #[must_use]
    pub fn new(body: impl Into<Bytes>, content_type: HeaderValue) -> Self {
        Self {
            body: body.into(),
            content_type: Some(content_type),
        }
    }
}

/// Renders the body of a resource-server rejection.
///
/// Configure with [`AuthProxy::error_body`](super::AuthProxy::error_body) or
/// [`BoundResourceBuilder::error_body`](super::BoundResourceBuilder::error_body).
/// The default renderer `()` produces an empty body. This does not customize
/// browser-login pages or metadata endpoint responses.
pub trait ErrorBody: Clone + Send + Sync + 'static {
    /// Builds a representation from structured failure details.
    fn error_body(&self, details: &ErrorDetails<'_>) -> ErrorBodyResponse;
}

impl ErrorBody for () {
    fn error_body(&self, _: &ErrorDetails<'_>) -> ErrorBodyResponse {
        ErrorBodyResponse::default()
    }
}

/// Owned failure details carried by [`Outcome::Deny`](super::Outcome::Deny).
///
/// These values come from the rejecting check, without parsing challenge text.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct FailureDetails {
    /// Client error code, absent for missing credentials and server failures.
    pub error_code: Option<TokenErrorCode>,
    /// Client-facing description, absent for server failures.
    pub error_description: Option<String>,
    /// Required scopes, when known.
    pub required_scopes: Option<Vec<String>>,
}

impl FailureDetails {
    pub(crate) fn from_challenge(challenge: &Challenge, scope: Option<&str>) -> Self {
        let TokenValidationError::Client(code) = challenge.error else {
            return Self::default();
        };
        Self {
            error_code: Some(code),
            error_description: challenge.description.clone(),
            required_scopes: challenge
                .scope
                .as_deref()
                .or(scope)
                .map(|s| s.split_whitespace().map(str::to_owned).collect()),
        }
    }
}
