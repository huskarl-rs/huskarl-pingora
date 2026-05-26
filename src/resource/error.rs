//! Error types for the resource server module.
//!
//! [`ConfigError`] covers build-time issues with [`Guard`](super::Guard)
//! construction (invalid route patterns, unreachable constraints on public
//! rules, metadata serialization failures). Internal error helpers map
//! validation outcomes to [RFC 6750] challenge responses.
//!
//! [RFC 6750]: https://datatracker.ietf.org/doc/html/rfc6750

use crate::resource_server::error::{ToRfc6750Error, TokenErrorCode, TokenValidationError};

/// Errors that can occur when building or configuring a [`Guard`](super::Guard)
/// or [`AuthProxy`](super::AuthProxy).
#[derive(Debug)]
pub enum ConfigError {
    /// A route pattern was invalid.
    Route(matchit::InsertError),
    /// A public route rule (`TokenRequirement::None`) has audience or scope
    /// constraints that can never be enforced because the token is never validated.
    ///
    /// The string is the route pattern, or `"<default>"` for the default rule.
    PublicRuleWithConstraints(String),
    /// Failed to serialize resource metadata.
    Metadata(serde_json::Error),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Route(e) => write!(f, "invalid route pattern: {e}"),
            Self::PublicRuleWithConstraints(pattern) => write!(
                f,
                "public rule for \"{pattern}\" has audience or scope constraints that can never be enforced"
            ),
            Self::Metadata(e) => write!(f, "failed to serialize resource metadata: {e}"),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Route(e) => Some(e),
            Self::Metadata(e) => Some(e),
            Self::PublicRuleWithConstraints(_) => None,
        }
    }
}

impl From<matchit::InsertError> for ConfigError {
    fn from(e: matchit::InsertError) -> Self {
        Self::Route(e)
    }
}

impl From<serde_json::Error> for ConfigError {
    fn from(e: serde_json::Error) -> Self {
        Self::Metadata(e)
    }
}

/// Helper for invalid request URI errors.
pub(crate) struct InvalidRequest(pub &'static str);

impl ToRfc6750Error for InvalidRequest {
    fn attempted_scheme(&self) -> Option<crate::resource_server::validator::extract::TokenType> {
        None
    }

    fn token_error(&self) -> TokenValidationError {
        TokenValidationError::Client(TokenErrorCode::InvalidRequest)
    }

    fn error_description(&self) -> Option<String> {
        Some(self.0.to_string())
    }
}

/// Helper for audience-mismatch errors.
pub(crate) struct InvalidToken(pub &'static str);

impl ToRfc6750Error for InvalidToken {
    fn attempted_scheme(&self) -> Option<crate::resource_server::validator::extract::TokenType> {
        None
    }

    fn token_error(&self) -> TokenValidationError {
        TokenValidationError::Client(TokenErrorCode::InvalidToken)
    }

    fn error_description(&self) -> Option<String> {
        Some(self.0.to_string())
    }
}

/// Helper for custom check errors.
pub(crate) struct CustomCheckError {
    pub code: TokenErrorCode,
    pub description: String,
}

impl ToRfc6750Error for CustomCheckError {
    fn attempted_scheme(&self) -> Option<crate::resource_server::validator::extract::TokenType> {
        None
    }

    fn token_error(&self) -> TokenValidationError {
        TokenValidationError::Client(self.code)
    }

    fn error_description(&self) -> Option<String> {
        Some(self.description.clone())
    }
}
