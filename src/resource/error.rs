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
    /// A route pattern could not be lowered into the route grammar — e.g. an in-segment
    /// prefix/suffix parameter (`/v{ver}`, which the whole-segment grammar cannot
    /// express), a non-final catch-all, or a conflict with another route.
    Route {
        /// The offending pattern.
        pattern: String,
        /// A human-readable reason.
        reason: &'static str,
    },
    /// A public route rule (`TokenRequirement::None`) has audience, scope, or
    /// custom-check constraints that can never be enforced because the token
    /// validator is never called for public routes.
    ///
    /// The string is the route pattern, or `"<default>"` for the default rule.
    PublicRuleWithConstraints(String),
    /// Failed to serialize resource metadata.
    Metadata(serde_json::Error),
    /// A registered route pattern is non-canonical: it carries a structural byte
    /// (`%2F`, `..`, `//`, `;`, or an enabled opt-in form) that the path-confusion
    /// guard treats as route structure, so a normalizing backend would never present
    /// it canonically and the route is effectively dead.
    ///
    /// Fix by registering the canonical pattern instead, or by disabling
    /// `path_confusion`.
    NonCanonicalPattern {
        /// The offending (non-canonical) pattern.
        pattern: String,
    },
    /// A registered route pattern contains ASCII uppercase but the backend is declared
    /// [`CaseSensitivity::Insensitive`](crate::path_confusion::CaseSensitivity). A
    /// case-folding backend resolves it to lowercase, so a differently-cased request
    /// could reach it (or it could shadow a lowercase route) without the matched rule's
    /// checks. Register the route in lowercase.
    NonCanonicalCasePattern {
        /// The offending pattern.
        pattern: String,
    },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Route { pattern, reason } => {
                write!(f, "invalid route pattern {pattern:?}: {reason}")
            }
            Self::PublicRuleWithConstraints(pattern) => write!(
                f,
                "public rule for \"{pattern}\" has audience, scope, or custom-check constraints \
                 that can never be enforced: the token validator is not called for public routes"
            ),
            Self::Metadata(e) => write!(f, "failed to serialize resource metadata: {e}"),
            Self::NonCanonicalPattern { pattern } => write!(
                f,
                "route pattern {pattern:?} is non-canonical — it carries a structural byte \
                 (%2F, .., //, ;, …) the path-confusion guard treats as route structure, so \
                 requests to it would always be denied; register the canonical pattern, or \
                 disable path_confusion"
            ),
            Self::NonCanonicalCasePattern { pattern } => write!(
                f,
                "route pattern {pattern:?} contains uppercase but the backend is declared \
                 case-insensitive; register it in lowercase (the form the backend resolves to)"
            ),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Metadata(e) => Some(e),
            Self::Route { .. }
            | Self::PublicRuleWithConstraints(_)
            | Self::NonCanonicalPattern { .. }
            | Self::NonCanonicalCasePattern { .. } => None,
        }
    }
}

impl From<serde_json::Error> for ConfigError {
    fn from(e: serde_json::Error) -> Self {
        Self::Metadata(e)
    }
}

impl From<crate::path_router::RuleRouterError> for ConfigError {
    fn from(e: crate::path_router::RuleRouterError) -> Self {
        use crate::path_router::RuleRouterError;
        match e {
            RuleRouterError::Route { pattern, reason } => Self::Route { pattern, reason },
            RuleRouterError::NonCanonical { pattern } => Self::NonCanonicalPattern { pattern },
            RuleRouterError::NonCanonicalCase { pattern } => {
                Self::NonCanonicalCasePattern { pattern }
            }
        }
    }
}

/// Builds an RFC 6750 `invalid_request` client error from a static description.
#[derive(Debug)]
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

/// Builds an RFC 6750 `invalid_token` client error from a static description.
#[derive(Debug)]
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

/// Builds a client error with a custom RFC 6750 code and description.
#[derive(Debug)]
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
