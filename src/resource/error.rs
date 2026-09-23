//! Error types for the resource server module.
//!
//! [`ConfigError`] covers build-time issues with [`Guard`](super::Guard)
//! construction (invalid route patterns, unreachable constraints on public
//! rules, metadata serialization failures). Internal error helpers map
//! validation outcomes to [RFC 6750] challenge responses.
//!
//! [RFC 6750]: https://datatracker.ietf.org/doc/html/rfc6750

use crate::resource_server::error::{
    Challenge, ToRfc6750Error, TokenErrorCode, TokenValidationError,
};

/// Errors that can occur when building or configuring a [`Guard`](super::Guard)
/// or [`AuthProxy`](super::AuthProxy).
#[derive(Debug)]
#[non_exhaustive]
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
    /// Validator metadata unexpectedly could not produce a resource document.
    ResourceMetadataDocumentUnavailable,
    /// The derived RFC 9728 resource identifier is invalid.
    InvalidResourceIdentifier {
        /// The offending resource identifier.
        resource: String,
        /// A human-readable reason.
        reason: &'static str,
    },
    /// The base URI used for `DPoP` request reconstruction is invalid.
    InvalidBaseUri {
        /// The offending base URI.
        base_uri: String,
        /// A human-readable reason.
        reason: &'static str,
    },
    /// Protected-resource metadata was enabled without the trusted public base
    /// URI also required for `DPoP` reconstruction.
    MissingBaseUri,
    /// A protected-resource subpath is invalid.
    InvalidResourcePath {
        /// The offending subpath.
        path: String,
    },
    /// A metadata publisher was given an endpoint for a different public
    /// origin than the endpoints it already owns.
    ResourceMetadataOriginMismatch {
        /// The metadata endpoint on the other origin.
        endpoint: String,
        /// The public origin established by the first published endpoint.
        expected_origin: String,
    },
    /// The configured `resource` identifier is not a URL RFC 9728 §3.1 can derive a
    /// Protected Resource Metadata URL from — it must be absolute HTTPS with no
    /// fragment.
    ///
    /// This is a configuration error so the proxy cannot advertise an
    /// identifier from which clients could not locate a metadata document.
    ResourceMetadataUrl {
        /// The offending resource identifier.
        resource: String,
        /// Why the derivation failed.
        source: crate::resource_server::core::Error,
    },
    /// A validator advertises a metadata URL other than the local endpoint
    /// derived from the configured resource identifier.
    ResourceMetadataUrlMismatch {
        /// URL supplied by the validator.
        configured: String,
        /// URL derived for the local endpoint.
        derived: String,
    },
    /// This auth integration was already bound to a protected resource.
    ProtectedResourceAlreadyConfigured,
    /// More than one document was registered for the same canonical metadata
    /// path and query.
    DuplicateResourceMetadataEndpoint {
        /// The complete path and optional query shared by the documents.
        path_and_query: String,
    },
    /// A protected resource was configured without any acceptable token
    /// audience.
    EmptyResourceAudiences {
        /// The protected-resource identifier.
        resource: String,
    },
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
            Self::Metadata(_) => f.write_str("failed to serialize resource metadata"),
            Self::ResourceMetadataDocumentUnavailable => {
                f.write_str("validator metadata could not produce an RFC 9728 document")
            }
            Self::InvalidResourceIdentifier { resource, reason } => {
                write!(
                    f,
                    "invalid protected-resource identifier {resource:?}: {reason}"
                )
            }
            Self::InvalidBaseUri { base_uri, reason } => {
                write!(f, "invalid DPoP base URI {base_uri:?}: {reason}")
            }
            Self::MissingBaseUri => f.write_str(
                "a protected resource requires the public base URI used for DPoP reconstruction",
            ),
            Self::InvalidResourcePath { path } => {
                write!(f, "invalid protected-resource subpath {path:?}")
            }
            Self::ResourceMetadataOriginMismatch {
                endpoint,
                expected_origin,
            } => write!(
                f,
                "metadata endpoint {endpoint:?} is outside publisher origin {expected_origin:?}"
            ),
            Self::ResourceMetadataUrl { resource, .. } => write!(
                f,
                "resource identifier {resource:?} cannot be used to derive an \
                 RFC 9728 metadata URL"
            ),
            Self::ResourceMetadataUrlMismatch {
                configured,
                derived,
            } => write!(
                f,
                "validator metadata URL {configured:?} does not match local endpoint {derived:?}"
            ),
            Self::ProtectedResourceAlreadyConfigured => {
                f.write_str("this auth integration already has a protected resource")
            }
            Self::DuplicateResourceMetadataEndpoint { path_and_query } => write!(
                f,
                "protected-resource metadata is already published at {path_and_query:?}"
            ),
            Self::EmptyResourceAudiences { resource } => write!(
                f,
                "protected resource {resource:?} must accept at least one token audience"
            ),
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
            Self::ResourceMetadataUrl { source, .. } => Some(source),
            Self::Route { .. }
            | Self::PublicRuleWithConstraints(_)
            | Self::ResourceMetadataDocumentUnavailable
            | Self::InvalidResourceIdentifier { .. }
            | Self::InvalidBaseUri { .. }
            | Self::MissingBaseUri
            | Self::InvalidResourcePath { .. }
            | Self::ResourceMetadataOriginMismatch { .. }
            | Self::ResourceMetadataUrlMismatch { .. }
            | Self::ProtectedResourceAlreadyConfigured
            | Self::DuplicateResourceMetadataEndpoint { .. }
            | Self::EmptyResourceAudiences { .. }
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

impl From<huskarl_route_guard::RuleRouterError> for ConfigError {
    fn from(e: huskarl_route_guard::RuleRouterError) -> Self {
        use huskarl_route_guard::RuleRouterError;
        match e {
            RuleRouterError::Route { pattern, reason } => Self::Route { pattern, reason },
            RuleRouterError::NonCanonical { pattern } => Self::NonCanonicalPattern { pattern },
            RuleRouterError::NonCanonicalCase { pattern } => {
                Self::NonCanonicalCasePattern { pattern }
            }
            RuleRouterError::EmptyMethodSet { pattern } => Self::Route {
                pattern,
                reason: "registration matches no method: its method set is empty",
            },
            RuleRouterError::EmptyPatternSet => Self::Route {
                pattern: String::new(),
                reason: "registration has no route patterns",
            },
            RuleRouterError::TooManyRegistrations => Self::Route {
                pattern: String::new(),
                reason: "too many route registrations",
            },
        }
    }
}

/// Builds an RFC 6750 `invalid_request` client error from a static description.
#[derive(Debug)]
pub(crate) struct InvalidRequest(pub &'static str);

impl std::fmt::Display for InvalidRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for InvalidRequest {}

impl ToRfc6750Error for InvalidRequest {
    fn attempted_scheme(&self) -> Option<crate::resource_server::validator::extract::TokenType> {
        None
    }

    fn challenge(&self) -> Challenge {
        Challenge::new(TokenValidationError::Client(TokenErrorCode::InvalidRequest))
            .with_description(self.0)
    }
}

/// Builds an RFC 6750 `invalid_token` client error from a static description.
#[derive(Debug)]
pub(crate) struct InvalidToken(pub &'static str);

impl std::fmt::Display for InvalidToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for InvalidToken {}

impl ToRfc6750Error for InvalidToken {
    fn attempted_scheme(&self) -> Option<crate::resource_server::validator::extract::TokenType> {
        None
    }

    fn challenge(&self) -> Challenge {
        Challenge::new(TokenValidationError::Client(TokenErrorCode::InvalidToken))
            .with_description(self.0)
    }
}

/// Builds a client error with a custom RFC 6750 code and description.
#[derive(Debug)]
pub(crate) struct CustomCheckError {
    pub code: TokenErrorCode,
    pub description: String,
}

impl std::fmt::Display for CustomCheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.description)
    }
}

impl std::error::Error for CustomCheckError {}

impl ToRfc6750Error for CustomCheckError {
    fn attempted_scheme(&self) -> Option<crate::resource_server::validator::extract::TokenType> {
        None
    }

    fn challenge(&self) -> Challenge {
        Challenge::new(TokenValidationError::Client(self.code))
            .with_description(self.description.clone())
    }
}
