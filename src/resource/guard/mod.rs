//! Token validation guard with path-based routing.
//!
//! [`Guard`] matches incoming request paths against registered [`Rule`]s using
//! `matchit` patterns and validates bearer tokens via an
//! [`AccessTokenValidator`]. It returns an [`Outcome`] indicating whether
//! the request should be forwarded or denied with [RFC 6750] challenges.
//!
//! [RFC 6750]: https://datatracker.ietf.org/doc/html/rfc6750

use std::sync::Arc;

use pingora_proxy::Session;

use crate::{
    metrics::CheckOutcome,
    path_confusion::{ResolveError, ResolveErrorKind, resolve_error_status},
    resource::{
        FailureDetails, ResourcePolicy,
        error::{ConfigError, CustomCheckError, InvalidRequest, InvalidToken},
        outcome::Outcome,
        rule::{CheckError, Rule, TokenRequirement},
        scopes::HasScopes,
    },
    resource_server::{
        core::url_mapping::PublicUrlMapping,
        error::{InsufficientScope, ToRfc6750Error, TokenErrorCode},
        validator::{
            AccessTokenValidator, ValidatedRequest,
            metadata::{ProvideValidatorMetadata, ValidatorMetadata},
        },
    },
};

#[cfg(test)]
mod tests;

/// DER-encoded X.509 client certificate from a mutual TLS connection.
///
/// Store this in the [`SslDigestExtension`](pingora_core::protocols::tls::SslDigest)
/// during the TLS handshake (via [`TlsAccept::handshake_complete_callback`](pingora_core::listeners::TlsAccept))
/// so that [`Guard::check`] can pass it to the token validator for mTLS
/// certificate-bound access token verification.
///
/// # Example
///
/// With Pingora's `rustls` feature enabled:
///
/// ```no_run
/// use std::{any::Any, sync::Arc};
///
/// use async_trait::async_trait;
/// use huskarl_pingora::resource::ClientCertDer;
/// use pingora_core::{listeners::TlsAccept, protocols::tls::TlsRef};
///
/// struct MyApp;
///
/// #[async_trait]
/// impl TlsAccept for MyApp {
///     async fn handshake_complete_callback(
///         &self,
///         ssl: &TlsRef,
///     ) -> Option<Arc<dyn Any + Send + Sync>> {
///         ssl.peer_certificate_der()
///             .map(|der| Arc::new(ClientCertDer(der.to_vec())) as _)
///     }
/// }
/// ```
pub struct ClientCertDer(pub Vec<u8>);

fn client_cert_der(session: &Session) -> Option<&[u8]> {
    session
        .as_downstream()
        .digest()
        .and_then(|d| d.ssl_digest.as_ref())
        .and_then(|ssl| ssl.extension.get::<ClientCertDer>())
        .map(|c| c.0.as_slice())
}

/// A guard that validates OAuth 2.0 access tokens against path-based rules.
///
/// Typically used via [`AuthProxy`](super::AuthProxy), which wraps a
/// `ProxyHttp` implementation and calls [`Guard::check`] automatically.
///
/// # Example
///
/// ```
/// # use huskarl_pingora::resource::{CaseSensitivity, DecodeDepth, GuardConfig, Guard, ResourcePolicy, Rule};
/// # fn build<V>(my_validator: V)
/// # where
/// #     V: huskarl_pingora::resource_server::validator::AccessTokenValidator
/// #         + huskarl_pingora::resource_server::validator::metadata::ProvideValidatorMetadata,
/// # {
/// let policy = ResourcePolicy::builder()
///     // Required: declare whether the upstream folds path case, and whether a
///     // decoding layer (CDN/WAF) sits in front of it.
///     .path_guard(GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne))
///     // `subtree` protects a path and everything beneath it (the usual intent).
///     .subtree("/admin", Rule::required().scopes(["admin"]))
///     .subtree("/public", Rule::public())
///     // `route` matches one exact path — here, a single health endpoint.
///     .route("/health", Rule::public())
///     .build()
///     .expect("route");
/// let guard = Guard::builder()
///     .validator(my_validator)
///     .policy(policy)
///     .build();
/// # }
/// ```
pub struct Guard<V: AccessTokenValidator + ProvideValidatorMetadata> {
    validator: V,
    metadata: ValidatorMetadata,
    policy: ResourcePolicy<V::Claims>,
    request_mapping: Option<PublicUrlMapping>,
}

/// Prepared RFC 9728 publication and its resource boundary.
pub(crate) struct ResourceMetadataConfig {
    pub(crate) resource_uri: http::Uri,
    pub(crate) resource_origin: String,
    pub(crate) resource_path: String,
    pub(crate) endpoint_uri: http::Uri,
    pub(crate) body: Vec<u8>,
}

impl<V: AccessTokenValidator + ProvideValidatorMetadata> std::fmt::Debug for Guard<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Guard")
            .field("scopes_supported", &self.policy.scopes_supported)
            .field("url_mapping", &self.request_mapping)
            .field("metrics_name", &self.policy.metrics_name)
            .finish_non_exhaustive()
    }
}

#[bon::bon]
impl<V: AccessTokenValidator + ProvideValidatorMetadata> Guard<V> {
    /// Starts a builder for a standalone guard.
    /// Call [`GuardBuilder::build`] to combine the validated policy and token validator.
    ///
    /// Supply a trusted URL mapping when accepting `DPoP` tokens. When omitted,
    /// the original request URI is passed to the validator; origin-form requests
    /// cannot establish a public `DPoP` target. Incoming Host headers are never trusted.
    /// For a defined resource, use [`super::BoundResource::builder`] instead: its
    /// definition supplies the only URL mapping.
    #[builder]
    pub fn new(
        /// Access-token validator used by this guard.
        validator: V,
        /// Validated access rules in incoming request coordinates.
        policy: ResourcePolicy<V::Claims>,
        /// Trusted mapping used to reconstruct the public request URL for `DPoP`.
        /// When omitted, the original request URI is passed to the validator;
        /// an origin-form URI cannot establish a public `DPoP` target.
        url_mapping: Option<PublicUrlMapping>,
    ) -> Self {
        let metadata = validator.validator_metadata(None);
        Self {
            validator,
            policy,
            metadata,
            request_mapping: url_mapping,
        }
    }

    pub(super) fn metrics_name(&self) -> Option<&str> {
        self.policy.metrics_name.as_deref()
    }

    #[cfg(test)]
    pub(super) fn into_test_parts(
        self,
    ) -> (V, ResourcePolicy<V::Claims>, Option<PublicUrlMapping>) {
        (self.validator, self.policy, self.request_mapping)
    }

    pub(crate) fn for_resource(
        validator: V,
        policy: ResourcePolicy<V::Claims>,
        definition: &crate::resource_server::resource::ResourceDefinition,
    ) -> Result<(Self, ResourceMetadataConfig), ConfigError> {
        let resource = definition.resource();
        let resource_uri: http::Uri =
            resource
                .parse()
                .map_err(|_| ConfigError::InvalidResourceIdentifier {
                    resource: resource.to_owned(),
                    reason: "not a valid URI",
                })?;
        let prepared = definition
            .prepare(&validator, policy.scopes_supported.clone())
            .map_err(|error| match error {
                crate::resource_server::resource::ResourceError::MetadataUrlMismatch {
                    configured,
                    derived,
                } => ConfigError::ResourceMetadataUrlMismatch {
                    configured,
                    derived,
                },
                crate::resource_server::resource::ResourceError::Serialization { source } => {
                    ConfigError::Metadata(source)
                }
                _ => ConfigError::ResourceMetadataDocumentUnavailable,
            })?;
        let config = ResourceMetadataConfig {
            resource_origin: format!(
                "{}://{}",
                resource_uri.scheme_str().unwrap_or_default(),
                resource_uri
                    .authority()
                    .map_or("", http::uri::Authority::as_str)
            ),
            resource_path: resource_uri.path().to_owned(),
            resource_uri,
            endpoint_uri: prepared.publication().uri.clone(),
            body: prepared.body,
        };
        let guard = Self {
            validator,
            policy,
            metadata: prepared.validator_metadata,
            request_mapping: Some(definition.mapping().clone()),
        };
        Ok((guard, config))
    }
}

impl<V: AccessTokenValidator + ProvideValidatorMetadata> Guard<V> {
    /// Builds a `400 Bad Request` deny outcome with an `invalid_request` challenge.
    ///
    /// Deliberately carries no `scope` hint: the 400s built here are pre-auth,
    /// rule-independent refusals (an ambiguous path, an unreconstructable URI), so the
    /// matched rule's scope is a binding the guard has just declined to trust —
    /// advertising it would misdirect clients into a futile re-auth and hand a prober
    /// the route table's policy layout.
    fn bad_request_with_metadata(
        metadata: &ValidatorMetadata,
        msg: &'static str,
    ) -> Outcome<V::Claims> {
        let challenges = metadata.challenges(Some(&InvalidRequest(msg)), None, None);
        Outcome::Deny {
            details: FailureDetails::from_challenge(&InvalidRequest(msg).challenge(), None),
            status: http::StatusCode::BAD_REQUEST,
            challenges,
            dpop_nonce: None,
            retry_after: None,
        }
    }

    fn route_denial(
        metadata: &ValidatorMetadata,
        reason: &ResolveError,
    ) -> (Outcome<V::Claims>, CheckOutcome) {
        let (challenges, outcome) = match reason.kind() {
            ResolveErrorKind::InvalidInput => (
                metadata.challenges(Some(&InvalidRequest(reason.message())), None, None),
                CheckOutcome::PathConfusion,
            ),
            ResolveErrorKind::PolicyDenied => (Vec::new(), CheckOutcome::PolicyDenied),
            ResolveErrorKind::Internal => (Vec::new(), CheckOutcome::ServerError),
        };
        (
            Outcome::Deny {
                details: if reason.kind() == ResolveErrorKind::InvalidInput {
                    FailureDetails::from_challenge(
                        &InvalidRequest(reason.message()).challenge(),
                        None,
                    )
                } else {
                    FailureDetails::default()
                },
                status: resolve_error_status(reason),
                challenges,
                dpop_nonce: None,
                retry_after: None,
            },
            outcome,
        )
    }

    /// Reconstructs the public URI with the same mapping used for `DPoP` validation.
    pub(crate) fn effective_request_uri(&self, uri: &http::Uri) -> Option<http::Uri> {
        self.request_mapping
            .as_ref()
            .map_or_else(|| Some(uri.clone()), |mapping| mapping.public_url(uri).ok())
    }

    /// Checks the given Pingora session.
    ///
    /// Convenience wrapper around [`check_request`](Self::check_request) that
    /// extracts the headers, method, URI, and client certificate from the
    /// session.
    ///
    /// Does **not** write any response to the session — that is the caller's
    /// responsibility.
    pub async fn check(&self, session: &Session) -> Outcome<V::Claims>
    where
        V::Claims: HasScopes,
    {
        let req = session.req_header();
        let client_cert_der = client_cert_der(session);
        self.check_request_with_metadata(
            &req.headers,
            &req.method,
            &req.uri,
            client_cert_der,
            &self.metadata,
            None,
        )
        .await
    }

    /// Runs the guard once and retains its classification for the adapter boundary.
    pub(crate) async fn check_for_proxy(
        &self,
        session: &Session,
        audiences: Option<&[String]>,
    ) -> (Outcome<V::Claims>, CheckOutcome)
    where
        V::Claims: HasScopes,
    {
        let req = session.req_header();
        let (outcome, category) = self
            .check_request_categorized(
                &req.headers,
                &req.method,
                &req.uri,
                client_cert_der(session),
                &self.metadata,
                audiences,
            )
            .await;
        category.emit(self.policy.metrics_name.as_deref());
        (outcome, category)
    }

    /// Low-level token check using plain HTTP types.
    ///
    /// Returns an [`Outcome`] describing whether the request should be
    /// forwarded or denied.
    ///
    /// The caller supplies the original request headers and method and a URI in
    /// incoming coordinates. A configured trusted URL mapping reconstructs the
    /// public target for the validator. Supply the DER client certificate when
    /// validating mTLS-bound tokens.
    ///
    /// This method neither forwards nor writes a response. On [`Outcome::Forward`],
    /// retain the validated token for application hooks, honor credential stripping,
    /// and propagate any response nonce. On [`Outcome::Deny`], send its status and
    /// protocol headers. [`super::AuthProxy`] handles these responsibilities for you.
    /// With `metrics` enabled, each completed check emits one guard counter; see
    /// the [telemetry reference](crate::_docs::reference::telemetry).
    pub async fn check_request(
        &self,
        headers: &http::HeaderMap,
        method: &http::Method,
        uri: &http::Uri,
        client_cert_der: Option<&[u8]>,
    ) -> Outcome<V::Claims>
    where
        V::Claims: HasScopes,
    {
        self.check_request_with_metadata(
            headers,
            method,
            uri,
            client_cert_der,
            &self.metadata,
            None,
        )
        .await
    }

    async fn check_request_with_metadata(
        &self,
        headers: &http::HeaderMap,
        method: &http::Method,
        uri: &http::Uri,
        client_cert_der: Option<&[u8]>,
        metadata: &ValidatorMetadata,
        resource_audiences: Option<&[String]>,
    ) -> Outcome<V::Claims>
    where
        V::Claims: HasScopes,
    {
        let (outcome, category) = self
            .check_request_categorized(
                headers,
                method,
                uri,
                client_cert_der,
                metadata,
                resource_audiences,
            )
            .await;
        category.emit(self.policy.metrics_name.as_deref());
        outcome
    }

    /// The body of [`check_request`](Self::check_request), returning the [`Outcome`]
    /// alongside the [`CheckOutcome`] category for metrics. Split out so the counter is
    /// emitted exactly once, at the single wrapper exit, rather than at each branch.
    async fn check_request_categorized(
        &self,
        headers: &http::HeaderMap,
        method: &http::Method,
        uri: &http::Uri,
        client_cert_der: Option<&[u8]>,
        metadata: &ValidatorMetadata,
        resource_audiences: Option<&[String]>,
    ) -> (Outcome<V::Claims>, CheckOutcome)
    where
        V::Claims: HasScopes,
    {
        let path = uri.path();

        // 0. Resolve in one call: the path-confusion verdict, then the rule match — a
        // denied (ambiguous) path gets a rule-independent 400 before any rule applies.
        // Metrics retain the bounded category; raw paths are never logged or labelled.
        let rule = match self.policy.routes.resolve(path, method) {
            Ok(matched) => matched.rule(),
            Err(reason) => {
                return Self::route_denial(metadata, &reason);
            }
        };

        let scope_param = rule.scope_param.as_deref();

        // 1. Public routes skip validation entirely.
        if rule.token == TokenRequirement::None {
            return (
                Outcome::Forward {
                    token: None,
                    dpop_nonce: None,
                    strip_credentials: rule.strip_credentials,
                },
                CheckOutcome::Forward,
            );
        }

        // 2. Call the validator.
        let Some(full_uri) = self.effective_request_uri(uri) else {
            return (
                Self::bad_request_with_metadata(metadata, "Invalid request URI"),
                CheckOutcome::InvalidRequest,
            );
        };

        let result = self
            .validator
            .validate_request(headers, method, &full_uri, client_cert_der)
            .await;

        let dpop_nonce = result.dpop_nonce;

        match result.outcome {
            Err(err) => {
                // The validator rejected, or could not reach a backing service. Build the
                // `Challenge` once and share it between the rejection and the metric
                // classification: it owns a description and parameters, so rebuilding it
                // per consumer would clone them repeatedly on a path an attacker chooses
                // how often to trigger.
                let challenge = err.challenge();
                let rejection = metadata.rejection_from(&err, &challenge, scope_param);
                // Classify from the same error: a server-side failure is a 5xx that was
                // never a token judgement, so labelling it `invalid_token` would both
                // overstate rejections and hide the outage. The error is asked rather than
                // the challenge, because outcomes like `Expired` and `UnrecognizedIssuer`
                // are indistinguishable from `invalid_token` on the wire.
                let outcome = CheckOutcome::from_validation(err.validation_outcome(&challenge));
                (
                    Outcome::Deny {
                        details: FailureDetails::from_challenge(&challenge, scope_param),
                        status: rejection.status,
                        challenges: rejection.www_authenticate,
                        dpop_nonce,
                        retry_after: rejection.retry_after,
                    },
                    outcome,
                )
            }
            Ok(None) => {
                // No token present.
                match rule.token {
                    TokenRequirement::Required => {
                        let challenges = metadata.unauthenticated_challenges(scope_param);
                        (
                            Outcome::Deny {
                                details: FailureDetails::default(),
                                status: http::StatusCode::UNAUTHORIZED,
                                challenges,
                                dpop_nonce,
                                retry_after: None,
                            },
                            CheckOutcome::Unauthenticated,
                        )
                    }
                    TokenRequirement::Optional | TokenRequirement::None => (
                        Outcome::Forward {
                            token: None,
                            dpop_nonce,
                            strip_credentials: rule.strip_credentials,
                        },
                        CheckOutcome::Forward,
                    ),
                }
            }
            Ok(Some(validated)) => {
                // Token present and valid — run rule checks.
                if let Some((outcome, category)) = Self::check_rule(
                    rule,
                    &validated,
                    scope_param,
                    dpop_nonce.as_deref(),
                    metadata,
                    resource_audiences,
                ) {
                    return (outcome, category);
                }

                (
                    Outcome::Forward {
                        token: Some(Arc::new(validated)),
                        dpop_nonce,
                        strip_credentials: rule.strip_credentials,
                    },
                    CheckOutcome::Forward,
                )
            }
        }
    }

    fn deny_error(
        metadata: &ValidatorMetadata,
        error: &impl ToRfc6750Error,
        scope: Option<&str>,
        dpop_nonce: Option<&str>,
    ) -> Outcome<V::Claims> {
        let challenge = error.challenge();
        let rejection = metadata.rejection_from(error, &challenge, scope);
        Outcome::Deny {
            details: FailureDetails::from_challenge(&challenge, scope),
            status: rejection.status,
            challenges: rejection.www_authenticate,
            dpop_nonce: dpop_nonce.map(str::to_owned),
            retry_after: rejection.retry_after,
        }
    }

    /// Runs audience, scope, and custom checks against the rule.
    fn check_rule(
        rule: &Rule<V::Claims>,
        validated: &ValidatedRequest<V::Claims>,
        scope_param: Option<&str>,
        dpop_nonce: Option<&str>,
        metadata: &ValidatorMetadata,
        resource_audiences: Option<&[String]>,
    ) -> Option<(Outcome<V::Claims>, CheckOutcome)>
    where
        V::Claims: HasScopes,
    {
        // A protected-resource binding and the rule can independently narrow audiences.
        let audience_error = if resource_audiences.is_some_and(|audiences| {
            !audiences
                .iter()
                .any(|audience| validated.aud.contains(audience))
        }) {
            Some("The access token audience does not match the protected resource")
        } else if !rule.audiences.is_empty()
            && !rule.audiences.iter().any(|a| validated.aud.contains(a))
        {
            Some("The access token audience does not match")
        } else {
            None
        };
        if let Some(message) = audience_error {
            return Some((
                Self::deny_error(metadata, &InvalidToken(message), scope_param, dpop_nonce),
                CheckOutcome::InvalidToken,
            ));
        }
        if rule
            .scopes
            .iter()
            .any(|required| !validated.claims.has_scope(required))
        {
            return Some((
                Self::deny_error(
                    metadata,
                    &InsufficientScope::default(),
                    scope_param,
                    dpop_nonce,
                ),
                CheckOutcome::InsufficientScope,
            ));
        }
        if let Some(check_fn) = &rule.check
            && let Err(error) = check_fn(validated)
        {
            let (code, description, outcome) = match error {
                CheckError::Forbidden(description) => (
                    TokenErrorCode::InsufficientScope,
                    description,
                    CheckOutcome::InsufficientScope,
                ),
                CheckError::InvalidToken(description) => (
                    TokenErrorCode::InvalidToken,
                    description,
                    CheckOutcome::InvalidToken,
                ),
            };
            return Some((
                Self::deny_error(
                    metadata,
                    &CustomCheckError { code, description },
                    None,
                    dpop_nonce,
                ),
                outcome,
            ));
        }
        None
    }
}
