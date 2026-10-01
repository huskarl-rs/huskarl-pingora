//! Token validation guard with path-based routing.
//!
//! [`Guard`] matches incoming request paths against registered [`Rule`]s using
//! `matchit` patterns and validates bearer tokens via an
//! [`AccessTokenValidator`]. It returns an [`Outcome`] indicating whether
//! the request should be forwarded or denied with [RFC 6750] challenges.
//!
//! [RFC 6750]: https://datatracker.ietf.org/doc/html/rfc6750

use std::{collections::BTreeSet, sync::Arc};

use bon::bon;
use huskarl_route_guard::{GuardConfig, RuleRouter};
use pingora_proxy::Session;

use crate::{
    metrics::CheckOutcome,
    path_confusion::{ResolveError, ResolveErrorKind, resolve_error_status},
    resource::{
        FailureDetails,
        error::{ConfigError, CustomCheckError, InvalidRequest, InvalidToken},
        outcome::Outcome,
        rule::{CheckError, Rule, TokenRequirement},
        scopes::HasScopes,
        uri::request_uri,
    },
    resource_server::{
        core::resource_metadata::well_known_url,
        error::{InsufficientScope, ToRfc6750Error, TokenErrorCode},
        validator::{
            AccessTokenValidator, ValidatedRequest,
            metadata::{ProvideValidatorMetadata, ValidatorMetadata},
        },
    },
    routing::RouteKind,
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
/// # use huskarl_pingora::resource::{CaseSensitivity, DecodeDepth, GuardConfig, Guard, Rule};
/// # fn build<V>(my_validator: V)
/// # where
/// #     V: huskarl_pingora::resource_server::validator::AccessTokenValidator
/// #         + huskarl_pingora::resource_server::validator::metadata::ProvideValidatorMetadata,
/// # {
/// let guard = Guard::builder()
///     .validator(my_validator)
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
/// # }
/// ```
pub struct Guard<V: AccessTokenValidator + ProvideValidatorMetadata> {
    validator: V,
    metadata: ValidatorMetadata,
    /// Path → rule routing with rule-granularity identity and the path-confusion
    /// structural guard (see [`RuleRouter`]).
    routes: RuleRouter<Rule<V::Claims>>,
    scopes_supported: Vec<String>,
    base_uri: Option<http::Uri>,
    strip_prefix: Option<String>,
    request_mapping: Option<crate::resource_server::core::url_mapping::PublicUrlMapping>,
    legacy_mapping: bool,
    /// Optional value for the `name` label on emitted metrics, distinguishing guard
    /// instances when one process runs several. `None` emits an empty name.
    pub(crate) metrics_name: Option<String>,
}

/// One locally served RFC 9728 document and the metadata used for challenges
/// on requests belonging to that protected resource.
pub(crate) struct ResourceMetadataConfig {
    pub(crate) resource_uri: http::Uri,
    pub(crate) resource_origin: String,
    pub(crate) resource_path: String,
    pub(crate) endpoint_uri: http::Uri,
    pub(crate) body: Vec<u8>,
    pub(crate) validator_metadata: ValidatorMetadata,
}

impl<V: AccessTokenValidator + ProvideValidatorMetadata> std::fmt::Debug for Guard<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Guard")
            .field("scopes_supported", &self.scopes_supported)
            .field("base_uri", &self.base_uri)
            .field("strip_prefix", &self.strip_prefix)
            .field("metrics_name", &self.metrics_name)
            .finish_non_exhaustive()
    }
}

#[bon]
impl<V: AccessTokenValidator + ProvideValidatorMetadata> Guard<V> {
    /// Builds a new [`Guard`] with the given validator and per-path rules.
    ///
    /// Use [`Guard::builder`] (the generated builder) to set routes and
    /// configuration; this constructor is the builder's terminal `build`
    /// step.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if the `DPoP` base URI or a route pattern is
    /// invalid, or if a public rule has constraints that can never be enforced.
    #[builder]
    pub fn new(
        // One entry per `route`/`subtree`/`blob_subtree` call, in registration order.
        // Rule-id assignment and subtree-pattern expansion are deferred to
        // `RuleRouter::from_registrations` at build time.
        #[builder(field)] routes: Vec<(RouteKind, String, Rule<V::Claims>)>,
        validator: V,
        /// Externally visible base URI used to reconstruct the complete request URI
        /// for **`DPoP` `htu` binding**. Its path is prepended to the incoming request
        /// path after `strip_prefix` is applied. It is also required when an
        /// [`AuthProxy`](super::AuthProxy) is bound to a protected-resource
        /// subpath; the same base and subpath derive that resource identifier.
        ///
        /// # Security
        ///
        /// For `DPoP`, set this to a value *you* control. The guard never derives the
        /// authority from the inbound `Host` header, so configuring `base_uri`
        /// explicitly keeps `htu` bound to your real origin. Without `base_uri` or
        /// `url_mapping`, the guard passes the raw request URI to the validator.
        /// Behind a reverse proxy this is normally origin-form (path and optional
        /// query, without scheme or authority), so `DPoP` validation fails closed
        /// with a server-side integration error. Configure `base_uri` or
        /// `url_mapping` whenever you accept DPoP-bound tokens.
        base_uri: Option<http::Uri>,
        /// Validated public/ingress mapping. Do not combine with `base_uri` or `strip_prefix`.
        url_mapping: Option<crate::resource_server::core::url_mapping::PublicUrlMapping>,
        /// Path prefix to strip from the request path before prepending the
        /// `base_uri` path during `DPoP` URI reconstruction.
        ///
        /// This is useful when a front proxy adds a path prefix that isn't part of the client-facing URI.
        #[builder(into)]
        strip_prefix: Option<String>,
        /// The default rule for paths that don't match any route.
        ///
        /// Defaults to [`Rule::required()`].
        #[builder(default)]
        default: Rule<V::Claims>,
        /// Path-confusion configuration, including the required downstream case
        /// sensitivity and decode depth. There is no default: declare these
        /// assumptions with [`GuardConfig::new`]. Clone the configuration to share
        /// it with other guards that have the same downstream parsing assumptions.
        path_guard: GuardConfig,
        /// Optional value for the `name` label on emitted metrics (the
        /// `huskarl.resource.check` counter). Set it to tell guard instances apart when
        /// one process runs several; leave unset for `name=""`. Requires the optional
        /// `metrics` feature; naming never wraps the supplied validator.
        #[builder(into)]
        metrics_name: Option<String>,
    ) -> Result<Self, ConfigError> {
        let legacy_mapping = url_mapping.is_none();
        let (base_uri, strip_prefix) = if let Some(mapping) = url_mapping {
            if base_uri.is_some() || strip_prefix.is_some() {
                return Err(ConfigError::InvalidBaseUri {
                    base_uri: mapping.public_base().to_string(),
                    reason: "url_mapping cannot be combined with base_uri or strip_prefix",
                });
            }
            (
                Some(mapping.public_base().clone()),
                (mapping.incoming_prefix() != "/").then(|| mapping.incoming_prefix().to_owned()),
            )
        } else {
            (base_uri, strip_prefix)
        };
        // Reject public rules with audience or scope constraints — they can never
        // be enforced because the token validator is skipped for public routes.
        for (_kind, pattern, rule) in &routes {
            if rule.public_constraints_requested() {
                return Err(ConfigError::PublicRuleWithConstraints(pattern.clone()));
            }
        }
        if default.public_constraints_requested() {
            return Err(ConfigError::PublicRuleWithConstraints("<default>".into()));
        }

        let request_mapping = base_uri
            .as_ref()
            .map(|base| {
                validate_base_uri(base)?;
                crate::resource_server::core::url_mapping::PublicUrlMapping::new(
                    &base.to_string(),
                    strip_prefix.as_deref().unwrap_or("/"),
                )
                .map_err(ConfigError::UrlMapping)
            })
            .transpose()?;
        let metadata = validator.validator_metadata(None);

        // Collect unique scopes from all route rules and the default rule.
        let mut all_scopes = BTreeSet::new();
        for (_kind, _pattern, rule) in &routes {
            all_scopes.extend(rule.scopes.iter().cloned());
        }
        all_scopes.extend(default.scopes.iter().cloned());
        let scopes_supported: Vec<String> = all_scopes.into_iter().collect();

        let registrations = routes.into_iter().map(|(kind, pattern, rule)| {
            let method = rule.method.clone();
            kind.registration(pattern, method, rule)
        });
        let routes = RuleRouter::from_registrations(default, path_guard, registrations)?;

        Ok(Self {
            validator,
            metadata,
            routes,
            scopes_supported,
            base_uri,
            strip_prefix,
            request_mapping,
            legacy_mapping,
            metrics_name,
        })
    }
}

impl<V: AccessTokenValidator + ProvideValidatorMetadata, S: guard_builder::State>
    GuardBuilder<V, S>
{
    /// Adds a single exact-match route pattern with an associated rule.
    ///
    /// Patterns use `matchit` syntax (e.g. `/users/{id}`, `/public/{*rest}`).
    ///
    /// This matches the given path *exactly* — `route("/admin", …)` does not
    /// cover `/admin/` or `/admin/users`. To protect a path and everything
    /// beneath it (the usual intent, and the safer default for authorization),
    /// prefer [`subtree`](Self::subtree).
    pub fn route(mut self, pattern: impl Into<String>, rule: Rule<V::Claims>) -> Self {
        self.routes.push((RouteKind::Exact, pattern.into(), rule));
        self
    }

    /// Applies a rule to a path **and everything beneath it**.
    ///
    /// This is the recommended way to protect an area of the URL space:
    /// matching only an exact path (via [`route`](Self::route)) is a common
    /// source of authorization gaps, because a request to `/admin/` or
    /// `/admin/users` would otherwise fall through to the default rule and skip
    /// the scope/audience checks you attached to `/admin`.
    ///
    /// The path is expanded into the `matchit` patterns that cover the
    /// subtree (each mapping to a clone of `rule`):
    ///
    /// - `subtree("/admin", …)`  covers `/admin`, `/admin/`, and `/admin/...`
    /// - `subtree("/admin/", …)` covers `/admin/` and `/admin/...` — a trailing
    ///   slash means "this directory and its contents, but not the bare
    ///   `/admin`".
    /// - `subtree("/", …)` covers the entire path space.
    ///
    /// A more-specific [`route`](Self::route) still takes precedence over a
    /// subtree's catch-all, so you can layer exceptions:
    ///
    /// ```
    /// # use huskarl_pingora::resource::{CaseSensitivity, DecodeDepth, GuardConfig, Guard, Rule};
    /// # fn build<V>(my_validator: V)
    /// # where
    /// #     V: huskarl_pingora::resource_server::validator::AccessTokenValidator
    /// #         + huskarl_pingora::resource_server::validator::metadata::ProvideValidatorMetadata,
    /// # {
    /// let guard = Guard::builder()
    ///     .validator(my_validator)
    ///     .path_guard(GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne))
    ///     .subtree("/admin", Rule::required().scopes(["admin"]))
    ///     .route("/admin/health", Rule::public()) // exact carve-out wins
    ///     .build()
    ///     .expect("routes");
    /// # }
    /// ```
    pub fn subtree(mut self, path: &str, rule: Rule<V::Claims>) -> Self {
        self.routes
            .push((RouteKind::Subtree, path.to_owned(), rule));
        self
    }

    /// Registers an exclusive subtree, rejecting nested route overrides at build time.
    ///
    /// The same ambiguity checks apply as for [`subtree`](Self::subtree).
    /// Encoded separators and dot-segments can pass only when analysis establishes
    /// that they stay within the same rule. NUL is denied in every active mode.
    pub fn blob_subtree(mut self, path: &str, rule: Rule<V::Claims>) -> Self {
        self.routes.push((RouteKind::Blob, path.to_owned(), rule));
        self
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

    /// Builds metadata advertisement for one RFC 9728 protected resource.
    ///
    /// Per RFC 9728 §3.1, the well-known URI is constructed by inserting
    /// `/.well-known/oauth-protected-resource` between the host and the path
    /// of the resource identifier. For example, a resource at
    /// `https://api.example.com/tenant1` has its metadata at
    /// `/.well-known/oauth-protected-resource/tenant1`.
    ///
    /// When the resource identifier has no path beyond `/`, the well-known path
    /// is `/.well-known/oauth-protected-resource`.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] if the resource identifier is invalid, the
    /// validator advertises a different endpoint, or the generated document
    /// cannot be serialized.
    pub(crate) fn build_resource_metadata(
        &self,
        resource: &str,
    ) -> Result<ResourceMetadataConfig, ConfigError> {
        self.build_resource_metadata_inner(resource, None)
    }

    pub(crate) fn build_resource_metadata_from_definition(
        &self,
        definition: &crate::resource_server::resource::ResourceDefinition,
    ) -> Result<ResourceMetadataConfig, ConfigError> {
        self.build_resource_metadata_inner(definition.resource(), Some(definition))
    }

    fn build_resource_metadata_inner(
        &self,
        resource: &str,
        definition: Option<&crate::resource_server::resource::ResourceDefinition>,
    ) -> Result<ResourceMetadataConfig, ConfigError> {
        validate_resource_identifier(resource)?;
        let resource_uri =
            resource
                .parse::<http::Uri>()
                .map_err(|_| ConfigError::InvalidResourceIdentifier {
                    resource: resource.to_owned(),
                    reason: "not a valid URI",
                })?;
        let metadata_url =
            well_known_url(resource).map_err(|source| ConfigError::ResourceMetadataUrl {
                resource: resource.to_owned(),
                source,
            })?;

        let prepared = match definition {
            Some(definition) => definition
                .prepare(&self.validator, self.scopes_supported.clone())
                .map(|prepared| (prepared.validator_metadata, prepared.body)),
            None => crate::resource_server::resource::prepare_metadata(
                resource,
                &self.validator,
                self.scopes_supported.clone(),
            ),
        };
        let (metadata, body) = prepared.map_err(|error| match error {
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
        let endpoint_uri = metadata_url.as_uri().clone();
        let resource_origin = format!(
            "{}://{}",
            resource_uri.scheme_str().unwrap_or_default(),
            resource_uri
                .authority()
                .map_or("", http::uri::Authority::as_str)
        );
        let resource_path = resource_uri.path().to_owned();
        Ok(ResourceMetadataConfig {
            resource_uri,
            resource_origin,
            resource_path,
            endpoint_uri,
            body,
            validator_metadata: metadata,
        })
    }

    /// Derives one protected-resource identifier from this guard's trusted
    /// public base URI and a resource subpath, then builds its RFC 9728 data.
    pub(crate) fn build_resource_metadata_for_path(
        &self,
        resource_path: &str,
    ) -> Result<ResourceMetadataConfig, ConfigError> {
        let base_uri = self.base_uri.as_ref().ok_or(ConfigError::MissingBaseUri)?;
        if !resource_path.starts_with('/') || resource_path.contains('#') {
            return Err(ConfigError::InvalidResourcePath {
                path: resource_path.to_owned(),
            });
        }
        let relative =
            resource_path
                .parse::<http::Uri>()
                .map_err(|_| ConfigError::InvalidResourcePath {
                    path: resource_path.to_owned(),
                })?;
        if relative.scheme().is_some() || relative.authority().is_some() {
            return Err(ConfigError::InvalidResourcePath {
                path: resource_path.to_owned(),
            });
        }
        let resource_uri = request_uri(Some(base_uri), None, &relative).ok_or_else(|| {
            ConfigError::InvalidResourcePath {
                path: resource_path.to_owned(),
            }
        })?;
        self.build_resource_metadata(&resource_uri.to_string())
    }

    /// Reconstructs the externally visible request URI using the same mapping
    /// passed to the validator for `DPoP` `htu` verification.
    pub(crate) fn effective_request_uri(&self, uri: &http::Uri) -> Option<http::Uri> {
        self.request_mapping.as_ref().map_or_else(
            || Some(uri.clone()),
            |mapping| {
                if self.legacy_mapping {
                    super::uri::legacy_request_uri(mapping, uri)
                } else {
                    mapping.public_url(uri).ok()
                }
            },
        )
    }

    pub(crate) fn bind_resource_mapping(
        &mut self,
        mapping: &crate::resource_server::core::url_mapping::PublicUrlMapping,
    ) -> Result<(), ConfigError> {
        if self
            .request_mapping
            .as_ref()
            .is_some_and(|configured| configured != mapping)
            || self
                .strip_prefix
                .as_deref()
                .is_some_and(|prefix| prefix != mapping.incoming_prefix())
        {
            return Err(ConfigError::InvalidBaseUri {
                base_uri: mapping.public_base().to_string(),
                reason: "resource definition and guard URL mappings differ",
            });
        }
        self.base_uri = Some(mapping.public_base().clone());
        self.strip_prefix =
            (mapping.incoming_prefix() != "/").then(|| mapping.incoming_prefix().to_owned());
        self.request_mapping = Some(mapping.clone());
        self.legacy_mapping = false;
        Ok(())
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
        binding: Option<(&ValidatorMetadata, &[String])>,
    ) -> (Outcome<V::Claims>, CheckOutcome)
    where
        V::Claims: HasScopes,
    {
        let req = session.req_header();
        let (metadata, audiences) = binding.map_or((&self.metadata, None), |(m, a)| (m, Some(a)));
        let (outcome, category) = self
            .check_request_categorized(
                &req.headers,
                &req.method,
                &req.uri,
                client_cert_der(session),
                metadata,
                audiences,
            )
            .await;
        category.emit(self.metrics_name.as_deref());
        (outcome, category)
    }

    /// Low-level token check using plain HTTP types.
    ///
    /// Returns an [`Outcome`] describing whether the request should be
    /// forwarded or denied.
    ///
    /// With `metrics` enabled, emits `huskarl.resource.check` once, with an `outcome` label naming
    /// what this call resolved to — `forward` for a success, or the specific deny reason
    /// (`path_confusion`, `policy_denied`, `unauthenticated`, `invalid_token`,
    /// `expired`, `unrecognized_issuer`, `binding_error`, `nonce_required`,
    /// `insufficient_scope`, `invalid_request`, `server_error`).
    /// The label set is closed; the request path is never a label.
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
        category.emit(self.metrics_name.as_deref());
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
        let rule = match self.routes.resolve(path, method) {
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

fn validate_resource_identifier(resource: &str) -> Result<(), ConfigError> {
    if resource.contains('#') {
        return Err(ConfigError::InvalidResourceIdentifier {
            resource: resource.to_owned(),
            reason: "fragments are not allowed",
        });
    }
    let uri =
        resource
            .parse::<http::Uri>()
            .map_err(|_| ConfigError::InvalidResourceIdentifier {
                resource: resource.to_owned(),
                reason: "not a valid URI",
            })?;
    if uri.scheme_str() != Some("https") || uri.authority().is_none() {
        return Err(ConfigError::InvalidResourceIdentifier {
            resource: resource.to_owned(),
            reason: "expected an absolute https URL with an authority",
        });
    }
    well_known_url(resource).map_err(|source| ConfigError::ResourceMetadataUrl {
        resource: resource.to_owned(),
        source,
    })?;
    Ok(())
}

fn validate_base_uri(base_uri: &http::Uri) -> Result<(), ConfigError> {
    if !matches!(base_uri.scheme_str(), Some("http" | "https")) || base_uri.authority().is_none() {
        return Err(ConfigError::InvalidBaseUri {
            base_uri: base_uri.to_string(),
            reason: "expected an absolute HTTP(S) URI",
        });
    }
    if base_uri.query().is_some() {
        return Err(ConfigError::InvalidBaseUri {
            base_uri: base_uri.to_string(),
            reason: "queries are not allowed",
        });
    }
    Ok(())
}
