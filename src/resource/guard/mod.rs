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
use huskarl_route_guard::{GuardConfig, PathRegistration, RuleRouter};
use pingora_proxy::Session;

use crate::{
    method::MethodMatch,
    metrics::CheckOutcome,
    path_confusion::{
        CaseSensitivity, DecodeDepth, GuardMode, ResolveError, ResolveErrorKind, StructuralClasses,
    },
    resource::{
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
/// ```ignore
/// use huskarl_pingora::ClientCertDer;
///
/// #[async_trait]
/// impl TlsAccept for MyApp {
///     async fn handshake_complete_callback(
///         &self,
///         ssl: &TlsRef,
///     ) -> Option<Arc<dyn Any + Send + Sync>> {
///         ssl.peer_certificate()
///             .and_then(|cert| cert.to_der().ok())
///             .map(|der| Arc::new(ClientCertDer(der)) as _)
///     }
/// }
/// ```
pub struct ClientCertDer(pub Vec<u8>);

/// A guard that validates OAuth 2.0 access tokens against path-based rules.
///
/// Typically used via [`AuthProxy`](super::AuthProxy), which wraps a
/// `ProxyHttp` implementation and calls [`Guard::check`] automatically.
///
/// # Example
///
/// ```
/// # use huskarl_pingora::resource::{CaseSensitivity, DecodeDepth, Guard, Rule};
/// # fn build<V>(my_validator: V)
/// # where
/// #     V: huskarl_pingora::resource_server::validator::AccessTokenValidator
/// #         + huskarl_pingora::resource_server::validator::metadata::ProvideValidatorMetadata,
/// # {
/// let guard = Guard::builder()
///     .validator(my_validator)
///     // Required: declare whether the upstream folds path case, and whether a
///     // decoding layer (CDN/WAF) sits in front of it.
///     .case_sensitivity(CaseSensitivity::Sensitive)
///     .decode_depth(DecodeDepth::UpToOne)
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
    /// Optional value for the `name` label on emitted metrics, distinguishing guard
    /// instances when one process runs several. `None` omits the label.
    metrics_name: Option<String>,
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
        /// explicitly is what keeps `htu` bound to your real origin. If it is left unset,
        /// `htu` is matched against the raw request URI — which from a downstream proxy is
        /// origin-form (path only) and therefore no longer pins scheme/host, so a captured
        /// proof could be replayed across origins. Set `base_uri` whenever you accept
        /// DPoP-bound tokens.
        base_uri: Option<http::Uri>,
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
        /// Whether the upstream resolves paths **case-insensitively** — a required
        /// declaration the library cannot infer (see [`CaseSensitivity`]). There is no
        /// default: every deployment must state it, because a case-folding backend
        /// turns a differently-cased path into a route-confusion vector.
        case_sensitivity: CaseSensitivity,
        /// Whether more than one percent-decode pass happens behind this layer — a
        /// CDN, WAF, or second proxy decoding in front of the upstream (see
        /// [`DecodeDepth`]). Required, no default: decode depth is a deployment assumption
        /// the library will not guess. When unsure, declare
        /// [`UpToTwo`](DecodeDepth::UpToTwo) — the safe, deny-more direction.
        decode_depth: DecodeDepth,
        /// Which path-confusion guard to apply — denies requests whose path a
        /// normalizing backend could route to a different rule than the one matched
        /// on the raw path. Defaults to [`GuardMode::RejectAmbiguous`].
        #[builder(default)]
        guard_mode: GuardMode,
        /// The structural classes and encodings the guard recognises beyond the
        /// built-in classes. Defaults to [`StructuralClasses::new`].
        #[builder(default)]
        structural_classes: StructuralClasses,
        /// Maximum original path length in bytes for ambiguity analysis.
        /// With custom probes this applies to every path. Disabled mode bypasses it.
        #[builder(default = 8192)]
        max_analysis_path_len: usize,
        /// Optional value for the `name` label on emitted metrics (the
        /// `huskarl.resource.check` counter). Set it to tell guard instances apart when
        /// one process runs several; leave unset to omit the label.
        #[builder(into)]
        metrics_name: Option<String>,
    ) -> Result<Self, ConfigError> {
        // Reject public rules with audience or scope constraints — they can never
        // be enforced because the token validator is skipped for public routes.
        for (_kind, pattern, rule) in &routes {
            if rule.token == TokenRequirement::None
                && (!rule.audiences.is_empty() || !rule.scopes.is_empty() || rule.check.is_some())
            {
                return Err(ConfigError::PublicRuleWithConstraints(pattern.clone()));
            }
        }
        if default.token == TokenRequirement::None
            && (!default.audiences.is_empty()
                || !default.scopes.is_empty()
                || default.check.is_some())
        {
            return Err(ConfigError::PublicRuleWithConstraints("<default>".into()));
        }

        if let Some(base_uri) = base_uri.as_ref() {
            validate_base_uri(base_uri)?;
        }
        let metadata = validator.validator_metadata(None);

        // Collect unique scopes from all route rules and the default rule.
        let mut all_scopes = BTreeSet::new();
        for (_kind, _pattern, rule) in &routes {
            all_scopes.extend(rule.scopes.iter().cloned());
        }
        all_scopes.extend(default.scopes.iter().cloned());
        let scopes_supported: Vec<String> = all_scopes.into_iter().collect();

        let config = GuardConfig::new(case_sensitivity, decode_depth)
            .with_mode(guard_mode)
            .with_structural_classes(structural_classes)
            .with_max_analysis_path_len(max_analysis_path_len);
        let registrations = routes.into_iter().map(|(kind, pattern, rule)| {
            let method = rule.method.clone();
            let registration = match kind {
                RouteKind::Exact => PathRegistration::path(pattern),
                RouteKind::Subtree => PathRegistration::subtree(&pattern),
                RouteKind::Blob => PathRegistration::exclusive_subtree(&pattern),
            };
            match method {
                MethodMatch::Any => registration.all(rule),
                MethodMatch::OneOf(methods) => registration.methods(methods, rule),
            }
        });
        let routes = RuleRouter::from_registrations(default, config, registrations)?;

        Ok(Self {
            validator,
            metadata,
            routes,
            scopes_supported,
            base_uri,
            strip_prefix,
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
    /// # use huskarl_pingora::resource::{CaseSensitivity, DecodeDepth, Guard, Rule};
    /// # fn build<V>(my_validator: V)
    /// # where
    /// #     V: huskarl_pingora::resource_server::validator::AccessTokenValidator
    /// #         + huskarl_pingora::resource_server::validator::metadata::ProvideValidatorMetadata,
    /// # {
    /// let guard = Guard::builder()
    ///     .validator(my_validator)
    ///     .case_sensitivity(CaseSensitivity::Sensitive)
    ///     .decode_depth(DecodeDepth::UpToOne)
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

/// How a registration on [`GuardBuilder`] is lowered onto [`RuleRouter::builder`] at
/// build time — an exact [`route`](GuardBuilder::route), a [`subtree`](GuardBuilder::subtree),
/// or an exclusive [`blob_subtree`](GuardBuilder::blob_subtree).
enum RouteKind {
    Exact,
    Subtree,
    Blob,
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
        match reason.kind() {
            ResolveErrorKind::InvalidInput => (
                Self::bad_request_with_metadata(metadata, reason.message()),
                CheckOutcome::PathConfusion,
            ),
            kind => (
                Outcome::Deny {
                    status: if kind == ResolveErrorKind::PolicyDenied {
                        http::StatusCode::FORBIDDEN
                    } else {
                        http::StatusCode::INTERNAL_SERVER_ERROR
                    },
                    challenges: Vec::new(),
                    dpop_nonce: None,
                    retry_after: None,
                },
                if kind == ResolveErrorKind::PolicyDenied {
                    CheckOutcome::PolicyDenied
                } else {
                    CheckOutcome::ServerError
                },
            ),
        }
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
        let derived = metadata_url.to_string();

        let mut metadata = self.validator.validator_metadata(Some(resource));
        if let Some(configured) = metadata.resource_metadata.as_ref()
            && configured != &derived
        {
            return Err(ConfigError::ResourceMetadataUrlMismatch {
                configured: configured.clone(),
                derived,
            });
        }
        metadata.resource = Some(resource.to_owned());
        metadata.resource_metadata = Some(derived);

        let Some(document) = metadata.to_resource_metadata() else {
            return Err(ConfigError::ResourceMetadataDocumentUnavailable);
        };
        let endpoint_uri = metadata_url.as_uri().clone();

        let mut value = serde_json::to_value(&document)?;

        if !self.scopes_supported.is_empty()
            && let Some(obj) = value.as_object_mut()
        {
            // Only insert if the metadata doesn't already provide scopes_supported.
            obj.entry("scopes_supported")
                .or_insert_with(|| serde_json::Value::from(self.scopes_supported.clone()));
        }

        let body = serde_json::to_vec(&value)?;
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
        request_uri(self.base_uri.as_ref(), self.strip_prefix.as_deref(), uri)
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
        let client_cert_der = session
            .as_downstream()
            .digest()
            .and_then(|d| d.ssl_digest.as_ref())
            .and_then(|ssl| ssl.extension.get::<ClientCertDer>())
            .map(|c| c.0.as_slice());
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

    /// Checks a Pingora session while using resource-specific challenge
    /// metadata selected by [`AuthProxy`](super::AuthProxy).
    pub(crate) async fn check_with_metadata(
        &self,
        session: &Session,
        metadata: &ValidatorMetadata,
        audiences: &[String],
    ) -> Outcome<V::Claims>
    where
        V::Claims: HasScopes,
    {
        let req = session.req_header();
        let client_cert_der = session
            .as_downstream()
            .digest()
            .and_then(|d| d.ssl_digest.as_ref())
            .and_then(|ssl| ssl.extension.get::<ClientCertDer>())
            .map(|c| c.0.as_slice());
        self.check_request_with_metadata(
            &req.headers,
            &req.method,
            &req.uri,
            client_cert_der,
            metadata,
            Some(audiences),
        )
        .await
    }

    /// Low-level token check using plain HTTP types.
    ///
    /// Returns an [`Outcome`] describing whether the request should be
    /// forwarded or denied.
    ///
    /// Emits the `huskarl.resource.check` counter once, with an `outcome` label naming
    /// what this call resolved to — `forward` for a success, or the specific deny reason
    /// (`path_confusion`, `unauthenticated`, `invalid_token`, `insufficient_scope`,
    /// `invalid_request`). The label set is closed; the request path is never a label.
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
        // The attributed reason (which check and byte class fired) goes to the log so
        // the denial is actionable; the client sees only the coarse static message.
        let rule = match self.routes.resolve(path, method) {
            Ok(matched) => matched.rule(),
            Err(reason) => {
                log::warn!("route guard denied {path:?}: {reason}");
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
        let Some(full_uri) = request_uri(self.base_uri.as_ref(), self.strip_prefix.as_deref(), uri)
        else {
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

    /// Runs audience, scope, and custom check against the rule.
    /// Returns `Some((Outcome::Deny, category))` if any check fails, `None` if all pass.
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
        // The protected-resource binding is the primary audience boundary. RFC
        // 8707 permits an authorization server to use the resource URI itself
        // or map it to another identifier, so AuthProxy supplies the configured
        // acceptable values for the selected resource.
        if let Some(audiences) = resource_audiences
            && !audiences
                .iter()
                .any(|audience| validated.aud.contains(audience))
        {
            let challenges = metadata.challenges(
                Some(&InvalidToken(
                    "The access token audience does not match the protected resource",
                )),
                scope_param,
                None,
            );
            return Some((
                Outcome::Deny {
                    status: http::StatusCode::UNAUTHORIZED,
                    challenges,
                    dpop_nonce: dpop_nonce.map(String::from),
                    retry_after: None,
                },
                CheckOutcome::InvalidToken,
            ));
        }

        // A rule can additionally narrow the accepted audiences.
        // Returns 401 (not 403) per RFC 6750 §3.1: a token whose audience does
        // not include this resource server is "invalid for other reasons" and
        // maps to the `invalid_token` error code.
        if !rule.audiences.is_empty() && !rule.audiences.iter().any(|a| validated.aud.contains(a)) {
            let challenges = metadata.challenges(
                Some(&InvalidToken("The access token audience does not match")),
                scope_param,
                None,
            );
            return Some((
                Outcome::Deny {
                    status: http::StatusCode::UNAUTHORIZED,
                    challenges,
                    dpop_nonce: dpop_nonce.map(String::from),
                    retry_after: None,
                },
                CheckOutcome::InvalidToken,
            ));
        }

        // Scope check.
        if !rule.scopes.is_empty() {
            for required in &rule.scopes {
                if !validated.claims.has_scope(required) {
                    let challenges =
                        metadata.challenges(Some(&InsufficientScope::default()), scope_param, None);
                    return Some((
                        Outcome::Deny {
                            status: http::StatusCode::FORBIDDEN,
                            challenges,
                            dpop_nonce: dpop_nonce.map(String::from),
                            retry_after: None,
                        },
                        CheckOutcome::InsufficientScope,
                    ));
                }
            }
        }

        // Custom check.
        if let Some(check_fn) = &rule.check {
            match check_fn(validated) {
                Ok(()) => {}
                Err(CheckError::Forbidden(desc)) => {
                    let err = CustomCheckError {
                        code: TokenErrorCode::InsufficientScope,
                        description: desc,
                    };
                    let challenges = metadata.challenges(Some(&err), None, None);
                    return Some((
                        Outcome::Deny {
                            status: http::StatusCode::FORBIDDEN,
                            challenges,
                            dpop_nonce: dpop_nonce.map(String::from),
                            retry_after: None,
                        },
                        CheckOutcome::InsufficientScope,
                    ));
                }
                Err(CheckError::InvalidToken(desc)) => {
                    let err = CustomCheckError {
                        code: TokenErrorCode::InvalidToken,
                        description: desc,
                    };
                    let challenges = metadata.challenges(Some(&err), None, None);
                    return Some((
                        Outcome::Deny {
                            status: http::StatusCode::UNAUTHORIZED,
                            challenges,
                            dpop_nonce: dpop_nonce.map(String::from),
                            retry_after: None,
                        },
                        CheckOutcome::InvalidToken,
                    ));
                }
            }
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
