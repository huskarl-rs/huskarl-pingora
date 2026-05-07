use std::{collections::BTreeSet, sync::Arc};

use bon::bon;
use matchit::Router;
use pingora_proxy::Session;

use crate::{
    error::{ConfigError, CustomCheckError, InvalidRequest, InvalidToken},
    outcome::Outcome,
    resource_server::{
        error::{InsufficientScope, ToRfc6750Error, TokenErrorCode},
        validator::{
            AccessTokenValidator, ValidatedRequest,
            metadata::{ProvideValidatorMetadata, ValidatorMetadata},
        },
    },
    rule::{CheckError, Rule, TokenRequirement},
    scopes::HasScopes,
    uri::request_uri,
};

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
/// Typically used via [`AuthProxy`](crate::AuthProxy), which wraps a
/// `ProxyHttp` implementation and calls [`Guard::check`] automatically.
///
/// # Example
///
/// ```
/// # use huskarl_pingora::{Guard, Rule};
/// # fn build<V>(my_validator: V)
/// # where
/// #     V: huskarl_pingora::resource_server::validator::AccessTokenValidator
/// #         + huskarl_pingora::resource_server::validator::metadata::ProvideValidatorMetadata,
/// # {
/// let guard = Guard::builder()
///     .validator(my_validator)
///     .route("/public/*rest", Rule::public())
///     .route("/api/admin", Rule::required().scopes(["admin"]))
///     .build()
///     .expect("route");
/// # }
/// ```
pub struct Guard<V: AccessTokenValidator + ProvideValidatorMetadata> {
    validator: V,
    metadata: ValidatorMetadata,
    router: Router<Rule<V::Claims>>,
    default: Rule<V::Claims>,
    scopes_supported: Vec<String>,
    base_uri: Option<http::Uri>,
    strip_prefix: Option<String>,
}

impl<V: AccessTokenValidator + ProvideValidatorMetadata> std::fmt::Debug for Guard<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Guard")
            .field("scopes_supported", &self.scopes_supported)
            .field("base_uri", &self.base_uri)
            .field("strip_prefix", &self.strip_prefix)
            .finish_non_exhaustive()
    }
}

#[bon]
impl<V: AccessTokenValidator + ProvideValidatorMetadata> Guard<V> {
    #[builder]
    pub fn new(
        #[builder(field)] routes: Vec<(String, Rule<V::Claims>)>,
        validator: V,
        /// the resource identifier for the validator metadata.
        resource: Option<http::Uri>,
        /// Path prefix to strip from the request path before prepending the resource path during DPoP URI reconstruction.
        ///
        /// This is useful when a front proxy adds a path prefix that isn't part of the client-facing URI.
        #[builder(into)]
        strip_prefix: Option<String>,
        /// The default rule for paths that don't match any route.
        ///
        /// Defaults to [`Rule::required()`].
        #[builder(default)]
        default: Rule<V::Claims>,
    ) -> Result<Self, ConfigError> {
        // Reject public rules with audience or scope constraints — they can never
        // be enforced because the token validator is skipped for public routes.
        for (pattern, rule) in &routes {
            if rule.token == TokenRequirement::None
                && (!rule.audiences.is_empty() || !rule.scopes.is_empty())
            {
                return Err(ConfigError::PublicRuleWithConstraints(pattern.clone()));
            }
        }
        if default.token == TokenRequirement::None
            && (!default.audiences.is_empty() || !default.scopes.is_empty())
        {
            return Err(ConfigError::PublicRuleWithConstraints("<default>".into()));
        }

        let resource_str = resource.as_ref().map(|u| u.to_string());
        let metadata = validator.validator_metadata(resource_str.as_deref());

        // Collect unique scopes from all route rules and the default rule.
        let mut all_scopes = BTreeSet::new();
        for (_pattern, rule) in &routes {
            all_scopes.extend(rule.scopes.iter().cloned());
        }
        all_scopes.extend(default.scopes.iter().cloned());
        let scopes_supported: Vec<String> = all_scopes.into_iter().collect();

        let mut router = Router::new();
        for (pattern, rule) in routes {
            router.insert(&pattern, rule)?;
        }

        Ok(Self {
            validator,
            metadata,
            router,
            default,
            scopes_supported,
            base_uri: resource,
            strip_prefix,
        })
    }
}

impl<V: AccessTokenValidator + ProvideValidatorMetadata, S: guard_builder::State>
    GuardBuilder<V, S>
{
    /// Adds a route pattern with an associated rule.
    ///
    /// Patterns use [`matchit`] syntax (e.g. `/users/{id}`, `/public/*rest`).
    pub fn route(mut self, pattern: impl Into<String>, rule: Rule<V::Claims>) -> Self {
        self.routes.push((pattern.into(), rule));
        self
    }
}

impl<V: AccessTokenValidator + ProvideValidatorMetadata> Guard<V> {
    /// Returns the well-known path and serialized JSON for RFC 9728 resource metadata.
    ///
    /// Per RFC 9728 §3.1, the well-known URI is constructed by inserting
    /// `/.well-known/oauth-protected-resource` between the host and the path
    /// of the resource identifier. For example, a resource at
    /// `https://api.example.com/tenant1` has its metadata at
    /// `/.well-known/oauth-protected-resource/tenant1`.
    ///
    /// When no resource identifier is set (or it has no path beyond `/`),
    /// the well-known path is `/.well-known/oauth-protected-resource`.
    pub(crate) fn resource_metadata(&self) -> Result<(String, Vec<u8>), ConfigError> {
        let suffix = self
            .base_uri
            .as_ref()
            .map(|uri| uri.path().to_owned())
            .filter(|p| p != "/")
            .unwrap_or_default();

        let path = format!("/.well-known/oauth-protected-resource{suffix}");

        let mut value = serde_json::to_value(&self.metadata)?;

        if !self.scopes_supported.is_empty()
            && let Some(obj) = value.as_object_mut()
        {
            // Only insert if the metadata doesn't already provide scopes_supported.
            obj.entry("scopes_supported")
                .or_insert_with(|| serde_json::Value::from(self.scopes_supported.clone()));
        }

        let json = serde_json::to_vec(&value)?;
        Ok((path, json))
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
        self.check_request(&req.headers, &req.method, &req.uri, client_cert_der)
            .await
    }

    /// Low-level token check using plain HTTP types.
    ///
    /// Returns an [`Outcome`] describing whether the request should be
    /// forwarded or denied.
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
        let path = uri.path();

        let rule = self
            .router
            .at(path)
            .map(|m| m.value)
            .unwrap_or(&self.default);

        let scope_param = rule.scope_param.as_deref();

        // 1. Public routes skip validation entirely.
        if rule.token == TokenRequirement::None {
            return Outcome::Forward {
                token: None,
                dpop_nonce: None,
                strip_credentials: rule.strip_credentials,
            };
        }

        // 2. Call the validator.
        let Some(full_uri) = request_uri(self.base_uri.as_ref(), self.strip_prefix.as_deref(), uri)
        else {
            let challenges = self.metadata.challenges(
                Some(&InvalidRequest("Invalid request URI")),
                scope_param,
                None,
            );
            return Outcome::Deny {
                status: http::StatusCode::BAD_REQUEST,
                challenges,
                dpop_nonce: None,
            };
        };

        let result = self
            .validator
            .validate_request(headers, method, &full_uri, client_cert_der)
            .await;

        let dpop_nonce = result.dpop_nonce;

        match result.outcome {
            Err(err) => {
                // Token present but invalid.
                let status = err.token_error().suggested_status();
                let challenges = self.metadata.challenges(Some(&err), scope_param, None);
                Outcome::Deny {
                    status,
                    challenges,
                    dpop_nonce,
                }
            }
            Ok(None) => {
                // No token present.
                match rule.token {
                    TokenRequirement::Required => {
                        let challenges = self.metadata.unauthenticated_challenges(scope_param);
                        Outcome::Deny {
                            status: http::StatusCode::UNAUTHORIZED,
                            challenges,
                            dpop_nonce,
                        }
                    }
                    TokenRequirement::Optional | TokenRequirement::None => Outcome::Forward {
                        token: None,
                        dpop_nonce,
                        strip_credentials: rule.strip_credentials,
                    },
                }
            }
            Ok(Some(validated)) => {
                // Token present and valid — run rule checks.
                if let Some(outcome) =
                    self.check_rule(rule, &validated, scope_param, dpop_nonce.as_deref())
                {
                    return outcome;
                }

                Outcome::Forward {
                    token: Some(Arc::new(validated)),
                    dpop_nonce,
                    strip_credentials: rule.strip_credentials,
                }
            }
        }
    }

    /// Runs audience, scope, and custom check against the rule.
    /// Returns `Some(Outcome::Deny)` if any check fails, `None` if all pass.
    fn check_rule(
        &self,
        rule: &Rule<V::Claims>,
        validated: &ValidatedRequest<V::Claims>,
        scope_param: Option<&str>,
        dpop_nonce: Option<&str>,
    ) -> Option<Outcome<V::Claims>>
    where
        V::Claims: HasScopes,
    {
        // Audience check.
        // Returns 401 (not 403) per RFC 6750 §3.1: a token whose audience does
        // not include this resource server is "invalid for other reasons" and
        // maps to the `invalid_token` error code.
        if !rule.audiences.is_empty()
            && !rule
                .audiences
                .iter()
                .any(|a| validated.audience.contains(a))
        {
            let challenges = self.metadata.challenges(
                Some(&InvalidToken("The access token audience does not match")),
                scope_param,
                None,
            );
            return Some(Outcome::Deny {
                status: http::StatusCode::UNAUTHORIZED,
                challenges,
                dpop_nonce: dpop_nonce.map(String::from),
            });
        }

        // Scope check.
        if !rule.scopes.is_empty() {
            for required in &rule.scopes {
                if !validated.claims.has_scope(required) {
                    let challenges =
                        self.metadata
                            .challenges(Some(&InsufficientScope), scope_param, None);
                    return Some(Outcome::Deny {
                        status: http::StatusCode::FORBIDDEN,
                        challenges,
                        dpop_nonce: dpop_nonce.map(String::from),
                    });
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
                    let challenges = self.metadata.challenges(Some(&err), None, None);
                    return Some(Outcome::Deny {
                        status: http::StatusCode::FORBIDDEN,
                        challenges,
                        dpop_nonce: dpop_nonce.map(String::from),
                    });
                }
                Err(CheckError::InvalidToken(desc)) => {
                    let err = CustomCheckError {
                        code: TokenErrorCode::InvalidToken,
                        description: desc,
                    };
                    let challenges = self.metadata.challenges(Some(&err), None, None);
                    return Some(Outcome::Deny {
                        status: http::StatusCode::UNAUTHORIZED,
                        challenges,
                        dpop_nonce: dpop_nonce.map(String::from),
                    });
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::resource_server::{
        error::{ToRfc6750Error, TokenErrorCode, TokenValidationError},
        validator::{ValidationResult, extract::TokenType, metadata::ValidatorMetadata},
    };

    // --- Mock types ---

    #[derive(Debug, Clone)]
    struct MockClaims {
        scopes: Option<String>,
    }

    impl HasScopes for MockClaims {
        fn has_scope(&self, scope: &str) -> bool {
            self.scopes
                .as_ref()
                .is_some_and(|s| s.split_whitespace().any(|t| t == scope))
        }
    }

    #[derive(Debug)]
    struct MockError;

    impl ToRfc6750Error for MockError {
        fn attempted_scheme(&self) -> Option<TokenType> {
            None
        }
        fn token_error(&self) -> TokenValidationError {
            TokenValidationError::Client(TokenErrorCode::InvalidToken)
        }
        fn error_description(&self) -> Option<String> {
            Some("mock invalid token".into())
        }
    }

    enum MockOutcome {
        NoToken,
        ValidToken {
            claims: MockClaims,
            audience: Vec<String>,
        },
        InvalidToken,
    }

    struct MockValidator {
        outcome: MockOutcome,
        captured_uri: Mutex<Option<http::Uri>>,
    }

    impl MockValidator {
        fn no_token() -> Self {
            Self {
                outcome: MockOutcome::NoToken,
                captured_uri: Mutex::new(None),
            }
        }

        fn valid(claims: MockClaims) -> Self {
            Self {
                outcome: MockOutcome::ValidToken {
                    claims,
                    audience: vec![],
                },
                captured_uri: Mutex::new(None),
            }
        }

        fn valid_with_audience(claims: MockClaims, audience: Vec<String>) -> Self {
            Self {
                outcome: MockOutcome::ValidToken { claims, audience },
                captured_uri: Mutex::new(None),
            }
        }

        fn invalid() -> Self {
            Self {
                outcome: MockOutcome::InvalidToken,
                captured_uri: Mutex::new(None),
            }
        }
    }

    impl AccessTokenValidator for MockValidator {
        type Claims = MockClaims;
        type Error = MockError;

        async fn validate_request(
            &self,
            _headers: &http::HeaderMap,
            _method: &http::Method,
            uri: &http::Uri,
            _client_cert_der: Option<&[u8]>,
        ) -> ValidationResult<MockClaims, MockError> {
            *self.captured_uri.lock().unwrap() = Some(uri.clone());

            let outcome = match &self.outcome {
                MockOutcome::NoToken => Ok(None),
                MockOutcome::ValidToken { claims, audience } => Ok(Some(ValidatedRequest {
                    issuer: None,
                    subject: None,
                    audience: audience.clone(),
                    jti: None,
                    issued_at: None,
                    expiration: None,
                    cnf: None,
                    claims: claims.clone(),
                    introspection_jwt: None,
                })),
                MockOutcome::InvalidToken => Err(MockError),
            };

            ValidationResult {
                outcome,
                dpop_nonce: None,
            }
        }
    }

    impl ProvideValidatorMetadata for MockValidator {
        fn validator_metadata(&self, resource: Option<&str>) -> ValidatorMetadata {
            ValidatorMetadata {
                realm: None,
                authorization_servers: None,
                dpop_signing_alg_values_supported: None,
                dpop_bound_access_tokens_required: None,
                resource: resource.map(String::from),
                bearer_methods_supported: None,
            }
        }
    }

    // --- Helpers ---

    fn build_guard(
        validator: MockValidator,
        routes: Vec<(&str, Rule<MockClaims>)>,
    ) -> Guard<MockValidator> {
        let mut builder = Guard::builder().validator(validator);
        for (pattern, rule) in routes {
            builder = builder.route(pattern, rule);
        }
        builder.build().unwrap()
    }

    fn build_guard_with_resource(
        validator: MockValidator,
        routes: Vec<(&str, Rule<MockClaims>)>,
        resource: &str,
        strip_prefix: Option<&str>,
    ) -> Guard<MockValidator> {
        let mut builder = Guard::builder()
            .validator(validator)
            .resource(resource.parse().unwrap())
            .maybe_strip_prefix(strip_prefix);
        for (pattern, rule) in routes {
            builder = builder.route(pattern, rule);
        }
        builder.build().unwrap()
    }

    async fn check(
        guard: &Guard<MockValidator>,
        method: &http::Method,
        uri: &str,
    ) -> Outcome<MockClaims> {
        guard
            .check_request(&http::HeaderMap::new(), method, &uri.parse().unwrap(), None)
            .await
    }

    // --- resource_metadata tests ---

    #[test]
    fn resource_metadata_default_path() {
        let guard = build_guard(MockValidator::no_token(), vec![]);
        let (path, _) = guard.resource_metadata().unwrap();
        assert_eq!(path, "/.well-known/oauth-protected-resource");
    }

    #[test]
    fn resource_metadata_with_resource_path() {
        let guard = build_guard_with_resource(
            MockValidator::no_token(),
            vec![],
            "https://api.example.com/tenant1",
            None,
        );
        let (path, _) = guard.resource_metadata().unwrap();
        assert_eq!(path, "/.well-known/oauth-protected-resource/tenant1");
    }

    #[test]
    fn resource_metadata_root_path_no_suffix() {
        let guard = build_guard_with_resource(
            MockValidator::no_token(),
            vec![],
            "https://api.example.com/",
            None,
        );
        let (path, _) = guard.resource_metadata().unwrap();
        assert_eq!(path, "/.well-known/oauth-protected-resource");
    }

    #[test]
    fn resource_metadata_includes_scopes() {
        let guard = build_guard(
            MockValidator::no_token(),
            vec![
                ("/admin", Rule::required().scopes(["admin", "write"])),
                ("/read", Rule::required().scopes(["read"])),
            ],
        );
        let (_, json) = guard.resource_metadata().unwrap();
        let value: serde_json::Value = serde_json::from_slice(&json).unwrap();
        let scopes = value["scopes_supported"].as_array().unwrap();
        let scope_strs: Vec<&str> = scopes.iter().map(|v| v.as_str().unwrap()).collect();
        // BTreeSet orders alphabetically
        assert_eq!(scope_strs, vec!["admin", "read", "write"]);
    }

    #[test]
    fn resource_metadata_no_scopes_omits_field() {
        let guard = build_guard(MockValidator::no_token(), vec![]);
        let (_, json) = guard.resource_metadata().unwrap();
        let value: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert!(value.get("scopes_supported").is_none());
    }

    // --- check_request: routing and token requirement ---

    #[tokio::test]
    async fn public_route_skips_validation() {
        let guard = build_guard(MockValidator::no_token(), vec![("/health", Rule::public())]);
        let outcome = check(&guard, &http::Method::GET, "/health").await;
        assert!(matches!(outcome, Outcome::Forward { token: None, .. }));
        // Validator must not have been called.
        assert!(guard.validator.captured_uri.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn required_route_no_token_denies_401() {
        let guard = build_guard(MockValidator::no_token(), vec![]);
        let outcome = check(&guard, &http::Method::GET, "/api").await;
        assert!(matches!(
            outcome,
            Outcome::Deny { status, .. } if status == http::StatusCode::UNAUTHORIZED
        ));
    }

    #[tokio::test]
    async fn required_route_valid_token_forwards() {
        let claims = MockClaims { scopes: None };
        let guard = build_guard(MockValidator::valid(claims), vec![]);
        let outcome = check(&guard, &http::Method::GET, "/api").await;
        assert!(matches!(outcome, Outcome::Forward { token: Some(_), .. }));
    }

    #[tokio::test]
    async fn required_route_invalid_token_denies() {
        let guard = build_guard(MockValidator::invalid(), vec![]);
        let outcome = check(&guard, &http::Method::GET, "/api").await;
        assert!(matches!(outcome, Outcome::Deny { .. }));
    }

    #[tokio::test]
    async fn optional_route_no_token_forwards() {
        let guard = build_guard(MockValidator::no_token(), vec![("/api", Rule::optional())]);
        let outcome = check(&guard, &http::Method::GET, "/api").await;
        assert!(matches!(outcome, Outcome::Forward { token: None, .. }));
    }

    #[tokio::test]
    async fn optional_route_valid_token_forwards_with_token() {
        let claims = MockClaims { scopes: None };
        let guard = build_guard(
            MockValidator::valid(claims),
            vec![("/api", Rule::optional())],
        );
        let outcome = check(&guard, &http::Method::GET, "/api").await;
        assert!(matches!(outcome, Outcome::Forward { token: Some(_), .. }));
    }

    #[tokio::test]
    async fn default_rule_applies_to_unmatched_paths() {
        let guard = Guard::builder()
            .validator(MockValidator::no_token())
            .route("/health", Rule::public())
            .default(Rule::optional())
            .build()
            .unwrap();

        let outcome = check(&guard, &http::Method::GET, "/health").await;
        assert!(matches!(outcome, Outcome::Forward { token: None, .. }));

        // Unmatched path uses the default Optional rule; no token → Forward.
        let outcome = check(&guard, &http::Method::GET, "/other").await;
        assert!(matches!(outcome, Outcome::Forward { token: None, .. }));
    }

    // --- check_request: scope enforcement ---

    #[tokio::test]
    async fn scope_check_passes() {
        let claims = MockClaims {
            scopes: Some("admin read".into()),
        };
        let guard = build_guard(
            MockValidator::valid(claims),
            vec![("/admin", Rule::required().scopes(["admin"]))],
        );
        let outcome = check(&guard, &http::Method::GET, "/admin").await;
        assert!(matches!(outcome, Outcome::Forward { token: Some(_), .. }));
    }

    #[tokio::test]
    async fn scope_check_failure_denies_403() {
        let claims = MockClaims {
            scopes: Some("read".into()),
        };
        let guard = build_guard(
            MockValidator::valid(claims),
            vec![("/admin", Rule::required().scopes(["admin"]))],
        );
        let outcome = check(&guard, &http::Method::GET, "/admin").await;
        assert!(matches!(
            outcome,
            Outcome::Deny { status, .. } if status == http::StatusCode::FORBIDDEN
        ));
    }

    #[tokio::test]
    async fn multiple_scopes_all_required() {
        let claims = MockClaims {
            scopes: Some("read".into()),
        };
        let guard = build_guard(
            MockValidator::valid(claims),
            vec![("/api", Rule::required().scopes(["read", "write"]))],
        );
        // Has "read" but not "write" → denied.
        let outcome = check(&guard, &http::Method::GET, "/api").await;
        assert!(matches!(
            outcome,
            Outcome::Deny { status, .. } if status == http::StatusCode::FORBIDDEN
        ));
    }

    // --- check_request: audience enforcement ---

    #[tokio::test]
    async fn audience_check_passes() {
        let claims = MockClaims { scopes: None };
        let guard = build_guard(
            MockValidator::valid_with_audience(claims, vec!["my-api".into()]),
            vec![("/api", Rule::required().audience("my-api"))],
        );
        let outcome = check(&guard, &http::Method::GET, "/api").await;
        assert!(matches!(outcome, Outcome::Forward { token: Some(_), .. }));
    }

    #[tokio::test]
    async fn audience_mismatch_denies_401() {
        let claims = MockClaims { scopes: None };
        let guard = build_guard(
            MockValidator::valid_with_audience(claims, vec!["other-api".into()]),
            vec![("/api", Rule::required().audience("my-api"))],
        );
        let outcome = check(&guard, &http::Method::GET, "/api").await;
        assert!(matches!(
            outcome,
            Outcome::Deny { status, .. } if status == http::StatusCode::UNAUTHORIZED
        ));
    }

    // --- check_request: custom checks ---

    #[tokio::test]
    async fn custom_check_forbidden_denies_403() {
        let claims = MockClaims { scopes: None };
        let guard = build_guard(
            MockValidator::valid(claims),
            vec![(
                "/api",
                Rule::required().check(|_| Err(CheckError::Forbidden("nope".into()))),
            )],
        );
        let outcome = check(&guard, &http::Method::GET, "/api").await;
        assert!(matches!(
            outcome,
            Outcome::Deny { status, .. } if status == http::StatusCode::FORBIDDEN
        ));
    }

    #[tokio::test]
    async fn custom_check_invalid_token_denies_401() {
        let claims = MockClaims { scopes: None };
        let guard = build_guard(
            MockValidator::valid(claims),
            vec![(
                "/api",
                Rule::required().check(|_| Err(CheckError::InvalidToken("bad".into()))),
            )],
        );
        let outcome = check(&guard, &http::Method::GET, "/api").await;
        assert!(matches!(
            outcome,
            Outcome::Deny { status, .. } if status == http::StatusCode::UNAUTHORIZED
        ));
    }

    #[tokio::test]
    async fn custom_check_ok_forwards() {
        let claims = MockClaims { scopes: None };
        let guard = build_guard(
            MockValidator::valid(claims),
            vec![("/api", Rule::required().check(|_| Ok(())))],
        );
        let outcome = check(&guard, &http::Method::GET, "/api").await;
        assert!(matches!(outcome, Outcome::Forward { token: Some(_), .. }));
    }

    // --- check_request: strip_credentials ---

    #[tokio::test]
    async fn strip_credentials_propagated() {
        let claims = MockClaims { scopes: None };
        let guard = build_guard(
            MockValidator::valid(claims),
            vec![("/api", Rule::required().strip_credentials(false))],
        );
        let outcome = check(&guard, &http::Method::GET, "/api").await;
        match outcome {
            Outcome::Forward {
                strip_credentials, ..
            } => assert!(!strip_credentials),
            other => panic!("expected Forward, got {other:?}"),
        }
    }

    // --- request_uri reconstruction ---

    #[tokio::test]
    async fn request_uri_without_base_passes_original() {
        let guard = build_guard(MockValidator::no_token(), vec![]);
        let _ = check(&guard, &http::Method::GET, "/api/data?q=1").await;
        let captured = guard
            .validator
            .captured_uri
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(captured.to_string(), "/api/data?q=1");
    }

    #[tokio::test]
    async fn request_uri_with_base_prepends_path() {
        let guard = build_guard_with_resource(
            MockValidator::no_token(),
            vec![],
            "https://api.example.com/v1",
            None,
        );
        let _ = check(&guard, &http::Method::GET, "/users").await;
        let captured = guard
            .validator
            .captured_uri
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(captured.to_string(), "https://api.example.com/v1/users");
    }

    #[tokio::test]
    async fn request_uri_with_strip_prefix() {
        let guard = build_guard_with_resource(
            MockValidator::no_token(),
            vec![],
            "https://api.example.com",
            Some("/proxy"),
        );
        let _ = check(&guard, &http::Method::GET, "/proxy/users").await;
        let captured = guard
            .validator
            .captured_uri
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(captured.to_string(), "https://api.example.com/users");
    }

    #[tokio::test]
    async fn request_uri_strip_prefix_no_match_denies() {
        let guard = build_guard_with_resource(
            MockValidator::no_token(),
            vec![],
            "https://api.example.com",
            Some("/proxy"),
        );
        let outcome = check(&guard, &http::Method::GET, "/other/users").await;

        // Validation should not have been called
        assert!(guard.validator.captured_uri.lock().unwrap().is_none());

        assert!(matches!(
            outcome,
            Outcome::Deny { status, .. } if status == http::StatusCode::BAD_REQUEST
        ));
    }

    #[tokio::test]
    async fn request_uri_preserves_query_string() {
        let guard = build_guard_with_resource(
            MockValidator::no_token(),
            vec![],
            "https://api.example.com",
            None,
        );
        let _ = check(&guard, &http::Method::GET, "/users?page=2").await;
        let captured = guard
            .validator
            .captured_uri
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(captured.to_string(), "https://api.example.com/users?page=2");
    }
}
