use std::collections::BTreeSet;
use std::sync::Arc;

use huskarl_resource_server::error::{
    InsufficientScope, TokenErrorCode, TokenValidationError, ToRfc6750Error,
};
use huskarl_resource_server::validator::metadata::{ProvideValidatorMetadata, ValidatorMetadata};
use huskarl_resource_server::validator::{AccessTokenValidator, ValidatedRequest};
use matchit::Router;
use pingora_proxy::Session;
use crate::outcome::Outcome;
use crate::rule::{CheckError, Rule, TokenRequirement};
use crate::scopes::HasScopes;

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
/// ```ignore
/// let guard = Guard::builder(my_validator)
///     .route("/public/*rest", Rule::public())
///     .route("/api/admin", Rule::required().scopes(["admin"]))
///     .build();
/// let proxy = AuthProxy::new(my_proxy, guard);
/// ```
pub struct Guard<V: AccessTokenValidator + ProvideValidatorMetadata> {
    validator: V,
    metadata: ValidatorMetadata,
    router: Router<Rule<V::Claims>>,
    default: Rule<V::Claims>,
    scopes_supported: Vec<String>,
    base_uri: Option<http::Uri>,
}

/// Builder for [`Guard`].
pub struct GuardBuilder<V: AccessTokenValidator + ProvideValidatorMetadata> {
    validator: V,
    resource: Option<http::Uri>,
    routes: Vec<(String, Rule<V::Claims>)>,
    default: Rule<V::Claims>,
}

impl<V: AccessTokenValidator + ProvideValidatorMetadata> GuardBuilder<V> {
    /// Sets the resource identifier for the validator metadata.
    pub fn resource(mut self, resource: http::Uri) -> Self {
        self.resource = Some(resource);
        self
    }

    /// Adds a route pattern with an associated rule.
    ///
    /// Patterns use [`matchit`] syntax (e.g. `/users/{id}`, `/public/*rest`).
    pub fn route(mut self, pattern: impl Into<String>, rule: Rule<V::Claims>) -> Self {
        self.routes.push((pattern.into(), rule));
        self
    }

    /// Sets the default rule for paths that don't match any route.
    ///
    /// Defaults to [`Rule::required()`].
    pub fn default_rule(mut self, rule: Rule<V::Claims>) -> Self {
        self.default = rule;
        self
    }

    /// Builds the [`Guard`].
    ///
    /// # Panics
    ///
    /// Panics if any route pattern is invalid or conflicts with another.
    pub fn build(self) -> Guard<V> {
        let resource_str = self.resource.as_ref().map(|u| u.to_string());
        let metadata = self
            .validator
            .validator_metadata(resource_str.as_deref());

        // Collect unique scopes from all route rules and the default rule.
        let mut all_scopes = BTreeSet::new();
        for (_pattern, rule) in &self.routes {
            all_scopes.extend(rule.scopes.iter().cloned());
        }
        all_scopes.extend(self.default.scopes.iter().cloned());
        let scopes_supported: Vec<String> = all_scopes.into_iter().collect();

        let mut router = Router::new();
        for (pattern, rule) in self.routes {
            router.insert(pattern, rule).expect("invalid route pattern");
        }
        Guard {
            validator: self.validator,
            metadata,
            router,
            default: self.default,
            scopes_supported,
            base_uri: self.resource,
        }
    }
}

impl<V: AccessTokenValidator + ProvideValidatorMetadata> Guard<V> {
    /// Creates a new builder for a `Guard`.
    pub fn builder(validator: V) -> GuardBuilder<V> {
        GuardBuilder {
            validator,
            resource: None,
            routes: Vec::new(),
            default: Rule::default(),
        }
    }

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
    pub(crate) fn resource_metadata(&self) -> (String, Vec<u8>) {
        let suffix = self
            .metadata
            .resource
            .as_deref()
            .and_then(|r| r.parse::<http::Uri>().ok())
            .map(|uri| uri.path().to_owned())
            .filter(|p| p != "/")
            .unwrap_or_default();

        let path = format!("/.well-known/oauth-protected-resource{suffix}");

        let mut value = serde_json::to_value(&self.metadata)
            .expect("ValidatorMetadata serialization should not fail");

        if !self.scopes_supported.is_empty() {
            value
                .as_object_mut()
                .expect("metadata serializes as object")
                .insert(
                    "scopes_supported".to_owned(),
                    serde_json::Value::from(self.scopes_supported.clone()),
                );
        }

        let json = serde_json::to_vec(&value).expect("JSON Value serialization should not fail");
        (path, json)
    }

    /// Reconstructs a full URI by combining the scheme and authority from
    /// `base_uri` with the path and query from the request URI. If no
    /// `base_uri` is set, returns `req_uri` unchanged.
    fn request_uri(&self, req_uri: &http::Uri) -> http::Uri {
        let Some(base) = &self.base_uri else {
            return req_uri.clone();
        };
        let mut parts = http::uri::Parts::default();
        parts.scheme = base.scheme().cloned();
        parts.authority = base.authority().cloned();
        parts.path_and_query = req_uri.path_and_query().cloned();
        http::Uri::from_parts(parts).unwrap_or_else(|_| req_uri.clone())
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

        let scope_param = scope_param_for(rule);

        // 1. Public routes skip validation entirely.
        if rule.token == TokenRequirement::None {
            return Outcome::Forward {
                token: None,
                dpop_nonce: None,
                strip_credentials: rule.strip_credentials,
            };
        }

        // 2. Call the validator.
        let full_uri = self.request_uri(uri);
        let result = self
            .validator
            .validate_request(headers, method, &full_uri, client_cert_der)
            .await;

        let dpop_nonce = result.dpop_nonce;

        match result.outcome {
            Err(err) => {
                // Token present but invalid.
                let status = err.token_error().suggested_status();
                let challenges = self.metadata.challenges(
                    Some(&err),
                    scope_param.as_deref(),
                    None,
                );
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
                        let challenges = self
                            .metadata
                            .unauthenticated_challenges(scope_param.as_deref());
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
                    self.check_rule(rule, &validated, scope_param.as_deref(), dpop_nonce.as_deref())
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
            let token_scopes: Vec<String> = validated.claims.scopes().unwrap_or_default();
            for required in &rule.scopes {
                if !token_scopes.contains(required) {
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
                    let challenges =
                        self.metadata.challenges(Some(&err), scope_param, None);
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
                    let challenges =
                        self.metadata.challenges(Some(&err), scope_param, None);
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

/// Computes the space-joined scope string for a rule, if it has scopes.
fn scope_param_for<C>(rule: &Rule<C>) -> Option<String> {
    if rule.scopes.is_empty() {
        None
    } else {
        Some(rule.scopes.join(" "))
    }
}

/// Helper for audience-mismatch errors.
struct InvalidToken(&'static str);

impl ToRfc6750Error for InvalidToken {
    fn attempted_scheme(&self) -> Option<huskarl_resource_server::validator::extract::TokenType> {
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
struct CustomCheckError {
    code: TokenErrorCode,
    description: String,
}

impl ToRfc6750Error for CustomCheckError {
    fn attempted_scheme(&self) -> Option<huskarl_resource_server::validator::extract::TokenType> {
        None
    }

    fn token_error(&self) -> TokenValidationError {
        TokenValidationError::Client(self.code)
    }

    fn error_description(&self) -> Option<String> {
        Some(self.description.clone())
    }
}
