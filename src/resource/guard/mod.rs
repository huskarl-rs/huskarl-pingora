//! Token validation guard with path-based routing.
//!
//! [`Guard`] matches incoming request paths against registered [`Rule`]s using
//! [`matchit`] patterns and validates bearer tokens via an
//! [`AccessTokenValidator`]. It returns an [`Outcome`] indicating whether
//! the request should be forwarded or denied with [RFC 6750] challenges.
//!
//! [RFC 6750]: https://datatracker.ietf.org/doc/html/rfc6750

use std::{collections::BTreeSet, sync::Arc};

use bon::bon;
use matchit::Router;
use pingora_proxy::Session;

use crate::{
    resource::{
        error::{ConfigError, CustomCheckError, InvalidRequest, InvalidToken},
        outcome::Outcome,
        rule::{CheckError, Rule, TokenRequirement},
        scopes::HasScopes,
        uri::request_uri,
    },
    resource_server::{
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
/// # use huskarl_pingora::resource::{Guard, Rule};
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
