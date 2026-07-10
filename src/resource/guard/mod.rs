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
use pingora_proxy::Session;

use crate::{
    path_confusion::{CaseSensitivity, PathConfusion, StructuralClasses},
    path_router::{RouteEntry, RuleRouter, next_rule_id},
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
/// # use huskarl_pingora::resource::{CaseSensitivity, Guard, Rule};
/// # fn build<V>(my_validator: V)
/// # where
/// #     V: huskarl_pingora::resource_server::validator::AccessTokenValidator
/// #         + huskarl_pingora::resource_server::validator::metadata::ProvideValidatorMetadata,
/// # {
/// let guard = Guard::builder()
///     .validator(my_validator)
///     // Required: declare whether the upstream folds path case.
///     .case_sensitivity(CaseSensitivity::Sensitive)
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
    /// Builds a new [`Guard`] with the given validator and per-path rules.
    ///
    /// Use [`Guard::builder`] (the generated builder) to set routes and
    /// configuration; this constructor is the builder's terminal `build`
    /// step.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if any route pattern is rejected by
    /// `matchit` or if a public rule is configured with audience or scope
    /// constraints (which can never be enforced).
    #[builder]
    pub fn new(
        // (pattern, rule, rule_id, opaque, method) — patterns from one route/subtree call
        // share an id; `opaque` marks a blob_subtree catch-all; `method` is the rule's
        // method qualifier (wildcard by default).
        #[builder(field)] routes: Vec<RouteEntry<Rule<V::Claims>>>,
        validator: V,
        /// This resource server's own externally-visible base URL — its scheme,
        /// authority, and base path (e.g. `https://api.example.com`). Used for two
        /// things: the resource identifier in RFC 9728 metadata, and **`DPoP` `htu`
        /// binding** — the guard reconstructs the client-facing request URL by combining
        /// this authority (and base path) with the request path and passes it to the
        /// validator to check against the proof's `htu` claim.
        ///
        /// # Security
        ///
        /// For `DPoP`, set this to a value *you* control. The guard never derives the
        /// authority from the inbound `Host` header, so configuring `resource`
        /// explicitly is what keeps `htu` bound to your real origin. If it is left unset,
        /// `htu` is matched against the raw request URI — which from a downstream proxy is
        /// origin-form (path only) and therefore no longer pins scheme/host, so a captured
        /// proof could be replayed across origins. Set `resource` whenever you accept
        /// DPoP-bound tokens.
        resource: Option<http::Uri>,
        /// Path prefix to strip from the request path before prepending the resource path during `DPoP` URI reconstruction.
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
        /// Which path-confusion guard to apply — denies requests whose path a
        /// normalizing backend could route to a different rule than the one matched
        /// on the raw path. Defaults to [`PathConfusion::RejectStructural`].
        #[builder(default)]
        path_confusion: PathConfusion,
        /// The structural classes and encodings the guard recognises beyond the
        /// always-on trio. Defaults to [`StructuralClasses::new`].
        #[builder(default)]
        structural_classes: StructuralClasses,
    ) -> Result<Self, ConfigError> {
        // Reject public rules with audience or scope constraints — they can never
        // be enforced because the token validator is skipped for public routes.
        for (pattern, rule, _id, _opaque, _method) in &routes {
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

        let resource_str = resource.as_ref().map(ToString::to_string);
        let metadata = validator.validator_metadata(resource_str.as_deref());

        // Collect unique scopes from all route rules and the default rule.
        let mut all_scopes = BTreeSet::new();
        for (_pattern, rule, _id, _opaque, _method) in &routes {
            all_scopes.extend(rule.scopes.iter().cloned());
        }
        all_scopes.extend(default.scopes.iter().cloned());
        let scopes_supported: Vec<String> = all_scopes.into_iter().collect();

        // Build the rule-id router + structural guard (also runs the build-time
        // canonical-pattern check).
        let routes = RuleRouter::build(
            routes,
            default,
            path_confusion,
            structural_classes,
            case_sensitivity.is_insensitive(),
        )?;

        Ok(Self {
            validator,
            metadata,
            routes,
            scopes_supported,
            base_uri: resource,
            strip_prefix,
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
        let id = next_rule_id(&self.routes);
        let method = rule.method.clone();
        self.routes.push((pattern.into(), rule, id, false, method));
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
    /// # use huskarl_pingora::resource::{CaseSensitivity, Guard, Rule};
    /// # fn build<V>(my_validator: V)
    /// # where
    /// #     V: huskarl_pingora::resource_server::validator::AccessTokenValidator
    /// #         + huskarl_pingora::resource_server::validator::metadata::ProvideValidatorMetadata,
    /// # {
    /// let guard = Guard::builder()
    ///     .validator(my_validator)
    ///     .case_sensitivity(CaseSensitivity::Sensitive)
    ///     .subtree("/admin", Rule::required().scopes(["admin"]))
    ///     .route("/admin/health", Rule::public()) // exact carve-out wins
    ///     .build()
    ///     .expect("routes");
    /// # }
    /// ```
    pub fn subtree(mut self, path: &str, rule: Rule<V::Claims>) -> Self {
        self.push_subtree(path, rule, false);
        self
    }

    /// Like [`subtree`](Self::subtree), but declares the subtree's catch-all tail an
    /// **opaque** key space: structural bytes (`%2F`, `;`, `\`) *inside the key* are
    /// tolerated rather than denied — for proxying opaque identifiers such as object-store
    /// keys. Dot-segments (`..`), NUL truncation, and case folding are **still** denied
    /// even in the blob, so traversal cannot escape it.
    ///
    /// Registering a more-specific [`route`](Self::route) or `subtree` *under* the blob is
    /// a build error: a structural byte in the key could then relocate into that nested
    /// route. Use a plain [`subtree`](Self::subtree) if you need nested routes.
    pub fn blob_subtree(mut self, path: &str, rule: Rule<V::Claims>) -> Self {
        self.push_subtree(path, rule, true);
        self
    }

    /// Expand `path` into its subtree patterns and push them under one rule id. Only the
    /// catch-all pattern's `opaque` flag is honored downstream (it is ignored on the bare
    /// and trailing-slash patterns, which are not catch-alls).
    fn push_subtree(&mut self, path: &str, rule: Rule<V::Claims>, opaque: bool) {
        let id = next_rule_id(&self.routes);
        let method = rule.method.clone();
        let mut patterns = crate::subtree_patterns(path).into_iter();
        // `subtree_patterns` always yields at least two patterns; all share one rule id.
        if let Some(first) = patterns.next() {
            for pattern in patterns {
                self.routes
                    .push((pattern, rule.clone(), id, opaque, method.clone()));
            }
            self.routes.push((first, rule, id, opaque, method));
        }
    }
}

impl<V: AccessTokenValidator + ProvideValidatorMetadata> Guard<V> {
    /// Builds a `400 Bad Request` deny outcome with an `invalid_request` challenge.
    fn bad_request(&self, msg: &'static str, scope_param: Option<&str>) -> Outcome<V::Claims> {
        let challenges = self
            .metadata
            .challenges(Some(&InvalidRequest(msg)), scope_param, None);
        Outcome::Deny {
            status: http::StatusCode::BAD_REQUEST,
            challenges,
            dpop_nonce: None,
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
    pub(crate) fn resource_metadata(&self) -> Result<(String, Vec<u8>), ConfigError> {
        let suffix = self
            .base_uri
            .as_ref()
            .map(|uri| uri.path().to_owned())
            .filter(|p| p != "/")
            .unwrap_or_default();

        let path = format!("/.well-known/oauth-protected-resource{suffix}");

        // RFC 9728 §2 requires the document's `resource` member, so
        // `to_resource_metadata` yields `None` when no resource identifier is
        // configured; fall back to an empty document and let the
        // scopes_supported insertion below carry what we do know.
        let mut value = match self.metadata.to_resource_metadata() {
            Some(document) => serde_json::to_value(&document)?,
            None => serde_json::Value::Object(serde_json::Map::new()),
        };

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

        let (_, rule) = self.routes.match_rule(path, method);

        let scope_param = rule.scope_param.as_deref();

        // 0. Path-confusion guard: reject ambiguous paths before any work.
        if let Some(msg) = self.routes.ambiguous(path) {
            return self.bad_request(msg, scope_param);
        }

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
                            .challenges(Some(&InsufficientScope::default()), scope_param, None);
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
