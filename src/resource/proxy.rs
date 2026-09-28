//! [`ProxyHttp`] decorator for bearer token protection.
//!
//! [`AuthProxy`] binds one logical protected resource to one [`Guard`].
//! [`ResourceMetadataProxy`] independently publishes the RFC 9728 documents
//! returned by any number of those integrations at the server root.

use bytes::Bytes;
use pingora_error::{Error, Result};
use pingora_http::RequestHeader;
use pingora_proxy::{ProxyHttp, Session};
use pingora_proxy_delegate::proxy_http_delegate;

use crate::{
    resource::{
        ctx::HasAuthState,
        error_body::{ErrorBody, ErrorDetails},
        guard::{Guard, ResourceMetadataConfig},
        outcome::Outcome,
        response::{
            write_challenge_response, write_method_not_allowed, write_resource_metadata_response,
        },
        scopes::HasScopes,
    },
    resource_server::validator::{
        AccessTokenValidator,
        metadata::{ProvideValidatorMetadata, ValidatorMetadata},
    },
};

/// How an RFC 8707 resource identifier maps to access-token audience values.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AudienceBinding {
    /// The token's `aud` claim must contain the protected-resource identifier
    /// exactly as configured.
    ResourceIdentifier,
    /// The authorization server maps the resource identifier to one of these
    /// token audience values.
    Mapped(Vec<String>),
}

impl AudienceBinding {
    /// Declares audience values produced by an authorization server that maps
    /// the resource identifier to another URI or opaque identifier.
    pub fn mapped<I, T>(audiences: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        Self::Mapped(audiences.into_iter().map(Into::into).collect())
    }

    fn into_audiences(self, resource: &str) -> Vec<String> {
        match self {
            Self::ResourceIdentifier => vec![resource.to_owned()],
            Self::Mapped(audiences) => audiences,
        }
    }
}

struct ProtectedResourceBinding {
    resource_path: String,
    validator_metadata: ValidatorMetadata,
    audiences: Vec<String>,
}

/// One RFC 9728 metadata document ready to be published at its canonical URL.
///
/// Obtain this together with a configured [`AuthProxy`] from
/// [`AuthProxy::with_protected_resource`], then add it to the server-level
/// [`ResourceMetadataProxy`]. Keeping this value separate lets each resource server
/// use its own guard, validator, and public base mapping while one outer proxy
/// owns the shared well-known namespace.
#[derive(Clone)]
pub struct ResourceMetadataEndpoint {
    resource_uri: http::Uri,
    resource_origin: String,
    endpoint_uri: http::Uri,
    body: Bytes,
}

impl std::fmt::Debug for ResourceMetadataEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResourceMetadataEndpoint")
            .field("resource_uri", &self.resource_uri)
            .field("endpoint_uri", &self.endpoint_uri)
            .finish_non_exhaustive()
    }
}

impl ResourceMetadataEndpoint {
    /// Returns the protected-resource identifier derived from the configured
    /// public base URI and resource subpath.
    #[must_use]
    pub fn resource(&self) -> &http::Uri {
        &self.resource_uri
    }

    /// Returns the absolute canonical URL at which this document is published.
    #[must_use]
    pub fn uri(&self) -> &http::Uri {
        &self.endpoint_uri
    }

    fn path_and_query(&self) -> Option<&http::uri::PathAndQuery> {
        self.endpoint_uri.path_and_query()
    }

    fn matches(&self, uri: &http::Uri) -> bool {
        uri.path_and_query() == self.path_and_query()
    }
}

fn split_resource_metadata(
    config: ResourceMetadataConfig,
    audiences: Vec<String>,
) -> (ProtectedResourceBinding, ResourceMetadataEndpoint) {
    let ResourceMetadataConfig {
        resource_uri,
        resource_origin,
        resource_path,
        endpoint_uri,
        body,
        validator_metadata,
    } = config;
    (
        ProtectedResourceBinding {
            resource_path,
            validator_metadata,
            audiences,
        },
        ResourceMetadataEndpoint {
            resource_uri,
            resource_origin,
            endpoint_uri,
            body: Bytes::from(body),
        },
    )
}

/// A decorator that wraps a [`ProxyHttp`] implementation to add OAuth 2.0
/// token validation via a [`Guard`].
///
/// Build it with [`new`](Self::new), then optionally call
/// [`with_protected_resource`](Self::with_protected_resource) to bind the one
/// protected resource handled by this integration to RFC 9728 metadata and token
/// audiences. All `ProxyHttp` methods not involved in validation delegate to
/// the inner proxy.
///
/// The inner proxy's context type must implement [`HasAuthState<V::Claims>`].
/// Compose independently configured resource servers with a `ProxyHttp` router;
/// each routed [`AuthProxy`] then owns its inner proxy and request context.
///
/// # Example
///
/// ```
/// # use huskarl_pingora::resource::{AuthProxy, CaseSensitivity, DecodeDepth, GuardConfig, Guard, Rule};
/// # fn build<V, P>(my_proxy: P, validator: V)
/// # where
/// #     V: huskarl_pingora::resource_server::validator::AccessTokenValidator
/// #         + huskarl_pingora::resource_server::validator::metadata::ProvideValidatorMetadata,
/// # {
/// let guard = Guard::builder()
///     .validator(validator)
///     .base_uri("https://gateway.example".parse().expect("valid URI"))
///     .path_guard(GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne))
///     .subtree("/public", Rule::public()) // /public and everything under it
///     .build()
///     .expect("route");
/// let proxy = AuthProxy::new(my_proxy, guard);
/// // pass `proxy` to pingora — it implements ProxyHttp with the same CTX as my_proxy
/// # }
/// ```
///
/// The returned endpoint is ferried back to the server-level metadata
/// publisher:
///
/// ```
/// # use huskarl_pingora::resource::{AudienceBinding, AuthProxy, CaseSensitivity, DecodeDepth, GuardConfig, Guard, ResourceMetadataProxy};
/// # fn build<V, P>(my_proxy: P, validator: V) -> Result<(), huskarl_pingora::resource::ConfigError>
/// # where
/// #     V: huskarl_pingora::resource_server::validator::AccessTokenValidator
/// #         + huskarl_pingora::resource_server::validator::metadata::ProvideValidatorMetadata,
/// # {
/// let guard = Guard::builder()
///     .validator(validator)
///     .base_uri("https://gateway.example".parse().expect("valid URI"))
///     .path_guard(GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne))
///     .build()?;
/// let (proxy, metadata) = AuthProxy::new(my_proxy, guard)
///     .with_protected_resource(
///         "/mcp/github",
///         AudienceBinding::mapped(["api://github"]),
///     )?;
/// let proxy = ResourceMetadataProxy::new(proxy).publish(metadata)?;
/// # let _ = proxy;
/// # Ok(())
/// # }
/// ```
#[must_use]
pub struct AuthProxy<P, V, E = ()>
where
    V: AccessTokenValidator + ProvideValidatorMetadata,
{
    inner: P,
    guard: Guard<V>,
    protected_resource: Option<ProtectedResourceBinding>,
    error_body: E,
}

impl<P, V, E> std::fmt::Debug for AuthProxy<P, V, E>
where
    V: AccessTokenValidator + ProvideValidatorMetadata,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthProxy")
            .field("guard", &self.guard)
            .field(
                "protected_resource_path",
                &self
                    .protected_resource
                    .as_ref()
                    .map(|binding| binding.resource_path.as_str()),
            )
            .finish_non_exhaustive()
    }
}

impl<P, V> AuthProxy<P, V>
where
    V: AccessTokenValidator + ProvideValidatorMetadata,
{
    /// Creates a new `AuthProxy` wrapping the given proxy with the given guard.
    pub fn new(inner: P, guard: Guard<V>) -> Self {
        Self {
            inner,
            guard,
            protected_resource: None,
            error_body: (),
        }
    }
}

impl<P, V, E> AuthProxy<P, V, E>
where
    V: AccessTokenValidator + ProvideValidatorMetadata,
{
    /// Configures a custom rejection body, preserving protocol status and headers.
    ///
    /// Uses structured failure details for validation, audience, scope, custom
    /// checks, and path-policy denials. Defaults to an empty body. Metadata
    /// responses and browser-login pages use separate configuration.
    pub fn error_body<NewE: ErrorBody>(self, error_body: NewE) -> AuthProxy<P, V, NewE> {
        AuthProxy {
            inner: self.inner,
            guard: self.guard,
            protected_resource: self.protected_resource,
            error_body,
        }
    }

    /// Binds this auth integration to one RFC 9728 protected resource.
    ///
    /// Returns the configured auth proxy together with the endpoint that must
    /// be collected by a server-level [`ResourceMetadataProxy`]. The document
    /// describes this resource server's OAuth 2.0 capabilities (authorization
    /// servers, scopes, `DPoP` configuration, etc.).
    ///
    /// `resource_path` must begin with `/`. It is appended to the guard's
    /// trusted public `base_uri`, which is also used for `DPoP` request-URI
    /// reconstruction. For example, base URI
    /// `https://api.example.com/gateway` and resource path `/mcp/inventory`
    /// identify `https://api.example.com/gateway/mcp/inventory`; RFC 9728 then
    /// places its document at
    /// `/.well-known/oauth-protected-resource/gateway/mcp/inventory`.
    ///
    /// The audience relationship is deliberately explicit: RFC 8707 permits an
    /// authorization server to use the resource identifier itself or map it to
    /// another URI or opaque identifier. Use
    /// [`AudienceBinding::ResourceIdentifier`] for the standard exact mapping,
    /// or [`AudienceBinding::mapped`] for an authorization-server-specific
    /// mapping. This resource-level check happens before any additional
    /// audience constraints on the matched [`Rule`](super::Rule).
    ///
    /// The guard's `base_uri`/`strip_prefix` mapping reconstructs the public
    /// request path before checking whether a request belongs to this resource,
    /// using the same URL passed to the validator for `DPoP`. Descendant request
    /// URLs are endpoints of the same logical resource and share its audience
    /// and challenge metadata.
    ///
    /// If a request is outside this protected resource's path, this decorator
    /// delegates without invoking its guard and leaves credentials untouched.
    /// A server hosting several resources should normally prevent this case by
    /// selecting the matching [`AuthProxy`] in `early_request_filter`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`](crate::resource::error::ConfigError) if this
    /// integration is already bound, there are no accepted audiences, the
    /// public base URI is missing, the resource subpath or derived identifier
    /// is invalid, the validator advertises a different endpoint, or the
    /// metadata document cannot be serialized.
    pub fn with_protected_resource(
        mut self,
        resource_path: impl AsRef<str>,
        audience_binding: AudienceBinding,
    ) -> Result<(Self, ResourceMetadataEndpoint), crate::resource::error::ConfigError> {
        if self.protected_resource.is_some() {
            return Err(crate::resource::error::ConfigError::ProtectedResourceAlreadyConfigured);
        }
        let config = self
            .guard
            .build_resource_metadata_for_path(resource_path.as_ref())?;
        let resource = config.resource_uri.to_string();
        let audiences = audience_binding.into_audiences(&resource);
        if audiences.is_empty() {
            return Err(crate::resource::error::ConfigError::EmptyResourceAudiences { resource });
        }
        let (binding, endpoint) = split_resource_metadata(config, audiences);
        self.protected_resource = Some(binding);
        Ok((self, endpoint))
    }
}

fn resource_path_matches(resource_path: &str, request_path: &str) -> bool {
    if resource_path == "/" || resource_path == request_path {
        return true;
    }
    let Some(remainder) = request_path.strip_prefix(resource_path) else {
        return false;
    };
    resource_path.ends_with('/') || remainder.starts_with('/')
}

/// A server-level publisher for RFC 9728 protected-resource metadata.
///
/// [`publish`](Self::publish) every endpoint returned by
/// [`AuthProxy::with_protected_resource`]. Use the resulting proxy as the
/// explicit well-known branch of a server-level router. It owns only the shared
/// metadata namespace and does not perform access-token validation.
#[must_use]
pub struct ResourceMetadataProxy<P> {
    inner: P,
    endpoints: Vec<ResourceMetadataEndpoint>,
}

impl<P> ResourceMetadataProxy<P> {
    /// Wraps the proxy used when this branch receives a non-metadata request.
    pub fn new(inner: P) -> Self {
        Self {
            inner,
            endpoints: Vec::new(),
        }
    }

    /// Adds one protected resource's canonical metadata endpoint.
    ///
    /// Endpoint paths and queries are matched exactly. This permits resources
    /// on one origin that differ by path or by a query component while keeping
    /// their documents distinct.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`](crate::resource::ConfigError) if the endpoint
    /// belongs to a different public origin or its complete path-and-query is
    /// already published by this proxy.
    pub fn publish(
        mut self,
        endpoint: ResourceMetadataEndpoint,
    ) -> Result<Self, crate::resource::error::ConfigError> {
        if let Some(configured) = self.endpoints.first()
            && configured.resource_origin != endpoint.resource_origin
        {
            return Err(
                crate::resource::error::ConfigError::ResourceMetadataOriginMismatch {
                    endpoint: endpoint.endpoint_uri.to_string(),
                    expected_origin: configured.resource_origin.clone(),
                },
            );
        }
        if self
            .endpoints
            .iter()
            .any(|configured| configured.path_and_query() == endpoint.path_and_query())
        {
            return Err(
                crate::resource::error::ConfigError::DuplicateResourceMetadataEndpoint {
                    path_and_query: endpoint
                        .path_and_query()
                        .map_or_else(String::new, ToString::to_string),
                },
            );
        }
        self.endpoints.push(endpoint);
        Ok(self)
    }
}

impl<P> std::fmt::Debug for ResourceMetadataProxy<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResourceMetadataProxy")
            .field(
                "endpoints",
                &self
                    .endpoints
                    .iter()
                    .map(ResourceMetadataEndpoint::uri)
                    .collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

#[proxy_http_delegate(self.inner)]
impl<P> ProxyHttp for ResourceMetadataProxy<P>
where
    P: ProxyHttp + Send + Sync,
    P::CTX: Send + Sync,
{
    type CTX = P::CTX;

    async fn request_filter(&self, session: &mut Session, ctx: &mut P::CTX) -> Result<bool> {
        let request_uri = &session.req_header().uri;
        if let Some(endpoint) = self
            .endpoints
            .iter()
            .find(|endpoint| endpoint.matches(request_uri))
        {
            let method = &session.req_header().method;
            if method == http::Method::GET || method == http::Method::HEAD {
                let include_body = method == http::Method::GET;
                write_resource_metadata_response(session, &endpoint.body, include_body).await?;
            } else {
                write_method_not_allowed(session, "GET, HEAD").await?;
            }
            return Ok(true);
        }

        self.inner.request_filter(session, ctx).await
    }
}

#[proxy_http_delegate(self.inner)]
impl<P, V, E> ProxyHttp for AuthProxy<P, V, E>
where
    P: ProxyHttp + Send + Sync,
    P::CTX: HasAuthState<V::Claims> + Send + Sync,
    V: AccessTokenValidator + ProvideValidatorMetadata + Send + Sync,
    V::Claims: HasScopes + Send + Sync,
    E: ErrorBody,
{
    type CTX = P::CTX;

    async fn request_filter(&self, session: &mut Session, ctx: &mut P::CTX) -> Result<bool> {
        let request_uri = &session.req_header().uri;
        let effective_uri = self.guard.effective_request_uri(request_uri);
        let effective_path = effective_uri.as_ref().map(http::Uri::path);
        let binding = self.protected_resource.as_ref().filter(|binding| {
            effective_path.is_some_and(|path| resource_path_matches(&binding.resource_path, path))
        });

        // A resource-bound decorator owns exactly one subtree. A router should
        // normally select it only for that subtree; outside it, remain inert.
        if self.protected_resource.is_some() && binding.is_none() {
            ctx.set_strip_credentials(false);
            return self.inner.request_filter(session, ctx).await;
        }

        let outcome = if let Some(binding) = binding {
            self.guard
                .check_with_metadata(session, &binding.validator_metadata, &binding.audiences)
                .await
        } else {
            self.guard.check(session).await
        };

        match outcome {
            Outcome::Forward {
                token,
                dpop_nonce,
                strip_credentials,
            } => {
                *ctx.validated_token_mut() = token;
                *ctx.dpop_nonce_mut() = dpop_nonce;
                ctx.set_strip_credentials(strip_credentials);
            }
            Outcome::Deny {
                details,
                status,
                challenges,
                dpop_nonce,
                retry_after,
            } => {
                let body = self.error_body.error_body(&ErrorDetails {
                    status,
                    error_code: details.error_code,
                    error_description: details.error_description.as_deref(),
                    required_scopes: details.required_scopes.as_deref(),
                    challenges: &challenges,
                });
                write_challenge_response(
                    session,
                    status,
                    &challenges,
                    dpop_nonce.as_deref(),
                    retry_after,
                    &body,
                )
                .await?;
                return Ok(true);
            }
        }

        self.inner.request_filter(session, ctx).await
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut P::CTX,
    ) -> Result<()> {
        if ctx.strip_credentials() {
            upstream_request.remove_header(&http::header::AUTHORIZATION);
            upstream_request.remove_header(&http::header::HeaderName::from_static("dpop"));
        }

        self.inner
            .upstream_request_filter(session, upstream_request, ctx)
            .await
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut pingora_http::ResponseHeader,
        ctx: &mut P::CTX,
    ) -> Result<()> {
        self.inner
            .response_filter(session, upstream_response, ctx)
            .await?;

        // Insert DPoP-Nonce header if the guard produced one during request_filter.
        if let Some(nonce) = ctx.dpop_nonce_mut().take() {
            upstream_response
                .insert_header("DPoP-Nonce", &nonce)
                .map_err(|e| {
                    Error::because(
                        pingora_error::ErrorType::InternalError,
                        "failed to set DPoP-Nonce header",
                        e,
                    )
                })?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // Mock trait impls satisfy `async fn` signatures without awaiting.
    #![allow(clippy::unused_async_trait_impl)]

    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use pingora_core::upstreams::peer::HttpPeer;
    use pingora_proxy_router::{RouteSlot, Router, context_lens, route};

    use super::*;
    use crate::{
        resource::{
            ctx::{AuthCtx, HasAuthState},
            guard::Guard,
            rule::Rule,
            test_support::{
                MockClaims, MockError, make_session, make_session_with_headers,
                mock_validator_metadata,
            },
        },
        resource_server::validator::{
            AccessTokenValidator, ValidatedRequest, ValidationResult,
            metadata::{ProvideValidatorMetadata, ValidatorMetadata},
        },
    };

    // ── Mock types ────────────────────────────────────────────────────

    enum MockOutcome {
        Missing,
        Valid(MockClaims),
        ValidFor(MockClaims, Vec<String>),
        Invalid,
        Server,
    }

    struct MockValidator(MockOutcome);

    impl AccessTokenValidator for MockValidator {
        type Claims = MockClaims;
        type Error = MockError;

        fn validate_request<'a>(
            &'a self,
            _headers: &'a http::HeaderMap,
            _method: &'a http::Method,
            _uri: &'a http::Uri,
            _client_cert_der: Option<&'a [u8]>,
        ) -> crate::resource_server::core::platform::MaybeSendBoxFuture<
            'a,
            ValidationResult<MockClaims, MockError>,
        > {
            let outcome = match &self.0 {
                MockOutcome::Missing => Ok(None),
                MockOutcome::Valid(claims) => Ok(Some(ValidatedRequest {
                    iss: None,
                    sub: None,
                    aud: vec![],
                    jti: None,
                    iat: None,
                    exp: None,
                    cnf: None,
                    claims: claims.clone(),
                    introspection_jwt: None,
                })),
                MockOutcome::ValidFor(claims, audience) => Ok(Some(ValidatedRequest {
                    iss: None,
                    sub: None,
                    aud: audience.clone(),
                    jti: None,
                    iat: None,
                    exp: None,
                    cnf: None,
                    claims: claims.clone(),
                    introspection_jwt: None,
                })),
                MockOutcome::Invalid => Err(MockError::invalid_token()),
                MockOutcome::Server => Err(MockError(
                    crate::resource::test_support::MockErrorKind::ServerError,
                )),
            };
            Box::pin(async move {
                ValidationResult {
                    outcome,
                    dpop_nonce: matches!(self.0, MockOutcome::Server)
                        .then(|| "server-nonce".to_owned()),
                }
            })
        }
    }

    impl ProvideValidatorMetadata for MockValidator {
        fn validator_metadata(&self, resource: Option<&str>) -> ValidatorMetadata {
            mock_validator_metadata(resource)
        }
    }

    // ── Mock inner proxy ──────────────────────────────────────────────

    struct InnerProxy {
        request_filter_called: Mutex<bool>,
    }

    struct TestContext {
        auth: AuthCtx<(), MockClaims>,
        route: RouteSlot<Self>,
    }

    impl Default for TestContext {
        fn default() -> Self {
            Self {
                auth: AuthCtx::new(()),
                route: RouteSlot::new(),
            }
        }
    }

    impl HasAuthState<MockClaims> for TestContext {
        fn validated_token(&self) -> Option<&Arc<ValidatedRequest<MockClaims>>> {
            self.auth.validated_token()
        }

        fn validated_token_mut(&mut self) -> &mut Option<Arc<ValidatedRequest<MockClaims>>> {
            self.auth.validated_token_mut()
        }

        fn dpop_nonce_mut(&mut self) -> &mut Option<String> {
            self.auth.dpop_nonce_mut()
        }

        fn strip_credentials(&self) -> bool {
            self.auth.strip_credentials()
        }

        fn set_strip_credentials(&mut self, strip: bool) {
            self.auth.set_strip_credentials(strip);
        }
    }

    impl InnerProxy {
        fn new() -> Self {
            Self {
                request_filter_called: Mutex::new(false),
            }
        }
    }

    #[async_trait]
    impl ProxyHttp for InnerProxy {
        type CTX = TestContext;

        fn new_ctx(&self) -> Self::CTX {
            TestContext::default()
        }

        async fn upstream_peer(
            &self,
            _session: &mut Session,
            _ctx: &mut Self::CTX,
        ) -> Result<Box<HttpPeer>> {
            let peer = HttpPeer::new("127.0.0.1:3000", false, String::new());
            Ok(Box::new(peer))
        }

        async fn request_filter(
            &self,
            _session: &mut Session,
            _ctx: &mut Self::CTX,
        ) -> Result<bool> {
            *self.request_filter_called.lock().unwrap() = true;
            Ok(false)
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────

    fn build_auth_proxy(
        validator: MockValidator,
        routes: Vec<(&str, Rule<MockClaims>)>,
    ) -> AuthProxy<InnerProxy, MockValidator> {
        build_auth_proxy_with_base("https://api.example.com", validator, routes)
    }

    fn build_auth_proxy_with_base(
        base_uri: &str,
        validator: MockValidator,
        routes: Vec<(&str, Rule<MockClaims>)>,
    ) -> AuthProxy<InnerProxy, MockValidator> {
        let mut builder = Guard::builder()
            .validator(validator)
            .base_uri(base_uri.parse().unwrap())
            .path_guard(crate::resource::GuardConfig::new(
                crate::resource::CaseSensitivity::Sensitive,
                crate::resource::DecodeDepth::UpToOne,
            ));
        for (pattern, rule) in routes {
            builder = builder.route(pattern, rule);
        }
        let guard = builder.build().unwrap();
        AuthProxy::new(InnerProxy::new(), guard)
    }

    // ── Tests ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn valid_token_forwards_to_inner() {
        let claims = MockClaims { scopes: None };
        let proxy = build_auth_proxy(MockValidator(MockOutcome::Valid(claims)), vec![]);
        let (mut session, _client) = make_session("GET", "/api").await;
        let mut ctx = proxy.inner.new_ctx();

        let handled = proxy.request_filter(&mut session, &mut ctx).await.unwrap();

        assert!(!handled); // forwarded
        assert!(ctx.validated_token().is_some());
        assert!(*proxy.inner.request_filter_called.lock().unwrap());
    }

    #[tokio::test]
    async fn no_token_on_required_route_returns_401() {
        let proxy = build_auth_proxy(MockValidator(MockOutcome::Missing), vec![]);
        let (mut session, _client) = make_session("GET", "/api").await;
        let mut ctx = proxy.inner.new_ctx();

        let handled = proxy.request_filter(&mut session, &mut ctx).await.unwrap();

        assert!(handled); // denied
        let resp = session.response_written().unwrap();
        assert_eq!(resp.status.as_u16(), 401);
        assert!(ctx.validated_token().is_none());
        assert!(!*proxy.inner.request_filter_called.lock().unwrap());
    }

    #[tokio::test]
    async fn invalid_token_returns_error_response() {
        let proxy = build_auth_proxy(MockValidator(MockOutcome::Invalid), vec![]);
        let (mut session, _client) = make_session("GET", "/api").await;
        let mut ctx = proxy.inner.new_ctx();

        let handled = proxy.request_filter(&mut session, &mut ctx).await.unwrap();

        assert!(handled);
        let resp = session.response_written().unwrap();
        assert!(resp.status.as_u16() == 401 || resp.status.as_u16() == 403);
        assert!(!*proxy.inner.request_filter_called.lock().unwrap());
    }

    #[tokio::test]
    async fn public_route_forwards_without_token() {
        let proxy = build_auth_proxy(
            MockValidator(MockOutcome::Missing),
            vec![("/health", Rule::public())],
        );
        let (mut session, _client) = make_session("GET", "/health").await;
        let mut ctx = proxy.inner.new_ctx();

        let handled = proxy.request_filter(&mut session, &mut ctx).await.unwrap();

        assert!(!handled);
        assert!(ctx.validated_token().is_none());
        assert!(*proxy.inner.request_filter_called.lock().unwrap());
    }

    #[tokio::test]
    async fn metadata_endpoint_serves_json() {
        let (auth, metadata) = build_auth_proxy(MockValidator(MockOutcome::Missing), vec![])
            .with_protected_resource("/", AudienceBinding::ResourceIdentifier)
            .unwrap();
        let proxy = ResourceMetadataProxy::new(auth).publish(metadata).unwrap();
        let (mut session, _client) =
            make_session("GET", "/.well-known/oauth-protected-resource").await;
        let mut ctx = proxy.inner.inner.new_ctx();

        let handled = proxy.request_filter(&mut session, &mut ctx).await.unwrap();

        assert!(handled);
        let resp = session.response_written().unwrap();
        assert_eq!(resp.status.as_u16(), 200);
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "application/json"
        );
        assert!(!*proxy.inner.inner.request_filter_called.lock().unwrap());
    }

    #[tokio::test]
    async fn metadata_endpoint_preserves_a_resource_query() {
        let (auth, metadata) = build_auth_proxy(MockValidator(MockOutcome::Missing), vec![])
            .with_protected_resource("/tenant?version=1", AudienceBinding::ResourceIdentifier)
            .unwrap();
        let proxy = ResourceMetadataProxy::new(auth).publish(metadata).unwrap();
        let (mut session, _client) = make_session(
            "GET",
            "/.well-known/oauth-protected-resource/tenant?version=1",
        )
        .await;
        let mut ctx = proxy.inner.inner.new_ctx();

        let handled = proxy.request_filter(&mut session, &mut ctx).await.unwrap();

        assert!(handled);
        assert_eq!(session.response_written().unwrap().status.as_u16(), 200);

        let (mut protected, _client) = make_session("POST", "/tenant/items").await;
        let mut protected_ctx = proxy.inner.inner.new_ctx();
        let handled = proxy
            .request_filter(&mut protected, &mut protected_ctx)
            .await
            .unwrap();
        assert!(handled);
        assert!(
            protected
                .response_written()
                .unwrap()
                .headers
                .get_all(http::header::WWW_AUTHENTICATE)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .any(|challenge| challenge.contains(
                    "https://api.example.com/.well-known/oauth-protected-resource/tenant?version=1"
                ))
        );
    }

    #[tokio::test]
    async fn metadata_endpoint_post_returns_405() {
        let (auth, metadata) = build_auth_proxy(MockValidator(MockOutcome::Missing), vec![])
            .with_protected_resource("/", AudienceBinding::ResourceIdentifier)
            .unwrap();
        let proxy = ResourceMetadataProxy::new(auth).publish(metadata).unwrap();
        let (mut session, _client) =
            make_session("POST", "/.well-known/oauth-protected-resource").await;
        let mut ctx = proxy.inner.inner.new_ctx();

        let handled = proxy.request_filter(&mut session, &mut ctx).await.unwrap();

        assert!(handled);
        let resp = session.response_written().unwrap();
        assert_eq!(resp.status.as_u16(), 405);
        assert_eq!(resp.headers.get("allow").unwrap(), "GET, HEAD");
    }

    #[tokio::test]
    async fn metadata_publisher_collects_multiple_mcp_integrations() {
        let payments_guard = Guard::builder()
            .validator(MockValidator(MockOutcome::Missing))
            .base_uri("https://api.example.com".parse().unwrap())
            .path_guard(crate::resource::GuardConfig::new(
                crate::resource::CaseSensitivity::Sensitive,
                crate::resource::DecodeDepth::UpToOne,
            ))
            .build()
            .unwrap();
        let (_payments, payments_metadata) = AuthProxy::new(InnerProxy::new(), payments_guard)
            .with_protected_resource("/mcp/payments", AudienceBinding::ResourceIdentifier)
            .unwrap();
        let inventory_guard = Guard::builder()
            .validator(MockValidator(MockOutcome::Missing))
            .base_uri("https://api.example.com".parse().unwrap())
            .path_guard(crate::resource::GuardConfig::new(
                crate::resource::CaseSensitivity::Sensitive,
                crate::resource::DecodeDepth::UpToOne,
            ))
            .build()
            .unwrap();
        let (_inventory, inventory_metadata) = AuthProxy::new(InnerProxy::new(), inventory_guard)
            .with_protected_resource("/mcp/inventory", AudienceBinding::ResourceIdentifier)
            .unwrap();
        let proxy = ResourceMetadataProxy::new(InnerProxy::new())
            .publish(payments_metadata)
            .unwrap()
            .publish(inventory_metadata)
            .unwrap();

        for resource_path in ["payments", "inventory"] {
            let (mut session, _client) = make_session(
                "GET",
                &format!("/.well-known/oauth-protected-resource/mcp/{resource_path}"),
            )
            .await;
            let mut ctx = proxy.inner.new_ctx();

            let handled = proxy.request_filter(&mut session, &mut ctx).await.unwrap();

            assert!(handled);
            let response = session.response_written().unwrap();
            assert_eq!(response.status.as_u16(), 200);
        }
        assert_eq!(proxy.endpoints.len(), 2);
    }

    #[tokio::test]
    async fn router_hosts_two_resource_servers_and_their_metadata() {
        let inventory_guard = Guard::builder()
            .validator(MockValidator(MockOutcome::ValidFor(
                MockClaims { scopes: None },
                vec!["https://api.example.com/mcp/inventory".to_owned()],
            )))
            .base_uri("https://api.example.com".parse().unwrap())
            .path_guard(crate::resource::GuardConfig::new(
                crate::resource::CaseSensitivity::Sensitive,
                crate::resource::DecodeDepth::UpToOne,
            ))
            .default(Rule::required().strip_credentials(false))
            .build()
            .unwrap();
        let (inventory, inventory_metadata) = AuthProxy::new(InnerProxy::new(), inventory_guard)
            .with_protected_resource("/mcp/inventory", AudienceBinding::ResourceIdentifier)
            .unwrap();

        let payments_guard = Guard::builder()
            .validator(MockValidator(MockOutcome::Missing))
            .base_uri("https://api.example.com".parse().unwrap())
            .path_guard(crate::resource::GuardConfig::new(
                crate::resource::CaseSensitivity::Sensitive,
                crate::resource::DecodeDepth::UpToOne,
            ))
            .build()
            .unwrap();
        let (payments, payments_metadata) = AuthProxy::new(InnerProxy::new(), payments_guard)
            .with_protected_resource("/mcp/payments", AudienceBinding::ResourceIdentifier)
            .unwrap();

        let metadata = ResourceMetadataProxy::new(InnerProxy::new())
            .publish(inventory_metadata)
            .unwrap()
            .publish(payments_metadata)
            .unwrap();
        let metadata = route(metadata);
        let inventory = route(inventory);
        let payments = route(payments);
        let proxy = Router::new(
            move |session: &Session, _ctx: &TestContext| {
                let path = session.req_header().uri.path();
                let selected = if path.starts_with("/.well-known/oauth-protected-resource") {
                    Some(Arc::clone(&metadata))
                } else if resource_path_matches("/mcp/inventory", path) {
                    Some(Arc::clone(&inventory))
                } else if resource_path_matches("/mcp/payments", path) {
                    Some(Arc::clone(&payments))
                } else {
                    None
                };
                Ok(selected)
            },
            route(InnerProxy::new()),
            context_lens!(TestContext, ctx => ctx.route),
        );

        let (mut inventory_session, _client) = make_session_with_headers(
            "POST",
            "/mcp/inventory/tools",
            "Authorization: DPoP token\r\n",
        )
        .await;
        let mut inventory_ctx = proxy.new_ctx();
        proxy
            .early_request_filter(&mut inventory_session, &mut inventory_ctx)
            .await
            .unwrap();
        assert!(
            !proxy
                .request_filter(&mut inventory_session, &mut inventory_ctx)
                .await
                .unwrap()
        );
        let mut upstream = RequestHeader::build("POST", b"/mcp/inventory/tools", None).unwrap();
        upstream
            .insert_header("Authorization", "DPoP token")
            .unwrap();
        proxy
            .upstream_request_filter(&mut inventory_session, &mut upstream, &mut inventory_ctx)
            .await
            .unwrap();
        assert!(upstream.headers.get(http::header::AUTHORIZATION).is_some());

        let (mut payments_session, _client) = make_session("POST", "/mcp/payments/tools").await;
        let mut payments_ctx = proxy.new_ctx();
        proxy
            .early_request_filter(&mut payments_session, &mut payments_ctx)
            .await
            .unwrap();
        assert!(
            proxy
                .request_filter(&mut payments_session, &mut payments_ctx)
                .await
                .unwrap()
        );
        assert_eq!(
            payments_session.response_written().unwrap().status.as_u16(),
            401
        );

        for path in [
            "/.well-known/oauth-protected-resource/mcp/inventory",
            "/.well-known/oauth-protected-resource/mcp/payments",
        ] {
            let (mut metadata_session, _client) = make_session("GET", path).await;
            let mut metadata_ctx = proxy.new_ctx();
            proxy
                .early_request_filter(&mut metadata_session, &mut metadata_ctx)
                .await
                .unwrap();
            assert!(
                proxy
                    .request_filter(&mut metadata_session, &mut metadata_ctx)
                    .await
                    .unwrap()
            );
            assert_eq!(
                metadata_session.response_written().unwrap().status.as_u16(),
                200
            );
        }
    }

    #[tokio::test]
    async fn rewritten_resource_path_uses_the_dpop_url_mapping_for_selection() {
        let guard = Guard::builder()
            .validator(MockValidator(MockOutcome::Missing))
            .base_uri("https://api.example.com/gateway".parse().unwrap())
            .strip_prefix("/internal")
            .path_guard(crate::resource::GuardConfig::new(
                crate::resource::CaseSensitivity::Sensitive,
                crate::resource::DecodeDepth::UpToOne,
            ))
            .build()
            .unwrap();
        let (proxy, metadata) = AuthProxy::new(InnerProxy::new(), guard)
            .with_protected_resource("/mcp/inventory", AudienceBinding::ResourceIdentifier)
            .unwrap();

        assert_eq!(
            metadata.resource(),
            "https://api.example.com/gateway/mcp/inventory"
        );
        assert_eq!(
            metadata.uri(),
            "https://api.example.com/.well-known/oauth-protected-resource/gateway/mcp/inventory"
        );

        let (mut session, _client) = make_session("POST", "/internal/mcp/inventory/tools").await;
        let mut ctx = proxy.inner.new_ctx();
        let handled = proxy.request_filter(&mut session, &mut ctx).await.unwrap();

        assert!(handled);
        let response = session.response_written().unwrap();
        assert_eq!(response.status.as_u16(), 401);
        assert!(
            response
                .headers
                .get_all(http::header::WWW_AUTHENTICATE)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .any(|challenge| challenge.contains(
                    "https://api.example.com/.well-known/oauth-protected-resource/gateway/mcp/inventory"
                ))
        );

        // RFC 9728 puts this endpoint at the origin root. The server-level
        // publisher collects it independently from the MCP path mapping.
        let publisher = ResourceMetadataProxy::new(proxy).publish(metadata).unwrap();
        let (mut metadata_session, _client) = make_session(
            "GET",
            "/.well-known/oauth-protected-resource/gateway/mcp/inventory",
        )
        .await;
        let mut metadata_ctx = publisher.inner.inner.new_ctx();
        let metadata_handled = publisher
            .request_filter(&mut metadata_session, &mut metadata_ctx)
            .await
            .unwrap();
        assert!(metadata_handled);
        assert_eq!(
            metadata_session.response_written().unwrap().status.as_u16(),
            200
        );
    }

    #[tokio::test]
    async fn resource_binding_rejects_token_for_another_mcp_server() {
        let claims = MockClaims { scopes: None };
        let (proxy, _metadata) = build_auth_proxy(
            MockValidator(MockOutcome::ValidFor(
                claims,
                vec!["https://api.example.com/mcp/payments".to_owned()],
            )),
            vec![],
        )
        .with_protected_resource("/mcp/inventory", AudienceBinding::ResourceIdentifier)
        .unwrap();
        let (mut session, _client) = make_session("POST", "/mcp/inventory").await;
        let mut ctx = proxy.inner.new_ctx();

        let handled = proxy.request_filter(&mut session, &mut ctx).await.unwrap();

        assert!(handled);
        let response = session.response_written().unwrap();
        assert_eq!(response.status.as_u16(), 401);
        let challenges = response
            .headers
            .get_all(http::header::WWW_AUTHENTICATE)
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>();
        assert!(challenges.iter().any(|challenge| {
            challenge.contains("error=\"invalid_token\"")
                && challenge.contains(
                    "https://api.example.com/.well-known/oauth-protected-resource/mcp/inventory",
                )
        }));
        assert!(!*proxy.inner.request_filter_called.lock().unwrap());
    }

    #[tokio::test]
    async fn mapped_resource_audience_is_accepted() {
        let claims = MockClaims { scopes: None };
        let (proxy, _metadata) = build_auth_proxy(
            MockValidator(MockOutcome::ValidFor(
                claims,
                vec!["api://inventory".to_owned()],
            )),
            vec![],
        )
        .with_protected_resource(
            "/mcp/inventory",
            AudienceBinding::mapped(["api://inventory"]),
        )
        .unwrap();
        let (mut session, _client) = make_session("POST", "/mcp/inventory").await;
        let mut ctx = proxy.inner.new_ctx();

        let handled = proxy.request_filter(&mut session, &mut ctx).await.unwrap();

        assert!(!handled);
        assert!(ctx.validated_token().is_some());
        assert!(*proxy.inner.request_filter_called.lock().unwrap());
    }

    #[tokio::test]
    async fn resource_binding_applies_to_descendant_requests() {
        let claims = MockClaims { scopes: None };
        let (proxy, _metadata) = build_auth_proxy(
            MockValidator(MockOutcome::ValidFor(
                claims,
                vec!["https://api.example.com/mcp/github".to_owned()],
            )),
            vec![],
        )
        .with_protected_resource("/mcp/github", AudienceBinding::ResourceIdentifier)
        .unwrap();
        let (mut session, _client) = make_session("POST", "/mcp/github/tools").await;
        let mut ctx = proxy.inner.new_ctx();

        let handled = proxy.request_filter(&mut session, &mut ctx).await.unwrap();

        assert!(!handled);
        assert!(*proxy.inner.request_filter_called.lock().unwrap());
    }

    #[test]
    fn resource_binding_and_metadata_publisher_reject_ambiguous_configuration() {
        let (proxy, endpoint) = build_auth_proxy(MockValidator(MockOutcome::Missing), vec![])
            .with_protected_resource("/mcp?tenant=one", AudienceBinding::ResourceIdentifier)
            .unwrap();
        let duplicate_binding =
            proxy.with_protected_resource("/mcp?tenant=two", AudienceBinding::ResourceIdentifier);
        assert!(matches!(
            duplicate_binding,
            Err(crate::resource::ConfigError::ProtectedResourceAlreadyConfigured)
        ));

        let duplicate_endpoint = ResourceMetadataProxy::new(InnerProxy::new())
            .publish(endpoint.clone())
            .unwrap()
            .publish(endpoint.clone());
        assert!(matches!(
            duplicate_endpoint,
            Err(crate::resource::ConfigError::DuplicateResourceMetadataEndpoint { .. })
        ));

        let (_other_query, other_query_endpoint) =
            build_auth_proxy(MockValidator(MockOutcome::Missing), vec![])
                .with_protected_resource("/mcp?tenant=two", AudienceBinding::ResourceIdentifier)
                .unwrap();
        let query_distinguished = ResourceMetadataProxy::new(InnerProxy::new())
            .publish(endpoint)
            .unwrap()
            .publish(other_query_endpoint)
            .unwrap();
        assert_eq!(query_distinguished.endpoints.len(), 2);

        let empty = build_auth_proxy(MockValidator(MockOutcome::Missing), vec![])
            .with_protected_resource(
                "/mcp",
                AudienceBinding::mapped(std::iter::empty::<String>()),
            );
        assert!(matches!(
            empty,
            Err(crate::resource::ConfigError::EmptyResourceAudiences { .. })
        ));

        let (_one, one_endpoint) = build_auth_proxy(MockValidator(MockOutcome::Missing), vec![])
            .with_protected_resource("/mcp/one", AudienceBinding::ResourceIdentifier)
            .unwrap();
        let (_two, two_endpoint) = build_auth_proxy_with_base(
            "https://other.example.com",
            MockValidator(MockOutcome::Missing),
            vec![],
        )
        .with_protected_resource("/mcp/two", AudienceBinding::ResourceIdentifier)
        .unwrap();
        let different_origin = ResourceMetadataProxy::new(InnerProxy::new())
            .publish(one_endpoint)
            .unwrap()
            .publish(two_endpoint);
        assert!(matches!(
            different_origin,
            Err(crate::resource::ConfigError::ResourceMetadataOriginMismatch { .. })
        ));
    }

    #[test]
    fn protected_resource_requires_a_base_uri_and_relative_subpath() {
        let guard = Guard::builder()
            .validator(MockValidator(MockOutcome::Missing))
            .path_guard(crate::resource::GuardConfig::new(
                crate::resource::CaseSensitivity::Sensitive,
                crate::resource::DecodeDepth::UpToOne,
            ))
            .build()
            .unwrap();
        let missing_base = AuthProxy::new(InnerProxy::new(), guard)
            .with_protected_resource("/mcp", AudienceBinding::ResourceIdentifier);
        assert!(matches!(
            missing_base,
            Err(crate::resource::ConfigError::MissingBaseUri)
        ));

        for invalid in ["mcp", "https://api.example.com/mcp", "/mcp#fragment"] {
            let result = build_auth_proxy(MockValidator(MockOutcome::Missing), vec![])
                .with_protected_resource(invalid, AudienceBinding::ResourceIdentifier);
            assert!(matches!(
                result,
                Err(crate::resource::ConfigError::InvalidResourcePath { .. })
            ));
        }
    }

    #[tokio::test]
    async fn strip_credentials_removes_auth_headers() {
        let claims = MockClaims { scopes: None };
        let proxy = build_auth_proxy(MockValidator(MockOutcome::Valid(claims)), vec![]);
        let (mut session, _client) =
            make_session_with_headers("GET", "/api", "Authorization: Bearer tok123\r\n").await;
        let mut ctx = proxy.inner.new_ctx();

        proxy.request_filter(&mut session, &mut ctx).await.unwrap();
        assert!(ctx.strip_credentials()); // default is true

        let mut upstream_req = RequestHeader::build("GET", b"/api", None).unwrap();
        upstream_req
            .insert_header("Authorization", "Bearer tok123")
            .unwrap();
        upstream_req.insert_header("DPoP", "proof").unwrap();

        proxy
            .upstream_request_filter(&mut session, &mut upstream_req, &mut ctx)
            .await
            .unwrap();

        assert!(upstream_req.headers.get("authorization").is_none());
        assert!(upstream_req.headers.get("dpop").is_none());
    }

    #[tokio::test]
    async fn strip_credentials_false_preserves_headers() {
        let claims = MockClaims { scopes: None };
        let proxy = build_auth_proxy(
            MockValidator(MockOutcome::Valid(claims)),
            vec![("/api", Rule::required().strip_credentials(false))],
        );
        let (mut session, _client) = make_session("GET", "/api").await;
        let mut ctx = proxy.inner.new_ctx();

        proxy.request_filter(&mut session, &mut ctx).await.unwrap();
        assert!(!ctx.strip_credentials());

        let mut upstream_req = RequestHeader::build("GET", b"/api", None).unwrap();
        upstream_req
            .insert_header("Authorization", "Bearer tok123")
            .unwrap();

        proxy
            .upstream_request_filter(&mut session, &mut upstream_req, &mut ctx)
            .await
            .unwrap();

        assert!(upstream_req.headers.get("authorization").is_some());
    }

    #[tokio::test]
    async fn response_filter_inserts_dpop_nonce() {
        let claims = MockClaims { scopes: None };
        let proxy = build_auth_proxy(MockValidator(MockOutcome::Valid(claims)), vec![]);
        let (mut session, _client) = make_session("GET", "/api").await;
        let mut ctx = proxy.inner.new_ctx();

        // Simulate request_filter having set a dpop_nonce
        *ctx.dpop_nonce_mut() = Some("test-nonce".into());

        let mut resp = pingora_http::ResponseHeader::build(200, Some(1)).unwrap();

        proxy
            .response_filter(&mut session, &mut resp, &mut ctx)
            .await
            .unwrap();

        assert_eq!(resp.headers.get("dpop-nonce").unwrap(), "test-nonce");
        // Nonce should be consumed
        assert!(ctx.dpop_nonce_mut().is_none());
    }

    #[tokio::test]
    async fn response_filter_no_nonce_leaves_response_clean() {
        let claims = MockClaims { scopes: None };
        let proxy = build_auth_proxy(MockValidator(MockOutcome::Valid(claims)), vec![]);
        let (mut session, _client) = make_session("GET", "/api").await;
        let mut ctx = proxy.inner.new_ctx();

        let mut resp = pingora_http::ResponseHeader::build(200, Some(1)).unwrap();

        proxy
            .response_filter(&mut session, &mut resp, &mut ctx)
            .await
            .unwrap();

        assert!(resp.headers.get("dpop-nonce").is_none());
    }
    #[derive(Clone)]
    struct JsonErrors;

    impl crate::resource::ErrorBody for JsonErrors {
        fn error_body(
            &self,
            details: &crate::resource::ErrorDetails<'_>,
        ) -> crate::resource::ErrorBodyResponse {
            crate::resource::ErrorBodyResponse::new(
                serde_json::json!({
                    "status": details.status.as_u16(),
                    "error": details.error_code.map(|code| code.as_str()),
                    "description": details.error_description,
                    "scopes": details.required_scopes,
                    "challenges": details.challenges,
                })
                .to_string(),
                http::HeaderValue::from_static("application/json"),
            )
        }
    }

    #[tokio::test]
    async fn custom_body_uses_guard_details_and_preserves_resource_binding() {
        use tokio::io::AsyncReadExt as _;
        for (outcome, scopes, expected_status, expected_code) in [
            (MockOutcome::Missing, vec![], 401, None),
            (MockOutcome::Server, vec![], 503, None),
            (MockOutcome::Invalid, vec![], 401, Some("invalid_token")),
            (
                MockOutcome::ValidFor(MockClaims { scopes: None }, vec!["api".into()]),
                vec!["read"],
                403,
                Some("insufficient_scope"),
            ),
            (
                MockOutcome::ValidFor(MockClaims { scopes: None }, vec!["wrong".into()]),
                vec![],
                401,
                Some("invalid_token"),
            ),
        ] {
            let (proxy, metadata) = build_auth_proxy(
                MockValidator(outcome),
                vec![("/api", Rule::required().scopes(scopes))],
            )
            .error_body(JsonErrors)
            .with_protected_resource("/api", AudienceBinding::mapped(["api"]))
            .unwrap();
            // Reconfiguration after binding must preserve the binding as well.
            let proxy = proxy.error_body(JsonErrors);
            let (mut session, mut client) = make_session("GET", "/api").await;
            assert!(
                proxy
                    .request_filter(&mut session, &mut proxy.new_ctx())
                    .await
                    .unwrap()
            );
            let resp = session.response_written().unwrap();
            assert_eq!(resp.status.as_u16(), expected_status);
            assert_eq!(resp.headers["content-type"], "application/json");
            assert_eq!(resp.headers["cache-control"], "no-store");
            if expected_status == 503 {
                assert!(!resp.headers.contains_key("www-authenticate"));
                assert_eq!(resp.headers["retry-after"], "42");
                assert_eq!(resp.headers["dpop-nonce"], "server-nonce");
            } else {
                assert!(
                    resp.headers["www-authenticate"]
                        .to_str()
                        .unwrap()
                        .contains(metadata.uri().to_string().as_str())
                );
            }
            drop(session);
            let mut wire = String::new();
            client.read_to_string(&mut wire).await.unwrap();
            let (_, body) = wire.split_once("\r\n\r\n").unwrap();
            let json: serde_json::Value = serde_json::from_str(body).unwrap();
            assert_eq!(json["status"], expected_status);
            assert_eq!(json["error"], serde_json::json!(expected_code));
            if expected_status == 503 {
                assert!(json["description"].is_null());
                assert!(json["scopes"].is_null());
                assert_eq!(json["challenges"], serde_json::json!([]));
            }
            if expected_status == 403 {
                assert_eq!(json["scopes"], serde_json::json!(["read"]));
            }
        }
    }

    #[derive(Clone)]
    struct NeverRender;
    impl crate::resource::ErrorBody for NeverRender {
        fn error_body(
            &self,
            _: &crate::resource::ErrorDetails<'_>,
        ) -> crate::resource::ErrorBodyResponse {
            panic!("successful requests and metadata must not render errors")
        }
    }

    #[tokio::test]
    async fn custom_body_does_not_run_for_success_or_metadata() {
        let (proxy, metadata) = build_auth_proxy(
            MockValidator(MockOutcome::ValidFor(
                MockClaims { scopes: None },
                vec!["api".into()],
            )),
            vec![],
        )
        .error_body(NeverRender)
        .with_protected_resource("/api", AudienceBinding::mapped(["api"]))
        .unwrap();
        let (mut session, _client) = make_session("GET", "/api").await;
        assert!(
            !proxy
                .request_filter(&mut session, &mut proxy.new_ctx())
                .await
                .unwrap()
        );
        let path = metadata.uri().path().to_owned();
        let publisher = ResourceMetadataProxy::new(proxy).publish(metadata).unwrap();
        let (mut session, _client) = make_session("GET", &path).await;
        assert!(
            publisher
                .request_filter(&mut session, &mut publisher.new_ctx())
                .await
                .unwrap()
        );
        assert_eq!(session.response_written().unwrap().status.as_u16(), 200);
    }
}
