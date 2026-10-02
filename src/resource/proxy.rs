//! [`ProxyHttp`] decorator for bearer token protection.
//!
//! [`ProtectedResourceProxy`] binds one logical protected resource to one [`Guard`].
//! [`ResourceMetadataProxy`] independently publishes the RFC 9728 documents
//! returned by any number of those integrations at the server root.

use bytes::Bytes;
pub use huskarl_resource_server::resource::AudienceBinding;
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
    resource_server::validator::{AccessTokenValidator, metadata::ProvideValidatorMetadata},
};

struct ProtectedResourceBinding {
    resource_path: String,
    audiences: Vec<String>,
}

/// One RFC 9728 metadata document ready to be published at its canonical URL.
///
/// Obtain this together with a configured [`ProtectedResourceProxy`] from
/// [`super::BoundResource::into_parts`], then add it to the server-level
/// [`ResourceMetadataProxy`]. Keeping this value separate lets each resource server
/// use its own guard, validator, and public base mapping. An external publisher
/// can consume [`publication`](Self::publication) without mounting a local proxy.
#[derive(Clone)]
pub struct ResourceMetadataEndpoint {
    resource_uri: http::Uri,
    resource_origin: String,
    endpoint_uri: http::Uri,
    incoming_uri: http::Uri,
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

    /// Exports the same prepared bytes used by this handler, without mounting it.
    /// The consumer owns routing, refresh, and HTTP serving policy.
    #[must_use]
    pub fn publication(&self) -> huskarl_resource_server::resource::ResourcePublication<'_> {
        huskarl_resource_server::resource::ResourcePublication {
            uri: &self.endpoint_uri,
            body: &self.body,
        }
    }

    /// Returns the absolute canonical URL at which this document is published.
    #[must_use]
    pub fn uri(&self) -> &http::Uri {
        &self.endpoint_uri
    }

    fn path_and_query(&self) -> Option<&http::uri::PathAndQuery> {
        self.incoming_uri.path_and_query()
    }

    /// Maps the canonical public endpoint into incoming request coordinates.
    /// The advertised URL and prepared document remain unchanged.
    ///
    /// # Errors
    /// Rejects mappings that cannot represent the canonical endpoint exactly.
    pub fn with_mapping(
        mut self,
        mapping: &huskarl_resource_server::core::url_mapping::PublicUrlMapping,
    ) -> std::result::Result<Self, huskarl_resource_server::core::url_mapping::MappingError> {
        self.incoming_uri = mapping.incoming_uri(&self.endpoint_uri)?;
        Ok(self)
    }
    /// Incoming dispatch URI; matching includes its path and query.
    #[must_use]
    pub fn incoming_uri(&self) -> &http::Uri {
        &self.incoming_uri
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
    } = config;
    (
        ProtectedResourceBinding {
            resource_path,
            audiences,
        },
        ResourceMetadataEndpoint {
            resource_uri,
            resource_origin,
            incoming_uri: endpoint_uri.clone(),
            endpoint_uri,
            body: Bytes::from(body),
        },
    )
}

/// Standalone token authentication without a protected-resource definition.
///
/// Wrap an executable [`Guard`] with [`new`](Self::new). All `ProxyHttp` methods
/// not involved in validation delegate to the inner proxy. Its context must
/// implement [`HasAuthState<V::Claims>`].
///
/// For resource identity, audience binding and discovery metadata, construct
/// [`super::BoundResource`] instead. That produces a [`ProtectedResourceProxy`]
/// together with its matching publication contribution.
///
/// # Example
///
/// ```
/// use huskarl_pingora::resource::{
///     AuthProxy, CaseSensitivity, DecodeDepth, Guard, GuardConfig, ResourcePolicy, Rule,
/// };
/// # fn build<V, P>(inner: P, validator: V)
/// # where V: huskarl_pingora::resource_server::validator::AccessTokenValidator
/// #     + huskarl_pingora::resource_server::validator::metadata::ProvideValidatorMetadata {
/// let policy = ResourcePolicy::builder()
///     .path_guard(GuardConfig::new(
///         CaseSensitivity::Sensitive,
///         DecodeDepth::UpToOne,
///     ))
///     .subtree("/public", Rule::public())
///     .build()
///     .expect("valid policy");
/// let guard = Guard::builder().validator(validator).policy(policy).build();
/// let proxy = AuthProxy::new(inner, guard);
/// # }
/// ```
#[must_use]
pub struct AuthProxy<P, V, E = ()>
where
    V: AccessTokenValidator + ProvideValidatorMetadata,
{
    inner: P,
    guard: Guard<V>,
    error_body: E,
}

impl<P, V, E> std::fmt::Debug for AuthProxy<P, V, E>
where
    V: AccessTokenValidator + ProvideValidatorMetadata,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthProxy")
            .field("guard", &self.guard)
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
            error_body,
        }
    }
}

/// An authenticated proxy bound to exactly one resource definition.
///
/// Construct through [`super::BoundResource::builder`]. Its mandatory binding fixes
/// the accepted audiences and public resource boundary. It cannot be rebound.
/// The bundle carries the matching metadata to the server's publication boundary.
pub struct ProtectedResourceProxy<P, V, E = ()>
where
    V: AccessTokenValidator + ProvideValidatorMetadata,
{
    auth: AuthProxy<P, V, E>,
    binding: ProtectedResourceBinding,
}

impl<P, V> ProtectedResourceProxy<P, V>
where
    V: AccessTokenValidator + ProvideValidatorMetadata,
{
    pub(crate) fn new(
        definition: &crate::resource_server::resource::ResourceDefinition,
        validator: V,
        policy: crate::resource::ResourcePolicy<V::Claims>,
        inner: P,
    ) -> Result<(Self, ResourceMetadataEndpoint), crate::resource::ConfigError> {
        let (guard, config) = Guard::for_resource(validator, policy, definition)?;
        let (binding, endpoint) = split_resource_metadata(config, definition.audiences().to_vec());
        Ok((
            Self {
                auth: AuthProxy::new(inner, guard),
                binding,
            },
            endpoint,
        ))
    }
}

impl<P, V, E> ProtectedResourceProxy<P, V, E>
where
    V: AccessTokenValidator + ProvideValidatorMetadata,
{
    /// Configures rejection bodies without changing the resource binding.
    pub fn error_body<NewE: ErrorBody>(
        self,
        error_body: NewE,
    ) -> ProtectedResourceProxy<P, V, NewE> {
        ProtectedResourceProxy {
            auth: self.auth.error_body(error_body),
            binding: self.binding,
        }
    }
}

impl<P, V, E> std::fmt::Debug for ProtectedResourceProxy<P, V, E>
where
    V: AccessTokenValidator + ProvideValidatorMetadata,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtectedResourceProxy")
            .field("auth", &self.auth)
            .field("resource_path", &self.binding.resource_path)
            .finish_non_exhaustive()
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
/// [`super::BoundResource::into_parts`]. Use the resulting proxy as the
/// explicit metadata branch of a server-level router. It matches only registered
/// endpoints and delegates misses to its inner proxy. It does not perform
/// access-token validation or claim other well-known protocols.
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
        self.authorize(session, ctx, None).await
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

        // Preserve the nonce through interim headers; a 101 upgrade is terminal.
        if upstream_response.status.is_informational()
            && upstream_response.status != http::StatusCode::SWITCHING_PROTOCOLS
        {
            return Ok(());
        }

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

impl<P, V, E> AuthProxy<P, V, E>
where
    P: ProxyHttp + Send + Sync,
    P::CTX: HasAuthState<V::Claims> + Send + Sync,
    V: AccessTokenValidator + ProvideValidatorMetadata + Send + Sync,
    V::Claims: HasScopes + Send + Sync,
    E: ErrorBody,
{
    async fn authorize(
        &self,
        session: &mut Session,
        ctx: &mut P::CTX,
        audiences: Option<&[String]>,
    ) -> Result<bool> {
        let (outcome, category) = self.guard.check_for_proxy(session, audiences).await;
        crate::metrics::emit_counter(
            "huskarl.pingora.resource.authorization",
            category.as_str(),
            self.guard.metrics_name(),
        );

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
                write_challenge_response()
                    .session(session)
                    .status(status)
                    .challenges(&challenges)
                    .maybe_dpop_nonce(dpop_nonce.as_deref())
                    .maybe_retry_after(retry_after)
                    .body(&body)
                    .call()
                    .await?;
                return Ok(true);
            }
        }

        self.inner.request_filter(session, ctx).await
    }
}

#[proxy_http_delegate(self.auth)]
impl<P, V, E> ProxyHttp for ProtectedResourceProxy<P, V, E>
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
        let effective_uri = self.auth.guard.effective_request_uri(request_uri);
        let effective_path = effective_uri.as_ref().map(http::Uri::path);
        // Fail closed if the server selected the wrong resource or reconstruction fails.
        if !effective_path
            .is_some_and(|path| resource_path_matches(&self.binding.resource_path, path))
        {
            crate::metrics::emit_counter(
                "huskarl.pingora.resource.authorization",
                if effective_uri.is_none() {
                    "invalid_request"
                } else {
                    "outside_resource"
                },
                self.auth.guard.metrics_name(),
            );
            let (status, description) = if effective_uri.is_none() {
                (http::StatusCode::BAD_REQUEST, "Invalid request URI")
            } else {
                (
                    http::StatusCode::FORBIDDEN,
                    "Request outside protected resource",
                )
            };
            let body = self.auth.error_body.error_body(&ErrorDetails {
                status,
                error_code: None,
                error_description: Some(description),
                required_scopes: None,
                challenges: &[],
            });
            write_challenge_response()
                .session(session)
                .status(status)
                .challenges(&[])
                .body(&body)
                .call()
                .await?;
            return Ok(true);
        }

        self.auth
            .authorize(session, ctx, Some(&self.binding.audiences))
            .await
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

    impl<P, V, E> AuthProxy<P, V, E>
    where
        V: AccessTokenValidator + ProvideValidatorMetadata,
        E: ErrorBody,
    {
        fn bind_for_test(
            self,
            subpath: &str,
            audience: AudienceBinding,
        ) -> Result<
            (ProtectedResourceProxy<P, V, E>, ResourceMetadataEndpoint),
            crate::resource::ConfigError,
        > {
            let (validator, policy, mapping) = self.guard.into_test_parts();
            let definition = crate::resource_server::resource::ResourceDefinition::new(
                mapping.unwrap(),
                subpath,
                audience,
            )
            .unwrap();
            let bound = crate::resource::BoundResource::builder()
                .definition(definition)
                .validator(validator)
                .policy(policy)
                .inner(self.inner)
                .build()?
                .error_body(self.error_body);
            let (_, proxy, endpoint) = bound.into_parts();
            Ok((proxy, endpoint))
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
        let mut builder = crate::resource::ResourcePolicy::builder().path_guard(
            crate::resource::GuardConfig::new(
                crate::resource::CaseSensitivity::Sensitive,
                crate::resource::DecodeDepth::UpToOne,
            ),
        );
        for (pattern, rule) in routes {
            builder = builder.route(pattern, rule);
        }
        let guard = Guard::builder()
            .validator(validator)
            .policy(builder.build().unwrap())
            .url_mapping(
                crate::resource_server::core::url_mapping::PublicUrlMapping::new(base_uri, "/")
                    .unwrap(),
            )
            .build();
        AuthProxy::new(InnerProxy::new(), guard)
    }

    // ── Tests ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn valid_token_forwards_to_inner() {
        let claims = MockClaims { scopes: None };
        let proxy = build_auth_proxy(MockValidator(MockOutcome::Valid(claims)), vec![]);
        let (mut session, _client) = make_session("GET", "/api").await;
        let mut ctx = proxy.new_ctx();

        let handled = proxy.request_filter(&mut session, &mut ctx).await.unwrap();

        assert!(!handled); // forwarded
        assert!(ctx.validated_token().is_some());
        assert!(*proxy.inner.request_filter_called.lock().unwrap());
    }

    #[tokio::test]
    async fn no_token_on_required_route_returns_401() {
        let proxy = build_auth_proxy(MockValidator(MockOutcome::Missing), vec![]);
        let (mut session, _client) = make_session("GET", "/api").await;
        let mut ctx = proxy.new_ctx();

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
        let mut ctx = proxy.new_ctx();

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
        let mut ctx = proxy.new_ctx();

        let handled = proxy.request_filter(&mut session, &mut ctx).await.unwrap();

        assert!(!handled);
        assert!(ctx.validated_token().is_none());
        assert!(*proxy.inner.request_filter_called.lock().unwrap());
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)] // End-to-end publication and authentication contract.
    async fn publication_export_and_mapped_handler_share_bound_metadata() {
        use huskarl_resource_server::core::url_mapping::PublicUrlMapping;
        use tokio::io::AsyncReadExt;

        let definition = crate::resource_server::resource::ResourceDefinition::builder()
            .mapping(PublicUrlMapping::new("https://api.example.com", "/").unwrap())
            .subpath("/app?tenant=one")
            .audience(AudienceBinding::ResourceIdentifier)
            .resource_name("Published API")
            .resource_documentation("https://api.example.com/docs")
            .scopes_supported(vec!["owner.read".into()])
            .build()
            .unwrap();
        let validator = MockValidator(MockOutcome::Missing);
        let resource_policy = crate::resource::ResourcePolicy::builder()
            .path_guard(crate::resource::GuardConfig::new(
                crate::resource::CaseSensitivity::Sensitive,
                crate::resource::DecodeDepth::UpToOne,
            ))
            .subtree("/app", Rule::required().scopes(["guard.read"]))
            .build()
            .unwrap();
        let bound = crate::resource::BoundResource::builder()
            .definition(definition)
            .validator(validator)
            .policy(resource_policy)
            .inner(InnerProxy::new())
            .build()
            .unwrap();
        let (_, auth, metadata) = bound.into_parts();
        let canonical = metadata.publication().uri.clone();
        let exported = metadata.publication().body.to_vec();
        let json: serde_json::Value = serde_json::from_slice(&exported).unwrap();
        assert_eq!(json["resource"], metadata.resource().to_string());
        assert_eq!(json["resource_name"], "Published API");
        assert_eq!(
            json["resource_documentation"],
            "https://api.example.com/docs"
        );
        assert_eq!(json["scopes_supported"], serde_json::json!(["owner.read"]));
        let (mut session, _client) = make_session("GET", "/app").await;
        assert!(
            auth.request_filter(&mut session, &mut auth.new_ctx())
                .await
                .unwrap()
        );
        let response = session.response_written().unwrap();
        assert_eq!(response.status.as_u16(), 401);
        let challenge = response.headers["www-authenticate"].to_str().unwrap();
        assert!(challenge.contains("guard.read"));
        assert!(!challenge.contains("owner.read"));

        let wrong = PublicUrlMapping::new("https://other.example", "/").unwrap();
        assert!(metadata.clone().with_mapping(&wrong).is_err());
        let mapping =
            PublicUrlMapping::new("https://api.example.com/.well-known", "/discovery").unwrap();
        let metadata = metadata.with_mapping(&mapping).unwrap();
        assert_eq!(metadata.uri(), &canonical);
        assert_eq!(metadata.publication().body, exported);
        let incoming = metadata
            .incoming_uri()
            .path_and_query()
            .unwrap()
            .to_string();
        assert_eq!(
            incoming,
            "/discovery/oauth-protected-resource/app?tenant=one"
        );

        // Binding alone does not install a local publication endpoint.
        let (mut session, _client) = make_session("GET", canonical.path()).await;
        let _ = auth
            .request_filter(&mut session, &mut auth.new_ctx())
            .await
            .unwrap();
        assert_ne!(
            session.response_written().map(|h| h.status.as_u16()),
            Some(200)
        );

        let publisher = ResourceMetadataProxy::new(InnerProxy::new())
            .publish(metadata)
            .unwrap();
        for (method, status) in [("GET", 200), ("HEAD", 200), ("POST", 405)] {
            let (mut session, mut client) = make_session(method, &incoming).await;
            let mut ctx = publisher.inner.new_ctx();
            assert!(
                publisher
                    .request_filter(&mut session, &mut ctx)
                    .await
                    .unwrap()
            );
            assert_eq!(session.response_written().unwrap().status.as_u16(), status);
            if status == 200 {
                assert_eq!(
                    session.response_written().unwrap().headers["content-type"],
                    "application/json"
                );
            }
            drop(session);
            let mut wire = Vec::new();
            client.read_to_end(&mut wire).await.unwrap();
            let boundary = wire.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
            assert_eq!(
                &wire[boundary..],
                if method == "GET" {
                    exported.as_slice()
                } else {
                    &[]
                }
            );
        }
        assert!(!*publisher.inner.request_filter_called.lock().unwrap());
    }

    #[tokio::test]
    async fn metadata_endpoint_serves_json() {
        let (auth, metadata) = build_auth_proxy(MockValidator(MockOutcome::Missing), vec![])
            .bind_for_test("/", AudienceBinding::ResourceIdentifier)
            .unwrap();
        let proxy = ResourceMetadataProxy::new(auth).publish(metadata).unwrap();
        let (mut session, _client) =
            make_session("GET", "/.well-known/oauth-protected-resource").await;
        let mut ctx = proxy.new_ctx();

        let handled = proxy.request_filter(&mut session, &mut ctx).await.unwrap();

        assert!(handled);
        let resp = session.response_written().unwrap();
        assert_eq!(resp.status.as_u16(), 200);
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "application/json"
        );
        assert!(!*proxy.inner.auth.inner.request_filter_called.lock().unwrap());
    }

    #[tokio::test]
    async fn metadata_endpoint_preserves_a_resource_query() {
        let (auth, metadata) = build_auth_proxy(MockValidator(MockOutcome::Missing), vec![])
            .bind_for_test("/tenant?version=1", AudienceBinding::ResourceIdentifier)
            .unwrap();
        let proxy = ResourceMetadataProxy::new(auth).publish(metadata).unwrap();
        let (mut session, _client) = make_session(
            "GET",
            "/.well-known/oauth-protected-resource/tenant?version=1",
        )
        .await;
        let mut ctx = proxy.new_ctx();

        let handled = proxy.request_filter(&mut session, &mut ctx).await.unwrap();

        assert!(handled);
        assert_eq!(session.response_written().unwrap().status.as_u16(), 200);

        let (mut protected, _client) = make_session("POST", "/tenant/items").await;
        let mut protected_ctx = proxy.new_ctx();
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
            .bind_for_test("/", AudienceBinding::ResourceIdentifier)
            .unwrap();
        let proxy = ResourceMetadataProxy::new(auth).publish(metadata).unwrap();
        let (mut session, _client) =
            make_session("POST", "/.well-known/oauth-protected-resource").await;
        let mut ctx = proxy.new_ctx();

        let handled = proxy.request_filter(&mut session, &mut ctx).await.unwrap();

        assert!(handled);
        let resp = session.response_written().unwrap();
        assert_eq!(resp.status.as_u16(), 405);
        assert_eq!(resp.headers.get("allow").unwrap(), "GET, HEAD");
    }

    #[tokio::test]
    async fn metadata_publisher_collects_multiple_mcp_integrations() {
        let payments_guard = crate::resource::ResourcePolicy::builder()
            .path_guard(crate::resource::GuardConfig::new(
                crate::resource::CaseSensitivity::Sensitive,
                crate::resource::DecodeDepth::UpToOne,
            ))
            .build()
            .map(|policy| {
                Guard::builder()
                    .validator(MockValidator(MockOutcome::Missing))
                    .policy(policy)
                    .url_mapping(
                        crate::resource_server::core::url_mapping::PublicUrlMapping::new(
                            "https://api.example.com",
                            "/",
                        )
                        .unwrap(),
                    )
                    .build()
            })
            .unwrap();
        let (_payments, payments_metadata) = AuthProxy::new(InnerProxy::new(), payments_guard)
            .bind_for_test("/mcp/payments", AudienceBinding::ResourceIdentifier)
            .unwrap();
        let inventory_guard = crate::resource::ResourcePolicy::builder()
            .path_guard(crate::resource::GuardConfig::new(
                crate::resource::CaseSensitivity::Sensitive,
                crate::resource::DecodeDepth::UpToOne,
            ))
            .build()
            .map(|policy| {
                Guard::builder()
                    .validator(MockValidator(MockOutcome::Missing))
                    .policy(policy)
                    .url_mapping(
                        crate::resource_server::core::url_mapping::PublicUrlMapping::new(
                            "https://api.example.com",
                            "/",
                        )
                        .unwrap(),
                    )
                    .build()
            })
            .unwrap();
        let (_inventory, inventory_metadata) = AuthProxy::new(InnerProxy::new(), inventory_guard)
            .bind_for_test("/mcp/inventory", AudienceBinding::ResourceIdentifier)
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
            let mut ctx = proxy.new_ctx();

            let handled = proxy.request_filter(&mut session, &mut ctx).await.unwrap();

            assert!(handled);
            let response = session.response_written().unwrap();
            assert_eq!(response.status.as_u16(), 200);
        }
        assert_eq!(proxy.endpoints.len(), 2);
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "keeps the multi-resource routing scenario together"
    )]
    async fn router_hosts_two_resource_servers_and_their_metadata() {
        let inventory_guard = crate::resource::ResourcePolicy::builder()
            .path_guard(crate::resource::GuardConfig::new(
                crate::resource::CaseSensitivity::Sensitive,
                crate::resource::DecodeDepth::UpToOne,
            ))
            .default(Rule::required().strip_credentials(false))
            .build()
            .map(|policy| {
                Guard::builder()
                    .validator(MockValidator(MockOutcome::ValidFor(
                        MockClaims { scopes: None },
                        vec!["https://api.example.com/mcp/inventory".to_owned()],
                    )))
                    .policy(policy)
                    .url_mapping(
                        crate::resource_server::core::url_mapping::PublicUrlMapping::new(
                            "https://api.example.com",
                            "/",
                        )
                        .unwrap(),
                    )
                    .build()
            })
            .unwrap();
        let (inventory, inventory_metadata) = AuthProxy::new(InnerProxy::new(), inventory_guard)
            .bind_for_test("/mcp/inventory", AudienceBinding::ResourceIdentifier)
            .unwrap();

        let payments_guard = crate::resource::ResourcePolicy::builder()
            .path_guard(crate::resource::GuardConfig::new(
                crate::resource::CaseSensitivity::Sensitive,
                crate::resource::DecodeDepth::UpToOne,
            ))
            .build()
            .map(|policy| {
                Guard::builder()
                    .validator(MockValidator(MockOutcome::Missing))
                    .policy(policy)
                    .url_mapping(
                        crate::resource_server::core::url_mapping::PublicUrlMapping::new(
                            "https://api.example.com",
                            "/",
                        )
                        .unwrap(),
                    )
                    .build()
            })
            .unwrap();
        let (payments, payments_metadata) = AuthProxy::new(InnerProxy::new(), payments_guard)
            .bind_for_test("/mcp/payments", AudienceBinding::ResourceIdentifier)
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
    async fn exact_mapping_keeps_bare_prefix_distinct_from_root_resource() {
        use crate::resource_server::{
            core::url_mapping::PublicUrlMapping, resource::ResourceDefinition,
        };
        let definition = ResourceDefinition::new(
            PublicUrlMapping::new("https://api.example.com/v1", "/proxy").unwrap(),
            "/",
            AudienceBinding::ResourceIdentifier,
        )
        .unwrap();
        let policy = crate::resource::ResourcePolicy::builder()
            .path_guard(crate::resource::GuardConfig::new(
                crate::resource::CaseSensitivity::Sensitive,
                crate::resource::DecodeDepth::UpToOne,
            ))
            .build()
            .unwrap();
        let bound = crate::resource::BoundResource::builder()
            .definition(definition.clone())
            .validator(MockValidator(MockOutcome::ValidFor(
                MockClaims { scopes: None },
                definition.audiences().to_vec(),
            )))
            .policy(policy)
            .inner(InnerProxy::new())
            .build()
            .unwrap();
        let (_, proxy, _) = bound.into_parts();
        for (path, allowed) in [
            ("/proxy", false),
            ("/proxy?q=a%20b", false),
            ("/proxy/", true),
            ("/proxy/?q=a%20b", true),
        ] {
            let (mut session, _client) = make_session("GET", path).await;
            let mut ctx = proxy.new_ctx();
            assert_eq!(
                proxy.request_filter(&mut session, &mut ctx).await.unwrap(),
                !allowed,
                "{path}"
            );
            if !allowed {
                assert_eq!(session.response_written().unwrap().status.as_u16(), 403);
            }
        }
    }

    #[tokio::test]
    async fn rewritten_resource_path_uses_the_dpop_url_mapping_for_selection() {
        let guard = crate::resource::ResourcePolicy::builder()
            .path_guard(crate::resource::GuardConfig::new(
                crate::resource::CaseSensitivity::Sensitive,
                crate::resource::DecodeDepth::UpToOne,
            ))
            .build()
            .map(|policy| {
                Guard::builder()
                    .validator(MockValidator(MockOutcome::Missing))
                    .policy(policy)
                    .url_mapping(
                        crate::resource_server::core::url_mapping::PublicUrlMapping::new(
                            "https://api.example.com/gateway",
                            "/internal",
                        )
                        .unwrap(),
                    )
                    .build()
            })
            .unwrap();
        let (proxy, metadata) = AuthProxy::new(InnerProxy::new(), guard)
            .bind_for_test("/mcp/inventory", AudienceBinding::ResourceIdentifier)
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
        let mut ctx = proxy.new_ctx();
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
        let mut metadata_ctx = publisher.new_ctx();
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
    async fn resource_binding_denies_out_of_scope_requests() {
        for path in ["/health", "/mcp/payments", "/mcp/inventory-other"] {
            let (proxy, _metadata) = build_auth_proxy(
                MockValidator(MockOutcome::ValidFor(
                    MockClaims { scopes: None },
                    vec!["https://api.example.com/mcp/inventory".to_owned()],
                )),
                vec![("/health", Rule::public())],
            )
            .bind_for_test("/mcp/inventory", AudienceBinding::ResourceIdentifier)
            .unwrap();
            let (mut session, _client) = make_session("GET", path).await;
            session
                .req_header_mut()
                .insert_header("Authorization", "Bearer secret")
                .unwrap();
            session
                .req_header_mut()
                .insert_header("DPoP", "proof")
                .unwrap();
            let mut ctx = proxy.new_ctx();

            assert!(proxy.request_filter(&mut session, &mut ctx).await.unwrap());
            let response = session.response_written().unwrap();
            assert_eq!(response.status.as_u16(), 403, "{path}");
            assert!(
                !response
                    .headers
                    .contains_key(http::header::WWW_AUTHENTICATE)
            );
            assert!(ctx.validated_token().is_none());
            assert!(!*proxy.auth.inner.request_filter_called.lock().unwrap());
        }
    }

    #[tokio::test]
    async fn resource_binding_denies_uri_reconstruction_failure_even_on_public_routes() {
        for path in ["/mcp/inventory", "/internalX/mcp/inventory"] {
            let guard = crate::resource::ResourcePolicy::builder()
                .default(Rule::public())
                .path_guard(crate::resource::GuardConfig::new(
                    crate::resource::CaseSensitivity::Sensitive,
                    crate::resource::DecodeDepth::UpToOne,
                ))
                .build()
                .map(|policy| {
                    Guard::builder()
                        .validator(MockValidator(MockOutcome::Missing))
                        .policy(policy)
                        .url_mapping(
                            crate::resource_server::core::url_mapping::PublicUrlMapping::new(
                                "https://api.example.com",
                                "/internal",
                            )
                            .unwrap(),
                        )
                        .build()
                })
                .unwrap();
            let (proxy, _metadata) = AuthProxy::new(InnerProxy::new(), guard)
                .bind_for_test("/mcp/inventory", AudienceBinding::ResourceIdentifier)
                .unwrap();
            let (mut session, _client) = make_session("GET", path).await;
            let mut ctx = proxy.new_ctx();

            assert!(proxy.request_filter(&mut session, &mut ctx).await.unwrap());
            assert_eq!(
                session.response_written().unwrap().status.as_u16(),
                400,
                "{path}"
            );
            assert!(!*proxy.auth.inner.request_filter_called.lock().unwrap());
        }
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
        .bind_for_test("/mcp/inventory", AudienceBinding::ResourceIdentifier)
        .unwrap();
        let (mut session, _client) = make_session("POST", "/mcp/inventory").await;
        let mut ctx = proxy.new_ctx();

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
        assert!(!*proxy.auth.inner.request_filter_called.lock().unwrap());
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
        .bind_for_test(
            "/mcp/inventory",
            AudienceBinding::mapped(["api://inventory"]),
        )
        .unwrap();
        let (mut session, _client) = make_session("POST", "/mcp/inventory").await;
        let mut ctx = proxy.new_ctx();

        let handled = proxy.request_filter(&mut session, &mut ctx).await.unwrap();

        assert!(!handled);
        assert!(ctx.validated_token().is_some());
        assert!(*proxy.auth.inner.request_filter_called.lock().unwrap());
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
        .bind_for_test("/mcp/github", AudienceBinding::ResourceIdentifier)
        .unwrap();
        let (mut session, _client) = make_session("POST", "/mcp/github/tools").await;
        let mut ctx = proxy.new_ctx();

        let handled = proxy.request_filter(&mut session, &mut ctx).await.unwrap();

        assert!(!handled);
        assert!(*proxy.auth.inner.request_filter_called.lock().unwrap());
    }

    #[test]
    fn resource_binding_and_metadata_publisher_reject_ambiguous_configuration() {
        let (_proxy, endpoint) = build_auth_proxy(MockValidator(MockOutcome::Missing), vec![])
            .bind_for_test("/mcp?tenant=one", AudienceBinding::ResourceIdentifier)
            .unwrap();
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
                .bind_for_test("/mcp?tenant=two", AudienceBinding::ResourceIdentifier)
                .unwrap();
        let query_distinguished = ResourceMetadataProxy::new(InnerProxy::new())
            .publish(endpoint)
            .unwrap()
            .publish(other_query_endpoint)
            .unwrap();
        assert_eq!(query_distinguished.endpoints.len(), 2);

        assert!(
            crate::resource_server::resource::ResourceDefinition::new(
                crate::resource_server::core::url_mapping::PublicUrlMapping::new(
                    "https://api.example.com",
                    "/"
                )
                .unwrap(),
                "/mcp",
                AudienceBinding::mapped(std::iter::empty::<String>()),
            )
            .is_err()
        );

        let (_one, one_endpoint) = build_auth_proxy(MockValidator(MockOutcome::Missing), vec![])
            .bind_for_test("/mcp/one", AudienceBinding::ResourceIdentifier)
            .unwrap();
        let (_two, two_endpoint) = build_auth_proxy_with_base(
            "https://other.example.com",
            MockValidator(MockOutcome::Missing),
            vec![],
        )
        .bind_for_test("/mcp/two", AudienceBinding::ResourceIdentifier)
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

    #[tokio::test]
    async fn strip_credentials_removes_auth_headers() {
        let claims = MockClaims { scopes: None };
        let proxy = build_auth_proxy(MockValidator(MockOutcome::Valid(claims)), vec![]);
        let (mut session, _client) =
            make_session_with_headers("GET", "/api", "Authorization: Bearer tok123\r\n").await;
        let mut ctx = proxy.new_ctx();

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
        let mut ctx = proxy.new_ctx();

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
        let mut ctx = proxy.new_ctx();

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
    async fn response_filter_preserves_dpop_nonce_until_final_or_upgrade_response() {
        for final_status in [200, 101] {
            let claims = MockClaims { scopes: None };
            let proxy = build_auth_proxy(MockValidator(MockOutcome::Valid(claims)), vec![]);
            let (mut session, _client) = make_session("GET", "/api").await;
            let mut ctx = proxy.new_ctx();
            *ctx.dpop_nonce_mut() = Some("test-nonce".into());

            for status in [100, 103] {
                let mut resp = pingora_http::ResponseHeader::build(status, Some(1)).unwrap();
                proxy
                    .response_filter(&mut session, &mut resp, &mut ctx)
                    .await
                    .unwrap();

                assert!(resp.headers.get("dpop-nonce").is_none());
                assert_eq!(ctx.dpop_nonce_mut().as_deref(), Some("test-nonce"));
            }

            let mut resp = pingora_http::ResponseHeader::build(final_status, Some(1)).unwrap();
            proxy
                .response_filter(&mut session, &mut resp, &mut ctx)
                .await
                .unwrap();

            assert_eq!(resp.headers.get("dpop-nonce").unwrap(), "test-nonce");
            assert!(ctx.dpop_nonce_mut().is_none());
        }
    }

    #[tokio::test]
    async fn response_filter_no_nonce_leaves_response_clean() {
        let claims = MockClaims { scopes: None };
        let proxy = build_auth_proxy(MockValidator(MockOutcome::Valid(claims)), vec![]);
        let (mut session, _client) = make_session("GET", "/api").await;
        let mut ctx = proxy.new_ctx();

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
            .bind_for_test("/api", AudienceBinding::mapped(["api"]))
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
        .bind_for_test("/api", AudienceBinding::mapped(["api"]))
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
    #[tokio::test]
    async fn bound_custom_body_survives_resource_assembly() {
        use tokio::io::AsyncReadExt as _;

        use crate::{
            resource::{BoundResource, assembly::ResourceAssembly},
            resource_server::{core::url_mapping::PublicUrlMapping, resource::ResourceDefinition},
        };

        let mapping = PublicUrlMapping::new("https://api.example.com", "/").unwrap();
        let definition =
            ResourceDefinition::new(mapping.clone(), "/api", AudienceBinding::ResourceIdentifier)
                .unwrap();
        let policy = crate::resource::GuardConfig::new(
            crate::resource::CaseSensitivity::Sensitive,
            crate::resource::DecodeDepth::UpToOne,
        );
        let validator = MockValidator(MockOutcome::Missing);
        let resource_policy = crate::resource::ResourcePolicy::builder()
            .path_guard(policy.clone())
            .build()
            .unwrap();
        let bound = BoundResource::builder()
            .definition(definition)
            .validator(validator)
            .policy(resource_policy)
            .inner(InnerProxy::new())
            .build()
            .unwrap();
        let metadata_uri = bound.metadata().uri().clone();
        let metadata_body = bound.metadata().publication().body.to_vec();
        // Replace a non-default renderer too, retaining the validated bundle.
        let bound = bound
            .error_body(NeverRender)
            .error_body(JsonErrors)
            .into_route();
        assert_eq!(bound.definition().metadata_uri(), &metadata_uri);
        assert_eq!(bound.metadata().publication().body, metadata_body);
        let proxy = ResourceAssembly::new(mapping)
            .register_bound(bound)
            .unwrap()
            .assemble()
            .fallback(route(InnerProxy::new()))
            .slot(context_lens!(TestContext, ctx => ctx.route))
            .path_guard(policy)
            .call()
            .unwrap();

        for (method, path, status) in [
            ("GET", "/api", 401),
            ("HEAD", "/api", 401),
            ("GET", metadata_uri.path(), 200),
        ] {
            let (mut session, mut client) = make_session(method, path).await;
            let mut ctx = proxy.new_ctx();
            proxy
                .early_request_filter(&mut session, &mut ctx)
                .await
                .unwrap();
            assert!(proxy.request_filter(&mut session, &mut ctx).await.unwrap());
            let response = session.response_written().unwrap();
            assert_eq!(response.status.as_u16(), status);
            assert_eq!(response.headers["content-type"], "application/json");
            if status == 401 {
                assert_eq!(response.headers["cache-control"], "no-store");
                assert!(
                    response.headers["www-authenticate"]
                        .to_str()
                        .unwrap()
                        .contains(&metadata_uri.to_string())
                );
            }
            drop(session);
            let mut wire = String::new();
            client.read_to_string(&mut wire).await.unwrap();
            let (_, body) = wire.split_once("\r\n\r\n").unwrap();
            if method == "HEAD" {
                assert!(body.is_empty());
            } else if status == 200 {
                assert_eq!(body.as_bytes(), metadata_body);
            } else {
                let json: serde_json::Value = serde_json::from_str(body).unwrap();
                assert_eq!(json["status"], 401);
                assert!(json["error"].is_null());
            }
        }
    }

    #[tokio::test]
    async fn resource_assembly_maps_routes_and_publishes_metadata_separately() {
        use crate::{
            resource::assembly::ResourceAssembly,
            resource_server::{core::url_mapping::PublicUrlMapping, resource::ResourceDefinition},
        };
        for (base, prefix, path) in [
            ("https://api.example.com", "/", "/app/items"),
            ("https://api.example.com/gateway", "/", "/app/items"),
            (
                "https://api.example.com/gateway",
                "/edge",
                "/edge/app/items",
            ),
        ] {
            let mapping = PublicUrlMapping::new(base, prefix).unwrap();
            let definition = ResourceDefinition::new(
                mapping.clone(),
                "/app",
                AudienceBinding::ResourceIdentifier,
            )
            .unwrap();
            let policy = crate::resource::GuardConfig::new(
                crate::resource::CaseSensitivity::Sensitive,
                crate::resource::DecodeDepth::UpToOne,
            );
            let validator = MockValidator(MockOutcome::ValidFor(
                MockClaims { scopes: None },
                definition.audiences().to_vec(),
            ));
            let resource_policy = crate::resource::ResourcePolicy::builder()
                .path_guard(policy.clone())
                .build()
                .unwrap();
            let proxy = ResourceAssembly::new(
                PublicUrlMapping::new("https://api.example.com", "/metadata-ingress").unwrap(),
            )
            .register()
            .definition(&definition)
            .validator(validator)
            .policy(resource_policy)
            .inner(InnerProxy::new())
            .call()
            .unwrap()
            .assemble()
            .fallback(route(InnerProxy::new()))
            .slot(context_lens!(TestContext, ctx => ctx.route))
            .path_guard(policy)
            .call()
            .unwrap();
            let (mut session, _client) = make_session("GET", path).await;
            let mut ctx = proxy.new_ctx();
            proxy
                .early_request_filter(&mut session, &mut ctx)
                .await
                .unwrap();
            assert!(!proxy.request_filter(&mut session, &mut ctx).await.unwrap());
            assert!(ctx.validated_token().is_some());
            let (mut session, _client) = make_session(
                "GET",
                &format!("/metadata-ingress{}", definition.metadata_uri().path()),
            )
            .await;
            let mut ctx = proxy.new_ctx();
            proxy
                .early_request_filter(&mut session, &mut ctx)
                .await
                .unwrap();
            assert!(proxy.request_filter(&mut session, &mut ctx).await.unwrap());
            assert_eq!(session.response_written().unwrap().status.as_u16(), 200);
            assert!(ctx.validated_token().is_none());
            let (mut session, _client) = make_session(
                "GET",
                &format!("{}/../outside", definition.incoming_mount()),
            )
            .await;
            let mut ctx = proxy.new_ctx();
            assert!(
                proxy
                    .early_request_filter(&mut session, &mut ctx)
                    .await
                    .is_err()
            );
            assert!(
                !ctx.route.is_selected(),
                "ambiguous paths must fail before selecting a branch"
            );
        }
    }

    #[tokio::test]
    async fn root_resource_reserves_metadata_and_never_uses_application_fallback_for_query_misses()
    {
        use crate::{
            resource::assembly::ResourceAssembly,
            resource_server::{core::url_mapping::PublicUrlMapping, resource::ResourceDefinition},
        };
        let mapping = PublicUrlMapping::new("https://api.example.com", "/").unwrap();
        let definition =
            ResourceDefinition::new(mapping.clone(), "/", AudienceBinding::ResourceIdentifier)
                .unwrap();
        let policy = crate::resource::GuardConfig::new(
            crate::resource::CaseSensitivity::Sensitive,
            crate::resource::DecodeDepth::UpToOne,
        );
        let validator = MockValidator(MockOutcome::Missing);
        let resource_policy = crate::resource::ResourcePolicy::builder()
            .path_guard(policy.clone())
            .build()
            .unwrap();
        let proxy = ResourceAssembly::new(mapping)
            .register()
            .definition(&definition)
            .validator(validator)
            .policy(resource_policy)
            .inner(InnerProxy::new())
            .call()
            .unwrap()
            .assemble()
            .fallback(route(InnerProxy::new()))
            .slot(context_lens!(TestContext, ctx => ctx.route))
            .path_guard(policy)
            .call()
            .unwrap();
        for (method, path, expected) in [
            ("GET", "/.well-known/oauth-protected-resource", 200),
            ("HEAD", "/.well-known/oauth-protected-resource", 200),
            ("POST", "/.well-known/oauth-protected-resource", 405),
            (
                "GET",
                "/.well-known/oauth-protected-resource?wrong=query",
                404,
            ),
            ("GET", "/", 401),
            ("GET", "/private", 401),
            ("GET", "/.well-known/other", 401),
            ("GET", "/.well-known/oauth-protected-resource/child", 401),
            ("GET", "/.well-known/oauth-protected-resource-other", 401),
        ] {
            let (mut session, _client) = make_session(method, path).await;
            let mut ctx = proxy.new_ctx();
            proxy
                .early_request_filter(&mut session, &mut ctx)
                .await
                .unwrap();
            assert!(
                proxy.request_filter(&mut session, &mut ctx).await.unwrap(),
                "{path} must not forward"
            );
            assert_eq!(
                session.response_written().unwrap().status.as_u16(),
                expected,
                "{method} {path}"
            );
        }
    }

    #[test]
    fn definition_supplies_mapping_and_pingora_rejects_route_syntax() {
        use crate::{
            resource::assembly::ResourceAssembly,
            resource_server::{core::url_mapping::PublicUrlMapping, resource::ResourceDefinition},
        };
        let mapping = PublicUrlMapping::new("https://api.example.com/gateway", "/edge").unwrap();
        let definition =
            ResourceDefinition::new(mapping.clone(), "/app", AudienceBinding::ResourceIdentifier)
                .unwrap();
        let policy = crate::resource::GuardConfig::new(
            crate::resource::CaseSensitivity::Sensitive,
            crate::resource::DecodeDepth::UpToOne,
        );
        let validator = MockValidator(MockOutcome::Missing);
        let resource_policy = crate::resource::ResourcePolicy::builder()
            .path_guard(policy.clone())
            .build()
            .unwrap();
        let (_, proxy, _) = crate::resource::BoundResource::builder()
            .definition(definition)
            .validator(validator)
            .policy(resource_policy)
            .inner(InnerProxy::new())
            .build()
            .unwrap()
            .into_parts();
        assert_eq!(
            proxy
                .auth
                .guard
                .effective_request_uri(&"/edge/app/items?q=a%20b".parse().unwrap())
                .unwrap(),
            "https://api.example.com/gateway/app/items?q=a%20b"
        );
        let definition =
            ResourceDefinition::new(mapping, "/{tenant}", AudienceBinding::ResourceIdentifier)
                .unwrap();
        let validator = MockValidator(MockOutcome::Missing);
        let resource_policy = crate::resource::ResourcePolicy::builder()
            .path_guard(policy)
            .build()
            .unwrap();
        assert!(
            ResourceAssembly::new(PublicUrlMapping::new("https://api.example.com", "/").unwrap())
                .register()
                .definition(&definition)
                .validator(validator)
                .policy(resource_policy)
                .inner(InnerProxy::new())
                .call()
                .is_err()
        );
    }

    #[tokio::test]
    async fn metadata_can_replace_the_exact_mount_without_exempting_descendants() {
        use crate::{
            resource::assembly::ResourceAssembly,
            resource_server::{core::url_mapping::PublicUrlMapping, resource::ResourceDefinition},
        };
        let definition = ResourceDefinition::new(
            PublicUrlMapping::new("https://api.example.com", "/").unwrap(),
            "/app",
            AudienceBinding::ResourceIdentifier,
        )
        .unwrap();
        let metadata_mapping = PublicUrlMapping::new(
            "https://api.example.com/.well-known/oauth-protected-resource",
            "/",
        )
        .unwrap();
        let policy = crate::resource::GuardConfig::new(
            crate::resource::CaseSensitivity::Sensitive,
            crate::resource::DecodeDepth::UpToOne,
        );
        let validator = MockValidator(MockOutcome::Missing);
        let resource_policy = crate::resource::ResourcePolicy::builder()
            .path_guard(policy.clone())
            .build()
            .unwrap();
        let proxy = ResourceAssembly::new(metadata_mapping)
            .register()
            .definition(&definition)
            .validator(validator)
            .policy(resource_policy)
            .inner(InnerProxy::new())
            .call()
            .unwrap()
            .assemble()
            .fallback(route(InnerProxy::new()))
            .slot(context_lens!(TestContext, ctx => ctx.route))
            .path_guard(policy)
            .call()
            .unwrap();
        for (path, status) in [
            ("/app", 200),
            ("/app/", 401),
            ("/app/private", 401),
            ("/app/private/..", 401),
            ("/app?unknown", 404),
        ] {
            let (mut session, _client) = make_session("GET", path).await;
            let mut ctx = proxy.new_ctx();
            proxy
                .early_request_filter(&mut session, &mut ctx)
                .await
                .unwrap();
            assert!(proxy.request_filter(&mut session, &mut ctx).await.unwrap());
            assert_eq!(
                session.response_written().unwrap().status.as_u16(),
                status,
                "{path}"
            );
        }
        let (mut session, _client) = make_session("GET", "/app/../app").await;
        let mut ctx = proxy.new_ctx();
        assert!(
            proxy
                .early_request_filter(&mut session, &mut ctx)
                .await
                .is_err()
        );
        assert!(!ctx.route.is_selected());
    }
    #[test]
    fn authorization_metrics_cover_binding_denials_without_guard_double_counts() {
        use crate::metrics_test_support::{assert_counter, with_metrics};
        for (path, outcome, guard_count) in [
            ("/edge/api/items", "unauthenticated", 1),
            ("/edge/outside", "outside_resource", 0),
            ("/wrong-prefix/api", "invalid_request", 0),
        ] {
            let ((), counters) = with_metrics(async {
                let guard = crate::resource::ResourcePolicy::builder()
                    .metrics_name("inventory")
                    .path_guard(crate::resource::GuardConfig::new(
                        crate::resource::CaseSensitivity::Sensitive,
                        crate::resource::DecodeDepth::UpToOne,
                    ))
                    .build()
                    .map(|policy| {
                        Guard::builder()
                            .validator(MockValidator(MockOutcome::Missing))
                            .policy(policy)
                            .url_mapping(
                                crate::resource_server::core::url_mapping::PublicUrlMapping::new(
                                    "https://api.example.com",
                                    "/edge",
                                )
                                .unwrap(),
                            )
                            .build()
                    })
                    .unwrap();
                let (proxy, _) = AuthProxy::new(InnerProxy::new(), guard)
                    .bind_for_test("/api", AudienceBinding::mapped(["api"]))
                    .unwrap();
                let (mut session, _client) = make_session("GET", path).await;
                let mut ctx = proxy.new_ctx();
                assert!(proxy.request_filter(&mut session, &mut ctx).await.unwrap());
                assert!(!*proxy.auth.inner.request_filter_called.lock().unwrap());
            });
            assert_counter(
                &counters,
                "huskarl.pingora.resource.authorization",
                &[("name", "inventory"), ("outcome", outcome)],
                1,
            );
            assert_counter(
                &counters,
                "huskarl.resource.check",
                &[("name", "inventory"), ("outcome", "unauthenticated")],
                guard_count,
            );
            assert_eq!(
                counters.len(),
                if cfg!(feature = "metrics") {
                    1 + usize::try_from(guard_count).unwrap()
                } else {
                    0
                }
            );
        }
    }

    #[test]
    fn assembly_metrics_have_an_independent_name_and_boundary() {
        use crate::{
            metrics_test_support::{assert_counter, with_metrics},
            resource::assembly::ResourceAssembly,
            resource_server::{core::url_mapping::PublicUrlMapping, resource::ResourceDefinition},
        };
        let ((), counters) = with_metrics(async {
            let mapping = PublicUrlMapping::new("https://api.example.com", "/").unwrap();
            let definition = ResourceDefinition::new(
                mapping.clone(),
                "/api",
                AudienceBinding::ResourceIdentifier,
            )
            .unwrap();
            let policy = crate::resource::GuardConfig::new(
                crate::resource::CaseSensitivity::Sensitive,
                crate::resource::DecodeDepth::UpToOne,
            );
            let validator = MockValidator(MockOutcome::Missing);
            let resource_policy = crate::resource::ResourcePolicy::builder()
                .metrics_name("api")
                .path_guard(policy.clone())
                .build()
                .unwrap();
            let proxy = ResourceAssembly::new(mapping)
                .metrics_name("router")
                .register()
                .definition(&definition)
                .validator(validator)
                .policy(resource_policy)
                .inner(InnerProxy::new())
                .call()
                .unwrap()
                .assemble()
                .fallback(route(InnerProxy::new()))
                .slot(context_lens!(TestContext, ctx => ctx.route))
                .path_guard(policy)
                .call()
                .unwrap();
            for path in [
                "/api",
                definition.metadata_uri().path(),
                "/fallback",
                "/outside/../api",
            ] {
                let (mut session, _client) = make_session("GET", path).await;
                let mut ctx = proxy.new_ctx();
                if path.contains("..") {
                    assert!(
                        proxy
                            .early_request_filter(&mut session, &mut ctx)
                            .await
                            .is_err()
                    );
                    assert!(!ctx.route.is_selected());
                } else {
                    proxy
                        .early_request_filter(&mut session, &mut ctx)
                        .await
                        .unwrap();
                    proxy.request_filter(&mut session, &mut ctx).await.unwrap();
                }
            }
        });
        assert_counter(
            &counters,
            "huskarl.pingora.resource.route",
            &[("name", "router"), ("outcome", "selected")],
            3,
        );
        assert_counter(
            &counters,
            "huskarl.pingora.resource.route",
            &[("name", "router"), ("outcome", "path_confusion")],
            1,
        );
        assert_counter(
            &counters,
            "huskarl.pingora.resource.authorization",
            &[("name", "api"), ("outcome", "unauthenticated")],
            1,
        );
        assert_counter(
            &counters,
            "huskarl.resource.check",
            &[("name", "api"), ("outcome", "unauthenticated")],
            1,
        );
        assert_eq!(
            counters.len(),
            if cfg!(feature = "metrics") { 4 } else { 0 }
        );
    }

    #[test]
    fn unnamed_authorization_metrics_remain_bounded_and_count_before_write_failure() {
        use crate::metrics_test_support::{assert_counter, with_metrics};
        let ((), counters) = with_metrics(async {
            let proxy = build_auth_proxy(MockValidator(MockOutcome::Missing), vec![]);
            for index in 0..16 {
                let (mut session, client) =
                    make_session("GET", &format!("/attacker-{index}?kid=untrusted-{index}")).await;
                drop(client);
                assert!(
                    proxy
                        .request_filter(&mut session, &mut proxy.new_ctx())
                        .await
                        .is_err()
                );
            }
        });
        for metric in [
            "huskarl.resource.check",
            "huskarl.pingora.resource.authorization",
        ] {
            assert_counter(
                &counters,
                metric,
                &[("name", ""), ("outcome", "unauthenticated")],
                16,
            );
        }
        assert_eq!(
            counters.len(),
            if cfg!(feature = "metrics") { 2 } else { 0 }
        );
    }
}
