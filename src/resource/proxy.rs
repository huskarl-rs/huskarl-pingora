//! [`ProxyHttp`](pingora_proxy::ProxyHttp) decorator for bearer token protection.
//!
//! [`AuthProxy`] wraps an inner proxy and intercepts `request_filter` to
//! validate tokens via [`Guard`](super::Guard), `upstream_request_filter` to
//! strip credentials, and `response_filter` to insert `DPoP-Nonce` headers.
//! All other hooks delegate directly to the inner proxy.

use bytes::Bytes;
use pingora_error::{Error, Result};
use pingora_http::RequestHeader;
use pingora_proxy::{ProxyHttp, Session};
use pingora_proxy_delegate::proxy_http_delegate;

use crate::{
    resource::{
        ctx::HasAuthState,
        guard::Guard,
        outcome::Outcome,
        response::{
            write_challenge_response, write_method_not_allowed, write_resource_metadata_response,
        },
        scopes::HasScopes,
    },
    resource_server::validator::{AccessTokenValidator, metadata::ProvideValidatorMetadata},
};

/// A decorator that wraps a [`ProxyHttp`] implementation to add OAuth 2.0
/// token validation via a [`Guard`].
///
/// `AuthProxy` intercepts `request_filter` to validate tokens and
/// `response_filter` to insert `DPoP-Nonce` headers. All other `ProxyHttp`
/// methods delegate directly to the inner proxy.
///
/// The inner proxy's context type must implement [`HasAuthState<V::Claims>`].
///
/// # Example
///
/// ```
/// # use huskarl_pingora::resource::{AuthProxy, Guard, Rule};
/// # fn build<V, P>(my_proxy: P, validator: V)
/// # where
/// #     V: huskarl_pingora::resource_server::validator::AccessTokenValidator
/// #         + huskarl_pingora::resource_server::validator::metadata::ProvideValidatorMetadata,
/// # {
/// let guard = Guard::builder()
///     .validator(validator)
///     .route("/public/*rest", Rule::public())
///     .build()
///     .expect("route");
/// let proxy = AuthProxy::new(my_proxy, guard);
/// // pass `proxy` to pingora — it implements ProxyHttp with the same CTX as my_proxy
/// # }
/// ```
#[must_use]
pub struct AuthProxy<P, V>
where
    V: AccessTokenValidator + ProvideValidatorMetadata,
{
    inner: P,
    guard: Guard<V>,
    resource_metadata: Option<(String, Bytes)>,
}

impl<P, V> std::fmt::Debug for AuthProxy<P, V>
where
    V: AccessTokenValidator + ProvideValidatorMetadata,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthProxy")
            .field("guard", &self.guard)
            .field(
                "resource_metadata",
                &self.resource_metadata.as_ref().map(|(path, _)| path),
            )
            .finish()
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
            resource_metadata: None,
        }
    }

    /// Enables or disables the RFC 9728 protected resource metadata endpoint.
    ///
    /// When enabled, the proxy serves a JSON document describing the resource
    /// server's OAuth 2.0 capabilities (authorization servers, scopes, DPoP
    /// config, etc.) at the well-known path derived from the resource identifier.
    ///
    /// Per RFC 9728 §3.1, the well-known segment is inserted between the host
    /// and path of the resource URI. For example, resource
    /// `https://api.example.com/tenant1` → path
    /// `/.well-known/oauth-protected-resource/tenant1`.
    ///
    /// Disabled by default.
    pub fn resource_metadata(
        mut self,
        enabled: bool,
    ) -> Result<Self, crate::resource::error::ConfigError> {
        self.resource_metadata = if enabled {
            let (path, json) = self.guard.resource_metadata()?;
            Some((path, Bytes::from(json)))
        } else {
            None
        };
        Ok(self)
    }
}

#[proxy_http_delegate(self.inner)]
impl<P, V> ProxyHttp for AuthProxy<P, V>
where
    P: ProxyHttp + Send + Sync,
    P::CTX: HasAuthState<V::Claims> + Send + Sync,
    V: AccessTokenValidator + ProvideValidatorMetadata + Send + Sync,
    V::Claims: HasScopes + Send + Sync,
{
    type CTX = P::CTX;

    async fn request_filter(&self, session: &mut Session, ctx: &mut P::CTX) -> Result<bool> {
        // Serve RFC 9728 protected resource metadata if enabled.
        if let Some((ref path, ref body)) = self.resource_metadata
            && session.req_header().uri.path() == path
        {
            let method = &session.req_header().method;
            if method == http::Method::GET || method == http::Method::HEAD {
                write_resource_metadata_response(session, body).await?;
            } else {
                write_method_not_allowed(session, "GET, HEAD").await?;
            }
            return Ok(true);
        }

        match self.guard.check(session).await {
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
                status,
                challenges,
                dpop_nonce,
            } => {
                write_challenge_response(session, status, &challenges, dpop_nonce.as_deref())
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
    use std::sync::Mutex;

    use async_trait::async_trait;
    use pingora_core::upstreams::peer::HttpPeer;
    use pingora_proxy::Session as ProxySession;
    use tokio::io::AsyncWriteExt;

    use super::*;
    use crate::{
        resource::{
            ctx::{AuthCtx, HasAuthState},
            guard::Guard,
            rule::Rule,
            test_support::{MockClaims, MockError, mock_validator_metadata},
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
        Invalid,
    }

    struct MockValidator(MockOutcome);

    impl AccessTokenValidator for MockValidator {
        type Claims = MockClaims;
        type Error = MockError;

        async fn validate_request(
            &self,
            _headers: &http::HeaderMap,
            _method: &http::Method,
            _uri: &http::Uri,
            _client_cert_der: Option<&[u8]>,
        ) -> ValidationResult<MockClaims, MockError> {
            let outcome = match &self.0 {
                MockOutcome::Missing => Ok(None),
                MockOutcome::Valid(claims) => Ok(Some(ValidatedRequest {
                    issuer: None,
                    subject: None,
                    audience: vec![],
                    jti: None,
                    issued_at: None,
                    expiration: None,
                    cnf: None,
                    claims: claims.clone(),
                    introspection_jwt: None,
                })),
                MockOutcome::Invalid => Err(MockError),
            };
            ValidationResult {
                outcome,
                dpop_nonce: None,
            }
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

    impl InnerProxy {
        fn new() -> Self {
            Self {
                request_filter_called: Mutex::new(false),
            }
        }
    }

    #[async_trait]
    impl ProxyHttp for InnerProxy {
        type CTX = AuthCtx<(), MockClaims>;

        fn new_ctx(&self) -> Self::CTX {
            AuthCtx::new(())
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

    use tokio::io::DuplexStream;

    async fn make_session_with_headers(
        method: &str,
        path: &str,
        extra_headers: &str,
    ) -> (ProxySession, DuplexStream) {
        let raw = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n{extra_headers}\r\n");
        let (mut client, server) = tokio::io::duplex(4096);
        client.write_all(raw.as_bytes()).await.unwrap();
        let mut session = ProxySession::new_h1(Box::new(server));
        session.downstream_session.read_request().await.unwrap();
        (session, client)
    }

    async fn make_session(method: &str, path: &str) -> (ProxySession, DuplexStream) {
        make_session_with_headers(method, path, "").await
    }

    fn build_auth_proxy(
        validator: MockValidator,
        routes: Vec<(&str, Rule<MockClaims>)>,
    ) -> AuthProxy<InnerProxy, MockValidator> {
        let mut builder = Guard::builder().validator(validator);
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
        let proxy = build_auth_proxy(MockValidator(MockOutcome::Missing), vec![])
            .resource_metadata(true)
            .unwrap();
        let (mut session, _client) =
            make_session("GET", "/.well-known/oauth-protected-resource").await;
        let mut ctx = proxy.inner.new_ctx();

        let handled = proxy.request_filter(&mut session, &mut ctx).await.unwrap();

        assert!(handled);
        let resp = session.response_written().unwrap();
        assert_eq!(resp.status.as_u16(), 200);
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "application/json"
        );
        assert!(!*proxy.inner.request_filter_called.lock().unwrap());
    }

    #[tokio::test]
    async fn metadata_endpoint_post_returns_405() {
        let proxy = build_auth_proxy(MockValidator(MockOutcome::Missing), vec![])
            .resource_metadata(true)
            .unwrap();
        let (mut session, _client) =
            make_session("POST", "/.well-known/oauth-protected-resource").await;
        let mut ctx = proxy.inner.new_ctx();

        let handled = proxy.request_filter(&mut session, &mut ctx).await.unwrap();

        assert!(handled);
        let resp = session.response_written().unwrap();
        assert_eq!(resp.status.as_u16(), 405);
        assert_eq!(resp.headers.get("allow").unwrap(), "GET, HEAD");
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
}
