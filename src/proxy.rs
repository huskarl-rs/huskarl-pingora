use std::borrow::Cow;
use std::marker::PhantomData;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http::header;
use pingora_cache::key::HashBinary;
use pingora_cache::{CacheKey, CacheMeta, ForcedFreshness, HitHandler, RespCacheable};
use pingora_core::modules::http::HttpModules;
use pingora_core::protocols::Digest;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::{Error, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{FailToProxy, ProxyHttp, PurgeStatus, RangeType, Session};
use tokio::sync::mpsc;

use huskarl_resource_server::validator::metadata::ProvideValidatorMetadata;
use huskarl_resource_server::validator::AccessTokenValidator;

use crate::ctx::AuthCtx;
use crate::guard::Guard;
use crate::outcome::Outcome;
use crate::response::{write_challenge_response, write_json_response};
use crate::scopes::HasScopes;

/// A decorator that wraps a [`ProxyHttp`] implementation to add OAuth 2.0
/// token validation via a [`Guard`].
///
/// `AuthProxy` intercepts `request_filter` to validate tokens and
/// `response_filter` to insert `DPoP-Nonce` headers. All other `ProxyHttp`
/// methods delegate directly to the inner proxy.
///
/// # Type Parameters
///
/// - `P`: The inner proxy implementing `ProxyHttp<CTX = AuthCtx<T, V::Claims>>`
/// - `V`: The token validator
/// - `T`: The user's inner context type
///
/// # Example
///
/// ```ignore
/// let guard = Guard::builder(validator)
///     .route("/public/*rest", Rule::public())
///     .build();
/// let proxy = AuthProxy::new(my_proxy, guard);
/// ```
pub struct AuthProxy<P, V, T>
where
    V: AccessTokenValidator + ProvideValidatorMetadata,
{
    inner: P,
    guard: Guard<V>,
    resource_metadata: Option<(String, Bytes)>,
    _marker: PhantomData<fn() -> T>,
}

impl<P, V, T> AuthProxy<P, V, T>
where
    V: AccessTokenValidator + ProvideValidatorMetadata,
    P: ProxyHttp<CTX = AuthCtx<T, V::Claims>>,
{
    /// Creates a new `AuthProxy` wrapping the given proxy with the given guard.
    pub fn new(inner: P, guard: Guard<V>) -> Self {
        Self {
            inner,
            guard,
            resource_metadata: None,
            _marker: PhantomData,
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
    pub fn resource_metadata(mut self, enabled: bool) -> Self {
        self.resource_metadata = if enabled {
            let (path, json) = self.guard.resource_metadata();
            Some((path, Bytes::from(json)))
        } else {
            None
        };
        self
    }
}

#[async_trait]
#[deny(clippy::missing_trait_methods)]
impl<P, V, T> ProxyHttp for AuthProxy<P, V, T>
where
    P: ProxyHttp<CTX = AuthCtx<T, V::Claims>> + Send + Sync,
    V: AccessTokenValidator + ProvideValidatorMetadata + Send + Sync,
    V::Claims: HasScopes + Send + Sync,
    T: Send + Sync,
{
    type CTX = AuthCtx<T, V::Claims>;

    fn new_ctx(&self) -> Self::CTX {
        self.inner.new_ctx()
    }

    fn init_downstream_modules(&self, modules: &mut HttpModules) {
        self.inner.init_downstream_modules(modules);
    }

    // --- Request phase (intercepted) ---

    async fn early_request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        self.inner.early_request_filter(session, ctx).await
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        // Serve RFC 9728 protected resource metadata if enabled.
        if let Some((ref path, ref body)) = self.resource_metadata
            && session.req_header().uri.path() == path
        {
            write_json_response(session, body).await?;
            return Ok(true);
        }

        match self.guard.check(session).await {
            Outcome::Forward {
                token,
                dpop_nonce,
                strip_credentials,
            } => {
                ctx.token = token;
                ctx.dpop_nonce = dpop_nonce;
                ctx.strip_credentials = strip_credentials;
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

    fn allow_spawning_subrequest(&self, session: &Session, ctx: &Self::CTX) -> bool {
        self.inner.allow_spawning_subrequest(session, ctx)
    }

    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        self.inner
            .request_body_filter(session, body, end_of_stream, ctx)
            .await
    }

    // --- Cache phase ---

    fn request_cache_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<()> {
        self.inner.request_cache_filter(session, ctx)
    }

    fn cache_key_callback(&self, session: &Session, ctx: &mut Self::CTX) -> Result<CacheKey> {
        self.inner.cache_key_callback(session, ctx)
    }

    fn cache_miss(&self, session: &mut Session, ctx: &mut Self::CTX) {
        self.inner.cache_miss(session, ctx);
    }

    async fn cache_hit_filter(
        &self,
        session: &mut Session,
        meta: &CacheMeta,
        hit_handler: &mut HitHandler,
        is_fresh: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<ForcedFreshness>> {
        self.inner
            .cache_hit_filter(session, meta, hit_handler, is_fresh, ctx)
            .await
    }

    fn cache_vary_filter(
        &self,
        meta: &CacheMeta,
        ctx: &mut Self::CTX,
        req: &RequestHeader,
    ) -> Option<HashBinary> {
        self.inner.cache_vary_filter(meta, ctx, req)
    }

    fn cache_not_modified_filter(
        &self,
        session: &Session,
        resp: &ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<bool> {
        self.inner.cache_not_modified_filter(session, resp, ctx)
    }

    fn range_header_filter(
        &self,
        session: &mut Session,
        resp: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> RangeType {
        self.inner.range_header_filter(session, resp, ctx)
    }

    fn response_cache_filter(
        &self,
        session: &Session,
        resp: &ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<RespCacheable> {
        self.inner.response_cache_filter(session, resp, ctx)
    }

    fn is_purge(&self, session: &Session, ctx: &Self::CTX) -> bool {
        self.inner.is_purge(session, ctx)
    }

    fn purge_response_filter(
        &self,
        session: &Session,
        ctx: &mut Self::CTX,
        purge_status: PurgeStatus,
        purge_response: &mut Cow<'static, ResponseHeader>,
    ) -> Result<()> {
        self.inner
            .purge_response_filter(session, ctx, purge_status, purge_response)
    }

    fn should_serve_stale(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
        error: Option<&Error>,
    ) -> bool {
        self.inner.should_serve_stale(session, ctx, error)
    }

    // --- Upstream phase ---

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        self.inner.upstream_peer(session, ctx).await
    }

    async fn proxy_upstream_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<bool> {
        self.inner.proxy_upstream_filter(session, ctx).await
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if ctx.strip_credentials {
            upstream_request.remove_header(&http::header::AUTHORIZATION);
        }

        self.inner
            .upstream_request_filter(session, upstream_request, ctx)
            .await
    }

    async fn connected_to_upstream(
        &self,
        session: &mut Session,
        reused: bool,
        peer: &HttpPeer,
        #[cfg(unix)] fd: std::os::unix::io::RawFd,
        #[cfg(windows)] sock: std::os::windows::io::RawSocket,
        digest: Option<&Digest>,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        self.inner
            .connected_to_upstream(
                session,
                reused,
                peer,
                #[cfg(unix)]
                fd,
                #[cfg(windows)]
                sock,
                digest,
                ctx,
            )
            .await
    }

    async fn upstream_response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        self.inner
            .upstream_response_filter(session, upstream_response, ctx)
            .await
    }

    fn upstream_response_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<Duration>> {
        self.inner
            .upstream_response_body_filter(session, body, end_of_stream, ctx)
    }

    fn upstream_response_trailer_filter(
        &self,
        session: &mut Session,
        upstream_trailers: &mut header::HeaderMap,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        self.inner
            .upstream_response_trailer_filter(session, upstream_trailers, ctx)
    }

    // --- Custom message phase (doc-hidden) ---

    async fn custom_forwarding(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
        custom_message_to_upstream: Option<mpsc::Sender<Bytes>>,
        custom_message_to_downstream: mpsc::Sender<Bytes>,
    ) -> Result<()> {
        self.inner
            .custom_forwarding(
                session,
                ctx,
                custom_message_to_upstream,
                custom_message_to_downstream,
            )
            .await
    }

    async fn downstream_custom_message_proxy_filter(
        &self,
        session: &mut Session,
        custom_message: Bytes,
        ctx: &mut Self::CTX,
        final_hop: bool,
    ) -> Result<Option<Bytes>> {
        self.inner
            .downstream_custom_message_proxy_filter(session, custom_message, ctx, final_hop)
            .await
    }

    async fn upstream_custom_message_proxy_filter(
        &self,
        session: &mut Session,
        custom_message: Bytes,
        ctx: &mut Self::CTX,
        final_hop: bool,
    ) -> Result<Option<Bytes>> {
        self.inner
            .upstream_custom_message_proxy_filter(session, custom_message, ctx, final_hop)
            .await
    }

    // --- Response phase (intercepted) ---

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        self.inner
            .response_filter(session, upstream_response, ctx)
            .await?;

        // Insert DPoP-Nonce header if the guard produced one during request_filter.
        if let Some(nonce) = ctx.dpop_nonce.take() {
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

    fn response_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<Duration>> {
        self.inner
            .response_body_filter(session, body, end_of_stream, ctx)
    }

    async fn response_trailer_filter(
        &self,
        session: &mut Session,
        upstream_trailers: &mut header::HeaderMap,
        ctx: &mut Self::CTX,
    ) -> Result<Option<Bytes>> {
        self.inner
            .response_trailer_filter(session, upstream_trailers, ctx)
            .await
    }

    // --- Error phase ---

    fn fail_to_connect(
        &self,
        session: &mut Session,
        peer: &HttpPeer,
        ctx: &mut Self::CTX,
        e: Box<Error>,
    ) -> Box<Error> {
        self.inner.fail_to_connect(session, peer, ctx, e)
    }

    fn error_while_proxy(
        &self,
        peer: &HttpPeer,
        session: &mut Session,
        e: Box<Error>,
        ctx: &mut Self::CTX,
        client_reused: bool,
    ) -> Box<Error> {
        self.inner
            .error_while_proxy(peer, session, e, ctx, client_reused)
    }

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &Error,
        ctx: &mut Self::CTX,
    ) -> FailToProxy {
        self.inner.fail_to_proxy(session, e, ctx).await
    }

    fn suppress_error_log(&self, session: &Session, ctx: &Self::CTX, error: &Error) -> bool {
        self.inner.suppress_error_log(session, ctx, error)
    }

    // --- Logging phase ---

    async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut Self::CTX) {
        self.inner.logging(session, e, ctx).await;
    }

    fn request_summary(&self, session: &Session, ctx: &Self::CTX) -> String {
        self.inner.request_summary(session, ctx)
    }
}
