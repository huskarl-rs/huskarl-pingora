use bytes::Bytes;
use pingora_error::{Error, Result};
use pingora_http::RequestHeader;
use pingora_proxy::{ProxyHttp, Session};
use pingora_proxy_delegate::proxy_http_delegate;

use crate::{
    ctx::HasAuthState,
    guard::Guard,
    outcome::Outcome,
    resource_server::validator::{AccessTokenValidator, metadata::ProvideValidatorMetadata},
    response::{
        write_challenge_response, write_method_not_allowed, write_resource_metadata_response,
    },
    scopes::HasScopes,
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
/// # use huskarl_pingora::{AuthProxy, Guard, Rule};
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
    pub fn resource_metadata(mut self, enabled: bool) -> Result<Self, crate::error::ConfigError> {
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
