//! [`ProxyHttp`](pingora_proxy::ProxyHttp) decorator for the login flow.
//!
//! [`LoginProxy`] wraps an inner proxy and intercepts `request_filter` to
//! manage the full Authorization Code Grant lifecycle: session loading,
//! lifetime enforcement, token refresh, OAuth callback handling, and logout.
//! Session mutations are automatically persisted in `upstream_response_filter`.

use std::time::{Duration, SystemTime};

use http::{Method, header};
use huskarl::{
    core::{
        crypto::cipher::{AeadV1Sealer, AeadV1Unsealer, BoxedAeadCipher},
        http::HttpClient,
    },
    grant::authorization_code::PendingState,
};
use pingora_error::{Error, ErrorType::InternalError, Result};
use pingora_proxy::{ProxyHttp, Session};
use pingora_proxy_delegate::proxy_http_delegate;
use serde::{Deserialize, Serialize};

use super::{
    config::LoginConfig,
    ctx::HasLoginSession,
    error_page::{DefaultErrorPage, ErrorPage},
    grant::LoginGrant,
    session::SessionDriver,
    token_session::TokenSession,
};

mod handlers;
#[cfg(test)]
mod tests;

// ── Cookie payload types ──────────────────────────────────────────────────────

/// Encrypted payload stored in the per-flow login-state cookie.
///
/// The flow's `state` value is used as AEAD associated data, binding the cookie
/// to the specific authorization request.
#[derive(Serialize, Deserialize)]
struct LoginStateCookie {
    original_url: String,
    pending_state: PendingState,
}

// ── LoginProxy ────────────────────────────────────────────────────────────────

/// A [`ProxyHttp`] decorator implementing OAuth 2.0 Authorization Code Grant login.
///
/// - Unauthenticated requests are redirected to the authorization server via
///   [`LoginGrant::start`]. A short-lived login-state cookie is set carrying the
///   [`PendingState`] and the original URL, encrypted with the flow's `state`
///   value as AEAD associated data.
/// - The callback path is handled internally: the code is exchanged via
///   [`LoginGrant::complete`], a session is created, the login-state cookie is
///   cleared, and the user is redirected to their original URL.
/// - Requests that present a valid session are forwarded to `P`.
///
/// # Type parameters
///
/// - `P` — inner proxy implementing [`ProxyHttp`]
/// - `G` — [`LoginGrant`] managing the auth code flow (PAR/JAR/DPoP/PKCE)
/// - `SD` — session driver ([`CookieSessionStore`](super::CookieSessionStore) or
///   [`StoreBackedSessionStore`](super::StoreBackedSessionStore))
/// - `H` — [`HttpClient`] for token endpoint and optional PAR requests
pub struct LoginProxy<P, G, SD, H>
where
    P: ProxyHttp + Send + Sync,
    P::CTX: HasLoginSession<SD::Session> + Send + Sync,
    G: LoginGrant + Send + Sync,
    SD: SessionDriver + Send + Sync,
    SD::Session: TokenSession,
    H: HttpClient + Send + Sync,
{
    inner: P,
    config: LoginConfig,
    grant: G,
    session_store: SD,
    sealer: AeadV1Sealer<BoxedAeadCipher>,
    unsealer: AeadV1Unsealer<BoxedAeadCipher>,
    http_client: H,
    error_page: Box<dyn ErrorPage>,
}

#[bon::bon]
impl<P, G, SD, H> LoginProxy<P, G, SD, H>
where
    P: ProxyHttp + Send + Sync,
    P::CTX: HasLoginSession<SD::Session> + Send + Sync,
    G: LoginGrant + Send + Sync,
    SD: SessionDriver + Send + Sync,
    SD::Session: TokenSession,
    H: HttpClient + Send + Sync,
{
    /// Creates a new `LoginProxy`.
    ///
    /// The `cipher` is used only for the short-lived login-state cookie (CSRF
    /// protection during the OAuth flow). Session persistence is handled
    /// entirely by the session store.
    #[builder]
    pub fn new(
        inner: P,
        config: LoginConfig,
        grant: G,
        session_store: SD,
        cipher: BoxedAeadCipher,
        http_client: H,
        /// Custom error page renderer. Defaults to [`DefaultErrorPage`] which
        /// renders minimal self-contained HTML.
        #[builder(default = Box::new(DefaultErrorPage) as Box<dyn ErrorPage>)]
        error_page: Box<dyn ErrorPage>,
    ) -> Self {
        Self {
            inner,
            config,
            grant,
            session_store,
            sealer: AeadV1Sealer::new(cipher.clone()),
            unsealer: AeadV1Unsealer::new(cipher),
            http_client,
            error_page,
        }
    }
}

// ── Navigation detection ─────────────────────────────────────────────────────

/// Returns `true` if this looks like a top-level browser navigation (as
/// opposed to a fetch/XHR, image load, script, etc.).
///
/// Uses the `Sec-Fetch-Mode` header when present (all modern browsers send
/// it). Falls back to checking the `Accept` header for `text/html`.
pub(super) fn is_navigation_request(session: &Session) -> bool {
    let headers = &session.req_header().headers;
    if let Some(mode) = headers.get("sec-fetch-mode") {
        return mode.as_bytes() == b"navigate";
    }
    // Fallback for older clients: HTML in Accept usually means a page load.
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("text/html"))
}

// ── ProxyHttp implementation ──────────────────────────────────────────────────

#[proxy_http_delegate(self.inner)]
impl<P, G, SD, H> ProxyHttp for LoginProxy<P, G, SD, H>
where
    P: ProxyHttp + Send + Sync,
    P::CTX: HasLoginSession<SD::Session> + Send + Sync,
    G: LoginGrant + Send + Sync,
    SD: SessionDriver + Send + Sync,
    SD::Session: TokenSession,
    H: HttpClient + Send + Sync,
{
    type CTX = P::CTX;

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        if session.req_header().uri.path() == self.config.callback_path {
            return self.handle_callback(session).await;
        }
        if self
            .config
            .logout_path
            .as_deref()
            .is_some_and(|p| session.req_header().uri.path() == p)
        {
            return self.handle_logout(session).await;
        }
        // Let CORS preflight requests pass through to the inner proxy
        // unauthenticated — browsers strip credentials from preflights, so
        // they will never carry a session cookie.
        if session.req_header().method == Method::OPTIONS
            && session
                .req_header()
                .headers
                .contains_key("access-control-request-method")
        {
            return self.inner.request_filter(session, ctx).await;
        }
        match self.session_store.load(&session.req_header().headers).await {
            Ok(Some(mut loaded)) => {
                let now = SystemTime::now();

                // ── Max lifetime check ───────────────────────────────
                if let Some(max_lifetime) = self.config.max_lifetime
                    && now
                        .duration_since(loaded.created_at())
                        .unwrap_or(Duration::ZERO)
                        > max_lifetime
                {
                    return self.expire_session(session, Some(&loaded)).await;
                }

                // ── Idle timeout check ───────────────────────────────
                if let Some(idle_timeout) = self.config.idle_timeout
                    && now
                        .duration_since(loaded.last_active())
                        .unwrap_or(Duration::ZERO)
                        > idle_timeout
                {
                    return self.expire_session(session, Some(&loaded)).await;
                }

                // ── Token expiry check ───────────────────────────────
                let token_expired = loaded
                    .token_expiry()
                    .is_some_and(|exp| now + self.config.token_refresh_margin >= exp);

                if token_expired {
                    let refresh_token = loaded.refresh_token().cloned();

                    if let Some(rt) = refresh_token {
                        match self.grant.refresh(&self.http_client, &rt).await {
                            Ok(token_response) => {
                                loaded.apply_refresh(&token_response);
                                ctx.set_login_session(Some(loaded));
                                // Mark dirty so upstream_response_filter persists
                                // the refreshed session.
                                let _ = ctx.login_session_mut();
                            }
                            Err(e) => {
                                log::error!("token refresh failed: {e}");
                                return self.expire_session(session, Some(&loaded)).await;
                            }
                        }
                    } else {
                        return self.expire_session(session, Some(&loaded)).await;
                    }
                } else {
                    loaded.record_activity();
                    ctx.set_login_session(Some(loaded));
                }

                return self.inner.request_filter(session, ctx).await;
            }
            Ok(None) => {} // fall through to redirect/401
            Err(e) => {
                log::error!("failed to load session: {e}");
                return self
                    .error_response(
                        session,
                        http::StatusCode::INTERNAL_SERVER_ERROR,
                        "failed to load session",
                        None,
                    )
                    .await;
            }
        }
        // Only start the OAuth flow for top-level navigations. Subresource
        // requests (fetch, images, scripts, etc.) get a 401 so they fail
        // cleanly instead of receiving an HTML redirect.
        if is_navigation_request(session) {
            if let Err(e) = self.redirect_to_as(session, None).await {
                log::error!("failed to redirect to authorization server: {e}");
                return self
                    .error_response(
                        session,
                        http::StatusCode::INTERNAL_SERVER_ERROR,
                        "failed to start login",
                        None,
                    )
                    .await;
            }
        } else {
            self.error_response(
                session,
                http::StatusCode::UNAUTHORIZED,
                "authentication required",
                None,
            )
            .await?;
        }
        Ok(true)
    }

    async fn upstream_response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut pingora_http::ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        self.inner
            .upstream_response_filter(session, upstream_response, ctx)
            .await?;

        if ctx.is_delete_requested() {
            if let Some(s) = ctx.login_session() {
                self.session_store
                    .delete(s, upstream_response)
                    .await
                    .map_err(|e| Error::because(InternalError, "failed to delete session", e))?;
            }
            ctx.set_login_session(None);
        } else if ctx.is_session_dirty() {
            if let Some(s) = ctx.login_session() {
                self.session_store
                    .save(s, upstream_response)
                    .await
                    .map_err(|e| Error::because(InternalError, "failed to save session", e))?;
            }
            ctx.clear_session_dirty();
        } else if let Some(s) = ctx.login_session() {
            self.session_store
                .touch(s, upstream_response)
                .await
                .map_err(|e| Error::because(InternalError, "failed to touch session", e))?;
        }

        Ok(())
    }
}
