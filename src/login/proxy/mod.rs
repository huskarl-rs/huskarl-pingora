//! [`ProxyHttp`](pingora_proxy::ProxyHttp) decorator for the login flow.
//!
//! [`LoginProxy`] wraps an inner proxy and runs each request through the
//! shared [`LoginEngine`]: `/callback` and `/logout` are handled internally,
//! the session is loaded (and refreshed if needed) for paths that need it,
//! and persistence happens in `upstream_response_filter`, with a `logging`
//! fallback for requests that never produce an upstream response.
//!
//! Per-path policy is configured via a routing DSL that mirrors the resource
//! side's [`Guard`](crate::resource::Guard): `.route(pattern, LoginRule::…)`
//! registers a [`LoginRule`] for paths matching a [`matchit`] pattern.

use std::sync::Arc;

use http::HeaderValue;
use huskarl_login::{
    DefaultPersistFailurePolicy, PersistFailurePolicy, SessionDriver,
    engine::{LoadedSession, LoginEngine, LoginResponse, error_chain, is_cors_preflight},
};
use matchit::{InsertError, Router};
use pingora_error::{
    Error,
    ErrorType::{HTTPStatus, InternalError},
    Result,
};
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};
use pingora_proxy_delegate::proxy_http_delegate;

use super::{
    ctx::HasLoginSession,
    rule::{CheckError, LoginRule},
};

#[cfg(test)]
mod tests;

// ── LoginProxy ────────────────────────────────────────────────────────────────

/// A [`ProxyHttp`] decorator implementing OAuth 2.0 Authorization Code Grant login.
///
/// All OAuth-flow logic lives in the shared [`LoginEngine`]. This decorator
/// adapts it to pingora's `ProxyHttp` lifecycle and applies a per-route
/// [`LoginRule`]:
///
/// - `request_filter` runs the engine's route handlers (callback/logout),
///   looks up the [`LoginRule`] for the request path, loads the session if
///   the rule requires it, and either gates the request (rule = `required`)
///   or forwards it to the inner proxy with the loaded session in the
///   context (rules `required` or `optional`). Paths matched by a `public`
///   rule skip session loading entirely.
/// - `upstream_response_filter` persists or deletes the session via the
///   engine, appending the resulting `Set-Cookie` headers to the response.
///   A failure here is handled by the configured [`PersistFailurePolicy`].
/// - `logging` is the persistence fallback for requests that never reach
///   `upstream_response_filter` — the inner proxy answered the request
///   itself in `request_filter`, or proxying failed. The response is
///   already sent at that point, so any `Set-Cookie` values the store
///   returns are dropped with a warning: external stores persist fine,
///   cookie-backed stores cannot. (Token refreshes are persisted eagerly
///   inside [`LoginEngine::load_session`], so what's at stake here is an
///   activity touch or a retry of a failed eager persist.)
///
/// # Type parameters
///
/// - `P` — inner proxy implementing [`ProxyHttp`]
/// - `SD` — session driver ([`CookieSessionStore`](super::CookieSessionStore) or
///   [`StoreBackedSessionStore`](super::StoreBackedSessionStore))
///
/// # Example
///
/// ```no_run
/// # use std::sync::Arc;
/// # use huskarl::core::crypto::cipher::AeadCipher;
/// # use huskarl::grant::authorization_code::AuthorizationCodeGrant;
/// # use huskarl_pingora::login::{
/// #     HasLoginSession, LoginConfig, LoginEngine, LoginProxy, LoginRule, SessionDriver,
/// # };
/// # use pingora_proxy::ProxyHttp;
/// # fn build<P, SD>(
/// #     my_upstream: P,
/// #     login_config: LoginConfig,
/// #     grant: AuthorizationCodeGrant,
/// #     store: SD,
/// #     cipher: impl AeadCipher + 'static,
/// # ) where
/// #     P: ProxyHttp + Send + Sync,
/// #     P::CTX: HasLoginSession<SD::SessionType> + Send + Sync,
/// #     SD: SessionDriver + Send + Sync,
/// # {
/// let engine = Arc::new(
///     LoginEngine::builder()
///         .config(login_config)
///         .grant(grant)
///         .session_store(store)
///         .cipher(cipher)
///         .build(),
/// );
///
/// let proxy = LoginProxy::builder()
///     .inner(my_upstream)
///     .engine(engine)
///     // Defaults to `LoginRule::required()` for paths that don't match.
///     .route("/health", LoginRule::public())
///     .route("/", LoginRule::optional())
///     .route("/dashboard/{*rest}", LoginRule::required())
///     .build()
///     .expect("valid routes");
/// # }
/// ```
pub struct LoginProxy<P, SD>
where
    P: ProxyHttp + Send + Sync,
    P::CTX: HasLoginSession<SD::SessionType> + Send + Sync,
    SD: SessionDriver + Send + Sync,
{
    inner: P,
    engine: Arc<LoginEngine<SD>>,
    router: Router<LoginRule<SD::SessionType>>,
    default: LoginRule<SD::SessionType>,
    persist_failure_policy: Box<dyn PersistFailurePolicy>,
}

#[bon::bon]
impl<P, SD> LoginProxy<P, SD>
where
    P: ProxyHttp + Send + Sync,
    P::CTX: HasLoginSession<SD::SessionType> + Send + Sync,
    SD: SessionDriver + Send + Sync,
{
    /// Creates a new `LoginProxy` from a pre-built [`LoginEngine`].
    ///
    /// Use [`LoginEngine::builder`] to construct the engine, then wrap it in
    /// an [`Arc`] so it can be shared between this proxy and any other
    /// consumer that needs engine primitives (for example, an inner-proxy
    /// handler that calls [`LoginEngine::redirect_to_login`] directly).
    ///
    /// Route patterns use [`matchit`] syntax. Paths that match no registered
    /// route fall back to `default` (defaults to [`LoginRule::required`]).
    #[builder]
    pub fn new(
        /// Per-route session policy. Patterns use [`matchit`] syntax.
        #[builder(field)]
        routes: Vec<(String, LoginRule<SD::SessionType>)>,
        inner: P,
        engine: Arc<LoginEngine<SD>>,
        /// Fallback rule for paths that don't match any registered route.
        /// Defaults to [`LoginRule::required`] — i.e. everything is protected
        /// unless explicitly opened up.
        #[builder(default)]
        default: LoginRule<SD::SessionType>,
        /// Decides how to react when the post-response session persist fails.
        ///
        /// Defaults to [`DefaultPersistFailurePolicy`]: fail closed when the
        /// owed post-response save (the retry of a failed eager refresh
        /// persist) fails — letting the response through would strand the
        /// rotated token.
        ///
        /// When the policy returns a replacement response, only its status
        /// code is honored — pingora has already committed to the upstream
        /// body, so the request is failed with that status instead.
        #[builder(default = Box::new(DefaultPersistFailurePolicy) as Box<dyn PersistFailurePolicy>)]
        persist_failure_policy: Box<dyn PersistFailurePolicy>,
    ) -> Result<Self, RouteConfigError> {
        let mut rule_router = Router::new();
        for (pattern, rule) in routes {
            rule_router
                .insert(&pattern, rule)
                .map_err(|err| RouteConfigError::Route { pattern, err })?;
        }
        Ok(Self {
            inner,
            engine,
            router: rule_router,
            default,
            persist_failure_policy,
        })
    }
}

// Custom builder method for the routes collection.
impl<P, SD, S: login_proxy_builder::State> LoginProxyBuilder<P, SD, S>
where
    P: ProxyHttp + Send + Sync,
    P::CTX: HasLoginSession<SD::SessionType> + Send + Sync,
    SD: SessionDriver + Send + Sync,
{
    /// Adds a route pattern with an associated [`LoginRule`].
    ///
    /// Patterns use [`matchit`] syntax (e.g. `/users/{id}`, `/static/{*rest}`).
    pub fn route(mut self, pattern: impl Into<String>, rule: LoginRule<SD::SessionType>) -> Self {
        self.routes.push((pattern.into(), rule));
        self
    }
}

impl<P, SD> LoginProxy<P, SD>
where
    P: ProxyHttp + Send + Sync,
    P::CTX: HasLoginSession<SD::SessionType> + Send + Sync,
    SD: SessionDriver + Send + Sync,
{
    /// Returns a handle to the underlying [`LoginEngine`].
    ///
    /// Exposed so an inner proxy can drive engine primitives directly — for
    /// example, calling [`LoginEngine::redirect_to_login`] from a handler
    /// that wants to force re-authentication outside the normal routing
    /// policy.
    pub fn engine(&self) -> &Arc<LoginEngine<SD>> {
        &self.engine
    }

    /// Looks up the rule for `path`, falling back to the configured default.
    fn rule_for(&self, path: &str) -> &LoginRule<SD::SessionType> {
        self.router.at(path).map_or(&self.default, |m| m.value)
    }
}

/// Errors that can occur when building a [`LoginProxy`]'s route table.
///
/// Distinct from [`huskarl_login::ConfigError`], which covers session driver
/// and [`LoginConfig`](huskarl_login::LoginConfig) validation.
#[derive(Debug)]
#[non_exhaustive]
pub enum RouteConfigError {
    /// A route pattern was rejected by [`matchit`].
    Route {
        /// The offending pattern.
        pattern: String,
        /// The error returned by [`matchit::Router::insert`].
        err: InsertError,
    },
}

impl std::fmt::Display for RouteConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Route { pattern, err } => {
                write!(f, "invalid route pattern {pattern:?}: {err}")
            }
        }
    }
}

impl std::error::Error for RouteConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Route { err, .. } => Some(err),
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Writes a framework-neutral [`LoginResponse`] back to a pingora session,
/// appending any extra `Set-Cookie` headers.
async fn write_login_response(
    session: &mut Session,
    resp: LoginResponse,
    extra_cookies: Vec<HeaderValue>,
) -> Result<()> {
    let (status, resp_headers, body) = resp.into_parts();
    let header_count = resp_headers.len() + extra_cookies.len();
    let mut header = ResponseHeader::build(status, Some(header_count))
        .map_err(|e| Error::explain(InternalError, format!("failed to build response: {e}")))?;
    for (name, value) in resp_headers {
        header
            .append_header(name, value)
            .map_err(|e| Error::explain(InternalError, format!("response header: {e}")))?;
    }
    for cookie in extra_cookies {
        header
            .append_header(http::header::SET_COOKIE, cookie)
            .map_err(|e| Error::explain(InternalError, format!("set-cookie: {e}")))?;
    }
    let has_body = !body.is_empty();
    session
        .write_response_header(Box::new(header), !has_body)
        .await?;
    if has_body {
        session.write_response_body(Some(body), true).await?;
    }
    Ok(())
}

/// Appends session `Set-Cookie` headers (eager-refresh re-seal, touch re-save,
/// or teardown clears) to the upstream response.
///
/// When any cookie is appended, the response is forced to
/// `Cache-Control: no-store`: the upstream may have marked the response
/// cacheable, and a shared cache storing a refreshed session cookie could
/// replay it to another user (RFC 6749 §5.1). Engine-authored responses
/// already carry `no-store`. An empty `cookies` (the steady-state authenticated
/// request) leaves the upstream's own cache headers untouched.
fn append_set_cookies(resp: &mut ResponseHeader, cookies: Vec<HeaderValue>) -> Result<()> {
    if cookies.is_empty() {
        return Ok(());
    }
    for c in cookies {
        resp.append_header(http::header::SET_COOKIE, c)
            .map_err(|e| Error::explain(InternalError, format!("set-cookie: {e}")))?;
    }
    resp.insert_header(http::header::CACHE_CONTROL, "no-store")
        .map_err(|e| Error::explain(InternalError, format!("cache-control: {e}")))?;
    Ok(())
}

// ── ProxyHttp implementation ──────────────────────────────────────────────────

#[proxy_http_delegate(self.inner)]
impl<P, SD> ProxyHttp for LoginProxy<P, SD>
where
    P: ProxyHttp + Send + Sync,
    P::CTX: HasLoginSession<SD::SessionType> + Send + Sync,
    SD: SessionDriver + Send + Sync,
{
    type CTX = P::CTX;

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let req = session.req_header();

        // CORS preflight: browsers strip credentials, so a session cookie
        // would never reach us. Let the inner proxy handle these directly.
        if is_cors_preflight(&req.method, &req.headers) {
            return self.inner.request_filter(session, ctx).await;
        }

        let uri = req.uri.clone();
        let method = req.method.clone();
        let headers = req.headers.clone();

        // The engine handles its configured callback / logout paths fully —
        // they take precedence over any user-registered route.
        if let Some(resp) = self
            .engine
            .try_handle_login_route(&method, &headers, &uri)
            .await
        {
            write_login_response(session, resp, vec![]).await?;
            return Ok(true);
        }

        let rule = self.rule_for(uri.path());

        // Public routes bypass session handling entirely; the others differ
        // only in whether a missing session is fatal, plus an optional check.
        let (required, check) = match rule {
            LoginRule::Public => {
                return self.inner.request_filter(session, ctx).await;
            }
            LoginRule::Optional { check } => (false, check),
            LoginRule::Required { check } => (true, check),
        };

        let loaded = match self.engine.load_session(&headers).await {
            Ok(l) => l,
            Err(e) => {
                log::error!("failed to load session: {}", error_chain(&e));
                let resp = self.engine.render_error(
                    http::StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to load session",
                );
                write_login_response(session, resp, vec![]).await?;
                return Ok(true);
            }
        };

        // Flatten the session state once, exhaustively: which session (if
        // any), what the response still owes the store, and which Set-Cookie
        // headers must reach the client.
        let (maybe_sess, pending_save, set_cookies) = match loaded {
            LoadedSession::Missing => (None, false, Vec::new()),
            LoadedSession::Cleared { clears, .. } => (None, false, clears),
            LoadedSession::Active {
                session: sess,
                set_cookies,
            } => (Some(sess), false, set_cookies),
            LoadedSession::ActivePending { session: sess } => (Some(sess), true, Vec::new()),
        };

        let Some(sess) = maybe_sess else {
            // No usable session. set_cookies carries clears for stale
            // cookies the engine decided to drop (expired, refresh failed).
            if required {
                let resp = self.engine.redirect_to_login(&headers, &uri).await;
                write_login_response(session, resp, set_cookies).await?;
                return Ok(true);
            }
            let state = ctx.login_state_mut();
            state.session = None;
            state.pending_save = false;
            state.request_headers = headers;
            state.set_cookies = set_cookies;
            state.delete_requested = false;
            return self.inner.request_filter(session, ctx).await;
        };

        if let Some(check) = check
            && let Err(err) = check(&sess)
        {
            let (status, msg) = match err {
                CheckError::Forbidden(msg) => (http::StatusCode::FORBIDDEN, msg),
            };
            // The deny response may still owe the store a post-response save:
            // the retry of an eager refresh persist that failed. Best-effort —
            // the user is denied either way.
            let mut cookies = set_cookies;
            if pending_save {
                match self.engine.persist_session(&sess, &headers).await {
                    Ok(more) => cookies.extend(more),
                    Err(e) => log::error!(
                        "failed to persist session on denied request: {}",
                        error_chain(&e)
                    ),
                }
            }
            let resp = self.engine.render_error(status, &msg);
            write_login_response(session, resp, cookies).await?;
            return Ok(true);
        }

        let state = ctx.login_state_mut();
        state.session = Some(sess);
        state.pending_save = pending_save;
        state.request_headers = headers;
        state.set_cookies = set_cookies;
        state.delete_requested = false;

        self.inner.request_filter(session, ctx).await
    }

    async fn upstream_response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        self.inner
            .upstream_response_filter(session, upstream_response, ctx)
            .await?;

        let state = ctx.login_state_mut();
        let maybe_sess = state.session.take();
        let request_headers = std::mem::take(&mut state.request_headers);
        let set_cookies = std::mem::take(&mut state.set_cookies);
        let pending_save = std::mem::replace(&mut state.pending_save, false);
        let delete_requested = std::mem::replace(&mut state.delete_requested, false);

        append_set_cookies(upstream_response, set_cookies)?;

        let Some(sess) = maybe_sess else {
            return Ok(());
        };

        if delete_requested {
            return match self.engine.delete_session(&sess, &request_headers).await {
                Ok(cookies) => append_set_cookies(upstream_response, cookies),
                Err(e) => {
                    // A failed delete means the session is still live;
                    // sending the response without its cookie clears would
                    // leave the client logged in. Always fail closed.
                    log::error!("failed to delete session: {}", error_chain(&e));
                    Err(Error::explain(
                        InternalError,
                        format!("failed to delete session: {}", error_chain(&e)),
                    ))
                }
            };
        }

        // Fully persisted at load time — nothing owed.
        if !pending_save {
            return Ok(());
        }
        match self.engine.persist_session(&sess, &request_headers).await {
            Ok(cookies) => append_set_cookies(upstream_response, cookies),
            Err(e) => {
                log::error!("failed to persist session: {}", error_chain(&e));
                match self.persist_failure_policy.handle(&e) {
                    // Pingora has already committed to the upstream body, so
                    // the replacement response can't be written as-is — fail
                    // the request with the policy's status code instead.
                    Some(resp) => Err(Error::explain(
                        HTTPStatus(resp.status().as_u16()),
                        format!("failed to persist session: {}", error_chain(&e)),
                    )),
                    None => Ok(()),
                }
            }
        }
    }

    async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut Self::CTX) {
        // Persistence fallback for requests that never reached
        // `upstream_response_filter`: the inner proxy answered in
        // `request_filter`, or proxying failed. On the normal proxied path
        // `upstream_response_filter` has already consumed the state and this
        // is a no-op. The response is gone, so `Set-Cookie` values can no
        // longer be delivered — external stores still persist correctly,
        // cookie-backed stores cannot.
        let state = ctx.login_state_mut();
        if let Some(sess) = state.session.take() {
            let request_headers = std::mem::take(&mut state.request_headers);
            let pending_save = std::mem::replace(&mut state.pending_save, false);
            let delete_requested = std::mem::replace(&mut state.delete_requested, false);
            state.set_cookies.clear();

            let result = if delete_requested {
                Some(self.engine.delete_session(&sess, &request_headers).await)
            } else if pending_save {
                Some(self.engine.persist_session(&sess, &request_headers).await)
            } else {
                // Fully persisted at load time — nothing owed.
                None
            };
            match result {
                Some(Ok(cookies)) if !cookies.is_empty() => {
                    log::warn!(
                        "session persisted after the response was sent — {} Set-Cookie header(s) could not be delivered",
                        cookies.len()
                    );
                }
                Some(Err(err)) => log::error!(
                    "failed to persist session in logging fallback: {}",
                    error_chain(&err)
                ),
                Some(Ok(_)) | None => {}
            }
        }

        self.inner.logging(session, e, ctx).await;
    }
}
