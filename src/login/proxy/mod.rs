//! [`ProxyHttp`](pingora_proxy::ProxyHttp) decorator for the login flow.
//!
//! [`LoginProxy`] wraps an inner proxy and runs each request through the
//! shared [`LoginEngine`]: `/callback` and `/logout` are handled internally,
//! the session is loaded (and refreshed if needed) for paths that need it,
//! and persistence happens in `upstream_response_filter`.
//!
//! Per-path policy is configured via a routing DSL that mirrors the resource
//! side's [`Guard`](crate::resource::Guard): `.route(pattern, LoginRule::…)`
//! registers a [`LoginRule`] for paths matching a [`matchit`] pattern.

use std::sync::Arc;

use http::HeaderValue;
use huskarl_login::{
    SessionDriver,
    engine::{LoginEngine, LoginResponse, SessionPersistence, error_chain, is_cors_preflight},
};
use matchit::{InsertError, Router};
use pingora_error::{Error, ErrorType::InternalError, Result};
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};
use pingora_proxy_delegate::proxy_http_delegate;

use super::{
    ctx::HasLoginSession,
    rule::{CheckError, LoginRule, SessionRequirement},
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
///
/// # Type parameters
///
/// - `P` — inner proxy implementing [`ProxyHttp`]
/// - `G` — [`LoginGrant`] managing the auth code flow (PAR/JAR/DPoP/PKCE)
/// - `SD` — session driver ([`CookieSessionStore`](super::CookieSessionStore) or
///   [`StoreBackedSessionStore`](super::StoreBackedSessionStore))
/// - `H` — [`HttpClient`] for token endpoint and optional PAR requests
///
/// # Example
///
/// ```ignore
/// let engine = Arc::new(
///     LoginEngine::builder()
///         .config(login_config)
///         .grant(grant)
///         .session_store(store)
///         .cipher(cipher)
///         .http_client(client)
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
/// and [`LoginConfig`] validation.
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
    let header_count = resp.headers.len() + extra_cookies.len();
    let mut header = ResponseHeader::build(resp.status, Some(header_count))
        .map_err(|e| Error::explain(InternalError, format!("failed to build response: {e}")))?;
    for (name, value) in resp.headers {
        header
            .append_header(name, value)
            .map_err(|e| Error::explain(InternalError, format!("response header: {e}")))?;
    }
    for cookie in extra_cookies {
        header
            .append_header(http::header::SET_COOKIE, cookie)
            .map_err(|e| Error::explain(InternalError, format!("set-cookie: {e}")))?;
    }
    let has_body = !resp.body.is_empty();
    session
        .write_response_header(Box::new(header), !has_body)
        .await?;
    if has_body {
        session.write_response_body(Some(resp.body), true).await?;
    }
    Ok(())
}

fn append_set_cookies(resp: &mut ResponseHeader, cookies: Vec<HeaderValue>) -> Result<()> {
    for c in cookies {
        resp.append_header(http::header::SET_COOKIE, c)
            .map_err(|e| Error::explain(InternalError, format!("set-cookie: {e}")))?;
    }
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
            .try_handle_login_route(uri.path(), &method, &headers, &uri)
            .await
        {
            write_login_response(session, resp, vec![]).await?;
            return Ok(true);
        }

        let rule = self.rule_for(uri.path());

        // Public routes bypass session handling entirely.
        let required = match rule.requirement {
            SessionRequirement::None => {
                return self.inner.request_filter(session, ctx).await;
            }
            SessionRequirement::Required => true,
            SessionRequirement::Optional => false,
        };

        let loaded = match self.engine.load_session(&headers).await {
            Ok(l) => l,
            Err(e) => {
                log::error!("failed to load session: {}", error_chain(&*e));
                let resp = self.engine.render_error(
                    http::StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to load session",
                );
                write_login_response(session, resp, vec![]).await?;
                return Ok(true);
            }
        };

        let Some((sess, persistence)) = loaded.session else {
            // No session. clear_cookies carries clears for stale cookies the
            // engine decided to drop (expired, refresh failed).
            if required {
                let resp = self.engine.redirect_to_login(&headers, &uri).await;
                write_login_response(session, resp, loaded.clear_cookies).await?;
                return Ok(true);
            }
            let state = ctx.login_state_mut();
            state.session = None;
            state.persistence = SessionPersistence::Skip;
            state.request_headers = headers;
            state.clear_cookies = loaded.clear_cookies;
            state.delete_requested = false;
            return self.inner.request_filter(session, ctx).await;
        };

        if let Some(check) = rule.check.as_ref()
            && let Err(err) = check(&sess)
        {
            let (status, msg) = match err {
                CheckError::Forbidden(msg) => (http::StatusCode::FORBIDDEN, msg),
            };
            let resp = self.engine.render_error(status, &msg);
            write_login_response(session, resp, loaded.clear_cookies).await?;
            return Ok(true);
        }

        let state = ctx.login_state_mut();
        state.session = Some(sess);
        state.persistence = persistence;
        state.request_headers = headers;
        state.clear_cookies = loaded.clear_cookies;
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
        let clear_cookies = std::mem::take(&mut state.clear_cookies);
        let persistence = std::mem::replace(&mut state.persistence, SessionPersistence::Skip);
        let delete_requested = std::mem::replace(&mut state.delete_requested, false);

        append_set_cookies(upstream_response, clear_cookies)?;

        let Some(sess) = maybe_sess else {
            return Ok(());
        };

        let result = if delete_requested {
            self.engine.delete_session(&sess, &request_headers).await
        } else {
            self.engine
                .persist_session(&sess, persistence, &request_headers)
                .await
        };

        match result {
            Ok(cookies) => append_set_cookies(upstream_response, cookies),
            Err(e) => {
                log::error!("failed to persist session: {}", error_chain(&*e));
                Err(Error::explain(
                    InternalError,
                    format!("failed to persist session: {}", error_chain(&*e)),
                ))
            }
        }
    }
}
