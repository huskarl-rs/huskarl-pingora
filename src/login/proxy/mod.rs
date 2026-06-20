//! [`ProxyHttp`](pingora_proxy::ProxyHttp) decorator for the login flow.
//!
//! [`LoginProxy`] wraps an inner proxy and runs each request through the
//! shared [`LoginEngine`]: `/callback` and `/logout` are handled internally,
//! the session is loaded (and refreshed if needed) for paths that need it,
//! and persistence happens in `upstream_response_filter`, with a `logging`
//! fallback for requests that never produce an upstream response.
//!
//! Per-path policy is configured via a routing DSL that mirrors the resource
//! side's [`Guard`](crate::resource::Guard). Register a [`LoginRule`] with
//! [`subtree`](LoginProxyBuilder::subtree) to cover a path and everything
//! beneath it (the usual choice), or [`route`](LoginProxyBuilder::route) for a
//! single exact path.

use std::sync::Arc;

use http::HeaderValue;
use huskarl_login::{
    DefaultPersistFailurePolicy, PersistFailurePolicy, SessionDriver,
    engine::{LoadedSession, LoginEngine, LoginResponse, error_chain, is_cors_preflight},
};
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
use crate::{
    path_confusion::{CaseSensitivity, PathConfusion, StructuralClasses},
    path_router::{RouteEntry, RuleRouter, RuleRouterError, next_rule_id},
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
/// # Session cookie forwarding (known limitation)
///
/// Unlike the resource side, which strips the `Authorization`/`DPoP` credentials
/// before the upstream, this proxy forwards the inbound `Cookie` header
/// **unchanged** — so the session cookie reaches the upstream. This is low
/// severity: the session cookie is sealed with the proxy's AEAD cipher and marked
/// `HttpOnly` / `__Host-`, so it is opaque to a backend that does not share the
/// cipher, and identity is delivered to the application through the session object
/// in the context, not the cookie. The cost is essentially bandwidth.
///
/// It is not stripped today only because, unlike a dedicated `Authorization`
/// header, the session lives *inside* a shared `Cookie` header alongside the
/// application's own cookies — and, for cookie-backed sessions, across a family of
/// chunk (`{name}.N`) and kid-sidecar (`{name}.kid`) cookies — so removing it means
/// parsing and rebuilding the header rather than dropping it. Revisit if the
/// upstream is not fully trusted.
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
/// #     CaseSensitivity, HasLoginSession, LoginConfig, LoginEngine, LoginProxy, LoginRule,
/// #     SessionDriver,
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
///     .case_sensitivity(CaseSensitivity::Sensitive) // required: declare backend case behavior
///     // Defaults to `LoginRule::required()` for paths that don't match.
///     // `subtree` covers a path and everything beneath it; `route` is one
///     // exact path.
///     .subtree("/dashboard", LoginRule::required()) // /dashboard and below
///     .route("/health", LoginRule::public()) // exactly /health
///     .route("/", LoginRule::optional()) // exactly /
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
    routes: RuleRouter<LoginRule<SD::SessionType>>,
    persist_failure_policy: Box<dyn PersistFailurePolicy>,
    cors_passthrough: bool,
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
    /// Route patterns use `matchit` syntax. Paths that match no registered
    /// route fall back to `default` (defaults to [`LoginRule::required`]).
    #[builder]
    pub fn new(
        /// Per-route session policy as `(pattern, rule, rule_id, opaque, method)` —
        /// patterns from one route/subtree call share an id; `opaque` marks a blob_subtree
        /// catch-all. Method differentiation is not yet exposed on `LoginRule`, so every
        /// entry is method-wildcard.
        #[builder(field)]
        routes: Vec<RouteEntry<LoginRule<SD::SessionType>>>,
        inner: P,
        engine: Arc<LoginEngine<SD>>,
        /// Fallback rule for paths that don't match any registered route.
        /// Defaults to [`LoginRule::required`] — i.e. everything is protected
        /// unless explicitly opened up.
        #[builder(default)]
        default: LoginRule<SD::SessionType>,
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
        /// Whether to pass CORS preflight requests — `OPTIONS` carrying an
        /// `Access-Control-Request-Method` header — straight to the inner proxy,
        /// bypassing session loading, the per-route [`LoginRule`], and the
        /// path-confusion guard.
        ///
        /// Defaults to `true`. A browser sends a preflight **without** credentials,
        /// so no session cookie reaches us and there is no authorization decision to
        /// make: the preflight only negotiates CORS, which belongs to the inner proxy
        /// or a dedicated CORS filter, not this login layer. Path confusion likewise
        /// has nothing to protect here — it equalizes which *authz rule* serves a path,
        /// and a credential-less preflight selects no rule.
        ///
        /// Set to `false` to instead route preflights through the normal flow (engine
        /// route handlers, rule lookup, path-confusion guard, session loading) — e.g.
        /// when a `required` route should refuse them outright rather than let the
        /// inner proxy answer.
        #[builder(default = true)]
        cors_passthrough: bool,
    ) -> Result<Self, RouteConfigError> {
        let routes = RuleRouter::build(
            routes,
            default,
            path_confusion,
            structural_classes,
            case_sensitivity.is_insensitive(),
        )?;
        Ok(Self {
            inner,
            engine,
            routes,
            persist_failure_policy,
            cors_passthrough,
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
    /// Adds a single exact-match route pattern with an associated [`LoginRule`].
    ///
    /// Patterns use `matchit` syntax (e.g. `/users/{id}`, `/static/{*rest}`).
    ///
    /// This matches the given path *exactly* — `route("/dashboard", …)` does
    /// not cover `/dashboard/` or `/dashboard/reports`. To apply a rule to a
    /// path and everything beneath it (the usual intent), prefer
    /// [`subtree`](Self::subtree).
    pub fn route(mut self, pattern: impl Into<String>, rule: LoginRule<SD::SessionType>) -> Self {
        let id = next_rule_id(&self.routes);
        let method = rule.method_match().clone();
        self.routes.push((pattern.into(), rule, id, false, method));
        self
    }

    /// Applies a [`LoginRule`] to a path **and everything beneath it**.
    ///
    /// Mirrors `Guard::subtree` on the resource side (plain code span, not a link:
    /// this module compiles without the `resource` feature). Matching only an exact
    /// path (via [`route`](Self::route))
    /// is a common source of gaps — a request to `/dashboard/` or
    /// `/dashboard/reports` would otherwise fall through to the default rule.
    ///
    /// The path is expanded into the `matchit` patterns that cover the
    /// subtree (each mapping to a clone of `rule`):
    ///
    /// - `subtree("/dashboard", …)`  covers `/dashboard`, `/dashboard/`, and
    ///   `/dashboard/...`
    /// - `subtree("/dashboard/", …)` covers `/dashboard/` and `/dashboard/...`
    ///   — a trailing slash excludes the bare `/dashboard`.
    /// - `subtree("/", …)` covers the entire path space.
    ///
    /// A more-specific [`route`](Self::route) still takes precedence over a
    /// subtree's catch-all.
    pub fn subtree(mut self, path: &str, rule: LoginRule<SD::SessionType>) -> Self {
        self.push_subtree(path, rule, false);
        self
    }

    /// Like [`subtree`](Self::subtree), but declares the subtree's catch-all tail an
    /// **opaque** key space: structural bytes (`%2F`, `;`, `\`) *inside the key* are
    /// tolerated rather than denied — for proxying opaque identifiers. Dot-segments
    /// (`..`), NUL truncation, and case folding are **still** denied even in the blob.
    ///
    /// Registering a more-specific route or `subtree` *under* the blob is a build error.
    pub fn blob_subtree(mut self, path: &str, rule: LoginRule<SD::SessionType>) -> Self {
        self.push_subtree(path, rule, true);
        self
    }

    /// Expand `path` into its subtree patterns under one rule id. Only the catch-all
    /// pattern's `opaque` flag is honored downstream.
    fn push_subtree(&mut self, path: &str, rule: LoginRule<SD::SessionType>, opaque: bool) {
        let id = next_rule_id(&self.routes);
        let mut patterns = crate::subtree_patterns(path).into_iter();
        let method = rule.method_match().clone();
        if let Some(first) = patterns.next() {
            for pattern in patterns {
                self.routes
                    .push((pattern, rule.clone(), id, opaque, method.clone()));
            }
            self.routes.push((first, rule, id, opaque, method));
        }
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
}

/// Errors that can occur when building a [`LoginProxy`]'s route table.
///
/// Distinct from [`huskarl_login::ConfigError`], which covers session driver
/// and [`LoginConfig`](huskarl_login::LoginConfig) validation.
#[derive(Debug)]
#[non_exhaustive]
pub enum RouteConfigError {
    /// A route pattern could not be lowered into the route grammar — e.g. an in-segment
    /// prefix/suffix parameter (`/v{ver}`, which the whole-segment grammar cannot
    /// express), a non-final catch-all, or a conflict with another route.
    Route {
        /// The offending pattern.
        pattern: String,
        /// A human-readable reason.
        reason: &'static str,
    },
    /// A registered pattern is non-canonical: it carries a structural byte (`%2F`,
    /// `..`, `//`, `;`, or an enabled opt-in form) the path-confusion guard treats as
    /// route structure, so a normalizing backend would never present it canonically
    /// and the route is effectively dead. Register the canonical pattern, or disable
    /// `path_confusion`.
    NonCanonicalPattern {
        /// The offending (non-canonical) pattern.
        pattern: String,
    },
    /// A registered pattern contains ASCII uppercase but the backend is declared
    /// [`CaseSensitivity::Insensitive`](crate::path_confusion::CaseSensitivity) — a
    /// case-folding backend resolves it to lowercase, so a differently-cased request
    /// could reach it (or it could shadow a lowercase route) without the matched rule's
    /// checks. Register the route in lowercase.
    NonCanonicalCasePattern {
        /// The offending pattern.
        pattern: String,
    },
}

impl std::fmt::Display for RouteConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Route { pattern, reason } => {
                write!(f, "invalid route pattern {pattern:?}: {reason}")
            }
            Self::NonCanonicalPattern { pattern } => write!(
                f,
                "route pattern {pattern:?} is non-canonical — it carries a structural byte \
                 (%2F, .., //, ;, …) the path-confusion guard treats as route structure, so \
                 requests to it would always be denied; register the canonical pattern, or \
                 disable path_confusion"
            ),
            Self::NonCanonicalCasePattern { pattern } => write!(
                f,
                "route pattern {pattern:?} contains uppercase but the backend is declared \
                 case-insensitive; register it in lowercase (the form the backend resolves to)"
            ),
        }
    }
}

impl std::error::Error for RouteConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Route { .. }
            | Self::NonCanonicalPattern { .. }
            | Self::NonCanonicalCasePattern { .. } => None,
        }
    }
}

impl From<RuleRouterError> for RouteConfigError {
    fn from(e: RuleRouterError) -> Self {
        match e {
            RuleRouterError::Route { pattern, reason } => Self::Route { pattern, reason },
            RuleRouterError::NonCanonical { pattern } => Self::NonCanonicalPattern { pattern },
            RuleRouterError::NonCanonicalCase { pattern } => {
                Self::NonCanonicalCasePattern { pattern }
            }
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

        // CORS preflight: browsers strip credentials, so a session cookie would never
        // reach us and there is no authz rule to select — path confusion has nothing to
        // protect. Let the inner proxy handle these directly, unless the deployment opts
        // out and wants preflights routed through the normal flow.
        if self.cors_passthrough && is_cors_preflight(&req.method, &req.headers) {
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

        let (_, rule) = self.routes.match_rule(uri.path(), &method);

        // Path-confusion guard: reject paths a normalizing backend would route
        // to a different rule than the one matched here.
        if let Some(msg) = self.routes.ambiguous(uri.path()) {
            let resp = self.engine.render_error(http::StatusCode::BAD_REQUEST, msg);
            write_login_response(session, resp, vec![]).await?;
            return Ok(true);
        }

        // Public routes bypass session handling entirely; the others differ
        // only in whether a missing session is fatal, plus an optional check.
        let (required, check) = match rule {
            LoginRule::Public { .. } => {
                return self.inner.request_filter(session, ctx).await;
            }
            LoginRule::Optional { check, .. } => (false, check),
            LoginRule::Required { check, .. } => (true, check),
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
