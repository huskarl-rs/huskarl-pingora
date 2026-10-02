//! [`ProxyHttp`] decorator for the login flow.
//!
//! [`LoginProxy`] wraps an inner proxy and runs each request through the
//! shared [`LoginEngine`]: `/callback` and `/logout` are handled internally,
//! the session is loaded (and refreshed if needed) for paths that need it,
//! and persistence happens in `response_filter`, with a `logging`
//! fallback for requests that never reach downstream finalization.
//!
//! Per-path policy is configured via a routing DSL that mirrors the resource
//! side's [`ResourcePolicy`](crate::resource::ResourcePolicy). Register a [`LoginRule`] with
//! [`subtree`](LoginProxyBuilder::subtree) to cover a path and everything
//! beneath it (the usual choice), or [`route`](LoginProxyBuilder::route) for a
//! single exact path.

use std::sync::Arc;

use http::HeaderValue;
use huskarl_login::{
    DefaultPersistFailurePolicy, PersistFailurePolicy, SessionDriver, SessionError,
    engine::{
        LoadedSession, LoginEngine, LoginResponse, SetCookies, error_chain, is_cors_preflight,
    },
};
use huskarl_route_guard::{GuardConfig, RuleRouter, RuleRouterError};
use pingora_error::{
    Error,
    ErrorType::{HTTPStatus, InternalError},
    Result,
};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session};
use pingora_proxy_delegate::proxy_http_delegate;

use super::{
    ctx::HasLoginSession,
    diagnostics::{DiagnosticHandler, LoginDiagnostic, LoginPhase, SessionOperation},
    rule::{CheckError, LoginRule},
};
use crate::{
    path_confusion::{ResolveError, resolve_error_status},
    routing::RouteKind,
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
/// - `response_filter` persists or terminates the session once, on the final
///   downstream response (including cache hits). It appends `Set-Cookie` after
///   cache processing, preserving the session for subsequent hooks. Interim
///   responses are skipped; a `101` upgrade finalizes the session.
/// - Inner handlers can queue a local response with
///   [`LoginState::respond`](super::LoginState::respond), then return `Ok(false)`.
///   The proxy finalizes and writes it without contacting an upstream.
///   A failure here is handled by the configured [`PersistFailurePolicy`].
/// - `logging` is the persistence fallback for requests that never reach
///   `response_filter` — the inner proxy answered the request
///   itself in `request_filter`, or proxying failed. The response is
///   already sent at that point, so any `Set-Cookie` values the store
///   returns are counted and reported to the optional diagnostic handler before
///   being discarded: external stores persist fine,
///   cookie-backed stores cannot. Eager refresh persistence prepares cookie
///   updates but does not deliver them: even a successful cookie save depends
///   on the response reaching the browser. See the
///   [lifecycle explanation](crate::_docs::explanation::login_lifecycle).
///
/// # Session credential stripping
///
/// Before forwarding, this proxy removes the session driver's cookies from the
/// inbound `Cookie` header, including cookie-session chunks and key-id sidecars.
/// Unrelated application cookies are preserved. The inner proxy can read identity
/// from its session context. A separate upstream service needs an explicit
/// identity assertion; see [Forward session identity](crate::_docs::how_to::identity).
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
/// # use huskarl::grant::authorization_code::AuthorizationCodeGrant;
/// # use huskarl_pingora::login::{
/// #     CaseSensitivity, DecodeDepth, GuardConfig, HasLoginSession, LoginConfig, LoginEngine, LoginProxy,
/// #     LoginRule, SessionDriver,
/// # };
/// # use pingora_proxy::ProxyHttp;
/// # fn build<P, SD>(
/// #     my_upstream: P,
/// #     login_config: LoginConfig,
/// #     grant: AuthorizationCodeGrant,
/// #     store: SD,
/// # ) where
/// #     P: ProxyHttp + Send + Sync,
/// #     P::CTX: HasLoginSession<SD::SessionType> + Send + Sync,
/// #     SD: SessionDriver + Send + Sync,
/// # {
/// // The login-state sealer is optional: omitted, it defaults to the session
/// // store's own sealer (the two seals are AAD-domain-separated, so sharing one
/// // key is safe). Pass `.sealer(...)` only to use a distinct one.
/// let engine = Arc::new(
///     LoginEngine::builder()
///         .config(login_config)
///         .grant(grant)
///         .session_store(store)
///         .build()
///         .expect("valid login config"),
/// );
///
/// let proxy = LoginProxy::builder()
///     .inner(my_upstream)
///     .engine(engine)
///     .path_guard(GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne))
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
    metrics_name: Option<String>,
    diagnostics: Option<DiagnosticHandler>,
}

#[bon::bon]
impl<P, SD> LoginProxy<P, SD>
where
    P: ProxyHttp + Send + Sync,
    P::CTX: HasLoginSession<SD::SessionType> + Send + Sync,
    SD: SessionDriver + Send + Sync,
{
    /// Starts a builder for a login proxy using a pre-built [`LoginEngine`].
    /// Call [`LoginProxyBuilder::build`] to validate routes and create the proxy.
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
        /// One entry per `route`/`subtree`/`blob_subtree` call, in registration order.
        /// Rule-id assignment and subtree-pattern expansion are deferred to
        /// `RuleRouter::from_registrations` at build time.
        #[builder(field)]
        routes: Vec<(RouteKind, String, LoginRule<SD::SessionType>)>,
        /// Inner proxy to invoke when the login rule permits the request.
        inner: P,
        /// Shared login engine that handles the OAuth flow and session lifecycle.
        engine: Arc<LoginEngine<SD>>,
        /// Fallback rule for paths that don't match any registered route.
        /// Defaults to [`LoginRule::required`] — i.e. everything is protected
        /// unless explicitly opened up.
        #[builder(default)]
        default: LoginRule<SD::SessionType>,
        /// Path-confusion configuration, including the required downstream case
        /// sensitivity and decode depth. There is no default: declare these
        /// assumptions with [`GuardConfig::new`]. Clone the configuration to share
        /// it with other guards that have the same downstream parsing assumptions.
        path_guard: GuardConfig,
        /// Decides how to react when the post-response session persist fails.
        ///
        /// Defaults to [`DefaultPersistFailurePolicy`]: fail closed when the
        /// owed post-response save (the retry of a failed eager refresh
        /// persist) fails — letting the response through would strand the
        /// rotated token.
        ///
        /// A replacement response becomes a filter error carrying its status;
        /// its headers and body are not used. Pingora 0.9 maps errors on fresh
        /// cache hits to 500; other paths normally use the supplied status.
        /// An inner `fail_to_proxy` override can also change error rendering.
        #[builder(default = Box::new(DefaultPersistFailurePolicy) as Box<dyn PersistFailurePolicy>)]
        persist_failure_policy: Box<dyn PersistFailurePolicy>,
        /// Whether to pass CORS preflight requests — `OPTIONS` carrying an
        /// `Access-Control-Request-Method` header — straight to the inner proxy,
        /// bypassing session loading and the per-route [`LoginRule`]. The
        /// path-confusion guard still validates the request path before it is
        /// passed through.
        ///
        /// Defaults to `true`. A browser sends a preflight **without** credentials,
        /// so no session cookie reaches us and there is no authorization decision to
        /// make: the preflight only negotiates CORS, which belongs to the inner proxy
        /// or a dedicated CORS filter, not this login layer.
        ///
        /// Set to `false` to instead route preflights through the normal flow (engine
        /// route handlers, rule lookup, path-confusion guard, session loading) — e.g.
        /// when a `required` route should refuse them outright rather than let the
        /// inner proxy answer.
        #[builder(default = true)]
        cors_passthrough: bool,
        /// Stable name for this adapter's metrics; unset emits `name=""`.
        /// Requires `metrics`. The shared engine retains its separately configured name.
        #[builder(into)]
        metrics_name: Option<String>,
        /// Handler for internally handled failures and stranded cookies.
        /// No handler is installed when omitted. Available without `metrics`.
        /// See [`LoginProxy::diagnostics`] for handler requirements.
        #[builder(with = |handler: impl Fn(LoginDiagnostic<'_>) + Send + Sync + 'static| Arc::new(handler) as DiagnosticHandler)]
        diagnostics: Option<DiagnosticHandler>,
    ) -> Result<Self, RouteConfigError> {
        for (_kind, pattern, rule) in &routes {
            if rule.public_check_requested() {
                return Err(RouteConfigError::PublicRuleWithCheck(pattern.clone()));
            }
        }
        if default.public_check_requested() {
            return Err(RouteConfigError::PublicRuleWithCheck("<default>".into()));
        }

        let registrations = routes.into_iter().map(|(kind, pattern, rule)| {
            let method = rule.method_match().clone();
            kind.registration(pattern, method, rule)
        });
        let routes = RuleRouter::from_registrations(default, path_guard, registrations)?;
        Ok(Self {
            inner,
            engine,
            routes,
            persist_failure_policy,
            cors_passthrough,
            metrics_name,
            diagnostics,
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
        self.routes.push((RouteKind::Exact, pattern.into(), rule));
        self
    }

    /// Applies a [`LoginRule`] to a path **and everything beneath it**.
    ///
    /// Mirrors `ResourcePolicyBuilder::subtree` on the resource side (plain code span, not a link:
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
        self.routes
            .push((RouteKind::Subtree, path.to_owned(), rule));
        self
    }

    /// Registers an exclusive subtree, rejecting nested route overrides at build time.
    ///
    /// The same ambiguity checks apply as for [`subtree`](Self::subtree).
    /// Encoded separators and dot-segments can pass only when analysis establishes
    /// that they stay within the same rule. NUL is denied in every active mode.
    pub fn blob_subtree(mut self, path: &str, rule: LoginRule<SD::SessionType>) -> Self {
        self.routes.push((RouteKind::Blob, path.to_owned(), rule));
        self
    }
}

impl<P, SD> LoginProxy<P, SD>
where
    P: ProxyHttp + Send + Sync,
    P::CTX: HasLoginSession<SD::SessionType> + Send + Sync,
    SD: SessionDriver + Send + Sync,
{
    /// Installs an application handler for internally handled failures and stranded
    /// cookies. Available independently of the `metrics` feature.
    ///
    /// The handler runs synchronously and may be called concurrently. It must not
    /// block or panic; panics propagate, and reentrant calls receive no serialization.
    /// For asynchronous export, copy only the needed fields into a bounded queue.
    /// The application owns redaction, sampling, queue overflow, and delivery policy.
    /// No handler is installed by default. Repeated calls replace the handler.
    /// To configure it during construction, use [`LoginProxyBuilder::diagnostics`].
    #[must_use]
    pub fn diagnostics(
        mut self,
        handler: impl Fn(LoginDiagnostic<'_>) + Send + Sync + 'static,
    ) -> Self {
        self.diagnostics = Some(Arc::new(handler));
        self
    }

    fn decision(&self, outcome: &'static str) {
        crate::metrics::emit_counter(
            "huskarl.pingora.login.check",
            outcome,
            self.metrics_name.as_deref(),
        );
    }

    fn observe_operation<T>(
        &self,
        operation: SessionOperation,
        phase: LoginPhase,
        result: &std::result::Result<T, SessionError>,
    ) {
        crate::metrics::login_operation(
            operation,
            phase,
            result.is_ok(),
            self.metrics_name.as_deref(),
        );
        if let Err(error) = result
            && let Some(handler) = &self.diagnostics
        {
            handler(LoginDiagnostic::SessionFailure {
                operation,
                phase,
                error,
            });
        }
    }

    fn report_stranded_cookies(&self, cookies: SetCookies) {
        if !cookies.is_empty() {
            crate::metrics::stranded_cookies(cookies.len(), self.metrics_name.as_deref());
            if let Some(handler) = &self.diagnostics {
                handler(LoginDiagnostic::StrandedCookies {
                    count: cookies.len(),
                });
            }
        }
        cookies.discard();
    }

    /// Returns a handle to the underlying [`LoginEngine`].
    ///
    /// Exposed so an inner proxy can drive engine primitives directly — for
    /// example, calling [`LoginEngine::redirect_to_login`] from a handler
    /// that wants to force re-authentication outside the normal routing
    /// policy.
    pub fn engine(&self) -> &Arc<LoginEngine<SD>> {
        &self.engine
    }

    /// Completes session work once, on the final downstream header block.
    async fn finalize_response(
        &self,
        response: &mut ResponseHeader,
        ctx: &mut P::CTX,
    ) -> Result<()> {
        let state = ctx.login_state_mut();
        if response.status.is_informational()
            && response.status != http::StatusCode::SWITCHING_PROTOCOLS
        {
            return Ok(());
        }
        if state.finalized {
            return Ok(());
        }
        state.finalized = true;
        crate::metrics::emit_counter(
            "huskarl.pingora.login.finalization",
            LoginPhase::Response.as_str(),
            self.metrics_name.as_deref(),
        );
        let maybe_sess = state.session.as_ref();
        let request_headers = std::mem::take(&mut state.request_headers);
        let set_cookies = std::mem::take(&mut state.set_cookies);
        let pending = state.pending.take();
        let terminate_requested = std::mem::replace(&mut state.terminate_requested, false);

        append_set_cookies(response, set_cookies)?;

        let Some(sess) = maybe_sess else {
            return Ok(());
        };

        if terminate_requested {
            // The owed persist (if any) is moot for a session being terminated.
            if let Some(pending) = pending {
                pending.abandon();
            }
            // The browser clears are built before server-side revocation and
            // are delivered whichever way revocation went: a backend failure
            // can leave a copied store pointer usable, but must not keep the
            // current browser logged in. Failing the request here would
            // replace this response — clears and all — and leave the client
            // holding a live session cookie, so report the revocation failure
            // instead and let operators monitor it.
            let (clears, revocation) = self
                .engine
                .terminate_session(sess, &request_headers)
                .await
                .into_parts();
            self.observe_operation(SessionOperation::Revoke, LoginPhase::Response, &revocation);
            append_set_cookies(response, clears)?;
            return Ok(());
        }

        // Fully persisted at load time — nothing owed.
        let Some(pending) = pending else {
            return Ok(());
        };
        let persisted = pending.commit(&self.engine, &request_headers).await;
        self.observe_operation(SessionOperation::Persist, LoginPhase::Response, &persisted);
        match persisted {
            Ok(cookies) => append_set_cookies(response, cookies),
            Err(e) => {
                match self.persist_failure_policy.handle(&e) {
                    // The filter cannot replace the body stream. Return a
                    // status-bearing error; Pingora's fresh-hit path maps it
                    // to 500, while its usual error handler honors the status.
                    Some(resp) => Err(Error::explain(
                        HTTPStatus(resp.status().as_u16()),
                        format!("failed to persist session: {}", error_chain(&e)),
                    )),
                    None => Ok(()),
                }
            }
        }
    }

    async fn forward_request(&self, session: &mut Session, ctx: &mut P::CTX) -> Result<bool>
    where
        SD::SessionType: Clone,
    {
        let handled = self.inner.request_filter(session, ctx).await?;
        let Some(response) = ctx.login_state_mut().response.take() else {
            return Ok(handled);
        };
        if handled || session.response_written().is_some() {
            return Err(Error::explain(
                InternalError,
                "queued login response requires an unwritten response and Ok(false)",
            ));
        }
        let (status, headers, body) = response.into_parts();
        let mut header = ResponseHeader::build(status, Some(headers.len() + 1))?;
        for (name, value) in headers {
            header.append_header(name, value)?;
        }
        header.remove_header(&http::header::TRANSFER_ENCODING);
        let body_allowed =
            status != http::StatusCode::NO_CONTENT && status != http::StatusCode::NOT_MODIFIED;
        if body_allowed {
            header.insert_header(http::header::CONTENT_LENGTH, body.len().to_string())?;
        } else {
            header.remove_header(&http::header::CONTENT_LENGTH);
        }
        self.response_filter(session, &mut header, ctx).await?;
        let send_body =
            body_allowed && session.req_header().method != http::Method::HEAD && !body.is_empty();
        session
            .write_response_header(Box::new(header), !send_body)
            .await?;
        if send_body {
            session.write_response_body(Some(body), true).await?;
        }
        Ok(true)
    }

    /// Serves a retryable `503` for a [`LoadedSession::RefreshUnavailable`]: the
    /// access token expired and its refresh is transiently failing, so the
    /// request is failed (not treated as anonymous) until the authorization
    /// server recovers.
    async fn serve_refresh_unavailable(&self, session: &mut Session) -> Result<bool> {
        let resp = self.engine.render_error(
            http::StatusCode::SERVICE_UNAVAILABLE,
            "session refresh temporarily unavailable",
        );
        write_login_response(session, resp, Vec::new()).await?;
        Ok(true)
    }

    /// Counts and renders a route-resolution denial.
    async fn serve_path_confusion(
        &self,
        session: &mut Session,
        reason: &ResolveError,
    ) -> Result<bool> {
        self.decision(crate::metrics::route_denial(reason));
        let status = resolve_error_status(reason);
        let resp = self.engine.render_error(status, reason.message());
        write_login_response(session, resp, vec![]).await?;
        Ok(true)
    }
}

/// Errors that can occur when building a [`LoginProxy`]'s route table.
///
/// Distinct from [`huskarl_login::ConfigError`], which covers session driver
/// and [`LoginConfig`](huskarl_login::LoginConfig) validation.
#[derive(Debug)]
#[non_exhaustive]
pub enum RouteConfigError {
    /// A public route has a custom check that can never run because public
    /// routes deliberately skip session loading.
    ///
    /// The string is the route pattern, or `"<default>"` for the default rule.
    PublicRuleWithCheck(String),
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
            Self::PublicRuleWithCheck(pattern) => write!(
                f,
                "public login rule for {pattern:?} has a custom check that can never run: public routes do not load a session"
            ),
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
            Self::PublicRuleWithCheck(_)
            | Self::Route { .. }
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
            RuleRouterError::EmptyMethodSet { pattern } => Self::Route {
                pattern,
                reason: "registration matches no method: its method set is empty",
            },
            RuleRouterError::EmptyPatternSet => Self::Route {
                pattern: String::new(),
                reason: "registration has no route patterns",
            },
            RuleRouterError::TooManyRegistrations => Self::Route {
                pattern: String::new(),
                reason: "too many route registrations",
            },
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
    // HEAD retains the response headers but must end without a body, including
    // on HTTP/2 where sending DATA would cause a protocol error.
    let send_body = session.req_header().method != http::Method::HEAD && !body.is_empty();
    session
        .write_response_header(Box::new(header), !send_body)
        .await?;
    if send_body {
        session.write_response_body(Some(body), true).await?;
    }
    Ok(())
}

/// Appends session `Set-Cookie` headers to the downstream response, after
/// Pingora cache processing.
///
/// When any cookie is appended, the response is forced to
/// `Cache-Control: no-store`: the upstream may have marked the response
/// cacheable, and a downstream shared cache storing a session cookie could
/// replay it to another user (RFC 6749 §5.1). Engine-authored responses
/// already carry `no-store`. An empty `cookies` (the steady-state authenticated
/// request) leaves the upstream's own cache headers untouched.
fn append_set_cookies(resp: &mut ResponseHeader, cookies: SetCookies) -> Result<()> {
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
    // `Clone` backs the deferred-persist path: the rare `ActivePending` load
    // clones the session into `LoginState` for the inner proxy, and
    // `PendingPersist::commit` requires it.
    SD::SessionType: Clone,
{
    type CTX = P::CTX;

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let req = session.req_header();
        let uri = req.uri.clone();
        let method = req.method.clone();
        let headers = &req.headers;

        // Preflights stay session-free but still cross the structural path guard;
        // non-browser clients can manufacture preflight-shaped requests.
        if self.cors_passthrough && is_cors_preflight(&method, headers) {
            if let Err(reason) = self.routes.resolve(uri.path(), &method) {
                return self.serve_path_confusion(session, &reason).await;
            }
            self.decision("preflight");
            return self.forward_request(session, ctx).await;
        }

        // The engine handles its configured callback / logout paths fully —
        // they take precedence over any user-registered route.
        if let Some(resp) = self
            .engine
            .try_handle_login_route(&method, headers, &uri)
            .await
        {
            self.decision("login_route");
            write_login_response(session, resp, vec![]).await?;
            return Ok(true);
        }

        // Resolve in one call: the path-confusion verdict, then the rule match — a
        // path a normalizing backend could route to a different rule is denied before
        // any rule applies. Only the bounded category enters metrics.
        let rule = match self.routes.resolve(uri.path(), &method) {
            Ok(matched) => matched.rule(),
            Err(reason) => {
                return self.serve_path_confusion(session, &reason).await;
            }
        };

        // Public routes bypass session handling entirely; the others differ
        // only in whether a missing session is fatal, plus an optional check.
        let (required, check) = match rule {
            LoginRule::Public { .. } => {
                self.decision("public");
                return self.forward_request(session, ctx).await;
            }
            LoginRule::Optional { check, .. } => (false, check),
            LoginRule::Required { check, .. } => (true, check),
        };

        let loaded = self.engine.load_session(headers).await;
        self.observe_operation(SessionOperation::Load, LoginPhase::Request, &loaded);
        let Ok(loaded) = loaded else {
            self.decision("server_error");
            let resp = self.engine.render_error(
                http::StatusCode::INTERNAL_SERVER_ERROR,
                "failed to load session",
            );
            write_login_response(session, resp, vec![]).await?;
            return Ok(true);
        };

        // Flatten the session state once, exhaustively: which session (if
        // any), what the response still owes the store, and which Set-Cookie
        // headers must reach the client.
        let (maybe_sess, pending, set_cookies) = match loaded {
            LoadedSession::Missing => (None, None, SetCookies::default()),
            LoadedSession::Cleared { clears, .. } => (None, None, clears),
            LoadedSession::Active {
                session: sess,
                set_cookies,
            } => (Some(sess), None, set_cookies),
            // The serving copy is cloned out of the pending persist so the
            // inner proxy sees the session in `LoginState` as usual; the
            // commit after the response carries its own copy.
            LoadedSession::ActivePending { pending } => (
                Some(pending.session().clone()),
                Some(pending),
                SetCookies::default(),
            ),
            // The access token expired and the refresh is transiently
            // unavailable — authentication can be neither confirmed nor refuted
            // right now. Serve a retryable error rather than bouncing the user
            // into a login flow against the same unavailable authorization
            // server, or leaking anonymous state into a per-user cache.
            LoadedSession::RefreshUnavailable => {
                self.decision("refresh_unavailable");
                return self.serve_refresh_unavailable(session).await;
            }
        };

        let Some(sess) = maybe_sess else {
            // No usable session. set_cookies carries clears for stale
            // cookies the engine decided to drop (expired, refresh failed).
            if required {
                self.decision("unauthenticated");
                let resp = self.engine.redirect_to_login(headers, &uri).await;
                write_login_response(session, resp, set_cookies.into_headers()).await?;
                return Ok(true);
            }
            self.decision("anonymous");
            ctx.login_state_mut()
                .prepare_forward(None, None, headers.clone(), set_cookies);
            return self.forward_request(session, ctx).await;
        };

        if let Some(check) = check
            && let Err(err) = check(&sess)
        {
            self.decision("forbidden");
            let (status, msg) = match err {
                CheckError::Forbidden(msg) => (http::StatusCode::FORBIDDEN, msg),
            };
            // The deny response may still owe the store a post-response save:
            // the retry of an eager refresh persist that failed. Best-effort —
            // the user is denied either way.
            let mut cookies = set_cookies.into_headers();
            if let Some(pending) = pending {
                let persisted = pending.commit(&self.engine, headers).await;
                self.observe_operation(SessionOperation::Persist, LoginPhase::Denied, &persisted);
                if let Ok(more) = persisted {
                    cookies.extend(more);
                }
            }
            let resp = self.engine.render_error(status, &msg);
            write_login_response(session, resp, cookies).await?;
            return Ok(true);
        }

        self.decision("authenticated");
        ctx.login_state_mut()
            .prepare_forward(Some(sess), pending, headers.clone(), set_cookies);

        self.forward_request(session, ctx).await
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // Pingora's header map is read-only; use its mutation methods to keep
        // the case-preserving header metadata in sync with the cookie values.
        let mut headers = upstream_request.headers.clone();
        self.engine.strip_session_credentials(&mut headers);
        upstream_request.remove_header(&http::header::COOKIE);
        for value in headers.get_all(http::header::COOKIE) {
            upstream_request.append_header("Cookie", value.clone())?;
        }

        self.inner
            .upstream_request_filter(session, upstream_request, ctx)
            .await
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        self.inner.response_filter(session, response, ctx).await?;
        self.finalize_response(response, ctx).await
    }

    async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut Self::CTX) {
        // Persistence fallback for requests that never reached
        // `response_filter`: the inner proxy wrote directly in
        // `request_filter`, or proxying failed. On a finalized response path
        // `response_filter` has already consumed the state and this
        // is a no-op. The response is gone, so `Set-Cookie` values can no
        // longer be delivered — external stores still persist correctly,
        // cookie-backed stores cannot.
        let state = ctx.login_state_mut();
        if state.finalized {
            self.inner.logging(session, e, ctx).await;
            return;
        }
        state.finalized = true;
        crate::metrics::emit_counter(
            "huskarl.pingora.login.finalization",
            LoginPhase::Logging.as_str(),
            self.metrics_name.as_deref(),
        );
        let set_cookies = std::mem::take(&mut state.set_cookies);
        self.report_stranded_cookies(set_cookies);
        if let Some(sess) = state.session.as_ref() {
            let request_headers = std::mem::take(&mut state.request_headers);
            let pending = state.pending.take();
            let terminate_requested = std::mem::replace(&mut state.terminate_requested, false);
            if terminate_requested {
                // The owed persist (if any) is moot for a session being terminated.
                if let Some(pending) = pending {
                    pending.abandon();
                }
                // The browser clears and the server-side revocation are
                // independent: the clears exist even when revocation fails.
                let (clears, revocation) = self
                    .engine
                    .terminate_session(sess, &request_headers)
                    .await
                    .into_parts();
                self.observe_operation(SessionOperation::Revoke, LoginPhase::Logging, &revocation);
                self.report_stranded_cookies(clears);
            } else if let Some(pending) = pending {
                let persisted = pending.commit(&self.engine, &request_headers).await;
                self.observe_operation(SessionOperation::Persist, LoginPhase::Logging, &persisted);
                if let Ok(cookies) = persisted {
                    self.report_stranded_cookies(cookies);
                }
            }
            // Otherwise fully persisted at load time — nothing owed.
        }

        self.inner.logging(session, e, ctx).await;
    }
}
