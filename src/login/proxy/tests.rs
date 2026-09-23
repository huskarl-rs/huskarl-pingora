//! Integration tests for [`LoginProxy`].
//!
//! These exercise the wrapper-level behavior: route matching, session
//! loading, gating, and persistence. The OAuth flow itself (callback,
//! refresh, expiry checks) is exercised in `huskarl-login`'s engine tests.

// Mock trait impls satisfy `async fn` signatures without awaiting.
#![allow(clippy::unused_async_trait_impl)]

use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use bon::Builder;
use bytes::Bytes;
use http::HeaderValue;
use huskarl::{
    core::{
        client_auth::NoAuth,
        http::{HttpClient, HttpResponse, Idempotency},
        jwk::OctBytes,
        platform::MaybeSendBoxFuture,
        secrets::{ProvidedSecret, Secret as _, SecretBytes},
    },
    grant::authorization_code::AuthorizationCodeGrant,
};
use huskarl_crypto_native::aead::AesGcmKey;
use huskarl_login::{
    CompletedLogin, ConfigError, DriverLoad, LoginConfig, SessionDriver, SessionError,
    SessionErrorKind, SessionLifetime, SessionPolicy, SessionState,
    core::crypto::seal::{AeadSealerUnsealer, AeadV1Sealer},
};
use pingora_core::upstreams::peer::HttpPeer;
use pingora_http::RequestHeader;
use pingora_proxy::{ProxyHttp, Session};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use super::*;
use crate::login::{LoginCtx, LoginRule};

// ── Mock session ─────────────────────────────────────────────────

#[derive(Clone, Builder)]
struct MockSession {
    #[builder(default = default_session_state())]
    state: SessionState,
    role: Option<&'static str>,
}

fn default_session_state() -> SessionState {
    let now = SystemTime::now();
    SessionState::builder()
        .token_expiry(now + Duration::from_hours(1))
        .created_at(now)
        .build()
}

/// A fabricated owed persist pairing `session` with a minimal refresh
/// response — the deferred save a post-response commit retries (a failed
/// eager refresh persist; see [`LoadedSession::ActivePending`]).
fn owed_persist_for<S>(session: S) -> huskarl_login::engine::PendingPersist<S> {
    let token_response = huskarl::grant::core::RawTokenResponse::builder()
        .access_token(huskarl::core::secrets::SecretString::new("access-token"))
        .token_type("Bearer")
        .build()
        .into_token_response(None, SystemTime::now())
        .unwrap();
    huskarl_login::engine::PendingPersist::new(session, token_response)
}

fn owed_persist() -> huskarl_login::engine::PendingPersist<MockSession> {
    owed_persist_for(MockSession::default())
}

impl Default for MockSession {
    fn default() -> Self {
        Self::builder().build()
    }
}

impl huskarl_login::Session for MockSession {
    fn state(&self) -> &SessionState {
        &self.state
    }

    fn set_state(&mut self, state: SessionState) {
        self.state = state;
    }
}

// ── Mock session store ───────────────────────────────────────────

#[derive(Builder, Default)]
struct MockSessionDriver {
    #[builder(with = |s: MockSession| Mutex::new(Some(s)), default)]
    load_session: Mutex<Option<MockSession>>,
    #[builder(with = |s: bool| Mutex::new(s), default)]
    revoke_called: Mutex<bool>,
    #[builder(with = |s: usize| Mutex::new(s), default)]
    save_calls: Mutex<usize>,
    #[builder(default)]
    fail_save: bool,
    #[builder(default)]
    fail_revoke: bool,
}

/// The `Set-Cookie` clear this driver emits for the browser's session cookie.
const MOCK_SESSION_CLEAR: &str = "mock-session=; Max-Age=0";

impl MockSessionDriver {
    fn was_revoke_called(&self) -> bool {
        *self.revoke_called.lock().unwrap()
    }
    fn was_save_called(&self) -> bool {
        *self.save_calls.lock().unwrap() > 0
    }
    fn save_count(&self) -> usize {
        *self.save_calls.lock().unwrap()
    }
}

impl huskarl_login::session::sealed::Sealed for MockSessionDriver {}

impl SessionDriver for MockSessionDriver {
    type SessionType = MockSession;
    type LoadError = Infallible;

    fn apply_session_policy(&mut self, _policy: &SessionPolicy) -> Result<(), ConfigError> {
        Ok(())
    }

    fn session_sealer(&self) -> Arc<dyn AeadSealerUnsealer> {
        // The engine is always built with an explicit `.sealer(...)` below, so
        // this default is never reached.
        unimplemented!()
    }

    fn clear_session_cookies(&self, _: &http::HeaderMap) -> Vec<HeaderValue> {
        vec![HeaderValue::from_static(MOCK_SESSION_CLEAR)]
    }

    fn strip_session_credentials(&self, headers: &mut http::HeaderMap) {
        let retained = headers
            .get(http::header::COOKIE)
            .and_then(|value| value.to_str().ok())
            .map(|value| {
                value
                    .split(';')
                    .map(str::trim)
                    .filter(|pair| !pair.starts_with("mock-session="))
                    .collect::<Vec<_>>()
                    .join("; ")
            });
        headers.remove(http::header::COOKIE);
        if let Some(retained) = retained.filter(|value| !value.is_empty()) {
            headers.insert(
                http::header::COOKIE,
                HeaderValue::from_str(&retained).unwrap(),
            );
        }
    }

    async fn create(
        &self,
        _: CompletedLogin,
        _: Duration,
        _: &http::HeaderMap,
    ) -> Result<(MockSession, Vec<HeaderValue>), SessionError> {
        unimplemented!()
    }
    async fn load(&self, _: &http::HeaderMap) -> Result<DriverLoad<MockSession>, Infallible> {
        Ok(self
            .load_session
            .lock()
            .unwrap()
            .take()
            .map_or(DriverLoad::Absent, DriverLoad::Valid))
    }
    async fn save(
        &self,
        _: &MockSession,
        _: &http::HeaderMap,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        *self.save_calls.lock().unwrap() += 1;
        if self.fail_save {
            return Err(SessionError::new(
                SessionErrorKind::Unavailable,
                "save failed",
            ));
        }
        Ok(vec![])
    }
    async fn revoke(&self, _: &MockSession) -> Result<(), SessionError> {
        *self.revoke_called.lock().unwrap() = true;
        if self.fail_revoke {
            return Err(SessionError::new(
                SessionErrorKind::Unavailable,
                "revoke failed",
            ));
        }
        Ok(())
    }
}

// ── Mock inner proxy ─────────────────────────────────────────────

struct InnerProxy {
    forwarded: Mutex<bool>,
}

impl InnerProxy {
    fn new() -> Self {
        Self {
            forwarded: Mutex::new(false),
        }
    }
    fn was_forwarded(&self) -> bool {
        *self.forwarded.lock().unwrap()
    }
}

#[async_trait]
impl ProxyHttp for InnerProxy {
    type CTX = LoginCtx<(), MockSession>;

    fn new_ctx(&self) -> Self::CTX {
        LoginCtx::new(())
    }

    async fn upstream_peer(
        &self,
        _: &mut Session,
        _: &mut Self::CTX,
    ) -> pingora_error::Result<Box<HttpPeer>> {
        unimplemented!()
    }

    async fn request_filter(
        &self,
        _: &mut Session,
        _: &mut Self::CTX,
    ) -> pingora_error::Result<bool> {
        *self.forwarded.lock().unwrap() = true;
        Ok(false)
    }
}

// ── Test fixtures ────────────────────────────────────────────────

async fn test_cipher() -> AesGcmKey {
    AesGcmKey::from_secret(
        ProvidedSecret::new(SecretBytes::new(vec![0u8; 32])).mapped(OctBytes::new("A256GCM")),
    )
    .await
    .unwrap()
}

async fn test_sealer() -> AeadV1Sealer<AesGcmKey> {
    AeadV1Sealer::new(test_cipher().await)
}

fn default_config() -> LoginConfig {
    LoginConfig::builder()
        .callback_path("/callback")
        .scope(vec![])
        .session_lifetime(SessionLifetime::Bounded(Duration::from_hours(8)))
        .build()
        .unwrap()
}

// ── Test grant (never actually exchanged; redirect_to_login uses start()) ──

struct MockHttpClient;

impl HttpClient for MockHttpClient {
    fn execute(
        &self,
        _: http::Request<Bytes>,
        _: Idempotency,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, huskarl::core::Error>> {
        unimplemented!("wrapper tests never reach the token endpoint")
    }
}

/// A real `AuthorizationCodeGrant` over a never-called HTTP double. `start()`
/// uses direct delivery (no PAR) and performs no HTTP, and these wrapper
/// tests never complete a token exchange.
async fn test_grant() -> AuthorizationCodeGrant {
    AuthorizationCodeGrant::builder()
        .client_id("client")
        .http_client(MockHttpClient)
        .client_auth(NoAuth)
        .token_endpoint("https://auth.example.com/token".parse().unwrap())
        .authorization_endpoint("https://auth.example.com/authorize".parse().unwrap())
        .redirect_uri("https://app.example.com/callback")
        .build()
        .await
        .unwrap()
}

// ── Build helpers ────────────────────────────────────────────────

type TestProxy = LoginProxy<InnerProxy, MockSessionDriver>;

/// Wraps a session store in a `LoginEngine` over the shared test config, grant,
/// and cipher — the engine every proxy-under-test is built on.
async fn build_engine<SD: SessionDriver>(store: SD) -> Arc<huskarl_login::engine::LoginEngine<SD>> {
    Arc::new(
        huskarl_login::engine::LoginEngine::builder()
            .config(default_config())
            .grant(test_grant().await)
            .session_store(store)
            .sealer(test_sealer().await)
            .build()
            .unwrap(),
    )
}

/// A rule check that only admits sessions whose role is `"admin"`.
fn admin_only(s: &MockSession) -> Result<(), CheckError> {
    if s.role == Some("admin") {
        Ok(())
    } else {
        Err(CheckError::Forbidden("admin only".into()))
    }
}

async fn build_proxy_with_routes(
    store: MockSessionDriver,
    routes: Vec<(&'static str, LoginRule<MockSession>)>,
) -> TestProxy {
    let mut builder = LoginProxy::builder()
        .inner(InnerProxy::new())
        .engine(build_engine(store).await)
        .case_sensitivity(crate::login::CaseSensitivity::Sensitive)
        .decode_depth(crate::login::DecodeDepth::UpToOne);
    for (pattern, rule) in routes {
        builder = builder.route(pattern, rule);
    }
    builder.build().expect("valid routes")
}

async fn build_proxy(store: MockSessionDriver) -> TestProxy {
    build_proxy_with_routes(store, vec![]).await
}

async fn make_session(method: &str, path: &str, extra_headers: &str) -> (Session, DuplexStream) {
    let raw = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n{extra_headers}\r\n");
    let (mut client, server) = tokio::io::duplex(4096);
    client.write_all(raw.as_bytes()).await.unwrap();
    let mut session = Session::new_h1(Box::new(server));
    session.downstream_session.read_request().await.unwrap();
    (session, client)
}

fn set_cookies(resp: &pingora_http::ResponseHeader) -> Vec<&str> {
    resp.headers
        .get_all(http::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect()
}

async fn read_status(client: &mut DuplexStream) -> u16 {
    let mut buf = vec![0u8; 8192];
    let n = client.read(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf[..n]).to_string();
    text.lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

// ── Default rule (required) ──────────────────────────────────────

#[tokio::test]
async fn default_required_with_session_forwards() {
    let proxy = build_proxy(
        MockSessionDriver::builder()
            .load_session(MockSession::default())
            .build(),
    )
    .await;
    let (mut s, _c) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    let handled = proxy.request_filter(&mut s, &mut ctx).await.unwrap();

    assert!(!handled);
    assert!(proxy.inner.was_forwarded());
    assert!(ctx.login_state().session.is_some());
}

#[tokio::test]
async fn default_required_no_session_xhr_returns_401() {
    let proxy = build_proxy(MockSessionDriver::default()).await;
    let (mut s, mut c) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    let handled = proxy.request_filter(&mut s, &mut ctx).await.unwrap();

    assert!(handled);
    assert!(!proxy.inner.was_forwarded());
    assert_eq!(read_status(&mut c).await, 401);
}

#[tokio::test]
async fn default_required_no_session_navigation_redirects() {
    let proxy = build_proxy(MockSessionDriver::default()).await;
    let (mut s, mut c) = make_session("GET", "/dashboard", "Sec-Fetch-Mode: navigate\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    let handled = proxy.request_filter(&mut s, &mut ctx).await.unwrap();

    assert!(handled);
    assert!(!proxy.inner.was_forwarded());
    assert_eq!(read_status(&mut c).await, 302);
}

// ── Subtree matching ─────────────────────────────────────────────

#[tokio::test]
async fn subtree_required_covers_path_and_descendants() {
    let engine = Arc::new(
        huskarl_login::engine::LoginEngine::builder()
            .config(default_config())
            .grant(test_grant().await)
            .session_store(MockSessionDriver::default())
            .sealer(test_sealer().await)
            .build()
            .unwrap(),
    );
    let proxy = LoginProxy::builder()
        .inner(InnerProxy::new())
        .engine(engine)
        .case_sensitivity(crate::login::CaseSensitivity::Sensitive)
        .decode_depth(DecodeDepth::UpToOne)
        .subtree("/dashboard", LoginRule::required())
        .build()
        .expect("valid routes");

    // No session: the bare path, the trailing-slash form, and descendants are
    // all gated (401 for an XHR request).
    for path in ["/dashboard", "/dashboard/", "/dashboard/reports"] {
        let (mut s, mut c) = make_session("GET", path, "Accept: application/json\r\n").await;
        let mut ctx = proxy.inner.new_ctx();

        let handled = proxy.request_filter(&mut s, &mut ctx).await.unwrap();

        assert!(handled, "{path} should be gated");
        assert_eq!(read_status(&mut c).await, 401, "{path}");
    }
}

// ── Public routes ────────────────────────────────────────────────

#[tokio::test]
async fn public_route_passes_through_without_loading() {
    let store = MockSessionDriver::builder()
        .load_session(MockSession::default())
        .build();
    let proxy = build_proxy_with_routes(store, vec![("/health", LoginRule::public())]).await;
    let (mut s, _c) = make_session("GET", "/health", "").await;
    let mut ctx = proxy.inner.new_ctx();

    let handled = proxy.request_filter(&mut s, &mut ctx).await.unwrap();

    assert!(!handled);
    assert!(proxy.inner.was_forwarded());
    // Public routes skip session loading — no session in ctx even though the
    // store had one ready.
    assert!(ctx.login_state().session.is_none());
}

#[tokio::test]
async fn session_cookie_is_stripped_but_application_cookies_are_preserved() {
    let proxy = build_proxy_with_routes(
        MockSessionDriver::default(),
        vec![("/health", LoginRule::public())],
    )
    .await;
    let (mut session, _client) = make_session(
        "GET",
        "/health",
        "Cookie: mock-session=secret; theme=dark\r\n",
    )
    .await;
    let mut ctx = proxy.inner.new_ctx();
    proxy.request_filter(&mut session, &mut ctx).await.unwrap();

    let mut upstream = RequestHeader::build("GET", b"/health", None).unwrap();
    upstream
        .insert_header("Cookie", "mock-session=secret; theme=dark")
        .unwrap();

    proxy
        .upstream_request_filter(&mut session, &mut upstream, &mut ctx)
        .await
        .unwrap();

    assert_eq!(
        upstream.headers.get(http::header::COOKIE).unwrap(),
        "theme=dark"
    );
}

#[tokio::test]
async fn cookie_header_is_removed_when_it_only_contains_the_session_cookie() {
    let proxy = build_proxy_with_routes(
        MockSessionDriver::default(),
        vec![("/health", LoginRule::public())],
    )
    .await;
    let (mut session, _client) =
        make_session("GET", "/health", "Cookie: mock-session=secret\r\n").await;
    let mut ctx = proxy.inner.new_ctx();
    proxy.request_filter(&mut session, &mut ctx).await.unwrap();

    let mut upstream = RequestHeader::build("GET", b"/health", None).unwrap();
    upstream
        .insert_header("Cookie", "mock-session=secret")
        .unwrap();

    proxy
        .upstream_request_filter(&mut session, &mut upstream, &mut ctx)
        .await
        .unwrap();

    assert!(upstream.headers.get(http::header::COOKIE).is_none());
}

// ── Optional routes ──────────────────────────────────────────────

#[tokio::test]
async fn optional_route_forwards_with_session_when_present() {
    let store = MockSessionDriver::builder()
        .load_session(MockSession::default())
        .build();
    let proxy = build_proxy_with_routes(store, vec![("/", LoginRule::optional())]).await;
    let (mut s, _c) = make_session("GET", "/", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    let handled = proxy.request_filter(&mut s, &mut ctx).await.unwrap();

    assert!(!handled);
    assert!(proxy.inner.was_forwarded());
    assert!(ctx.login_state().session.is_some());
}

#[tokio::test]
async fn optional_route_forwards_without_session() {
    let proxy = build_proxy_with_routes(
        MockSessionDriver::default(),
        vec![("/", LoginRule::optional())],
    )
    .await;
    let (mut s, _c) = make_session("GET", "/", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    let handled = proxy.request_filter(&mut s, &mut ctx).await.unwrap();

    assert!(!handled);
    assert!(proxy.inner.was_forwarded());
    assert!(ctx.login_state().session.is_none());
}

// ── Required check (authorization) ───────────────────────────────

#[tokio::test]
async fn required_check_pass_forwards() {
    let store = MockSessionDriver::builder()
        .load_session(MockSession::builder().role("admin").build())
        .build();
    let proxy = build_proxy_with_routes(
        store,
        vec![("/admin", LoginRule::required().check(admin_only))],
    )
    .await;
    let (mut s, _c) = make_session("GET", "/admin", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    let handled = proxy.request_filter(&mut s, &mut ctx).await.unwrap();

    assert!(!handled);
    assert!(proxy.inner.was_forwarded());
}

#[tokio::test]
async fn required_check_fail_returns_403() {
    let store = MockSessionDriver::builder()
        .load_session(MockSession::builder().role("user").build())
        .build();
    let proxy = build_proxy_with_routes(
        store,
        vec![("/admin", LoginRule::required().check(admin_only))],
    )
    .await;
    let (mut s, mut c) = make_session("GET", "/admin", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    let handled = proxy.request_filter(&mut s, &mut ctx).await.unwrap();

    assert!(handled);
    assert!(!proxy.inner.was_forwarded());
    assert_eq!(read_status(&mut c).await, 403);
}

// ── CORS preflight ───────────────────────────────────────────────

#[tokio::test]
async fn cors_preflight_passes_through() {
    let proxy = build_proxy(MockSessionDriver::default()).await;
    let (mut s, _c) =
        make_session("OPTIONS", "/api", "Access-Control-Request-Method: POST\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    let handled = proxy.request_filter(&mut s, &mut ctx).await.unwrap();

    assert!(!handled);
    assert!(proxy.inner.was_forwarded());
}

#[tokio::test]
async fn cors_preflight_not_passed_through_when_disabled() {
    // With cors_passthrough(false) a preflight is subject to the normal flow: the
    // default `required` rule has no session, so the engine gates it instead of
    // letting it reach the inner proxy.
    let proxy = LoginProxy::builder()
        .inner(InnerProxy::new())
        .engine(build_engine(MockSessionDriver::default()).await)
        .case_sensitivity(crate::login::CaseSensitivity::Sensitive)
        .decode_depth(DecodeDepth::UpToOne)
        .cors_passthrough(false)
        .build()
        .expect("valid routes");
    let (mut s, _c) =
        make_session("OPTIONS", "/api", "Access-Control-Request-Method: POST\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    let handled = proxy.request_filter(&mut s, &mut ctx).await.unwrap();

    assert!(handled, "preflight gated by the required rule");
    assert!(!proxy.inner.was_forwarded());
}

#[tokio::test]
async fn cors_preflight_still_runs_path_confusion_guard() {
    let proxy = build_structural_proxy(
        vec![("/dashboard", LoginRule::required())],
        crate::login::GuardMode::RejectAmbiguous,
    )
    .await;
    let (mut session, mut client) = make_session(
        "OPTIONS",
        "/x/../dashboard",
        "Access-Control-Request-Method: POST\r\n",
    )
    .await;
    let mut ctx = proxy.inner.new_ctx();

    let handled = proxy.request_filter(&mut session, &mut ctx).await.unwrap();

    assert!(handled);
    assert!(!proxy.inner.was_forwarded());
    assert_eq!(read_status(&mut client).await, 400);
}

// ── Callback handling delegates to engine ────────────────────────

#[tokio::test]
async fn callback_with_missing_state_returns_400() {
    let proxy = build_proxy(MockSessionDriver::default()).await;
    let (mut s, mut c) = make_session("GET", "/callback?code=abc", "").await;
    let mut ctx = proxy.inner.new_ctx();

    let handled = proxy.request_filter(&mut s, &mut ctx).await.unwrap();

    assert!(handled);
    assert!(!proxy.inner.was_forwarded());
    assert_eq!(read_status(&mut c).await, 400);
}

// ── upstream_response_filter persistence paths ───────────────────

#[tokio::test]
async fn response_filter_save_on_dirty_persistence() {
    let store = MockSessionDriver::builder()
        .load_session(MockSession::default())
        .build();
    let proxy = build_proxy(store).await;
    let (mut s, _c) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    proxy.request_filter(&mut s, &mut ctx).await.unwrap();
    // A normal load owes nothing; force a pending save to exercise the branch
    // (in the wild this is the retry of a failed eager refresh persist).
    ctx.login_state_mut().pending = Some(owed_persist());

    let mut resp = pingora_http::ResponseHeader::build(200, Some(1)).unwrap();
    proxy
        .upstream_response_filter(&mut s, &mut resp, &mut ctx)
        .await
        .unwrap();

    assert!(proxy.engine().session_store().was_save_called());
    assert!(!proxy.engine().session_store().was_revoke_called());
}

#[tokio::test]
async fn response_filter_owes_nothing_on_plain_request() {
    // A loaded, fully-persisted session with no owed save touches no store.
    // (Activity/idle tracking is now server-side in huskarl-login's liveness
    // store, not adapter-visible.)
    let store = MockSessionDriver::builder()
        .load_session(MockSession::default())
        .build();
    let proxy = build_proxy(store).await;
    let (mut s, _c) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    proxy.request_filter(&mut s, &mut ctx).await.unwrap();

    let mut resp = pingora_http::ResponseHeader::build(200, Some(1)).unwrap();
    proxy
        .upstream_response_filter(&mut s, &mut resp, &mut ctx)
        .await
        .unwrap();

    assert!(!proxy.engine().session_store().was_save_called());
    assert!(!proxy.engine().session_store().was_revoke_called());
}

#[tokio::test]
async fn response_filter_termination_path() {
    let store = MockSessionDriver::builder()
        .load_session(MockSession::default())
        .build();
    let proxy = build_proxy(store).await;
    let (mut s, _c) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    proxy.request_filter(&mut s, &mut ctx).await.unwrap();
    ctx.login_state_mut().terminate_requested = true;

    let mut resp = pingora_http::ResponseHeader::build(200, Some(1)).unwrap();
    proxy
        .upstream_response_filter(&mut s, &mut resp, &mut ctx)
        .await
        .unwrap();

    assert!(proxy.engine().session_store().was_revoke_called());
    assert!(!proxy.engine().session_store().was_save_called());
    assert_eq!(set_cookies(&resp), vec![MOCK_SESSION_CLEAR]);
}

#[tokio::test]
async fn response_filter_termination_delivers_clears_when_revocation_fails() {
    // The browser clears are built before server-side revocation and must
    // reach the response either way: a store outage can leave a copied
    // pointer usable, but must not keep this browser logged in. Failing the
    // request instead would replace the response — clears and all.
    let store = MockSessionDriver::builder()
        .load_session(MockSession::default())
        .fail_revoke(true)
        .build();
    let proxy = build_proxy(store).await;
    let (mut s, _c) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    proxy.request_filter(&mut s, &mut ctx).await.unwrap();
    ctx.login_state_mut().terminate_requested = true;

    let mut resp = pingora_http::ResponseHeader::build(200, Some(1)).unwrap();
    proxy
        .upstream_response_filter(&mut s, &mut resp, &mut ctx)
        .await
        .unwrap();

    assert!(proxy.engine().session_store().was_revoke_called());
    assert_eq!(set_cookies(&resp), vec![MOCK_SESSION_CLEAR]);
}

#[tokio::test]
async fn response_filter_forces_no_store_when_session_cookie_appended() {
    // A re-sealed session cookie (here, an eager-refresh result handed back on
    // the load state) riding on the upstream response must not be cacheable by
    // shared caches — even if the upstream marked it cacheable (RFC 6749 §5.1).
    let store = MockSessionDriver::builder()
        .load_session(MockSession::default())
        .build();
    let proxy = build_proxy(store).await;
    let (mut s, _c) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    proxy.request_filter(&mut s, &mut ctx).await.unwrap();
    let (set_cookies, revocation) = proxy
        .engine()
        .terminate_session(&MockSession::default(), &http::HeaderMap::new())
        .await
        .into_parts();
    revocation.unwrap();
    ctx.login_state_mut().set_cookies = set_cookies;

    let mut resp = pingora_http::ResponseHeader::build(200, Some(2)).unwrap();
    resp.insert_header(http::header::CACHE_CONTROL, "max-age=600")
        .unwrap();
    proxy
        .upstream_response_filter(&mut s, &mut resp, &mut ctx)
        .await
        .unwrap();

    assert_eq!(
        resp.headers
            .get(http::header::CACHE_CONTROL)
            .unwrap()
            .to_str()
            .unwrap(),
        "no-store",
        "a session Set-Cookie on the upstream response must override caching",
    );
    assert!(resp.headers.get(http::header::SET_COOKIE).is_some());
}

#[tokio::test]
async fn response_filter_preserves_cache_control_without_session_cookie() {
    // Steady-state authenticated request: no owed persistence, no session
    // cookie. The upstream's cache headers must be left exactly as set.
    let store = MockSessionDriver::builder()
        .load_session(MockSession::default())
        .build();
    let proxy = build_proxy(store).await;
    let (mut s, _c) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    proxy.request_filter(&mut s, &mut ctx).await.unwrap();

    let mut resp = pingora_http::ResponseHeader::build(200, Some(1)).unwrap();
    resp.insert_header(http::header::CACHE_CONTROL, "max-age=600")
        .unwrap();
    proxy
        .upstream_response_filter(&mut s, &mut resp, &mut ctx)
        .await
        .unwrap();

    assert_eq!(
        resp.headers
            .get(http::header::CACHE_CONTROL)
            .unwrap()
            .to_str()
            .unwrap(),
        "max-age=600",
        "a request carrying no session cookie must keep the upstream cache headers",
    );
}

// ── Persist failure policy ───────────────────────────────────────

#[tokio::test]
async fn persist_save_failure_fails_closed_with_policy_status() {
    // Save is the retry of a failed eager refresh persist — the default
    // policy fails closed (503) rather than strand the rotated token.
    let mut store = MockSessionDriver::builder()
        .load_session(MockSession::default())
        .build();

    store.fail_save = true;
    let proxy = build_proxy(store).await;
    let (mut s, _c) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    proxy.request_filter(&mut s, &mut ctx).await.unwrap();
    ctx.login_state_mut().pending = Some(owed_persist());

    let mut resp = pingora_http::ResponseHeader::build(200, Some(1)).unwrap();
    let result = proxy
        .upstream_response_filter(&mut s, &mut resp, &mut ctx)
        .await;

    let err = result.unwrap_err();
    assert!(matches!(
        err.etype(),
        pingora_error::ErrorType::HTTPStatus(503)
    ));
}

// ── Persistence on non-proxied paths ─────────────────────────────

#[tokio::test]
async fn denied_check_returns_403() {
    // A rule check that denies the request produces a 403 handled in
    // `request_filter`. (The persist-on-denied branch only fires for an owed
    // save from a failed eager refresh, which this mock can't produce; that
    // path is covered in huskarl-login.)
    let session = MockSession {
        state: default_session_state(),
        role: Some("user"),
    };
    let store = MockSessionDriver::builder().load_session(session).build();
    let proxy = build_proxy_with_routes(
        store,
        vec![("/admin", LoginRule::required().check(admin_only))],
    )
    .await;
    let (mut s, mut c) = make_session("GET", "/admin", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    let handled = proxy.request_filter(&mut s, &mut ctx).await.unwrap();

    assert!(handled);
    assert_eq!(read_status(&mut c).await, 403);
}

#[tokio::test]
async fn logging_fallback_persists_when_response_not_proxied() {
    // The inner proxy self-handled the request (or proxying failed), so
    // `upstream_response_filter` never ran — `logging` picks up the owed save.
    let store = MockSessionDriver::builder()
        .load_session(MockSession::default())
        .build();
    let proxy = build_proxy(store).await;
    let (mut s, _c) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    proxy.request_filter(&mut s, &mut ctx).await.unwrap();
    ctx.login_state_mut().pending = Some(owed_persist());
    proxy.logging(&mut s, None, &mut ctx).await;

    assert!(proxy.engine().session_store().was_save_called());
}

#[tokio::test]
async fn logging_after_response_filter_does_not_double_persist() {
    let store = MockSessionDriver::builder()
        .load_session(MockSession::default())
        .build();
    let proxy = build_proxy(store).await;
    let (mut s, _c) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    proxy.request_filter(&mut s, &mut ctx).await.unwrap();
    ctx.login_state_mut().pending = Some(owed_persist());

    let mut resp = pingora_http::ResponseHeader::build(200, Some(1)).unwrap();
    proxy
        .upstream_response_filter(&mut s, &mut resp, &mut ctx)
        .await
        .unwrap();
    proxy.logging(&mut s, None, &mut ctx).await;

    assert_eq!(proxy.engine().session_store().save_count(), 1);
}

#[tokio::test]
async fn logging_fallback_revokes_when_termination_requested() {
    let store = MockSessionDriver::builder()
        .load_session(MockSession::default())
        .build();
    let proxy = build_proxy(store).await;
    let (mut s, _c) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    proxy.request_filter(&mut s, &mut ctx).await.unwrap();
    ctx.login_state_mut().terminate_requested = true;
    proxy.logging(&mut s, None, &mut ctx).await;

    assert!(proxy.engine().session_store().was_revoke_called());
}

#[tokio::test]
async fn response_filter_no_session_does_nothing() {
    let proxy = build_proxy_with_routes(
        MockSessionDriver::default(),
        vec![("/", LoginRule::optional())],
    )
    .await;
    let (mut s, _c) = make_session("GET", "/", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    proxy.request_filter(&mut s, &mut ctx).await.unwrap();

    let mut resp = pingora_http::ResponseHeader::build(200, Some(1)).unwrap();
    proxy
        .upstream_response_filter(&mut s, &mut resp, &mut ctx)
        .await
        .unwrap();

    assert!(!proxy.engine().session_store().was_revoke_called());
    assert!(!proxy.engine().session_store().was_save_called());
}

// ── Path-confusion guard ────────────────────────────────────────

async fn build_structural_proxy(
    routes: Vec<(&'static str, LoginRule<MockSession>)>,
    guard_mode: crate::login::GuardMode,
) -> TestProxy {
    let mut builder = LoginProxy::builder()
        .inner(InnerProxy::new())
        .engine(build_engine(MockSessionDriver::default()).await)
        .case_sensitivity(crate::login::CaseSensitivity::Sensitive)
        .decode_depth(DecodeDepth::UpToOne)
        .guard_mode(guard_mode);
    for (pattern, rule) in routes {
        builder = builder.subtree(pattern, rule);
    }
    builder.build().expect("valid routes")
}

#[tokio::test]
async fn structural_denies_traversal_into_subtree() {
    let proxy = build_structural_proxy(
        vec![("/dashboard", LoginRule::required())],
        crate::login::GuardMode::RejectAmbiguous,
    )
    .await;
    let (mut s, mut c) =
        make_session("GET", "/x/../dashboard", "Sec-Fetch-Mode: navigate\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    let handled = proxy.request_filter(&mut s, &mut ctx).await.unwrap();

    assert!(handled);
    assert!(!proxy.inner.was_forwarded());
    assert_eq!(read_status(&mut c).await, 400);
}

#[tokio::test]
async fn structural_denies_path_param_vector() {
    let proxy = build_structural_proxy(
        vec![("/dashboard", LoginRule::required())],
        crate::login::GuardMode::RejectAmbiguous,
    )
    .await;
    let (mut s, mut c) = make_session(
        "GET",
        "/dashboard/..;/secret",
        "Accept: application/json\r\n",
    )
    .await;
    let mut ctx = proxy.inner.new_ctx();

    let handled = proxy.request_filter(&mut s, &mut ctx).await.unwrap();

    assert!(handled);
    assert_eq!(read_status(&mut c).await, 400);
}

#[tokio::test]
async fn structural_allows_same_rule_encoded_content() {
    // Non-structural encoded content (`%20`) decodes to a deeper path under the same
    // public `/files/{*rest}` rule — no route change → forwarded. (A structural byte
    // like `%2f` would be denied under the uniform-live model unless declared opaque.)
    let proxy = build_structural_proxy(
        vec![("/files", LoginRule::public())],
        crate::login::GuardMode::RejectAmbiguous,
    )
    .await;
    let (mut s, _c) = make_session("GET", "/files/a%20b", "").await;
    let mut ctx = proxy.inner.new_ctx();

    let handled = proxy.request_filter(&mut s, &mut ctx).await.unwrap();

    assert!(!handled);
    assert!(proxy.inner.was_forwarded());
}

#[tokio::test]
async fn method_specific_rule_does_not_escape_to_catchall() {
    // A method gap must deny before session loading or catch-all fallback.
    let proxy = build_proxy_with_routes(
        MockSessionDriver::default(),
        vec![
            ("/{*rest}", LoginRule::public()),
            ("/admin", LoginRule::public().method(http::Method::GET)),
        ],
    )
    .await;

    // GET /admin → its GET-public rule → forwarded.
    let (mut s, _c) = make_session("GET", "/admin", "").await;
    let mut ctx = proxy.inner.new_ctx();
    let handled = proxy.request_filter(&mut s, &mut ctx).await.unwrap();
    assert!(!handled);
    assert!(proxy.inner.was_forwarded());

    // POST has no configured policy and returns 403.
    let proxy = build_proxy_with_routes(
        MockSessionDriver::default(),
        vec![
            ("/{*rest}", LoginRule::public()),
            ("/admin", LoginRule::public().method(http::Method::GET)),
        ],
    )
    .await;
    let (mut s, mut c) = make_session("POST", "/admin", "").await;
    let mut ctx = proxy.inner.new_ctx();
    let _ = proxy.request_filter(&mut s, &mut ctx).await.unwrap();
    assert!(!proxy.inner.was_forwarded());
    assert_eq!(read_status(&mut c).await, 403);
}

#[tokio::test]
async fn structural_off_allows_traversal() {
    let proxy = build_structural_proxy(
        vec![("/dashboard", LoginRule::required())],
        crate::login::GuardMode::Disabled,
    )
    .await;
    let (mut s, mut c) =
        make_session("GET", "/x/../dashboard", "Sec-Fetch-Mode: navigate\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    let handled = proxy.request_filter(&mut s, &mut ctx).await.unwrap();

    // No guard → default (required) rule, unauthenticated navigation → 302.
    assert!(handled);
    assert_eq!(read_status(&mut c).await, 302);
}

#[tokio::test]
async fn build_rejects_pattern_with_empty_segment() {
    let result = LoginProxy::builder()
        .inner(InnerProxy::new())
        .engine(build_engine(MockSessionDriver::default()).await)
        .case_sensitivity(crate::login::CaseSensitivity::Sensitive)
        .decode_depth(DecodeDepth::UpToOne)
        .route("/a/b", LoginRule::public())
        .route("/a//b", LoginRule::required())
        .build();
    assert!(matches!(
        result,
        Err(crate::login::RouteConfigError::Route { pattern, reason })
            if pattern == "/a//b" && reason == "route pattern has an empty path segment"
    ));
}

#[tokio::test]
async fn build_rejects_check_on_public_rule() {
    let result = LoginProxy::builder()
        .inner(InnerProxy::new())
        .engine(build_engine(MockSessionDriver::default()).await)
        .case_sensitivity(crate::login::CaseSensitivity::Sensitive)
        .decode_depth(DecodeDepth::UpToOne)
        .route("/health", LoginRule::public().check(admin_only))
        .build();

    assert!(matches!(
        result,
        Err(crate::login::RouteConfigError::PublicRuleWithCheck(pattern))
            if pattern == "/health"
    ));
}

// ── Store-backed (server-side) integration ───────────────────────
//
// The tests above drive the low-level `SessionDriver` through a mock. These
// exercise the real `StoreBackedSessionStore` over a user-implemented
// `ExternalSessionStore`, using `PersistedSessionState` as the session type —
// the "simplest case" server-side setup — end to end through `LoginProxy`.
// Everything is imported from the `crate::login` facade, so the test also
// pins that the server-side path is reachable without dipping into
// `huskarl_login` directly.
mod store_backed {
    use huskarl_login::testing::InMemoryExternalSessionStore;

    use super::*;
    use crate::login::{LoginProxy, PersistedSessionState, StoreBackedSessionStore};

    // ── In-memory external store, keyed by session key, with call counters ──

    type InMemoryStore = InMemoryExternalSessionStore<PersistedSessionState>;

    // ── Inner proxy whose context carries a `PersistedSessionState` ─────────

    struct StoreInner {
        forwarded: Mutex<bool>,
    }
    impl StoreInner {
        fn new() -> Self {
            Self {
                forwarded: Mutex::new(false),
            }
        }
        fn was_forwarded(&self) -> bool {
            *self.forwarded.lock().unwrap()
        }
    }

    #[async_trait]
    impl ProxyHttp for StoreInner {
        type CTX = LoginCtx<(), PersistedSessionState>;

        fn new_ctx(&self) -> Self::CTX {
            LoginCtx::new(())
        }

        async fn upstream_peer(
            &self,
            _: &mut Session,
            _: &mut Self::CTX,
        ) -> pingora_error::Result<Box<HttpPeer>> {
            unimplemented!()
        }

        async fn request_filter(
            &self,
            _: &mut Session,
            _: &mut Self::CTX,
        ) -> pingora_error::Result<bool> {
            *self.forwarded.lock().unwrap() = true;
            Ok(false)
        }
    }

    // ── Build helpers ──────────────────────────────────────────────────────

    type StoreProxy = LoginProxy<StoreInner, StoreBackedSessionStore<InMemoryStore>>;

    async fn build_store(external: InMemoryStore) -> StoreBackedSessionStore<InMemoryStore> {
        StoreBackedSessionStore::builder()
            .external(external)
            .sealer(test_sealer().await)
            .cookie_name("session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build()
    }

    async fn build_store_proxy(store: StoreBackedSessionStore<InMemoryStore>) -> StoreProxy {
        LoginProxy::builder()
            .inner(StoreInner::new())
            .engine(build_engine(store).await)
            .case_sensitivity(crate::login::CaseSensitivity::Sensitive)
            .decode_depth(DecodeDepth::UpToOne)
            .build()
            .expect("valid routes")
    }

    /// A minimal completed login (bearer token, no ID token claims) — enough to
    /// drive `SessionDriver::create`, which seeds the external store and mints
    /// the encrypted pointer cookie.
    fn completed_login() -> CompletedLogin {
        let token_response = huskarl::grant::core::RawTokenResponse::builder()
            .access_token(huskarl::core::secrets::SecretString::new("access-token"))
            .token_type("Bearer")
            .build()
            .into_token_response(None, SystemTime::now())
            .unwrap();
        CompletedLogin::builder()
            .token_response(token_response)
            .build()
    }

    /// Extracts the `__Host-session=<value>` pointer cookie from a `Set-Cookie`
    /// list (the entry with a non-empty value; the no-identity test cipher also
    /// emits a `__Host-session.kid` `Max-Age=0` sidecar clear).
    fn pointer_cookie(set_cookies: &[HeaderValue]) -> String {
        set_cookies
            .iter()
            .filter_map(|h| h.to_str().ok())
            .filter_map(|s| s.split(';').next())
            .find(|pair| {
                pair.split_once('=').is_some_and(|(name, value)| {
                    name.trim() == "__Host-session" && !value.is_empty()
                })
            })
            .expect("pointer cookie present")
            .to_owned()
    }

    // ── Tests ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn load_roundtrip_forwards_with_session_from_external_store() {
        let external = InMemoryStore::default();
        let store = build_store(external.clone()).await;

        // Mint a real server-side session: this inserts into the external store
        // and returns the encrypted pointer cookie a browser would carry back.
        let (_session, set_cookies) = store
            .create(
                completed_login(),
                Duration::from_hours(1),
                &http::HeaderMap::new(),
            )
            .await
            .expect("create session");
        assert_eq!(external.calls().inserts, 1);
        assert_eq!(external.len(), 1);
        let cookie = pointer_cookie(&set_cookies);

        // The same store now backs the proxy; replay the pointer cookie.
        let proxy = build_store_proxy(store).await;
        let (mut s, _c) = make_session("GET", "/api", &format!("Cookie: {cookie}\r\n")).await;
        let mut ctx = proxy.inner.new_ctx();

        let handled = proxy.request_filter(&mut s, &mut ctx).await.unwrap();

        assert!(!handled);
        assert!(proxy.inner.was_forwarded());
        // The session was loaded from the external store via the pointer cookie.
        assert!(ctx.login_state().session.is_some());
    }

    #[tokio::test]
    async fn no_cookie_on_required_route_redirects_without_touching_store() {
        let external = InMemoryStore::default();
        let proxy = build_store_proxy(build_store(external.clone()).await).await;
        let (mut s, mut c) =
            make_session("GET", "/dashboard", "Sec-Fetch-Mode: navigate\r\n").await;
        let mut ctx = proxy.inner.new_ctx();

        let handled = proxy.request_filter(&mut s, &mut ctx).await.unwrap();

        assert!(handled);
        assert!(!proxy.inner.was_forwarded());
        assert_eq!(read_status(&mut c).await, 302);
        assert!(ctx.login_state().session.is_none());
    }

    #[tokio::test]
    async fn save_persists_to_external_store() {
        let external = InMemoryStore::default();
        let store = build_store(external.clone()).await;
        let (session, _cookies) = store
            .create(
                completed_login(),
                Duration::from_hours(1),
                &http::HeaderMap::new(),
            )
            .await
            .expect("create session");
        let proxy = build_store_proxy(store).await;

        let (mut s, _c) = make_session("GET", "/api", "Accept: application/json\r\n").await;
        let mut ctx = proxy.inner.new_ctx();
        // Stand in for a request that loaded this session and owes the store a
        // persist of an eager refresh whose initial save failed. The store-backed
        // driver re-commits it through compare-and-swap (merge-safe), not a plain
        // last-writer-wins `save`.
        ctx.login_state_mut().session = Some(session.clone());
        ctx.login_state_mut().pending = Some(super::owed_persist_for(session));

        let mut resp = pingora_http::ResponseHeader::build(200, Some(1)).unwrap();
        proxy
            .upstream_response_filter(&mut s, &mut resp, &mut ctx)
            .await
            .unwrap();

        assert_eq!(external.calls().compare_and_swaps, 1);
        assert_eq!(external.calls().saves, 0);
        assert_eq!(external.calls().deletes, 0);
    }

    #[tokio::test]
    async fn termination_removes_session_from_external_store() {
        let external = InMemoryStore::default();
        let store = build_store(external.clone()).await;
        let (session, _cookies) = store
            .create(
                completed_login(),
                Duration::from_hours(1),
                &http::HeaderMap::new(),
            )
            .await
            .expect("create session");
        assert_eq!(external.len(), 1);
        let proxy = build_store_proxy(store).await;

        let (mut s, _c) = make_session("GET", "/api", "Accept: application/json\r\n").await;
        let mut ctx = proxy.inner.new_ctx();
        ctx.login_state_mut().session = Some(session);
        ctx.login_state_mut().terminate_requested = true;

        let mut resp = pingora_http::ResponseHeader::build(200, Some(1)).unwrap();
        proxy
            .upstream_response_filter(&mut s, &mut resp, &mut ctx)
            .await
            .unwrap();

        assert_eq!(external.calls().deletes, 1);
        assert!(external.is_empty());
    }
}

#[tokio::test]
async fn disabled_guard_denies_method_gaps_with_public_default() {
    let proxy = LoginProxy::builder()
        .inner(InnerProxy::new())
        .engine(build_engine(MockSessionDriver::default()).await)
        .case_sensitivity(crate::login::CaseSensitivity::Sensitive)
        .decode_depth(DecodeDepth::UpToOne)
        .guard_mode(crate::login::GuardMode::Disabled)
        .default(LoginRule::public())
        .route("/admin", LoginRule::public().method(http::Method::GET))
        .build()
        .unwrap();
    let (mut session, mut client) = make_session("POST", "/admin", "").await;
    let mut ctx = proxy.inner.new_ctx();
    assert!(proxy.request_filter(&mut session, &mut ctx).await.unwrap());
    assert_eq!(read_status(&mut client).await, 403);
    assert!(!proxy.inner.was_forwarded());
}
