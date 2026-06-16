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
        platform::MaybeSendBoxFuture,
        secrets::{Secret, SecretBytes, SecretOutput},
    },
    grant::authorization_code::AuthorizationCodeGrant,
};
use huskarl_crypto_native::aead::AesGcmKey;
use huskarl_login::{
    CompletedLogin, LoginConfig, SessionDriver, SessionError, SessionErrorKind, SessionState,
};
use pingora_core::upstreams::peer::HttpPeer;
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
    delete_called: Mutex<bool>,
    #[builder(with = |s: usize| Mutex::new(s), default)]
    save_calls: Mutex<usize>,
    #[builder(default)]
    fail_save: bool,
}

impl MockSessionDriver {
    fn was_delete_called(&self) -> bool {
        *self.delete_called.lock().unwrap()
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

    fn apply_cookie_secure(&mut self, _secure: bool) {}

    async fn create(
        &self,
        _: CompletedLogin,
        _: Duration,
        _: &http::HeaderMap,
    ) -> Result<(MockSession, Vec<HeaderValue>), SessionError> {
        unimplemented!()
    }
    async fn load(&self, _: &http::HeaderMap) -> Result<Option<MockSession>, Infallible> {
        Ok(self.load_session.lock().unwrap().take())
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
    async fn delete(
        &self,
        _: &MockSession,
        _: &http::HeaderMap,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        *self.delete_called.lock().unwrap() = true;
        Ok(vec![])
    }

    fn session_aead_cipher(&self) -> Arc<dyn huskarl::core::crypto::cipher::AeadCipher> {
        unimplemented!()
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

#[derive(Clone)]
struct TestSecret(SecretBytes);

impl Secret for TestSecret {
    type Output = SecretBytes;
    fn get_secret_value(
        &self,
    ) -> MaybeSendBoxFuture<
        '_,
        Result<SecretOutput<SecretBytes>, huskarl_resource_server::core::Error>,
    > {
        Box::pin(async {
            Ok(SecretOutput {
                value: self.0.clone(),
                identity: None,
            })
        })
    }
}

async fn test_cipher() -> AesGcmKey {
    AesGcmKey::from_secret(TestSecret(SecretBytes::new(vec![0u8; 32])), |_| None)
        .await
        .unwrap()
}

fn default_config() -> LoginConfig {
    LoginConfig::builder()
        .callback_path("/callback".into())
        .scopes(vec![])
        .base_url("https://app.example.com".parse().unwrap())
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

async fn build_proxy_with_routes(
    store: MockSessionDriver,
    routes: Vec<(&'static str, LoginRule<MockSession>)>,
) -> TestProxy {
    let engine = Arc::new(
        huskarl_login::engine::LoginEngine::builder()
            .config(default_config())
            .grant(test_grant().await)
            .session_store(store)
            .cipher(test_cipher().await)
            .build(),
    );
    let mut builder = LoginProxy::builder()
        .inner(InnerProxy::new())
        .engine(engine);
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
        vec![(
            "/admin",
            LoginRule::required().check(|s: &MockSession| {
                if s.role == Some("admin") {
                    Ok(())
                } else {
                    Err(CheckError::Forbidden("admin only".into()))
                }
            }),
        )],
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
        vec![(
            "/admin",
            LoginRule::required().check(|s: &MockSession| {
                if s.role == Some("admin") {
                    Ok(())
                } else {
                    Err(CheckError::Forbidden("admin only".into()))
                }
            }),
        )],
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
    ctx.login_state_mut().pending_save = true;

    let mut resp = pingora_http::ResponseHeader::build(200, Some(1)).unwrap();
    proxy
        .upstream_response_filter(&mut s, &mut resp, &mut ctx)
        .await
        .unwrap();

    assert!(proxy.engine().session_store.was_save_called());
    assert!(!proxy.engine().session_store.was_delete_called());
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

    assert!(!proxy.engine().session_store.was_save_called());
    assert!(!proxy.engine().session_store.was_delete_called());
}

#[tokio::test]
async fn response_filter_delete_path() {
    let store = MockSessionDriver::builder()
        .load_session(MockSession::default())
        .build();
    let proxy = build_proxy(store).await;
    let (mut s, _c) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    proxy.request_filter(&mut s, &mut ctx).await.unwrap();
    ctx.login_state_mut().delete_requested = true;

    let mut resp = pingora_http::ResponseHeader::build(200, Some(1)).unwrap();
    proxy
        .upstream_response_filter(&mut s, &mut resp, &mut ctx)
        .await
        .unwrap();

    assert!(proxy.engine().session_store.was_delete_called());
    assert!(!proxy.engine().session_store.was_save_called());
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
    ctx.login_state_mut().set_cookies = vec![HeaderValue::from_static(
        "__Host-session.0=abc; Secure; HttpOnly",
    )];

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
    ctx.login_state_mut().pending_save = true;

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
        vec![(
            "/admin",
            LoginRule::required().check(|s: &MockSession| {
                if s.role == Some("admin") {
                    Ok(())
                } else {
                    Err(CheckError::Forbidden("admin only".into()))
                }
            }),
        )],
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
    ctx.login_state_mut().pending_save = true;
    proxy.logging(&mut s, None, &mut ctx).await;

    assert!(proxy.engine().session_store.was_save_called());
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
    ctx.login_state_mut().pending_save = true;

    let mut resp = pingora_http::ResponseHeader::build(200, Some(1)).unwrap();
    proxy
        .upstream_response_filter(&mut s, &mut resp, &mut ctx)
        .await
        .unwrap();
    proxy.logging(&mut s, None, &mut ctx).await;

    assert_eq!(proxy.engine().session_store.save_count(), 1);
}

#[tokio::test]
async fn logging_fallback_deletes_when_requested() {
    let store = MockSessionDriver::builder()
        .load_session(MockSession::default())
        .build();
    let proxy = build_proxy(store).await;
    let (mut s, _c) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    proxy.request_filter(&mut s, &mut ctx).await.unwrap();
    ctx.login_state_mut().delete_requested = true;
    proxy.logging(&mut s, None, &mut ctx).await;

    assert!(proxy.engine().session_store.was_delete_called());
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

    assert!(!proxy.engine().session_store.was_delete_called());
    assert!(!proxy.engine().session_store.was_save_called());
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
    use std::collections::HashMap;

    use huskarl_login::SaveOutcome;
    use uuid::Uuid;

    use super::*;
    use crate::login::{
        ExternalSessionStore, LoginProxy, PersistedSessionState, StoreBackedSessionStore,
    };

    // ── In-memory external store, keyed by session key, with call counters ──

    #[derive(Default)]
    struct StoreState {
        map: HashMap<Uuid, PersistedSessionState>,
        inserts: usize,
        saves: usize,
        deletes: usize,
    }

    #[derive(Clone, Default)]
    struct InMemoryStore(Arc<Mutex<StoreState>>);

    impl InMemoryStore {
        fn state(&self) -> std::sync::MutexGuard<'_, StoreState> {
            self.0.lock().unwrap()
        }
    }

    impl ExternalSessionStore for InMemoryStore {
        type SessionType = PersistedSessionState;
        type Error = Infallible;

        async fn insert(&self, session: &PersistedSessionState) -> Result<(), Infallible> {
            let mut st = self.state();
            st.inserts += 1;
            st.map.insert(session.session_key, session.clone());
            Ok(())
        }
        async fn load(
            &self,
            session_key: Uuid,
        ) -> Result<Option<PersistedSessionState>, Infallible> {
            Ok(self.state().map.get(&session_key).cloned())
        }
        async fn save(&self, session: &PersistedSessionState) -> Result<(), Infallible> {
            let mut st = self.state();
            st.saves += 1;
            st.map.insert(session.session_key, session.clone());
            Ok(())
        }
        async fn compare_and_swap(
            &self,
            session: &PersistedSessionState,
            _expected: i32,
        ) -> Result<SaveOutcome, Infallible> {
            // The proxy never drives OCC; a trivial unconditional write suffices.
            self.state()
                .map
                .insert(session.session_key, session.clone());
            Ok(SaveOutcome::Committed)
        }
        async fn delete(&self, session: &PersistedSessionState) -> Result<(), Infallible> {
            let mut st = self.state();
            st.deletes += 1;
            st.map.remove(&session.session_key);
            Ok(())
        }
    }

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
            .cipher(test_cipher().await)
            .cookie_name("session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build()
    }

    async fn build_store_proxy(store: StoreBackedSessionStore<InMemoryStore>) -> StoreProxy {
        let engine = Arc::new(
            huskarl_login::engine::LoginEngine::builder()
                .config(default_config())
                .grant(test_grant().await)
                .session_store(store)
                .cipher(test_cipher().await)
                .build(),
        );
        LoginProxy::builder()
            .inner(StoreInner::new())
            .engine(engine)
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
        assert_eq!(external.state().inserts, 1);
        assert_eq!(external.state().map.len(), 1);
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
        // `Save` (e.g. the retry of a failed eager refresh persist).
        ctx.login_state_mut().session = Some(session);
        ctx.login_state_mut().pending_save = true;

        let mut resp = pingora_http::ResponseHeader::build(200, Some(1)).unwrap();
        proxy
            .upstream_response_filter(&mut s, &mut resp, &mut ctx)
            .await
            .unwrap();

        assert_eq!(external.state().saves, 1);
        assert_eq!(external.state().deletes, 0);
    }

    #[tokio::test]
    async fn delete_removes_session_from_external_store() {
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
        assert_eq!(external.state().map.len(), 1);
        let proxy = build_store_proxy(store).await;

        let (mut s, _c) = make_session("GET", "/api", "Accept: application/json\r\n").await;
        let mut ctx = proxy.inner.new_ctx();
        ctx.login_state_mut().session = Some(session);
        ctx.login_state_mut().delete_requested = true;

        let mut resp = pingora_http::ResponseHeader::build(200, Some(1)).unwrap();
        proxy
            .upstream_response_filter(&mut s, &mut resp, &mut ctx)
            .await
            .unwrap();

        assert_eq!(external.state().deletes, 1);
        assert!(external.state().map.is_empty());
    }
}
