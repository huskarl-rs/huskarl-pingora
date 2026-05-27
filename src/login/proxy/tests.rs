//! Integration tests for [`LoginProxy`].
//!
//! These exercise the wrapper-level behavior: route matching, session
//! loading, gating, and persistence. The OAuth flow itself (callback,
//! refresh, expiry checks) is exercised in `huskarl-login`'s engine tests.

use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use bytes::Bytes;
use http::HeaderValue;
use huskarl::{
    core::{
        BoxedError,
        crypto::cipher::BoxedAeadCipher,
        http::{HttpClient, HttpResponse as HuskarlHttpResponse},
        secrets::{Secret, SecretBytes, SecretOutput},
    },
    grant::{
        authorization_code::{PendingState, StartOutput},
        core::TokenResponse,
    },
    token::RefreshToken,
};
use huskarl_crypto_native::aead::{AesGcmKey, AesGcmKeyType};
use huskarl_login::{
    CompletedLogin, LoginConfig, LoginGrant, Session as LoginSession, SessionDriver, SessionError,
    SessionState,
};
use pingora_core::upstreams::peer::HttpPeer;
use pingora_proxy::{ProxyHttp, Session};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use super::*;
use crate::login::{LoginCtx, LoginRule};

// ── Mock HTTP client (never actually called) ─────────────────────

struct MockHttpResponse;

impl HuskarlHttpResponse for MockHttpResponse {
    type Error = Infallible;
    fn status(&self) -> http::StatusCode {
        unimplemented!()
    }
    fn headers(&self) -> http::HeaderMap {
        unimplemented!()
    }
    async fn body(self) -> Result<Bytes, Infallible> {
        unimplemented!()
    }
}

struct MockHttpClient;

impl HttpClient for MockHttpClient {
    type Response = MockHttpResponse;
    type Error = Infallible;
    type ResponseError = Infallible;
    async fn execute(&self, _: http::Request<Bytes>) -> Result<MockHttpResponse, Infallible> {
        unimplemented!()
    }
}

// ── Mock session ─────────────────────────────────────────────────

#[derive(Clone)]
struct MockSession {
    state: SessionState,
    role: Option<&'static str>,
}

impl LoginSession for MockSession {
    fn state(&self) -> &SessionState {
        &self.state
    }
    fn set_state(&mut self, state: SessionState) {
        self.state = state;
    }
}

fn mock_session() -> MockSession {
    let now = SystemTime::now();
    MockSession {
        state: SessionState::builder()
            .token_expiry(now + Duration::from_hours(1))
            .created_at(now)
            .last_active(now)
            .build(),
        role: None,
    }
}

fn mock_session_with_role(role: &'static str) -> MockSession {
    let mut s = mock_session();
    s.role = Some(role);
    s
}

// ── Mock session store ───────────────────────────────────────────

struct MockSessionDriver {
    load_session: Mutex<Option<MockSession>>,
    delete_called: Mutex<bool>,
    save_called: Mutex<bool>,
    touch_called: Mutex<bool>,
}

impl MockSessionDriver {
    fn with_session(session: MockSession) -> Self {
        Self {
            load_session: Mutex::new(Some(session)),
            delete_called: Mutex::new(false),
            save_called: Mutex::new(false),
            touch_called: Mutex::new(false),
        }
    }
    fn empty() -> Self {
        Self {
            load_session: Mutex::new(None),
            delete_called: Mutex::new(false),
            save_called: Mutex::new(false),
            touch_called: Mutex::new(false),
        }
    }
    fn was_delete_called(&self) -> bool {
        *self.delete_called.lock().unwrap()
    }
    fn was_save_called(&self) -> bool {
        *self.save_called.lock().unwrap()
    }
    fn was_touch_called(&self) -> bool {
        *self.touch_called.lock().unwrap()
    }
}

impl huskarl_login::session::sealed::Sealed for MockSessionDriver {}

impl SessionDriver for MockSessionDriver {
    type SessionType = MockSession;
    type LoadError = Infallible;

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
        *self.save_called.lock().unwrap() = true;
        Ok(vec![])
    }
    async fn touch(
        &self,
        _: &MockSession,
        _: &http::HeaderMap,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        *self.touch_called.lock().unwrap() = true;
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
    type Error = Infallible;
    async fn get_secret_value(&self) -> Result<SecretOutput<SecretBytes>, Infallible> {
        Ok(SecretOutput {
            value: self.0.clone(),
            identity: None,
        })
    }
}

async fn test_cipher() -> BoxedAeadCipher {
    let key = AesGcmKey::from_secret(
        AesGcmKeyType::Aes256,
        TestSecret(SecretBytes::new(vec![0u8; 32])),
        |_| None,
    )
    .await
    .unwrap();
    BoxedAeadCipher::new(key)
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

struct TestGrant {
    authorization_url: String,
    state: String,
}

impl TestGrant {
    fn new(authorization_url: &str, state: &str) -> Self {
        Self {
            authorization_url: authorization_url.to_owned(),
            state: state.to_owned(),
        }
    }
}

impl LoginGrant for TestGrant {
    async fn start(&self, _: &impl HttpClient, _: Vec<String>) -> Result<StartOutput, BoxedError> {
        Ok(StartOutput {
            authorization_url: self.authorization_url.parse().unwrap(),
            expires_in: None,
            pending_state: PendingState {
                redirect_uri: "https://localhost/callback".to_owned(),
                pkce_verifier: None,
                state: self.state.clone(),
                nonce: "test_nonce".to_owned(),
                dpop_jkt: None,
            },
        })
    }
    async fn complete(
        &self,
        _: &impl HttpClient,
        _: &PendingState,
        _: String,
        _: String,
        _: Option<String>,
    ) -> Result<CompletedLogin, BoxedError> {
        Err(BoxedError::from_err("\0".parse::<http::Uri>().unwrap_err()))
    }
    async fn refresh(
        &self,
        _: &impl HttpClient,
        _: &RefreshToken,
    ) -> Result<TokenResponse, BoxedError> {
        Err(BoxedError::from_err("\0".parse::<http::Uri>().unwrap_err()))
    }
}

// ── Build helpers ────────────────────────────────────────────────

type TestProxy = LoginProxy<InnerProxy, TestGrant, MockSessionDriver, MockHttpClient>;

async fn build_proxy_with_routes(
    store: MockSessionDriver,
    routes: Vec<(&'static str, LoginRule<MockSession>)>,
) -> TestProxy {
    let engine = Arc::new(
        huskarl_login::engine::LoginEngine::builder()
            .config(default_config())
            .grant(TestGrant::new("https://auth.example.com/authorize", "s"))
            .session_store(store)
            .cipher(test_cipher().await)
            .http_client(MockHttpClient)
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
    let proxy = build_proxy(MockSessionDriver::with_session(mock_session())).await;
    let (mut s, _c) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    let handled = proxy.request_filter(&mut s, &mut ctx).await.unwrap();

    assert!(!handled);
    assert!(proxy.inner.was_forwarded());
    assert!(ctx.login_session().is_some());
}

#[tokio::test]
async fn default_required_no_session_xhr_returns_401() {
    let proxy = build_proxy(MockSessionDriver::empty()).await;
    let (mut s, mut c) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    let handled = proxy.request_filter(&mut s, &mut ctx).await.unwrap();

    assert!(handled);
    assert!(!proxy.inner.was_forwarded());
    assert_eq!(read_status(&mut c).await, 401);
}

#[tokio::test]
async fn default_required_no_session_navigation_redirects() {
    let proxy = build_proxy(MockSessionDriver::empty()).await;
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
    let store = MockSessionDriver::with_session(mock_session());
    let proxy = build_proxy_with_routes(store, vec![("/health", LoginRule::public())]).await;
    let (mut s, _c) = make_session("GET", "/health", "").await;
    let mut ctx = proxy.inner.new_ctx();

    let handled = proxy.request_filter(&mut s, &mut ctx).await.unwrap();

    assert!(!handled);
    assert!(proxy.inner.was_forwarded());
    // Public routes skip session loading — no session in ctx even though the
    // store had one ready.
    assert!(ctx.login_session().is_none());
}

// ── Optional routes ──────────────────────────────────────────────

#[tokio::test]
async fn optional_route_forwards_with_session_when_present() {
    let store = MockSessionDriver::with_session(mock_session());
    let proxy = build_proxy_with_routes(store, vec![("/", LoginRule::optional())]).await;
    let (mut s, _c) = make_session("GET", "/", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    let handled = proxy.request_filter(&mut s, &mut ctx).await.unwrap();

    assert!(!handled);
    assert!(proxy.inner.was_forwarded());
    assert!(ctx.login_session().is_some());
}

#[tokio::test]
async fn optional_route_forwards_without_session() {
    let proxy = build_proxy_with_routes(
        MockSessionDriver::empty(),
        vec![("/", LoginRule::optional())],
    )
    .await;
    let (mut s, _c) = make_session("GET", "/", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    let handled = proxy.request_filter(&mut s, &mut ctx).await.unwrap();

    assert!(!handled);
    assert!(proxy.inner.was_forwarded());
    assert!(ctx.login_session().is_none());
}

// ── Required check (authorization) ───────────────────────────────

#[tokio::test]
async fn required_check_pass_forwards() {
    let store = MockSessionDriver::with_session(mock_session_with_role("admin"));
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
    let store = MockSessionDriver::with_session(mock_session_with_role("user"));
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
    let proxy = build_proxy(MockSessionDriver::empty()).await;
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
    let proxy = build_proxy(MockSessionDriver::empty()).await;
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
    use huskarl_login::engine::SessionPersistence;
    let store = MockSessionDriver::with_session(mock_session());
    let proxy = build_proxy(store).await;
    let (mut s, _c) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    proxy.request_filter(&mut s, &mut ctx).await.unwrap();
    // Engine assigns Touch by default when no refresh fires. Force Save to
    // exercise the save branch.
    ctx.login_state_mut().persistence = SessionPersistence::Save;

    let mut resp = pingora_http::ResponseHeader::build(200, Some(1)).unwrap();
    proxy
        .upstream_response_filter(&mut s, &mut resp, &mut ctx)
        .await
        .unwrap();

    assert!(proxy.engine().session_store().was_save_called());
    assert!(!proxy.engine().session_store().was_delete_called());
}

#[tokio::test]
async fn response_filter_touch_path() {
    let store = MockSessionDriver::with_session(mock_session());
    let proxy = build_proxy(store).await;
    let (mut s, _c) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    proxy.request_filter(&mut s, &mut ctx).await.unwrap();

    let mut resp = pingora_http::ResponseHeader::build(200, Some(1)).unwrap();
    proxy
        .upstream_response_filter(&mut s, &mut resp, &mut ctx)
        .await
        .unwrap();

    assert!(proxy.engine().session_store().was_touch_called());
    assert!(!proxy.engine().session_store().was_save_called());
    assert!(!proxy.engine().session_store().was_delete_called());
}

#[tokio::test]
async fn response_filter_delete_path() {
    let store = MockSessionDriver::with_session(mock_session());
    let proxy = build_proxy(store).await;
    let (mut s, _c) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    proxy.request_filter(&mut s, &mut ctx).await.unwrap();
    ctx.request_session_delete();

    let mut resp = pingora_http::ResponseHeader::build(200, Some(1)).unwrap();
    proxy
        .upstream_response_filter(&mut s, &mut resp, &mut ctx)
        .await
        .unwrap();

    assert!(proxy.engine().session_store().was_delete_called());
    assert!(!proxy.engine().session_store().was_save_called());
    assert!(!proxy.engine().session_store().was_touch_called());
}

#[tokio::test]
async fn response_filter_no_session_does_nothing() {
    let proxy = build_proxy_with_routes(
        MockSessionDriver::empty(),
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

    assert!(!proxy.engine().session_store().was_delete_called());
    assert!(!proxy.engine().session_store().was_save_called());
    assert!(!proxy.engine().session_store().was_touch_called());
}
