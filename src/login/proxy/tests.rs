//! Integration tests for [`LoginProxy`].
//!
//! These exercise the wrapper-level behavior: route matching, session
//! loading, gating, and persistence. The OAuth flow itself (callback,
//! refresh, expiry checks) is exercised in `huskarl-login`'s engine tests.

// Mock trait impls satisfy `async fn` signatures without awaiting.
#![allow(clippy::unused_async_trait_impl)]

use std::{
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
    CompletedLogin, ExternalSessionStore, LoginConfig, PersistedSession, PersistedSessionState,
    SaveOutcome, SessionDriver, SessionError, SessionErrorKind, SessionLifetime, SessionState,
    StoreBackedSessionStore, core::crypto::seal::AeadV1Sealer,
};
use huskarl_route_guard::PathRegistration;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_http::RequestHeader;
use pingora_proxy::{ProxyHttp, Session};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use super::*;
use crate::{
    login::{LoginCtx, LoginRule},
    path_confusion::DecodeDepth,
};

// ── Mock session ─────────────────────────────────────────────────

#[derive(Clone, Builder)]
struct MockSession {
    #[builder(default = default_persisted_state())]
    persisted: PersistedSessionState,
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
fn owed_persist_for<S: huskarl_login::Session>(
    session: S,
) -> huskarl_login::engine::PendingPersist<S> {
    let token_response = huskarl::grant::core::RawTokenResponse::builder()
        .access_token(huskarl::core::secrets::SecretString::new("access-token"))
        .token_type("Bearer")
        .build()
        .into_token_response(None, SystemTime::now())
        .unwrap();
    let revision = session.state().refresh_revision;
    huskarl_login::engine::PendingPersist::builder()
        .session(session)
        .token_response(token_response)
        .expected_refresh_revision(revision)
        .build()
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
        &self.persisted.state
    }

    fn set_state(&mut self, state: SessionState) {
        self.persisted.state = state;
    }
}

fn default_persisted_state() -> PersistedSessionState {
    PersistedSessionState::builder()
        .session_key(uuid::Uuid::nil())
        .state(default_session_state())
        .build()
}

impl PersistedSession for MockSession {
    fn persisted(&self) -> &PersistedSessionState {
        &self.persisted
    }
    fn persisted_mut(&mut self) -> &mut PersistedSessionState {
        &mut self.persisted
    }
}
impl From<PersistedSessionState> for MockSession {
    fn from(persisted: PersistedSessionState) -> Self {
        Self {
            persisted,
            role: None,
        }
    }
}

#[derive(Default)]
struct SaveGate {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

// ── Mock session store ───────────────────────────────────────────

#[derive(Builder, Clone, Default)]
struct TestBackend {
    #[builder(with = |s: MockSession| Arc::new(Mutex::new(Some(s))), default)]
    load_session: Arc<Mutex<Option<MockSession>>>,
    #[builder(with = |s: bool| Arc::new(Mutex::new(s)), default)]
    revoke_called: Arc<Mutex<bool>>,
    #[builder(with = |s: usize| Arc::new(Mutex::new(s)), default)]
    save_calls: Arc<Mutex<usize>>,
    #[builder(default)]
    fail_save: bool,
    #[builder(default)]
    version: Arc<Mutex<u64>>,
    save_gate: Option<Arc<SaveGate>>,
    #[builder(default)]
    save_completions: Arc<Mutex<usize>>,
    #[builder(default)]
    fail_revoke: bool,
    #[builder(default)]
    fail_load: bool,
}

/// The `Set-Cookie` clear this driver emits for the browser's session cookie.
const MOCK_SESSION_CLEAR: &str =
    "__Host-mock-session=; HttpOnly; SameSite=Lax; Path=/; Secure; Max-Age=0";

impl TestBackend {
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

// Use the real sealed driver with a controllable external backend. The backend
// models one fixed-key record with CAS/delete, cancellation gates, and counters.
// Backend TTL expiry is outside these adapter lifecycle tests.
type TestDriver = StoreBackedSessionStore<TestBackend>;

impl ExternalSessionStore for TestBackend {
    type SessionType = MockSession;
    type Version = u64;
    async fn insert(&self, session: &MockSession, _: SystemTime) -> Result<(), SessionError> {
        let mut current = self.load_session.lock().unwrap();
        let mut version = self.version.lock().unwrap();
        *current = Some(session.clone());
        *version += 1;
        Ok(())
    }
    async fn load(
        &self,
        key: uuid::Uuid,
    ) -> Result<huskarl_login::LoadOutcome<Self>, SessionError> {
        if self.fail_load {
            return Err(SessionError::new(
                SessionErrorKind::Unavailable,
                "load failed",
            ));
        }
        let session = self.load_session.lock().unwrap();
        Ok(session
            .as_ref()
            .filter(|s| s.persisted.session_key == key)
            .map(|s| (s.clone(), *self.version.lock().unwrap())))
    }
    async fn compare_and_swap(
        &self,
        session: &MockSession,
        expected: u64,
        _: SystemTime,
    ) -> Result<SaveOutcome, SessionError> {
        *self.save_calls.lock().unwrap() += 1;
        if let Some(gate) = &self.save_gate {
            gate.entered.notify_one();
            gate.release.notified().await;
        }
        if self.fail_save {
            return Err(SessionError::new(
                SessionErrorKind::Unavailable,
                "save failed",
            ));
        }
        let mut current = self.load_session.lock().unwrap();
        let mut version = self.version.lock().unwrap();
        if current.is_none() {
            return Ok(SaveOutcome::Missing);
        }
        if *version != expected {
            return Ok(SaveOutcome::Conflict);
        }
        *current = Some(session.clone());
        *version += 1;
        *self.save_completions.lock().unwrap() += 1;
        Ok(SaveOutcome::Committed)
    }
    async fn delete(&self, _: &MockSession) -> Result<(), SessionError> {
        *self.revoke_called.lock().unwrap() = true;
        if self.fail_revoke {
            return Err(SessionError::new(
                SessionErrorKind::Unavailable,
                "revoke failed",
            ));
        }
        *self.load_session.lock().unwrap() = None;
        Ok(())
    }
}

trait TestStore {
    type Driver: SessionDriver;
    fn into_driver(self) -> impl std::future::Future<Output = Self::Driver>;
}
impl TestStore for TestBackend {
    type Driver = TestDriver;
    async fn into_driver(self) -> TestDriver {
        StoreBackedSessionStore::builder()
            .external(self)
            .sealer(test_sealer().await)
            .cookie_name("mock-session".parse().unwrap())
            .build()
    }
}
impl<E: ExternalSessionStore> TestStore for StoreBackedSessionStore<E> {
    type Driver = Self;
    async fn into_driver(self) -> Self {
        self
    }
}

// Mint a real encrypted pointer once. Each backend independently controls the
// record for this fixed key; a pointer alone does not authenticate a request.
async fn test_pointer_cookie() -> &'static str {
    static COOKIE: tokio::sync::OnceCell<String> = tokio::sync::OnceCell::const_new();
    COOKIE
        .get_or_init(|| async {
            let store = StoreBackedSessionStore::builder()
                .external(TestBackend::default())
                .sealer(test_sealer().await)
                .cookie_name("mock-session".parse().unwrap())
                .build_with_claims(|mut state, _| {
                    state.session_key = uuid::Uuid::nil();
                    Ok(MockSession::from(state))
                });
            let engine = build_engine(store).await;
            let (_, headers) = engine
                .session_store()
                .create(
                    store_backed::completed_login(),
                    Duration::from_hours(1),
                    &http::HeaderMap::new(),
                )
                .await
                .unwrap();
            headers
                .iter()
                .filter_map(|h| h.to_str().ok())
                .filter_map(|h| h.split(';').next())
                .find(|h| h.starts_with("__Host-mock-session="))
                .unwrap()
                .to_owned()
        })
        .await
}

// Real engine output for a cookie-delivery obligation, independently of the
// store-backed refresh (which deliberately returns no replacement pointer).
async fn owed_cookies() -> huskarl_login::engine::SetCookies {
    let engine = build_engine(TestBackend::default()).await;
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::COOKIE,
        HeaderValue::from_static("__Host-mock-session=invalid"),
    );
    match engine.load_session(&headers).await.unwrap() {
        LoadedSession::Cleared { clears, .. } => clears,
        _ => panic!("invalid pointer must produce cookie clears"),
    }
}

// ── Mock inner proxy ─────────────────────────────────────────────

struct InnerProxy {
    store: Option<TestBackend>,
    forwarded: Mutex<bool>,
}

impl InnerProxy {
    fn new() -> Self {
        Self {
            store: None,
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

type TestProxy = LoginProxy<InnerProxy, TestDriver>;

/// Wraps a session store in a `LoginEngine` over the shared test config, grant,
/// and cipher — the engine every proxy-under-test is built on.
async fn build_engine<T: TestStore>(
    store: T,
) -> Arc<huskarl_login::engine::LoginEngine<T::Driver>> {
    let store = store.into_driver().await;
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
    store: TestBackend,
    routes: Vec<(&'static str, LoginRule<MockSession>)>,
) -> TestProxy {
    let mut inner = InnerProxy::new();
    inner.store = Some(store.clone());
    let mut builder = LoginProxy::builder()
        .inner(inner)
        .engine(build_engine(store).await)
        .path_guard(crate::login::GuardConfig::new(
            crate::login::CaseSensitivity::Sensitive,
            crate::login::DecodeDepth::UpToOne,
        ));
    for (pattern, rule) in routes {
        builder = builder.route(pattern, rule);
    }
    builder.build().expect("valid routes")
}

async fn build_proxy(store: TestBackend) -> TestProxy {
    build_proxy_with_routes(store, vec![]).await
}

async fn make_session(method: &str, path: &str, extra_headers: &str) -> (Session, DuplexStream) {
    let cookie = if extra_headers.to_ascii_lowercase().contains("cookie:") {
        String::new()
    } else {
        format!("Cookie: {}\r\n", test_pointer_cookie().await)
    };
    let raw = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n{cookie}{extra_headers}\r\n");
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
        TestBackend::builder()
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
    let proxy = build_proxy(TestBackend::default()).await;
    let (mut s, mut c) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    let handled = proxy.request_filter(&mut s, &mut ctx).await.unwrap();

    assert!(handled);
    assert!(!proxy.inner.was_forwarded());
    assert_eq!(read_status(&mut c).await, 401);
}

#[tokio::test]
async fn default_required_no_session_navigation_redirects() {
    let proxy = build_proxy(TestBackend::default()).await;
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
            .session_store(TestBackend::default().into_driver().await)
            .sealer(test_sealer().await)
            .build()
            .unwrap(),
    );
    let proxy = LoginProxy::builder()
        .inner(InnerProxy::new())
        .engine(engine)
        .path_guard(crate::login::GuardConfig::new(
            crate::login::CaseSensitivity::Sensitive,
            DecodeDepth::UpToOne,
        ))
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
    let store = TestBackend::builder()
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
        TestBackend::default(),
        vec![("/health", LoginRule::public())],
    )
    .await;
    let (mut session, _client) = make_session(
        "GET",
        "/health",
        "Cookie: __Host-mock-session=secret; theme=dark\r\n",
    )
    .await;
    let mut ctx = proxy.inner.new_ctx();
    proxy.request_filter(&mut session, &mut ctx).await.unwrap();

    let mut upstream = RequestHeader::build("GET", b"/health", None).unwrap();
    upstream
        .insert_header("Cookie", "__Host-mock-session=secret; theme=dark")
        .unwrap();
    upstream.insert_header("X-App", "preserved").unwrap();

    proxy
        .upstream_request_filter(&mut session, &mut upstream, &mut ctx)
        .await
        .unwrap();

    assert_eq!(
        upstream.headers.get(http::header::COOKIE).unwrap(),
        "theme=dark"
    );
    let mut wire = Vec::new();
    upstream.header_to_h1_wire(&mut wire);
    let wire = String::from_utf8(wire).unwrap();
    assert!(wire.contains("Cookie: theme=dark\r\n"));
    assert!(wire.contains("X-App: preserved\r\n"));
    assert!(!wire.contains("mock-session"));
}

#[tokio::test]
async fn cookie_header_is_removed_when_it_only_contains_the_session_cookie() {
    let proxy = build_proxy_with_routes(
        TestBackend::default(),
        vec![("/health", LoginRule::public())],
    )
    .await;
    let (mut session, _client) =
        make_session("GET", "/health", "Cookie: __Host-mock-session=secret\r\n").await;
    let mut ctx = proxy.inner.new_ctx();
    proxy.request_filter(&mut session, &mut ctx).await.unwrap();

    let mut upstream = RequestHeader::build("GET", b"/health", None).unwrap();
    upstream
        .insert_header("Cookie", "__Host-mock-session=secret")
        .unwrap();

    proxy
        .upstream_request_filter(&mut session, &mut upstream, &mut ctx)
        .await
        .unwrap();

    assert!(upstream.headers.get(http::header::COOKIE).is_none());
    let mut wire = Vec::new();
    upstream.header_to_h1_wire(&mut wire);
    let wire = String::from_utf8(wire).unwrap();
    assert!(!wire.contains("Cookie:"));
    assert!(!wire.contains("mock-session"));
}

// ── Optional routes ──────────────────────────────────────────────

#[tokio::test]
async fn optional_route_forwards_with_session_when_present() {
    let store = TestBackend::builder()
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
    let proxy =
        build_proxy_with_routes(TestBackend::default(), vec![("/", LoginRule::optional())]).await;
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
    let store = TestBackend::builder()
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
    let store = TestBackend::builder()
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
    let proxy = build_proxy(TestBackend::default()).await;
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
        .engine(build_engine(TestBackend::default()).await)
        .path_guard(crate::login::GuardConfig::new(
            crate::login::CaseSensitivity::Sensitive,
            DecodeDepth::UpToOne,
        ))
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
    let proxy = build_proxy(TestBackend::default()).await;
    let (mut s, mut c) = make_session("GET", "/callback?code=abc", "").await;
    let mut ctx = proxy.inner.new_ctx();

    let handled = proxy.request_filter(&mut s, &mut ctx).await.unwrap();

    assert!(handled);
    assert!(!proxy.inner.was_forwarded());
    assert_eq!(read_status(&mut c).await, 400);
}

// ── response_filter persistence paths ───────────────────

#[tokio::test]
async fn response_filter_save_on_dirty_persistence() {
    let store = TestBackend::builder()
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
        .response_filter(&mut s, &mut resp, &mut ctx)
        .await
        .unwrap();

    assert!(proxy.inner.store.as_ref().unwrap().was_save_called());
    assert!(!proxy.inner.store.as_ref().unwrap().was_revoke_called());
}

#[tokio::test]
async fn response_filter_owes_nothing_on_plain_request() {
    // A loaded, fully-persisted session with no owed save touches no store.
    // (Activity/idle tracking is now server-side in huskarl-login's liveness
    // store, not adapter-visible.)
    let store = TestBackend::builder()
        .load_session(MockSession::default())
        .build();
    let proxy = build_proxy(store).await;
    let (mut s, _c) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    proxy.request_filter(&mut s, &mut ctx).await.unwrap();

    let mut resp = pingora_http::ResponseHeader::build(200, Some(1)).unwrap();
    proxy
        .response_filter(&mut s, &mut resp, &mut ctx)
        .await
        .unwrap();

    assert!(!proxy.inner.store.as_ref().unwrap().was_save_called());
    assert!(!proxy.inner.store.as_ref().unwrap().was_revoke_called());
}

#[tokio::test]
async fn response_filter_termination_path() {
    let store = TestBackend::builder()
        .load_session(MockSession::default())
        .build();
    let proxy = build_proxy(store).await;
    let (mut s, _c) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    proxy.request_filter(&mut s, &mut ctx).await.unwrap();
    ctx.login_state_mut().terminate_requested = true;

    let mut resp = pingora_http::ResponseHeader::build(200, Some(1)).unwrap();
    proxy
        .response_filter(&mut s, &mut resp, &mut ctx)
        .await
        .unwrap();

    assert!(proxy.inner.store.as_ref().unwrap().was_revoke_called());
    assert!(!proxy.inner.store.as_ref().unwrap().was_save_called());
    assert_eq!(
        set_cookies(&resp),
        proxy
            .engine()
            .session_store()
            .clear_session_cookies(&http::HeaderMap::new())
            .iter()
            .map(|h| h.to_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn response_filter_termination_delivers_clears_when_revocation_fails() {
    // The browser clears are built before server-side revocation and must
    // reach the response either way: a store outage can leave a copied
    // pointer usable, but must not keep this browser logged in. Failing the
    // request instead would replace the response — clears and all.
    let store = TestBackend::builder()
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
        .response_filter(&mut s, &mut resp, &mut ctx)
        .await
        .unwrap();

    assert!(proxy.inner.store.as_ref().unwrap().was_revoke_called());
    assert_eq!(
        set_cookies(&resp),
        proxy
            .engine()
            .session_store()
            .clear_session_cookies(&http::HeaderMap::new())
            .iter()
            .map(|h| h.to_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn response_filter_forces_no_store_when_session_cookie_appended() {
    // A re-sealed session cookie (here, an eager-refresh result handed back on
    // the load state) riding on the upstream response must not be cacheable by
    // shared caches — even if the upstream marked it cacheable (RFC 6749 §5.1).
    let store = TestBackend::builder()
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
        .response_filter(&mut s, &mut resp, &mut ctx)
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
    let store = TestBackend::builder()
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
        .response_filter(&mut s, &mut resp, &mut ctx)
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
    let mut store = TestBackend::builder()
        .load_session(MockSession::default())
        .build();

    store.fail_save = true;
    let proxy = build_proxy(store).await;
    let (mut s, _c) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    proxy.request_filter(&mut s, &mut ctx).await.unwrap();
    ctx.login_state_mut().pending = Some(owed_persist());

    let mut resp = pingora_http::ResponseHeader::build(200, Some(1)).unwrap();
    let result = proxy.response_filter(&mut s, &mut resp, &mut ctx).await;

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
        persisted: default_persisted_state(),
        role: Some("user"),
    };
    let store = TestBackend::builder().load_session(session).build();
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
    // `response_filter` never ran — `logging` picks up the owed save.
    let store = TestBackend::builder()
        .load_session(MockSession::default())
        .build();
    let proxy = build_proxy(store).await;
    let (mut s, _c) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    proxy.request_filter(&mut s, &mut ctx).await.unwrap();
    ctx.login_state_mut().pending = Some(owed_persist());
    proxy.logging(&mut s, None, &mut ctx).await;

    assert!(proxy.inner.store.as_ref().unwrap().was_save_called());
}

#[tokio::test]
async fn logging_after_response_filter_does_not_double_persist() {
    let store = TestBackend::builder()
        .load_session(MockSession::default())
        .build();
    let proxy = build_proxy(store).await;
    let (mut s, _c) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    proxy.request_filter(&mut s, &mut ctx).await.unwrap();
    ctx.login_state_mut().pending = Some(owed_persist());

    let mut resp = pingora_http::ResponseHeader::build(200, Some(1)).unwrap();
    proxy
        .response_filter(&mut s, &mut resp, &mut ctx)
        .await
        .unwrap();
    proxy.logging(&mut s, None, &mut ctx).await;

    assert_eq!(proxy.inner.store.as_ref().unwrap().save_count(), 1);
}

#[tokio::test]
async fn logging_fallback_revokes_when_termination_requested() {
    let store = TestBackend::builder()
        .load_session(MockSession::default())
        .build();
    let proxy = build_proxy(store).await;
    let (mut s, _c) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    proxy.request_filter(&mut s, &mut ctx).await.unwrap();
    ctx.login_state_mut().terminate_requested = true;
    proxy.logging(&mut s, None, &mut ctx).await;

    assert!(proxy.inner.store.as_ref().unwrap().was_revoke_called());
}

#[tokio::test]
async fn response_filter_no_session_does_nothing() {
    let proxy =
        build_proxy_with_routes(TestBackend::default(), vec![("/", LoginRule::optional())]).await;
    let (mut s, _c) = make_session("GET", "/", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    proxy.request_filter(&mut s, &mut ctx).await.unwrap();

    let mut resp = pingora_http::ResponseHeader::build(200, Some(1)).unwrap();
    proxy
        .response_filter(&mut s, &mut resp, &mut ctx)
        .await
        .unwrap();

    assert!(!proxy.inner.store.as_ref().unwrap().was_revoke_called());
    assert!(!proxy.inner.store.as_ref().unwrap().was_save_called());
}

// ── Path-confusion guard ────────────────────────────────────────

async fn build_structural_proxy(
    routes: Vec<(&'static str, LoginRule<MockSession>)>,
    guard_mode: crate::login::GuardMode,
) -> TestProxy {
    let mut builder = LoginProxy::builder()
        .inner(InnerProxy::new())
        .engine(build_engine(TestBackend::default()).await)
        .path_guard(
            crate::login::GuardConfig::new(
                crate::login::CaseSensitivity::Sensitive,
                DecodeDepth::UpToOne,
            )
            .with_mode(guard_mode),
        );
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
        TestBackend::default(),
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
        TestBackend::default(),
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
        .engine(build_engine(TestBackend::default()).await)
        .path_guard(crate::login::GuardConfig::new(
            crate::login::CaseSensitivity::Sensitive,
            DecodeDepth::UpToOne,
        ))
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
        .engine(build_engine(TestBackend::default()).await)
        .path_guard(crate::login::GuardConfig::new(
            crate::login::CaseSensitivity::Sensitive,
            DecodeDepth::UpToOne,
        ))
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
// The tests above use the real driver with a controllable backend. These
// additionally exercise the shared in-memory backend and use
// `PersistedSessionState` as the session type —
// the "simplest case" server-side setup — end to end through `LoginProxy`.
// Everything is imported from the `crate::login` facade, so the test also
// pins that the server-side path is reachable without dipping into
// `huskarl_login` directly.
mod store_backed {
    use huskarl_login::testing::InMemoryExternalSessionStore;

    use super::*;
    use crate::{
        login::{LoginProxy, PersistedSessionState, StoreBackedSessionStore},
        path_confusion::DecodeDepth,
    };

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
            .path_guard(crate::login::GuardConfig::new(
                crate::login::CaseSensitivity::Sensitive,
                DecodeDepth::UpToOne,
            ))
            .build()
            .expect("valid routes")
    }

    /// A minimal completed login (bearer token, no ID token claims) — enough to
    /// drive `SessionDriver::create`, which seeds the external store and mints
    /// the encrypted pointer cookie.
    pub(super) fn completed_login() -> CompletedLogin {
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
            .response_filter(&mut s, &mut resp, &mut ctx)
            .await
            .unwrap();

        assert_eq!(external.calls().compare_and_swaps, 1);
        assert_eq!(external.calls().inserts, 1);
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
            .response_filter(&mut s, &mut resp, &mut ctx)
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
        .engine(build_engine(TestBackend::default()).await)
        .path_guard(
            crate::login::GuardConfig::new(
                crate::login::CaseSensitivity::Sensitive,
                DecodeDepth::UpToOne,
            )
            .with_mode(crate::login::GuardMode::Disabled),
        )
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

#[tokio::test]
async fn shared_path_guard_config_preserves_downstream_assumptions() {
    use crate::login::{CaseSensitivity, GuardConfig, StructuralClasses};

    let config = GuardConfig::new(CaseSensitivity::Insensitive, DecodeDepth::UpToTwo)
        .with_structural_classes(StructuralClasses::new().with_backslash())
        .with_max_analysis_path_len(32);
    let router = RuleRouter::from_registrations(
        false,
        config.clone(),
        [
            PathRegistration::subtree("/public").all(true),
            PathRegistration::subtree("/admin").all(false),
        ],
    )
    .unwrap();
    let proxy = LoginProxy::builder()
        .inner(InnerProxy::new())
        .engine(build_engine(TestBackend::default()).await)
        .path_guard(config)
        .subtree("/public", LoginRule::public())
        .subtree("/admin", LoginRule::required())
        .build()
        .unwrap();

    for (path, allowed) in [
        ("/public/file", true),
        ("/PUBLIC/file", false),
        ("/public%252ffile", false),
        ("/public%5cfile", false),
        ("/public/long-encoded-file-name%20here", false),
    ] {
        assert_eq!(
            router.resolve(path, &http::Method::GET).is_ok(),
            allowed,
            "{path}"
        );
        let (mut session, mut client) = make_session("GET", path, "").await;
        let mut ctx = proxy.inner.new_ctx();
        assert_eq!(
            proxy.request_filter(&mut session, &mut ctx).await.unwrap(),
            !allowed,
            "{path}"
        );
        if !allowed {
            assert_eq!(read_status(&mut client).await, 400, "{path}");
        }
    }
}

mod lifecycle;

#[tokio::test]
async fn interim_headers_preserve_work_until_final_or_upgrade_response() {
    for final_status in [101, 200, 204, 304] {
        let proxy = build_proxy(
            TestBackend::builder()
                .load_session(MockSession::default())
                .build(),
        )
        .await;
        let (mut session, _client) =
            make_session("GET", "/api", "Accept: application/json\r\n").await;
        let mut ctx = proxy.new_ctx();
        proxy.request_filter(&mut session, &mut ctx).await.unwrap();
        ctx.login_state_mut().pending = Some(owed_persist());
        ctx.login_state_mut().set_cookies = owed_cookies().await;
        for status in [100, 103] {
            let mut header = ResponseHeader::build(status, None).unwrap();
            proxy
                .response_filter(&mut session, &mut header, &mut ctx)
                .await
                .unwrap();
            assert!(set_cookies(&header).is_empty());
            assert_eq!(proxy.inner.store.as_ref().unwrap().save_count(), 0);
            assert!(ctx.login_state().pending.is_some());
        }
        let mut header = ResponseHeader::build(final_status, None).unwrap();
        proxy
            .response_filter(&mut session, &mut header, &mut ctx)
            .await
            .unwrap();
        assert_eq!(
            set_cookies(&header),
            [
                MOCK_SESSION_CLEAR,
                "__Host-mock-session.kid=; HttpOnly; SameSite=Lax; Path=/; Secure; Max-Age=0"
            ]
        );
        proxy
            .response_filter(&mut session, &mut header, &mut ctx)
            .await
            .unwrap();
        proxy.logging(&mut session, None, &mut ctx).await;
        assert_eq!(
            set_cookies(&header),
            [
                MOCK_SESSION_CLEAR,
                "__Host-mock-session.kid=; HttpOnly; SameSite=Lax; Path=/; Secure; Max-Age=0"
            ]
        );
        assert_eq!(proxy.inner.store.as_ref().unwrap().save_count(), 1);
        assert!(ctx.login_state().session.is_some());
    }
}

#[test]
fn telemetry_classifies_login_decisions_with_bounded_labels() {
    use crate::metrics_test_support::{assert_counter, with_metrics};

    for (rule, has_session, expected) in [
        (LoginRule::public(), false, "public"),
        (LoginRule::optional(), false, "anonymous"),
        (LoginRule::required(), false, "unauthenticated"),
        (LoginRule::required(), true, "authenticated"),
        (LoginRule::required().check(admin_only), true, "forbidden"),
    ] {
        let ((), counters) = with_metrics(async {
            let mut store = TestBackend::default();
            if has_session {
                store.load_session = Arc::new(Mutex::new(Some(MockSession::default())));
            }
            let proxy = LoginProxy::builder()
                .inner(InnerProxy::new())
                .engine(build_engine(store).await)
                .metrics_name("browser")
                .path_guard(crate::login::GuardConfig::new(
                    crate::login::CaseSensitivity::Sensitive,
                    crate::login::DecodeDepth::UpToOne,
                ))
                .default(rule)
                .build()
                .unwrap();
            let (mut session, _client) = make_session(
                "GET",
                "/untrusted?subject=secret",
                "Accept: application/json\r\n",
            )
            .await;
            proxy
                .request_filter(&mut session, &mut proxy.new_ctx())
                .await
                .unwrap();
        });
        assert_counter(
            &counters,
            "huskarl.pingora.login.check",
            &[("name", "browser"), ("outcome", expected)],
            1,
        );
        assert_counter(
            &counters,
            "huskarl.pingora.login.session_operation",
            &[
                ("name", "browser"),
                ("operation", "load"),
                ("phase", "request"),
                ("outcome", "success"),
            ],
            u64::from(expected != "public"),
        );
        let own: Vec<_> = counters
            .iter()
            .filter(|(name, _, _)| name.starts_with("huskarl.pingora."))
            .collect();
        assert_eq!(
            own.len(),
            if cfg!(feature = "metrics") {
                if expected == "public" { 1 } else { 2 }
            } else {
                0
            }
        );
    }
}

fn diagnostic_detail(event: &LoginDiagnostic<'_>) -> String {
    match event {
        LoginDiagnostic::SessionFailure {
            operation,
            phase,
            error,
        } => {
            assert_eq!(error.kind(), SessionErrorKind::Unavailable);
            format!("{operation:?}/{phase:?}: {}", error_chain(*error))
        }
        LoginDiagnostic::StrandedCookies { count } => format!("stranded={count}"),
    }
}

#[test]
fn telemetry_finalizes_once_and_preserves_handled_failure_diagnostics() {
    use crate::metrics_test_support::{assert_counter, with_metrics};

    for (phase, revoke, fail) in [
        (LoginPhase::Response, false, false),
        (LoginPhase::Response, false, true),
        (LoginPhase::Response, true, true),
        (LoginPhase::Logging, false, false),
        (LoginPhase::Logging, false, true),
        (LoginPhase::Logging, true, true),
    ] {
        let diagnostics = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&diagnostics);
        let ((), counters) = with_metrics(async {
            let store = TestBackend::builder()
                .load_session(MockSession::default())
                .fail_save(fail)
                .fail_revoke(fail)
                .build();
            let proxy = LoginProxy::builder()
                .inner(InnerProxy::new())
                .engine(build_engine(store).await)
                .path_guard(crate::login::GuardConfig::new(
                    crate::login::CaseSensitivity::Sensitive,
                    crate::login::DecodeDepth::UpToOne,
                ))
                .diagnostics(move |event| {
                    let detail = diagnostic_detail(&event);
                    captured.lock().unwrap().push(detail);
                })
                .build()
                .expect("valid routes");
            let (mut session, _client) = make_session("GET", "/api", "").await;
            let mut ctx = proxy.new_ctx();
            proxy.request_filter(&mut session, &mut ctx).await.unwrap();
            ctx.login_state_mut().pending = Some(owed_persist());
            ctx.login_state_mut().terminate_requested = revoke;
            if !revoke {
                ctx.login_state_mut().set_cookies = owed_cookies().await;
            }
            if phase == LoginPhase::Response {
                let mut interim = ResponseHeader::build(103, None).unwrap();
                proxy
                    .response_filter(&mut session, &mut interim, &mut ctx)
                    .await
                    .unwrap();
                assert!(!ctx.login_state().finalized);
                let mut response = ResponseHeader::build(200, None).unwrap();
                let result = proxy
                    .response_filter(&mut session, &mut response, &mut ctx)
                    .await;
                assert_eq!(result.is_err(), fail && !revoke);
                proxy
                    .response_filter(&mut session, &mut response, &mut ctx)
                    .await
                    .unwrap();
            }
            proxy.logging(&mut session, None, &mut ctx).await;
            proxy.logging(&mut session, None, &mut ctx).await;
        });
        let operation = if revoke { "revoke" } else { "persist" };
        assert_counter(
            &counters,
            "huskarl.pingora.login.session_operation",
            &[
                ("name", ""),
                ("operation", operation),
                ("phase", phase.as_str()),
                ("outcome", if fail { "error" } else { "success" }),
            ],
            1,
        );
        assert_counter(
            &counters,
            "huskarl.pingora.login.finalization",
            &[("name", ""), ("outcome", phase.as_str())],
            1,
        );
        let stranded = 2 * u64::from(phase == LoginPhase::Logging);
        assert_counter(
            &counters,
            "huskarl.pingora.login.stranded_cookies",
            &[("name", "")],
            stranded,
        );
        let details = diagnostics.lock().unwrap();
        assert_eq!(details.len(), usize::from(fail) + usize::from(stranded > 0));
        if fail {
            assert!(
                details
                    .iter()
                    .any(|detail| detail.contains("failed")
                        && detail.contains(&format!("{phase:?}")))
            );
        }
    }
}

#[test]
fn telemetry_counts_preflights_engine_routes_and_route_denials() {
    use crate::metrics_test_support::{assert_counter, with_metrics};

    for (method, path, headers, rule, expected) in [
        (
            "OPTIONS",
            "/api",
            "Access-Control-Request-Method: GET\r\n",
            LoginRule::required(),
            "preflight",
        ),
        (
            "OPTIONS",
            "/api",
            "Access-Control-Request-Method: GET\r\n",
            LoginRule::required().method(http::Method::GET),
            "policy_denied",
        ),
        ("GET", "/callback", "", LoginRule::required(), "login_route"),
        (
            "GET",
            "/public/../api",
            "",
            LoginRule::required(),
            "path_confusion",
        ),
    ] {
        let ((), counters) = with_metrics(async {
            let proxy = build_proxy_with_routes(
                TestBackend::default(),
                vec![("/api", rule), ("/public", LoginRule::public())],
            )
            .await;
            let (mut session, _client) = make_session(method, path, headers).await;
            proxy
                .request_filter(&mut session, &mut proxy.new_ctx())
                .await
                .unwrap();
        });
        assert_counter(
            &counters,
            "huskarl.pingora.login.check",
            &[("name", ""), ("outcome", expected)],
            1,
        );
        assert!(
            !counters
                .iter()
                .any(|(name, _, _)| name == "huskarl.pingora.login.session_operation")
        );
    }
}

#[test]
fn telemetry_load_failure_preserves_the_original_error_without_metrics() {
    use crate::metrics_test_support::{assert_counter, with_metrics};

    let events = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&events);
    let ((), counters) = with_metrics(async {
        let proxy = LoginProxy::builder()
            .inner(InnerProxy::new())
            .engine(build_engine(TestBackend::builder().fail_load(true).build()).await)
            .path_guard(crate::login::GuardConfig::new(
                crate::login::CaseSensitivity::Sensitive,
                crate::login::DecodeDepth::UpToOne,
            ))
            .diagnostics(|_| panic!("replaced handler must not run"))
            .build()
            .expect("valid routes")
            .diagnostics(move |event| {
                let LoginDiagnostic::SessionFailure {
                    operation,
                    phase,
                    error,
                } = event
                else {
                    panic!("expected session-load diagnostic");
                };
                assert_eq!(operation, SessionOperation::Load);
                assert_eq!(phase, LoginPhase::Request);
                captured.lock().unwrap().push(error_chain(error));
            });
        let (mut session, _client) = make_session("GET", "/api", "").await;
        assert!(
            proxy
                .request_filter(&mut session, &mut proxy.new_ctx())
                .await
                .unwrap()
        );
        assert_eq!(session.response_written().unwrap().status.as_u16(), 500);
    });
    let events = events.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert!(events[0].contains("load failed"));
    assert_counter(
        &counters,
        "huskarl.pingora.login.check",
        &[("name", ""), ("outcome", "server_error")],
        1,
    );
    assert_counter(
        &counters,
        "huskarl.pingora.login.session_operation",
        &[
            ("name", ""),
            ("operation", "load"),
            ("phase", "request"),
            ("outcome", "error"),
        ],
        1,
    );
}

#[test]
fn telemetry_cancellation_does_not_claim_a_completed_persist() {
    use crate::metrics_test_support::{assert_counter, with_metrics};

    let ((), counters) = with_metrics(async {
        let gate = Arc::new(SaveGate::default());
        let store = TestBackend::builder()
            .load_session(MockSession::default())
            .save_gate(Arc::clone(&gate))
            .build();
        let proxy = build_proxy(store).await;
        let (mut session, _client) = make_session("GET", "/api", "").await;
        let mut ctx = proxy.new_ctx();
        proxy.request_filter(&mut session, &mut ctx).await.unwrap();
        ctx.login_state_mut().pending = Some(owed_persist());
        let mut response = ResponseHeader::build(200, None).unwrap();
        {
            let work = proxy.response_filter(&mut session, &mut response, &mut ctx);
            tokio::pin!(work);
            tokio::select! {
                result = &mut work => panic!("persist should remain pending: {result:?}"),
                () = gate.entered.notified() => {}
            }
        }
        assert!(ctx.login_state().finalized);
        proxy.logging(&mut session, None, &mut ctx).await;
        assert_eq!(proxy.inner.store.as_ref().unwrap().save_count(), 1);
    });
    assert_counter(
        &counters,
        "huskarl.pingora.login.finalization",
        &[("name", ""), ("outcome", "response")],
        1,
    );
    for outcome in ["success", "error"] {
        assert_counter(
            &counters,
            "huskarl.pingora.login.session_operation",
            &[
                ("name", ""),
                ("operation", "persist"),
                ("phase", "response"),
                ("outcome", outcome),
            ],
            0,
        );
    }
}
