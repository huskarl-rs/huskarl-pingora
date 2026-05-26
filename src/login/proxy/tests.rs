use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use huskarl::core::crypto::cipher::{AeadSealer, AeadUnsealer};
// ── is_navigation_request tests ───────────────────────────────────
use pingora_proxy::Session as ProxySession;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::login::cookie::login_state_cookie_name;

#[tokio::test]
async fn navigation_with_sec_fetch_mode_navigate() {
    let (session, _) = make_session("GET", "/", "Sec-Fetch-Mode: navigate\r\n").await;
    assert!(is_navigation_request(&session));
}

#[tokio::test]
async fn non_navigation_with_sec_fetch_mode_cors() {
    let (session, _) = make_session("GET", "/api", "Sec-Fetch-Mode: cors\r\n").await;
    assert!(!is_navigation_request(&session));
}

#[tokio::test]
async fn non_navigation_with_sec_fetch_mode_no_cors() {
    let (session, _) = make_session("GET", "/img.png", "Sec-Fetch-Mode: no-cors\r\n").await;
    assert!(!is_navigation_request(&session));
}

#[tokio::test]
async fn fallback_accept_html_is_navigation() {
    let (session, _) =
        make_session("GET", "/", "Accept: text/html,application/xhtml+xml\r\n").await;
    assert!(is_navigation_request(&session));
}

#[tokio::test]
async fn fallback_accept_json_is_not_navigation() {
    let (session, _) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    assert!(!is_navigation_request(&session));
}

#[tokio::test]
async fn no_accept_no_sec_fetch_is_not_navigation() {
    let (session, _) = make_session("GET", "/api", "").await;
    assert!(!is_navigation_request(&session));
}

#[tokio::test]
async fn sec_fetch_mode_takes_precedence_over_accept() {
    // Sec-Fetch-Mode says "cors" but Accept has text/html — mode wins.
    let (session, _) =
        make_session("GET", "/", "Sec-Fetch-Mode: cors\r\nAccept: text/html\r\n").await;
    assert!(!is_navigation_request(&session));
}

// ── Policy flow integration tests ────────────────────────────────

use std::{convert::Infallible, sync::Mutex};

use async_trait::async_trait;
use huskarl::{
    core::{
        BoxedError,
        http::HttpResponse as HuskarlHttpResponse,
        secrets::{Secret, SecretBytes, SecretOutput, SecretString},
    },
    grant::{authorization_code::StartOutput, core::TokenResponse},
    token::RefreshToken,
};
use huskarl_crypto_native::aead::{AesGcmKey, AesGcmKeyType};
use pingora_core::upstreams::peer::HttpPeer;
use tokio::io::DuplexStream;

use crate::login::{LoginCtx, SessionError, session::SessionDriver};

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

struct MockSession {
    state: crate::login::token_session::TokenState,
}

impl TokenSession for MockSession {
    fn token_state(&self) -> &crate::login::token_session::TokenState {
        &self.state
    }
    fn set_token_state(&mut self, state: crate::login::token_session::TokenState) {
        self.state = state;
    }
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

impl crate::login::session::sealed::Sealed for MockSessionDriver {}

impl SessionDriver for MockSessionDriver {
    type Session = MockSession;
    type LoadError = Infallible;

    async fn create(
        &self,
        _: crate::login::grant::CompletedLogin,
    ) -> Result<MockSession, SessionError> {
        unimplemented!()
    }
    async fn load(&self, _: &http::HeaderMap) -> Result<Option<MockSession>, Infallible> {
        Ok(self.load_session.lock().unwrap().take())
    }
    async fn save(
        &self,
        _: &MockSession,
        _: &mut pingora_http::ResponseHeader,
    ) -> Result<(), SessionError> {
        *self.save_called.lock().unwrap() = true;
        Ok(())
    }
    async fn touch(
        &self,
        _: &MockSession,
        _: &mut pingora_http::ResponseHeader,
    ) -> Result<(), SessionError> {
        *self.touch_called.lock().unwrap() = true;
        Ok(())
    }
    async fn delete(
        &self,
        _: &MockSession,
        _: &mut pingora_http::ResponseHeader,
    ) -> Result<(), SessionError> {
        *self.delete_called.lock().unwrap() = true;
        Ok(())
    }
}

// ── Mock inner proxy ─────────────────────────────────────────────

struct PolicyInnerProxy {
    forwarded: Mutex<bool>,
}

impl PolicyInnerProxy {
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
impl ProxyHttp for PolicyInnerProxy {
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

// ── Test cipher helper ───────────────────────────────────────────

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

// ── Build helpers ────────────────────────────────────────────────

async fn build_policy_proxy(
    store: MockSessionDriver,
    config: LoginConfig,
) -> LoginProxy<PolicyInnerProxy, CallbackTestGrant, MockSessionDriver, MockHttpClient> {
    let grant = CallbackTestGrant::new("https://auth.example.com/authorize", "unused");
    build_callback_proxy(store, config, grant).await
}

fn default_policy_config() -> LoginConfig {
    LoginConfig::builder()
        .callback_path("/callback".into())
        .scopes(vec![])
        .base_url("https://app.example.com".parse().unwrap())
        .build()
        .unwrap()
}

fn mock_session(
    token_expiry: Option<SystemTime>,
    refresh_token: Option<RefreshToken>,
    created_at: SystemTime,
    last_active: SystemTime,
) -> MockSession {
    MockSession {
        state: crate::login::token_session::TokenState {
            raw_token_response: serde_json::Value::Null,
            token_expiry,
            refresh_token,
            id_token: None,
            created_at,
            last_active,
        },
    }
}

fn valid_mock_session() -> MockSession {
    mock_session(
        Some(SystemTime::now() + Duration::from_secs(3600)),
        None,
        SystemTime::now(),
        SystemTime::now(),
    )
}

async fn make_session(
    method: &str,
    path: &str,
    extra_headers: &str,
) -> (ProxySession, DuplexStream) {
    let raw = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n{extra_headers}\r\n");
    let (mut client, server) = tokio::io::duplex(4096);
    client.write_all(raw.as_bytes()).await.unwrap();
    let mut session = ProxySession::new_h1(Box::new(server));
    session.downstream_session.read_request().await.unwrap();
    (session, client)
}

// ── Policy flow tests ────────────────────────────────────────────

#[tokio::test]
async fn policy_valid_session_forwards() {
    let store = MockSessionDriver::with_session(valid_mock_session());
    let proxy = build_policy_proxy(store, default_policy_config()).await;
    let (mut session, _client) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    let handled = proxy.request_filter(&mut session, &mut ctx).await.unwrap();

    assert!(!handled);
    assert!(proxy.inner.was_forwarded());
    assert!(ctx.login_session().is_some());
}

#[tokio::test]
async fn policy_max_lifetime_exceeded_expires() {
    let ms = mock_session(
        Some(SystemTime::now() + Duration::from_secs(3600)),
        None,
        SystemTime::now() - Duration::from_secs(7200),
        SystemTime::now(),
    );
    let store = MockSessionDriver::with_session(ms);
    let config = LoginConfig::builder()
        .callback_path("/callback".into())
        .scopes(vec![])
        .base_url("https://app.example.com".parse().unwrap())
        .max_lifetime(Duration::from_secs(3600))
        .build()
        .unwrap();
    let proxy = build_policy_proxy(store, config).await;
    let (mut session, _client) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    let handled = proxy.request_filter(&mut session, &mut ctx).await.unwrap();

    assert!(handled);
    assert!(!proxy.inner.was_forwarded());
    assert!(proxy.session_store.was_delete_called());
}

#[tokio::test]
async fn policy_idle_timeout_exceeded_expires() {
    let ms = mock_session(
        Some(SystemTime::now() + Duration::from_secs(3600)),
        None,
        SystemTime::now(),
        SystemTime::now() - Duration::from_secs(1800),
    );
    let store = MockSessionDriver::with_session(ms);
    let config = LoginConfig::builder()
        .callback_path("/callback".into())
        .scopes(vec![])
        .base_url("https://app.example.com".parse().unwrap())
        .idle_timeout(Duration::from_secs(900))
        .build()
        .unwrap();
    let proxy = build_policy_proxy(store, config).await;
    let (mut session, _client) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    let handled = proxy.request_filter(&mut session, &mut ctx).await.unwrap();

    assert!(handled);
    assert!(!proxy.inner.was_forwarded());
    assert!(proxy.session_store.was_delete_called());
}

#[tokio::test]
async fn policy_token_expired_no_refresh_token_expires() {
    let ms = mock_session(
        Some(SystemTime::now() - Duration::from_secs(60)),
        None,
        SystemTime::now(),
        SystemTime::now(),
    );
    let store = MockSessionDriver::with_session(ms);
    let proxy = build_policy_proxy(store, default_policy_config()).await;
    let (mut session, _client) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    let handled = proxy.request_filter(&mut session, &mut ctx).await.unwrap();

    assert!(handled);
    assert!(!proxy.inner.was_forwarded());
    assert!(proxy.session_store.was_delete_called());
}

#[tokio::test]
async fn policy_token_expired_refresh_fails_expires() {
    let ms = mock_session(
        Some(SystemTime::now() - Duration::from_secs(60)),
        Some(RefreshToken::new(SecretString::new("test_refresh"), None)),
        SystemTime::now(),
        SystemTime::now(),
    );
    let store = MockSessionDriver::with_session(ms);
    let proxy = build_policy_proxy(store, default_policy_config()).await;
    let (mut session, _client) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    let handled = proxy.request_filter(&mut session, &mut ctx).await.unwrap();

    assert!(handled);
    assert!(!proxy.inner.was_forwarded());
    assert!(proxy.session_store.was_delete_called());
}

#[tokio::test]
async fn policy_cors_preflight_bypasses_session() {
    let store = MockSessionDriver::empty();
    let proxy = build_policy_proxy(store, default_policy_config()).await;
    let (mut session, _client) =
        make_session("OPTIONS", "/api", "Access-Control-Request-Method: POST\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    let handled = proxy.request_filter(&mut session, &mut ctx).await.unwrap();

    assert!(!handled);
    assert!(proxy.inner.was_forwarded());
}

#[tokio::test]
async fn policy_no_session_returns_401() {
    let store = MockSessionDriver::empty();
    let proxy = build_policy_proxy(store, default_policy_config()).await;
    let (mut session, _client) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    let handled = proxy.request_filter(&mut session, &mut ctx).await.unwrap();

    assert!(handled);
    assert!(!proxy.inner.was_forwarded());
}

// ── Response reading helpers ─────────────────────────────────────

async fn read_response(client: &mut DuplexStream) -> (u16, String) {
    let mut buf = vec![0u8; 8192];
    let n = client.read(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf[..n]).to_string();
    let status: u16 = text
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    (status, text)
}

fn find_header<'a>(raw: &'a str, name: &str) -> Option<&'a str> {
    let name_lower = name.to_lowercase();
    for line in raw.lines() {
        if let Some((k, v)) = line.split_once(':')
            && k.trim().to_lowercase() == name_lower
        {
            return Some(v.trim());
        }
    }
    None
}

fn find_headers<'a>(raw: &'a str, name: &str) -> Vec<&'a str> {
    let name_lower = name.to_lowercase();
    raw.lines()
        .filter_map(|line| {
            let (k, v) = line.split_once(':')?;
            if k.trim().to_lowercase() == name_lower {
                Some(v.trim())
            } else {
                None
            }
        })
        .collect()
}

// ── Callback test grant ─────────────────────────────────────────

struct CallbackTestGrant {
    authorization_url: String,
    state: String,
}

impl CallbackTestGrant {
    fn new(authorization_url: &str, state: &str) -> Self {
        Self {
            authorization_url: authorization_url.to_owned(),
            state: state.to_owned(),
        }
    }
}

impl LoginGrant for CallbackTestGrant {
    async fn start(&self, _: &impl HttpClient, _: Vec<String>) -> Result<StartOutput, BoxedError> {
        Ok(StartOutput {
            authorization_url: self.authorization_url.parse().unwrap(),
            expires_in: None,
            pending_state: test_pending_state(&self.state),
        })
    }
    async fn complete(
        &self,
        _: &impl HttpClient,
        _: &PendingState,
        _: String,
        _: String,
        _: Option<String>,
    ) -> Result<crate::login::CompletedLogin, BoxedError> {
        Err(BoxedError::from_err("\0".parse::<http::Uri>().unwrap_err()))
    }
    async fn refresh(
        &self,
        _: &impl HttpClient,
        _: &RefreshToken,
    ) -> Result<TokenResponse, BoxedError> {
        // Always fails — constructing a TokenResponse requires crate-private
        // RawTokenResponse::into_token_response, so we can only test the
        // failure path here.
        Err(BoxedError::from_err("\0".parse::<http::Uri>().unwrap_err()))
    }
}

// ── Additional helpers ───────────────────────────────────────────

fn test_pending_state(state: &str) -> PendingState {
    PendingState {
        redirect_uri: "https://localhost/callback".to_owned(),
        pkce_verifier: None,
        state: state.to_owned(),
        nonce: "test_nonce".to_owned(),
        dpop_jkt: None,
    }
}

async fn seal_login_cookie(state: &str, original_url: &str, pending: &PendingState) -> String {
    let cipher = test_cipher().await;
    let sealer = AeadV1Sealer::new(cipher);
    let cookie = LoginStateCookie {
        original_url: original_url.to_owned(),
        pending_state: pending.clone(),
    };
    let payload = serde_json::to_vec(&cookie).unwrap();
    let bundle = sealer.seal(&payload, state.as_bytes()).await.unwrap();
    URL_SAFE_NO_PAD.encode(&bundle)
}

async fn build_callback_proxy(
    store: MockSessionDriver,
    config: LoginConfig,
    grant: CallbackTestGrant,
) -> LoginProxy<PolicyInnerProxy, CallbackTestGrant, MockSessionDriver, MockHttpClient> {
    LoginProxy::builder()
        .inner(PolicyInnerProxy::new())
        .config(config)
        .grant(grant)
        .session_store(store)
        .cipher(test_cipher().await)
        .http_client(MockHttpClient)
        .build()
}

// ── Redirect flow tests ─────────────────────────────────────────

#[tokio::test]
async fn redirect_no_session_navigation_sends_302() {
    let store = MockSessionDriver::empty();
    let grant = CallbackTestGrant::new("https://auth.example.com/authorize?client_id=test", "s1");
    let proxy = build_callback_proxy(store, default_policy_config(), grant).await;
    let (mut session, mut client) =
        make_session("GET", "/protected", "Sec-Fetch-Mode: navigate\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    let handled = proxy.request_filter(&mut session, &mut ctx).await.unwrap();
    assert!(handled);

    let (status, raw) = read_response(&mut client).await;
    assert_eq!(status, 302);
    assert_eq!(
        find_header(&raw, "location").unwrap(),
        "https://auth.example.com/authorize?client_id=test"
    );

    let cookies = find_headers(&raw, "set-cookie");
    let login_cookie = cookies
        .iter()
        .find(|c| c.contains("huskarl_login_"))
        .expect("login state cookie should be set");
    assert!(login_cookie.contains("HttpOnly"));
    assert!(login_cookie.contains("SameSite=Lax"));
    assert!(login_cookie.contains("Path=/"));
    assert!(login_cookie.contains("Max-Age=600"));
    assert!(login_cookie.contains("Secure"));
}

#[tokio::test]
async fn redirect_omits_secure_flag_when_disabled() {
    let store = MockSessionDriver::empty();
    let grant = CallbackTestGrant::new("https://auth.example.com/authorize", "s2");
    let config = LoginConfig::builder()
        .callback_path("/callback".into())
        .scopes(vec![])
        .base_url("https://app.example.com".parse().unwrap())
        .secure(false)
        .build()
        .unwrap();
    let proxy = build_callback_proxy(store, config, grant).await;
    let (mut session, mut client) = make_session("GET", "/", "Sec-Fetch-Mode: navigate\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    proxy.request_filter(&mut session, &mut ctx).await.unwrap();

    let (status, raw) = read_response(&mut client).await;
    assert_eq!(status, 302);

    let cookies = find_headers(&raw, "set-cookie");
    let login_cookie = cookies
        .iter()
        .find(|c| c.contains("huskarl_login_"))
        .expect("login state cookie should be set");
    assert!(!login_cookie.contains("Secure"));
    assert!(!login_cookie.contains("__Host-"));
    assert!(!login_cookie.contains("__Secure-"));
}

#[tokio::test]
async fn redirect_preserves_original_url_in_cookie() {
    let store = MockSessionDriver::empty();
    let state = "roundtrip";
    let grant = CallbackTestGrant::new("https://auth.example.com/authorize", state);
    let proxy = build_callback_proxy(store, default_policy_config(), grant).await;
    let (mut session, mut client) = make_session(
        "GET",
        "/app/page?foo=bar&baz=1",
        "Sec-Fetch-Mode: navigate\r\n",
    )
    .await;
    let mut ctx = proxy.inner.new_ctx();

    proxy.request_filter(&mut session, &mut ctx).await.unwrap();

    let (_status, raw) = read_response(&mut client).await;
    let cookies = find_headers(&raw, "set-cookie");
    let login_cookie = cookies
        .iter()
        .find(|c| c.contains("huskarl_login_"))
        .expect("login state cookie");

    // Extract the cookie value: name=value; attrs...
    let value_part = login_cookie
        .split_once('=')
        .unwrap()
        .1
        .split(';')
        .next()
        .unwrap();

    // Decrypt and verify original_url
    let bundle = URL_SAFE_NO_PAD.decode(value_part).unwrap();
    let cipher = test_cipher().await;
    let unsealer = AeadV1Unsealer::new(cipher);
    let plaintext = unsealer
        .unseal(None, &bundle, state.as_bytes())
        .await
        .unwrap();
    let login_state: LoginStateCookie = serde_json::from_slice(&plaintext).unwrap();
    assert_eq!(
        login_state.original_url,
        "https://app.example.com/app/page?foo=bar&baz=1"
    );
}

#[tokio::test]
async fn expired_session_navigation_redirects_to_as() {
    let ms = mock_session(
        Some(SystemTime::now() + Duration::from_secs(3600)),
        None,
        SystemTime::now() - Duration::from_secs(7200),
        SystemTime::now(),
    );
    let store = MockSessionDriver::with_session(ms);
    let config = LoginConfig::builder()
        .callback_path("/callback".into())
        .scopes(vec![])
        .base_url("https://app.example.com".parse().unwrap())
        .max_lifetime(Duration::from_secs(3600))
        .build()
        .unwrap();
    let grant = CallbackTestGrant::new("https://auth.example.com/authorize", "expired_s");
    let proxy = build_callback_proxy(store, config, grant).await;
    let (mut session, mut client) =
        make_session("GET", "/dashboard", "Sec-Fetch-Mode: navigate\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    let handled = proxy.request_filter(&mut session, &mut ctx).await.unwrap();
    assert!(handled);
    assert!(proxy.session_store.was_delete_called());

    let (status, _) = read_response(&mut client).await;
    assert_eq!(status, 302);
}

// ── Callback handler tests ──────────────────────────────────────

/// Sends a GET to the given callback path and asserts the response status.
async fn assert_callback_status(path: &str, extra_headers: &str, expected: u16) {
    let store = MockSessionDriver::empty();
    let grant = CallbackTestGrant::new("https://auth.example.com/authorize", "unused");
    let proxy = build_callback_proxy(store, default_policy_config(), grant).await;
    let (mut session, mut client) = make_session("GET", path, extra_headers).await;
    let mut ctx = proxy.inner.new_ctx();

    let handled = proxy.request_filter(&mut session, &mut ctx).await.unwrap();
    assert!(handled);

    let (status, _) = read_response(&mut client).await;
    assert_eq!(status, expected);
}

/// Sends a callback with code + state params and a login cookie, asserts status.
async fn assert_callback_cookie_status(state: &str, cookie_value: &str, expected: u16) {
    let store = MockSessionDriver::empty();
    let cookie_name = login_state_cookie_name(state, true, "/callback");
    let grant = CallbackTestGrant::new("https://auth.example.com/authorize", state);
    let proxy = build_callback_proxy(store, default_policy_config(), grant).await;
    let (mut session, mut client) = make_session(
        "GET",
        &format!("/callback?code=authcode&state={state}"),
        &format!("Cookie: {cookie_name}={cookie_value}\r\n"),
    )
    .await;
    let mut ctx = proxy.inner.new_ctx();

    let handled = proxy.request_filter(&mut session, &mut ctx).await.unwrap();
    assert!(handled);

    let (status, _) = read_response(&mut client).await;
    assert_eq!(status, expected);
}

#[tokio::test]
async fn callback_missing_code_returns_400() {
    assert_callback_status("/callback?state=abc", "", 400).await;
}

#[tokio::test]
async fn callback_missing_state_returns_400() {
    assert_callback_status("/callback?code=authcode", "", 400).await;
}

#[tokio::test]
async fn callback_no_params_returns_400() {
    assert_callback_status("/callback", "", 400).await;
}

#[tokio::test]
async fn callback_no_cookie_returns_400() {
    assert_callback_status("/callback?code=authcode&state=abc", "", 400).await;
}

#[tokio::test]
async fn callback_malformed_base64_cookie_returns_400() {
    assert_callback_cookie_status("b64bad", "not-valid!!!base64", 400).await;
}

#[tokio::test]
async fn callback_tampered_cookie_returns_400() {
    let fake = URL_SAFE_NO_PAD.encode(b"this is not an AEAD ciphertext bundle");
    assert_callback_cookie_status("tampered", &fake, 400).await;
}

#[tokio::test]
async fn callback_mismatched_state_aad_returns_400() {
    // Seal with AAD "right", present under state "wrong" — AEAD decryption fails
    let pending = test_pending_state("right");
    let sealed = seal_login_cookie("right", "/original", &pending).await;
    assert_callback_cookie_status("wrong", &sealed, 400).await;
}

#[tokio::test]
async fn callback_token_exchange_fails_returns_502() {
    let state = "exchange_fail";
    let pending = test_pending_state(state);
    let sealed = seal_login_cookie(state, "/original", &pending).await;
    assert_callback_cookie_status(state, &sealed, 502).await;
}

// ── upstream_response_filter tests ───────────────────────────────

#[tokio::test]
async fn upstream_response_filter_delete_path() {
    let store = MockSessionDriver::with_session(valid_mock_session());
    let proxy = build_policy_proxy(store, default_policy_config()).await;
    let (mut session, _client) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    // Simulate: session loaded + delete requested
    proxy.request_filter(&mut session, &mut ctx).await.unwrap();
    ctx.request_session_delete();

    let mut resp = pingora_http::ResponseHeader::build(200, Some(1)).unwrap();
    proxy
        .upstream_response_filter(&mut session, &mut resp, &mut ctx)
        .await
        .unwrap();

    assert!(proxy.session_store.was_delete_called());
    assert!(!proxy.session_store.was_save_called());
    assert!(!proxy.session_store.was_touch_called());
    assert!(ctx.login_session().is_none());
}

#[tokio::test]
async fn upstream_response_filter_save_path() {
    let store = MockSessionDriver::with_session(valid_mock_session());
    let proxy = build_policy_proxy(store, default_policy_config()).await;
    let (mut session, _client) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    // Simulate: session loaded + mutated (dirty)
    proxy.request_filter(&mut session, &mut ctx).await.unwrap();
    // Access via login_session_mut to trigger the dirty flag
    ctx.login_session_mut().unwrap().record_activity();

    let mut resp = pingora_http::ResponseHeader::build(200, Some(1)).unwrap();
    proxy
        .upstream_response_filter(&mut session, &mut resp, &mut ctx)
        .await
        .unwrap();

    assert!(proxy.session_store.was_save_called());
    assert!(!proxy.session_store.was_delete_called());
    assert!(!ctx.is_session_dirty());
}

#[tokio::test]
async fn upstream_response_filter_touch_path() {
    let store = MockSessionDriver::with_session(valid_mock_session());
    let proxy = build_policy_proxy(store, default_policy_config()).await;
    let (mut session, _client) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();

    // Simulate: session loaded, not dirty, not delete
    proxy.request_filter(&mut session, &mut ctx).await.unwrap();
    assert!(!ctx.is_session_dirty());
    assert!(!ctx.is_delete_requested());

    let mut resp = pingora_http::ResponseHeader::build(200, Some(1)).unwrap();
    proxy
        .upstream_response_filter(&mut session, &mut resp, &mut ctx)
        .await
        .unwrap();

    assert!(proxy.session_store.was_touch_called());
    assert!(!proxy.session_store.was_save_called());
    assert!(!proxy.session_store.was_delete_called());
}

#[tokio::test]
async fn upstream_response_filter_no_session() {
    let store = MockSessionDriver::empty();
    let proxy = build_policy_proxy(store, default_policy_config()).await;
    let (mut session, _client) = make_session("GET", "/api", "Accept: application/json\r\n").await;
    let mut ctx = proxy.inner.new_ctx();
    // No session in context at all

    let mut resp = pingora_http::ResponseHeader::build(200, Some(1)).unwrap();
    proxy
        .upstream_response_filter(&mut session, &mut resp, &mut ctx)
        .await
        .unwrap();

    assert!(!proxy.session_store.was_delete_called());
    assert!(!proxy.session_store.was_save_called());
    assert!(!proxy.session_store.was_touch_called());
}
