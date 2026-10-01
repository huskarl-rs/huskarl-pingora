//! Contract tests through Pingora's real request runner, not a simulated hook order.
use std::sync::{
    LazyLock,
    atomic::{AtomicUsize, Ordering},
};

use pingora_cache::{CacheKey, CacheMeta, MemCache, RespCacheable, storage::Storage};
use pingora_core::{
    apps::HttpServerApp, protocols::http::ServerSession, server::configuration::ServerConf,
};

use super::*;

static CACHE: LazyLock<MemCache> = LazyLock::new(MemCache::new);
static NEXT_KEY: AtomicUsize = AtomicUsize::new(0);
const COOKIE: &str = "mock-session=rotated; Secure; HttpOnly";

#[derive(Clone, Copy, Debug)]
enum ResponsePath {
    Upstream,
    EarlyHints,
    CacheHit,
    Revalidated,
    Local,
    LocalLarge,
    LocalHead,
    LocalNoContent,
    LocalNotModified,
    UpstreamFailure,
    Direct,
}

struct LifecycleInner {
    path: ResponsePath,
    upstream: Option<std::net::SocketAddr>,
    upstream_h2: bool,
    key: String,
    observed: Arc<Mutex<Vec<&'static str>>>,
    request_gate: Option<Arc<SaveGate>>,
}

#[async_trait]
impl ProxyHttp for LifecycleInner {
    type CTX = LoginCtx<(), MockSession>;
    fn new_ctx(&self) -> Self::CTX {
        LoginCtx::new(())
    }
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        ctx.login_state_mut().pending = Some(owed_persist());
        if let Some(gate) = &self.request_gate {
            gate.entered.notify_one();
            gate.release.notified().await;
        }
        match self.path {
            ResponsePath::Local
            | ResponsePath::LocalLarge
            | ResponsePath::LocalHead
            | ResponsePath::LocalNoContent
            | ResponsePath::LocalNotModified => {
                ctx.login_state_mut().respond(LoginResponse::Rendered {
                    status: match self.path {
                        ResponsePath::LocalNoContent => http::StatusCode::NO_CONTENT,
                        ResponsePath::LocalNotModified => http::StatusCode::NOT_MODIFIED,
                        _ => http::StatusCode::OK,
                    },
                    headers: vec![],
                    body: if matches!(self.path, ResponsePath::LocalLarge) {
                        Bytes::from(vec![b'x'; 65536])
                    } else {
                        Bytes::from_static(b"local")
                    },
                })?;
                Ok(false)
            }
            ResponsePath::Direct => {
                session.respond_error(200).await?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    async fn upstream_peer(&self, _: &mut Session, _: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        if matches!(self.path, ResponsePath::UpstreamFailure) {
            return Err(Error::explain(
                pingora_error::ErrorType::ConnectError,
                "simulated upstream failure",
            )
            .into_up());
        }
        let mut peer = HttpPeer::new(
            self.upstream.expect("cache hit must not contact upstream"),
            false,
            String::new(),
        );
        if self.upstream_h2 {
            peer.options.set_http_version(2, 2);
        }
        Ok(Box::new(peer))
    }
    fn request_cache_filter(&self, session: &mut Session, _: &mut Self::CTX) -> Result<()> {
        if matches!(
            self.path,
            ResponsePath::CacheHit | ResponsePath::Revalidated | ResponsePath::Upstream
        ) {
            session.cache.enable(&*CACHE, None, None, None, None);
        }
        Ok(())
    }
    fn cache_key_callback(&self, _: &Session, _: &mut Self::CTX) -> Result<CacheKey> {
        Ok(CacheKey::new(self.key.clone(), ""))
    }
    fn response_cache_filter(
        &self,
        _: &Session,
        response: &ResponseHeader,
        _: &mut Self::CTX,
    ) -> Result<RespCacheable> {
        assert!(
            set_cookies(response).is_empty(),
            "session cookies must never enter cache admission"
        );
        let now = SystemTime::now();
        Ok(RespCacheable::Cacheable(CacheMeta::new(
            now + Duration::from_secs(60),
            now,
            0,
            0,
            response.clone(),
        )))
    }
    async fn response_filter(
        &self,
        _: &mut Session,
        response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        assert!(ctx.login_state().session.is_some());
        if response.status.is_informational() {
            self.observed.lock().unwrap().push("interim");
        } else {
            self.observed.lock().unwrap().push("final");
        }
        Ok(())
    }
    async fn logging(&self, _: &mut Session, error: Option<&Error>, ctx: &mut Self::CTX) {
        assert!(
            ctx.login_state().session.is_some(),
            "identity must survive finalization"
        );
        if error.is_some() {
            self.observed.lock().unwrap().push("error");
        }
        self.observed.lock().unwrap().push("logging");
    }
}

async fn seed_cache(key: &str, stale: bool) {
    let mut header = ResponseHeader::build(200, None).unwrap();
    header.insert_header("Content-Length", "6").unwrap();
    header.insert_header("ETag", "\"version-1\"").unwrap();
    let now = SystemTime::now();
    let expiry = if stale {
        now - Duration::from_secs(60)
    } else {
        now + Duration::from_secs(60)
    };
    let meta = CacheMeta::new(expiry, now - Duration::from_secs(120), 0, 0, header);
    let trace = pingora_cache::trace::Span::inactive().handle();
    let mut miss = CACHE
        .get_miss_handler(&CacheKey::new(key, ""), &meta, &trace)
        .await
        .unwrap();
    miss.write_body(Bytes::from_static(b"cached"), true)
        .await
        .unwrap();
    miss.finish().await.unwrap();
}

async fn start_upstream(
    path: ResponsePath,
    http2: bool,
) -> (
    Option<std::net::SocketAddr>,
    Option<tokio::task::JoinHandle<()>>,
) {
    if matches!(
        path,
        ResponsePath::Upstream | ResponsePath::EarlyHints | ResponsePath::Revalidated
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            if http2 {
                let mut connection = h2::server::handshake(stream).await.unwrap();
                let (request, mut response) = connection.accept().await.unwrap().unwrap();
                assert_eq!(request.version(), http::Version::HTTP_2);
                if matches!(path, ResponsePath::EarlyHints) {
                    response
                        .send_informational(http::Response::builder().status(103).body(()).unwrap())
                        .unwrap();
                }
                if matches!(path, ResponsePath::Revalidated) {
                    assert!(request.headers().contains_key("if-none-match"));
                    response
                        .send_response(
                            http::Response::builder().status(304).body(()).unwrap(),
                            true,
                        )
                        .unwrap();
                } else {
                    let mut body = response
                        .send_response(
                            http::Response::builder()
                                .status(200)
                                .header("content-length", "8")
                                .body(())
                                .unwrap(),
                            false,
                        )
                        .unwrap();
                    body.send_data(Bytes::from_static(b"upstream"), true)
                        .unwrap();
                }
                connection.graceful_shutdown();
                while let Some(request) = connection.accept().await {
                    request.unwrap();
                }
                return;
            }
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(stream.read_u8().await.unwrap());
            }
            if matches!(path, ResponsePath::Revalidated) {
                assert!(
                    String::from_utf8_lossy(&request)
                        .to_lowercase()
                        .contains("if-none-match:")
                );
                stream
                    .write_all(b"HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n")
                    .await
                    .unwrap();
            } else {
                if matches!(path, ResponsePath::EarlyHints) {
                    stream
                        .write_all(
                            b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n",
                        )
                        .await
                        .unwrap();
                }
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nupstream").await.unwrap();
            }
        });
        (Some(address), Some(task))
    } else {
        (None, None)
    }
}

type LifecycleApp = pingora_proxy::HttpProxy<LoginProxy<LifecycleInner, MockSessionDriver>>;

async fn exchange_h1(app: Arc<impl HttpServerApp>, method: &str) -> String {
    let (mut client, server) = tokio::io::duplex(16384);
    client.write_all(format!("{method} /api HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let (_shutdown_tx, shutdown) = tokio::sync::watch::channel(false);
    let serve = async {
        drop(
            app.process_new_http(ServerSession::new_http1(Box::new(server)), &shutdown)
                .await,
        );
    };
    let read = async {
        let mut bytes = Vec::new();
        client.read_to_end(&mut bytes).await.unwrap();
        String::from_utf8(bytes).unwrap()
    };
    let ((), wire) = tokio::join!(serve, read);
    wire
}

async fn exchange_h2(app: Arc<impl HttpServerApp>, method: &str) -> String {
    use pingora_core::protocols::{
        Digest,
        http::v2::server::{H2Accept, HttpSession, handshake},
    };
    let (client, server) = tokio::io::duplex(16384);
    let (tx, rx) = tokio::sync::oneshot::channel();
    let server_driver = tokio::spawn(async move {
        let mut connection = handshake(Box::new(server), None).await.unwrap();
        let Some(H2Accept::Session(session)) =
            HttpSession::from_h2_conn(&mut connection, Arc::new(Digest::default()))
                .await
                .unwrap()
        else {
            panic!("expected h2 request");
        };
        assert!(tx.send(session).is_ok());
        while let Some(request) = connection.accept().await {
            request.unwrap();
        }
    });
    let (mut sender, connection) = h2::client::handshake(client).await.unwrap();
    let client_driver = tokio::spawn(connection);
    let request = http::Request::builder()
        .method(method)
        .uri("https://localhost/api")
        .header("accept", "application/json")
        .body(())
        .unwrap();
    let (response, _stream) = sender.send_request(request, true).unwrap();
    let session = rx.await.unwrap();
    let (_tx, shutdown) = tokio::sync::watch::channel(false);
    let serve = async {
        drop(
            app.process_new_http(ServerSession::new_http2(session), &shutdown)
                .await,
        );
    };
    let read = async {
        let response = response.await.unwrap();
        let mut wire = format!("HTTP/2 {}\r\n", response.status());
        for (name, value) in response.headers() {
            use std::fmt::Write;
            write!(wire, "{name}: {}\r\n", value.to_str().unwrap()).unwrap();
        }
        wire.push_str("\r\n");
        let mut body = response.into_body();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.unwrap();
            wire.push_str(std::str::from_utf8(&chunk).unwrap());
            body.flow_control().release_capacity(chunk.len()).unwrap();
        }
        wire
    };
    let ((), wire) = tokio::join!(serve, read);
    client_driver.abort();
    server_driver.abort();
    let _ = client_driver.await;
    let _ = server_driver.await;
    wire
}

#[tokio::test]
async fn login_denial_omits_head_body_for_both_downstream_protocols() {
    let proxy = build_proxy(MockSessionDriver::default()).await;
    let mut app = pingora_proxy::HttpProxy::new(proxy, Arc::new(ServerConf::default()));
    app.handle_init_modules();
    let app = Arc::new(app);

    for http2 in [false, true] {
        for method in ["GET", "HEAD"] {
            let wire = tokio::time::timeout(Duration::from_secs(5), async {
                if http2 {
                    exchange_h2(Arc::clone(&app), method).await
                } else {
                    exchange_h1(Arc::clone(&app), method).await
                }
            })
            .await
            .expect("login denial timed out");
            let (headers, body) = wire.split_once("\r\n\r\n").unwrap();
            assert!(headers.lines().next().unwrap().contains("401"), "{wire}");
            assert!(headers.to_lowercase().contains("cache-control: no-store"));
            assert!(headers.to_lowercase().contains("content-type:"));
            if method == "HEAD" {
                assert!(body.is_empty(), "HEAD must not send a body: {wire}");
            } else {
                assert!(!body.is_empty(), "GET must retain its error body: {wire}");
            }
        }
    }
}

async fn run_case(path: ResponsePath, fail_save: bool) -> (String, Vec<&'static str>) {
    run_case_with_protocol(path, fail_save, false).await
}

async fn run_case_with_protocol(
    path: ResponsePath,
    fail_save: bool,
    http2: bool,
) -> (String, Vec<&'static str>) {
    run_case_with_protocols(path, fail_save, http2, false).await
}

async fn run_case_with_protocols(
    path: ResponsePath,
    fail_save: bool,
    http2: bool,
    upstream_h2: bool,
) -> (String, Vec<&'static str>) {
    let key = format!("finalization-{}", NEXT_KEY.fetch_add(1, Ordering::Relaxed));
    if matches!(path, ResponsePath::CacheHit | ResponsePath::Revalidated) {
        seed_cache(&key, matches!(path, ResponsePath::Revalidated)).await;
    }
    let (upstream, task) = start_upstream(path, upstream_h2).await;
    let engine = build_engine(
        MockSessionDriver::builder()
            .load_session(MockSession::default())
            .fail_save(fail_save)
            .save_cookies(vec![HeaderValue::from_static(COOKIE)])
            .build(),
    )
    .await;
    let observed = Arc::new(Mutex::new(Vec::new()));
    let proxy = LoginProxy::builder()
        .inner(LifecycleInner {
            path,
            upstream,
            upstream_h2,
            key: key.clone(),
            observed: observed.clone(),
            request_gate: None,
        })
        .engine(engine.clone())
        .path_guard(GuardConfig::new(
            crate::login::CaseSensitivity::Sensitive,
            DecodeDepth::UpToOne,
        ))
        .build()
        .unwrap();
    let mut app = pingora_proxy::HttpProxy::new(proxy, Arc::new(ServerConf::default()));
    app.handle_init_modules();
    let app = Arc::new(app);
    let method = if matches!(path, ResponsePath::LocalHead) {
        "HEAD"
    } else {
        "GET"
    };
    let wire = tokio::time::timeout(Duration::from_secs(5), async {
        if http2 {
            exchange_h2(app, method).await
        } else {
            exchange_h1(app, method).await
        }
    })
    .await
    .expect("request lifecycle timed out");
    if let Some(task) = task {
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
    }
    assert_eq!(
        engine.session_store().save_count(),
        1,
        "{path:?}: must finalize exactly once"
    );
    if matches!(
        path,
        ResponsePath::Upstream | ResponsePath::CacheHit | ResponsePath::Revalidated
    ) {
        let trace = pingora_cache::trace::Span::inactive().handle();
        let (meta, _) = CACHE
            .lookup(&CacheKey::new(key, ""), &trace)
            .await
            .unwrap()
            .unwrap();
        assert!(
            set_cookies(meta.response_header()).is_empty(),
            "stored response must not contain session cookies"
        );
    }
    let events = observed.lock().unwrap().clone();
    (wire, events)
}

#[tokio::test]
async fn real_pingora_response_paths_deliver_cookies_once() {
    for path in [
        ResponsePath::Upstream,
        ResponsePath::EarlyHints,
        ResponsePath::CacheHit,
        ResponsePath::Revalidated,
        ResponsePath::Local,
    ] {
        let (wire, events) = run_case(path, false).await;
        assert!(wire.contains("200 OK"), "{path:?}: {wire}");
        assert_eq!(wire.matches(COOKIE).count(), 1, "{path:?}: {wire}");
        assert!(wire.to_lowercase().contains("cache-control: no-store"));
        assert_eq!(events.last(), Some(&"logging"));
        assert_eq!(events.iter().filter(|event| **event == "final").count(), 1);
        if matches!(path, ResponsePath::EarlyHints) {
            assert!(events.contains(&"interim"));
            let final_header = wire.find("HTTP/1.1 200").unwrap();
            assert!(!wire[..final_header].contains(COOKIE));
        }
    }
}

#[tokio::test]
async fn real_pingora_persist_failures_never_serve_success() {
    for path in [
        ResponsePath::Upstream,
        ResponsePath::CacheHit,
        ResponsePath::Revalidated,
        ResponsePath::Local,
    ] {
        let (wire, _) = run_case(path, true).await;
        // Pingora's fresh cache-hit handler maps response-filter errors to 500.
        let expected = if matches!(path, ResponsePath::CacheHit) {
            "500"
        } else {
            "503"
        };
        assert!(
            wire.starts_with(&format!("HTTP/1.1 {expected}")),
            "{path:?}: {wire}"
        );
        assert!(!wire.contains(COOKIE));
        assert!(!wire.contains("cached") && !wire.contains("upstream") && !wire.ends_with("local"));
    }
}

#[tokio::test]
async fn direct_writes_demonstrate_the_documented_boundary() {
    let (wire, events) = run_case(ResponsePath::Direct, false).await;
    assert!(wire.contains("200 OK"));
    assert!(!wire.contains(COOKIE));
    assert_eq!(events, ["logging"]);
}

#[tokio::test]
async fn buffered_local_responses_obey_bodyless_response_rules() {
    for (path, status) in [
        (ResponsePath::LocalHead, 200),
        (ResponsePath::LocalNoContent, 204),
        (ResponsePath::LocalNotModified, 304),
    ] {
        let (wire, _) = run_case(path, false).await;
        assert!(
            wire.starts_with(&format!("HTTP/1.1 {status}")),
            "{path:?}: {wire}"
        );
        assert!(
            wire.ends_with("\r\n\r\n"),
            "{path:?}: unexpected body: {wire}"
        );
        assert_eq!(wire.matches(COOKIE).count(), 1);
        if matches!(path, ResponsePath::LocalHead) {
            assert!(wire.to_lowercase().contains("content-length: 5"));
        } else {
            assert!(!wire.to_lowercase().contains("content-length:"));
        }
    }
}

#[tokio::test]
async fn upstream_failure_uses_cleanup_without_claiming_cookie_delivery() {
    let (wire, events) = run_case(ResponsePath::UpstreamFailure, false).await;
    assert!(wire.starts_with("HTTP/1.1 502"), "{wire}");
    assert!(!wire.contains(COOKIE));
    assert_eq!(events, ["error", "logging"]);
}

#[tokio::test]
async fn http2_response_paths_finalize_and_keep_cookies_out_of_cache() {
    for path in [
        ResponsePath::Upstream,
        ResponsePath::EarlyHints,
        ResponsePath::CacheHit,
        ResponsePath::Revalidated,
        ResponsePath::Local,
        ResponsePath::LocalHead,
        ResponsePath::LocalNoContent,
        ResponsePath::LocalNotModified,
    ] {
        let (wire, events) = run_case_with_protocol(path, false, true).await;
        let status = match path {
            ResponsePath::LocalNoContent => 204,
            ResponsePath::LocalNotModified => 304,
            _ => 200,
        };
        assert!(
            wire.starts_with(&format!("HTTP/2 {status}")),
            "{path:?}: {wire}"
        );
        assert_eq!(wire.matches(COOKIE).count(), 1, "{path:?}: {wire}");
        assert!(wire.contains("cache-control: no-store"));
        assert_eq!(events.last(), Some(&"logging"));
        assert_eq!(events.iter().filter(|event| **event == "final").count(), 1);
        if matches!(path, ResponsePath::EarlyHints) {
            assert!(events.contains(&"interim"));
        }
        if matches!(
            path,
            ResponsePath::LocalHead | ResponsePath::LocalNoContent | ResponsePath::LocalNotModified
        ) {
            assert!(wire.ends_with("\r\n\r\n"), "{path:?}: unexpected body");
        }
    }
}

#[tokio::test]
async fn http2_persist_failures_never_deliver_success_or_cookies() {
    for path in [
        ResponsePath::Upstream,
        ResponsePath::CacheHit,
        ResponsePath::Revalidated,
        ResponsePath::Local,
    ] {
        let (wire, events) = run_case_with_protocol(path, true, true).await;
        let status = if matches!(path, ResponsePath::CacheHit) {
            500
        } else {
            503
        };
        assert!(
            wire.starts_with(&format!("HTTP/2 {status}")),
            "{path:?}: {wire}"
        );
        assert!(!wire.contains(COOKIE));
        assert!(!wire.contains("cached") && !wire.contains("upstream") && !wire.ends_with("local"));
        assert_eq!(events.last(), Some(&"logging"));
    }
}

struct LocalFixture {
    app: Arc<LifecycleApp>,
    engine: Arc<LoginEngine<MockSessionDriver>>,
    observed: Arc<Mutex<Vec<&'static str>>>,
}

async fn local_fixture(
    path: ResponsePath,
    save_gate: Option<Arc<SaveGate>>,
    request_gate: Option<Arc<SaveGate>>,
) -> LocalFixture {
    let engine = build_engine(
        MockSessionDriver::builder()
            .load_session(MockSession::default())
            .save_cookies(vec![HeaderValue::from_static(COOKIE)])
            .maybe_save_gate(save_gate)
            .build(),
    )
    .await;
    let observed = Arc::new(Mutex::new(Vec::new()));
    let proxy = LoginProxy::builder()
        .inner(LifecycleInner {
            path,
            upstream: None,
            upstream_h2: false,
            key: String::new(),
            observed: observed.clone(),
            request_gate,
        })
        .engine(engine.clone())
        .path_guard(GuardConfig::new(
            crate::login::CaseSensitivity::Sensitive,
            DecodeDepth::UpToOne,
        ))
        .build()
        .unwrap();
    let mut app = pingora_proxy::HttpProxy::new(proxy, Arc::new(ServerConf::default()));
    app.handle_init_modules();
    LocalFixture {
        app: Arc::new(app),
        engine,
        observed,
    }
}

async fn start_local_request(
    app: Arc<LifecycleApp>,
) -> (DuplexStream, tokio::task::JoinHandle<()>) {
    let (mut client, server) = tokio::io::duplex(1024);
    client.write_all(b"GET /api HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\n\r\n").await.unwrap();
    let task = tokio::spawn(async move {
        let (_tx, shutdown) = tokio::sync::watch::channel(false);
        drop(
            app.process_new_http(ServerSession::new_http1(Box::new(server)), &shutdown)
                .await,
        );
    });
    (client, task)
}

#[tokio::test]
async fn disconnect_before_headers_does_not_repeat_completed_persistence() {
    let gate = Arc::new(SaveGate::default());
    let fixture = local_fixture(ResponsePath::Local, Some(gate.clone()), None).await;
    let (client, task) = start_local_request(fixture.app).await;
    tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
        .await
        .unwrap();
    assert_eq!(
        *fixture
            .engine
            .session_store()
            .save_completions
            .lock()
            .unwrap(),
        0
    );
    // Persistence is in flight. Closing the reader guarantees the subsequent
    // downstream header write fails, without relying on socket timing.
    drop(client);
    gate.release.notify_one();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fixture.engine.session_store().save_count(), 1);
    assert_eq!(
        *fixture
            .engine
            .session_store()
            .save_completions
            .lock()
            .unwrap(),
        1
    );
    assert_eq!(
        *fixture.observed.lock().unwrap(),
        ["final", "error", "logging"]
    );
}

#[tokio::test]
async fn disconnect_during_body_preserves_the_already_delivered_cookie() {
    let fixture = local_fixture(ResponsePath::LocalLarge, None, None).await;
    let (mut client, task) = start_local_request(fixture.app).await;
    let header = tokio::time::timeout(Duration::from_secs(5), async {
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(client.read_u8().await.unwrap());
        }
        String::from_utf8(header).unwrap()
    })
    .await
    .unwrap();
    assert_eq!(header.matches(COOKIE).count(), 1);
    assert!(header.to_lowercase().contains("content-length: 65536"));
    // The body exceeds the duplex buffer, so the writer cannot have completed.
    assert!(!task.is_finished());
    drop(client);
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fixture.engine.session_store().save_count(), 1);
    assert_eq!(
        *fixture
            .engine
            .session_store()
            .save_completions
            .lock()
            .unwrap(),
        1
    );
    assert_eq!(
        *fixture.observed.lock().unwrap(),
        ["final", "error", "logging"]
    );
}

#[tokio::test]
async fn aborting_the_request_task_does_not_run_async_cleanup() {
    for during_save in [false, true] {
        let gate = Arc::new(SaveGate::default());
        let fixture = local_fixture(
            ResponsePath::Local,
            during_save.then(|| gate.clone()),
            (!during_save).then(|| gate.clone()),
        )
        .await;
        let (mut client, task) = start_local_request(fixture.app).await;
        tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
            .await
            .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let mut wire = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut wire))
            .await
            .unwrap()
            .unwrap();
        assert!(
            wire.is_empty(),
            "cancellation before headers cannot deliver cookies"
        );
        assert_eq!(
            fixture.engine.session_store().save_count(),
            usize::from(during_save)
        );
        assert_eq!(
            *fixture
                .engine
                .session_store()
                .save_completions
                .lock()
                .unwrap(),
            0
        );
        assert_eq!(
            *fixture.observed.lock().unwrap(),
            if during_save { vec!["final"] } else { vec![] }
        );
    }
}

#[tokio::test]
async fn http2_upstreams_finalize_for_both_downstream_protocols() {
    for downstream_h2 in [false, true] {
        for path in [
            ResponsePath::Upstream,
            ResponsePath::EarlyHints,
            ResponsePath::Revalidated,
        ] {
            for fail_save in [false, true] {
                let (wire, events) =
                    run_case_with_protocols(path, fail_save, downstream_h2, true).await;
                let status = if fail_save { 503 } else { 200 };
                let protocol = if downstream_h2 { "HTTP/2" } else { "HTTP/1.1" };
                assert!(
                    wire.contains(&format!("{protocol} {status}")),
                    "{path:?}: {wire}"
                );
                assert_eq!(wire.matches(COOKIE).count(), usize::from(!fail_save));
                if fail_save {
                    assert!(!wire.ends_with("upstream") && !wire.ends_with("cached"));
                }
                assert_eq!(events.last(), Some(&"logging"));
                if matches!(path, ResponsePath::EarlyHints) {
                    // Pingora's h2 upstream reader polls only the final
                    // ResponseFuture; it does not forward informational headers.
                    assert!(!events.contains(&"interim"));
                }
            }
        }
    }
}

#[tokio::test]
async fn http2_stream_reset_during_save_completes_once_and_runs_cleanup() {
    use pingora_core::protocols::{
        Digest,
        http::v2::server::{H2Accept, HttpSession, handshake},
    };
    let gate = Arc::new(SaveGate::default());
    let fixture = local_fixture(ResponsePath::Local, Some(gate.clone()), None).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        let (client, server) = tokio::io::duplex(16384);
        let (tx, rx) = tokio::sync::oneshot::channel();
        let server_driver = tokio::spawn(async move {
            let mut connection = handshake(Box::new(server), None).await.unwrap();
            let Some(H2Accept::Session(session)) =
                HttpSession::from_h2_conn(&mut connection, Arc::new(Digest::default()))
                    .await
                    .unwrap()
            else {
                panic!("expected h2 request");
            };
            assert!(tx.send(session).is_ok());
            while let Some(request) = connection.accept().await {
                request.unwrap();
            }
        });
        let (mut sender, mut connection) = h2::client::handshake(client).await.unwrap();
        let mut ping = connection.ping_pong().unwrap();
        let client_driver = tokio::spawn(connection);
        let request = http::Request::builder()
            .uri("https://localhost/api")
            .header("accept", "application/json")
            .body(())
            .unwrap();
        let (response, mut stream) = sender.send_request(request, true).unwrap();
        let session = rx.await.unwrap();
        let task = tokio::spawn(async move {
            let (_tx, shutdown) = tokio::sync::watch::channel(false);
            drop(
                fixture
                    .app
                    .process_new_http(ServerSession::new_http2(session), &shutdown)
                    .await,
            );
        });
        gate.entered.notified().await;
        stream.send_reset(h2::Reason::CANCEL);
        // The round trip orders reset processing before persistence resumes.
        ping.ping(h2::Ping::opaque()).await.unwrap();
        assert_eq!(
            response.await.unwrap_err().reason(),
            Some(h2::Reason::CANCEL)
        );
        gate.release.notify_one();
        task.await.unwrap();
        client_driver.abort();
        server_driver.abort();
        let _ = client_driver.await;
        let _ = server_driver.await;
    })
    .await
    .expect("reset lifecycle timed out");
    assert_eq!(fixture.engine.session_store().save_count(), 1);
    assert_eq!(
        *fixture
            .engine
            .session_store()
            .save_completions
            .lock()
            .unwrap(),
        1
    );
    assert_eq!(
        *fixture.observed.lock().unwrap(),
        ["final", "error", "logging"]
    );
}
