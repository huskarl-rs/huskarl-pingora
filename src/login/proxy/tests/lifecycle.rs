//! Contract tests through Pingora's real request runner, not a simulated hook order.
use super::*;
use pingora_cache::{CacheKey, CacheMeta, MemCache, RespCacheable, storage::Storage};
use pingora_core::{
    apps::HttpServerApp, protocols::http::ServerSession, server::configuration::ServerConf,
};
use std::sync::{
    LazyLock,
    atomic::{AtomicUsize, Ordering},
};

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
    LocalHead,
    LocalNoContent,
    LocalNotModified,
    UpstreamFailure,
    Direct,
}

struct LifecycleInner {
    path: ResponsePath,
    upstream: Option<std::net::SocketAddr>,
    key: String,
    observed: Arc<Mutex<Vec<&'static str>>>,
}

#[async_trait]
impl ProxyHttp for LifecycleInner {
    type CTX = LoginCtx<(), MockSession>;
    fn new_ctx(&self) -> Self::CTX {
        LoginCtx::new(())
    }
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        ctx.login_state_mut().pending = Some(owed_persist());
        match self.path {
            ResponsePath::Local
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
                    body: Bytes::from_static(b"local"),
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
        Ok(Box::new(HttpPeer::new(
            self.upstream.expect("cache hit must not contact upstream"),
            false,
            String::new(),
        )))
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
    async fn logging(&self, _: &mut Session, _: Option<&Error>, ctx: &mut Self::CTX) {
        assert!(
            ctx.login_state().session.is_some(),
            "identity must survive finalization"
        );
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

async fn run_case(path: ResponsePath, fail_save: bool) -> (String, Vec<&'static str>) {
    let key = format!("finalization-{}", NEXT_KEY.fetch_add(1, Ordering::Relaxed));
    if matches!(path, ResponsePath::CacheHit | ResponsePath::Revalidated) {
        seed_cache(&key, matches!(path, ResponsePath::Revalidated)).await;
    }
    let (upstream, task) = start_upstream(path).await;
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
            key: key.clone(),
            observed: observed.clone(),
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
    let (mut client, server) = tokio::io::duplex(16384);
    let method = if matches!(path, ResponsePath::LocalHead) {
        "HEAD"
    } else {
        "GET"
    };
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
    let ((), wire) =
        tokio::time::timeout(Duration::from_secs(5), async { tokio::join!(serve, read) })
            .await
            .unwrap();
    if let Some(task) = task {
        task.await.unwrap();
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
    assert_eq!(events, ["logging"]);
}
