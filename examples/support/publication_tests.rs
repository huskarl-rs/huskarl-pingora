//! Drive the example's consumer router through Pingora's HTTP request runner.
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};

use huskarl_pingora::resource_server::{
    core::platform::MaybeSendBoxFuture,
    validator::{
        AccessTokenValidator, ValidationResult,
        metadata::{ProvideValidatorMetadata, ValidatorMetadata},
    },
};
use pingora_core::{
    apps::HttpServerApp, protocols::http::ServerSession, server::configuration::ServerConf,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

#[derive(Default)]
struct Observed {
    prepared: AtomicUsize,
    early: AtomicUsize,
    validated: Mutex<Vec<String>>,
    application: AtomicUsize,
}

struct Validator {
    observed: Arc<Observed>,
    audience: String,
}
impl AccessTokenValidator for Validator {
    type Claims = Claims;
    type Error = <Rfc9068Validator as AccessTokenValidator>::Error;

    fn validate_request<'a>(
        &'a self,
        headers: &'a http::HeaderMap,
        _method: &'a http::Method,
        uri: &'a http::Uri,
        _cert: Option<&'a [u8]>,
    ) -> MaybeSendBoxFuture<'a, ValidationResult<Claims, Self::Error>> {
        self.observed
            .validated
            .lock()
            .unwrap()
            .push(uri.to_string());
        // Test fixture only: production main always constructs the JWT validator.
        let token = headers
            .contains_key("authorization")
            .then(|| ValidatedRequest {
                iss: None,
                sub: None,
                aud: vec![self.audience.clone()],
                jti: None,
                iat: None,
                exp: None,
                cnf: None,
                introspection_jwt: None,
                claims: Claims {
                    client_id: "test".into(),
                    auth_time: None,
                    acr: None,
                    amr: vec![],
                    scope: None,
                    extra_claims: (),
                },
            });
        Box::pin(async move {
            ValidationResult {
                outcome: Ok(token),
                dpop_nonce: None,
            }
        })
    }
}
impl ProvideValidatorMetadata for Validator {
    fn validator_metadata(&self, _resource: Option<&str>) -> ValidatorMetadata {
        self.observed.prepared.fetch_add(1, Ordering::SeqCst);
        ValidatorMetadata::builder().build()
    }
}

struct Application(Arc<Observed>);
#[async_trait]
impl ProxyHttp for Application {
    type CTX = AppContext;
    fn new_ctx(&self) -> AppContext {
        AppContext::default()
    }
    async fn early_request_filter(
        &self,
        _session: &mut Session,
        _ctx: &mut AppContext,
    ) -> Result<()> {
        self.0.early.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn request_filter(&self, session: &mut Session, _ctx: &mut AppContext) -> Result<bool> {
        self.0.application.fetch_add(1, Ordering::SeqCst);
        let mut response = pingora_http::ResponseHeader::build(204, None)?;
        response.insert_header("cache-control", "private, no-store")?;
        session
            .write_response_header(Box::new(response), true)
            .await?;
        Ok(true)
    }
    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut AppContext,
    ) -> Result<Box<HttpPeer>> {
        Err(pingora_error::Error::new(
            pingora_error::ErrorType::HTTPStatus(500),
        ))
    }
}

fn guard_config() -> GuardConfig {
    GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne)
}

fn branch(
    mapping: PublicUrlMapping,
    path: &str,
    observed: &Arc<Observed>,
) -> BoundResource<Route<AppContext>> {
    let definition =
        ResourceDefinition::new(mapping, path, AudienceBinding::ResourceIdentifier).unwrap();
    let validator = Validator {
        observed: Arc::clone(observed),
        audience: definition.resource().to_owned(),
    };
    let policy = ResourcePolicy::builder()
        .path_guard(guard_config())
        .build()
        .unwrap();
    BoundResource::builder()
        .definition(definition)
        .validator(validator)
        .policy(policy)
        .inner(Application(Arc::clone(observed)))
        .error_body(())
        .build()
        .unwrap()
        .into_route()
}

async fn exchange(
    app: &Arc<pingora_proxy::HttpProxy<AppRouter>>,
    method: &str,
    path: &str,
    authenticated: bool,
) -> (String, String) {
    let (mut client, server) = tokio::io::duplex(16384);
    let auth = if authenticated {
        "Authorization: Bearer fixture\r\n"
    } else {
        ""
    };
    client.write_all(format!("{method} {path} HTTP/1.1\r\nHost: untrusted.example\r\n{auth}Connection: close\r\n\r\n").as_bytes()).await.unwrap();
    let (_tx, shutdown) = tokio::sync::watch::channel(false);
    let serve = async {
        drop(
            app.process_new_http(ServerSession::new_http1(Box::new(server)), &shutdown)
                .await,
        );
    };
    let read = async {
        let mut wire = String::new();
        client.read_to_string(&mut wire).await.unwrap();
        wire
    };
    let (_, wire) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(serve, read)
    })
    .await
    .unwrap();
    let (headers, body) = wire.split_once("\r\n\r\n").unwrap();
    (headers.to_ascii_lowercase(), body.to_owned())
}

fn app(router: AppRouter) -> Arc<pingora_proxy::HttpProxy<AppRouter>> {
    let mut app = pingora_proxy::HttpProxy::new(router, Arc::new(ServerConf::default()));
    app.handle_init_modules();
    Arc::new(app)
}

#[tokio::test]
async fn root_application_and_independent_publications_keep_their_boundaries() {
    let observed = Arc::new(Observed::default());
    let mapping = PublicUrlMapping::new("https://api.example.com", "/").unwrap();
    let resource = branch(mapping.clone(), "/", &observed);
    let canonical = resource.metadata().uri().to_string();
    let exported = resource.metadata().publication().body.to_vec();
    let metadata_path = resource.metadata().uri().path().to_owned();
    let security = "Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\n";
    let app = app(build_router(
        vec![resource],
        &mapping,
        Some(Bytes::from(security)),
        guard_config(),
    )
    .unwrap());
    for (method, path, status) in [
        ("GET", metadata_path.as_str(), 200),
        ("HEAD", metadata_path.as_str(), 200),
        ("POST", metadata_path.as_str(), 405),
        (
            "GET",
            "/.well-known/oauth-protected-resource?unknown=1",
            404,
        ),
        ("GET", "/.well-known/security.txt", 200),
        ("HEAD", "/.well-known/security.txt", 200),
        ("POST", "/.well-known/security.txt", 405),
    ] {
        let (headers, body) = exchange(&app, method, path, false).await;
        assert!(
            headers.starts_with(&format!("http/1.1 {status}")),
            "{method} {path}: {headers}"
        );
        assert!(!headers.contains("www-authenticate"));
        assert!(!headers.contains("set-cookie"));
        if method == "GET" && status == 200 {
            assert_eq!(
                body.as_bytes(),
                if path == metadata_path {
                    &exported
                } else {
                    security.as_bytes()
                }
            );
            let content_type = if path == metadata_path {
                "application/json"
            } else {
                "text/plain; charset=utf-8"
            };
            assert!(headers.contains(&format!("content-type: {content_type}")));
        }
        if method == "HEAD" {
            assert!(body.is_empty());
        }
    }
    // A path that changes ownership after normalization is denied before any
    // protected branch's early hook can run.
    let (headers, _) = exchange(&app, "GET", "/private/../.well-known/security.txt", false).await;
    assert!(headers.starts_with("http/1.1 400"));
    assert_eq!(observed.early.load(Ordering::SeqCst), 0);
    assert!(observed.validated.lock().unwrap().is_empty());
    assert_eq!(observed.application.load(Ordering::SeqCst), 0);
    for path in [
        "/private",
        "/.well-known/unknown",
        "/.well-known/security.txt/child",
        "/.well-known/security.txt-other",
        "/.well-known/oauth-protected-resource/child",
    ] {
        let (headers, _) = exchange(&app, "GET", path, false).await;
        assert!(headers.starts_with("http/1.1 401"), "{path}: {headers}");
        assert!(headers.contains(&canonical));
    }
    assert_eq!(observed.validated.lock().unwrap().len(), 5);
    assert_eq!(observed.application.load(Ordering::SeqCst), 0);
    let (headers, _) = exchange(&app, "GET", "/private", true).await;
    assert!(headers.starts_with("http/1.1 204"));
    assert!(headers.contains("cache-control: private, no-store"));
    assert_eq!(observed.application.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn rewritten_publications_preserve_public_identity_and_application_mapping() {
    let observed = Arc::new(Observed::default());
    let resource = branch(
        PublicUrlMapping::new("https://api.example.com/gateway", "/edge").unwrap(),
        "/app",
        &observed,
    );
    let exported = resource.metadata().publication().body.to_vec();
    let canonical = resource.metadata().uri().to_string();
    let mapping = PublicUrlMapping::new("https://api.example.com", "/discovery").unwrap();
    let incoming = mapping.incoming_uri(resource.metadata().uri()).unwrap();
    let app = app(build_router(
        vec![resource],
        &mapping,
        Some(Bytes::from_static(b"operator data")),
        guard_config(),
    )
    .unwrap());
    let (headers, body) = exchange(&app, "GET", incoming.path(), false).await;
    assert!(headers.starts_with("http/1.1 200"));
    assert_eq!(body.as_bytes(), exported);
    let document: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(document["resource"], "https://api.example.com/gateway/app");
    for path in [
        "/.well-known/oauth-protected-resource/gateway/app",
        "/.well-known/security.txt",
    ] {
        assert!(
            exchange(&app, "GET", path, false)
                .await
                .0
                .starts_with("http/1.1 404")
        );
    }
    assert!(
        exchange(&app, "GET", "/discovery/.well-known/security.txt", false)
            .await
            .0
            .starts_with("http/1.1 200")
    );
    assert!(observed.validated.lock().unwrap().is_empty());
    let (headers, _) = exchange(&app, "GET", "/edge/app/items", false).await;
    assert!(headers.starts_with("http/1.1 401"));
    assert!(headers.contains(&canonical));
    assert_eq!(
        *observed.validated.lock().unwrap(),
        ["https://api.example.com/gateway/app/items"]
    );
    assert_eq!(observed.application.load(Ordering::SeqCst), 0);
}

#[test]
fn overlapping_resources_and_nonliteral_publication_paths_fail_at_startup() {
    let observed = Arc::new(Observed::default());
    let mapping = PublicUrlMapping::new("https://api.example.com", "/").unwrap();
    let first = branch(mapping.clone(), "/app", &observed);
    let second = branch(mapping.clone(), "/app/child", &observed);
    assert!(build_router(vec![first, second], &mapping, None, guard_config()).is_err());
    let resource = branch(mapping.clone(), "/app", &observed);
    let invalid = PublicUrlMapping::new("https://api.example.com", "/{tenant}").unwrap();
    assert!(build_router(vec![resource], &invalid, None, guard_config()).is_err());
}

#[test]
fn convenience_assembly_consumes_bound_resource_without_repreparing() {
    let observed = Arc::new(Observed::default());
    let mapping = PublicUrlMapping::new("https://api.example.com", "/").unwrap();
    let bound = branch(mapping.clone(), "/", &observed);
    assert_eq!(bound.definition().metadata_uri(), bound.metadata().uri());
    let prepared = observed.prepared.load(Ordering::SeqCst);
    assert_eq!(prepared, 1, "binding prepares metadata exactly once");
    let _proxy = huskarl_pingora::resource::assembly::ResourceAssembly::new(mapping)
        .register_bound(bound)
        .unwrap()
        .assemble()
        .fallback(route(NotFound))
        .slot(context_lens!(AppContext, ctx => ctx.route))
        .path_guard(guard_config())
        .call()
        .unwrap();
    // Assembly consumes the binding, rather than asking the validator to prepare
    // a potentially different document a second time.
    assert_eq!(observed.prepared.load(Ordering::SeqCst), prepared);
}
