//! Shared example transport setup, not a library-level resource abstraction.
use async_trait::async_trait;
use huskarl_pingora::{
    resource::{AuthCtx, HasAuthState},
    resource_server::{
        core::{jwk::JwksSource, server_metadata::AuthorizationServerMetadata},
        validator::{ValidatedRequest, rfc9068::Rfc9068Validator},
    },
};
use huskarl_reqwest::ReqwestClient;
use pingora_core::{server::Server, upstreams::peer::HttpPeer};
use pingora_error::Result;
use pingora_proxy::{ProxyHttp, Session, http_proxy_service};
use pingora_proxy_router::RouteSlot;
use std::sync::Arc;
pub type Claims = huskarl_pingora::resource_server::validator::rfc9068::Rfc9068AccessTokenClaims;

pub struct AppContext {
    auth: AuthCtx<(), Claims>,
    pub route: RouteSlot<Self>,
}

impl Default for AppContext {
    fn default() -> Self {
        Self {
            auth: AuthCtx::new(()),
            route: RouteSlot::new(),
        }
    }
}

impl HasAuthState<Claims> for AppContext {
    fn validated_token(&self) -> Option<&Arc<ValidatedRequest<Claims>>> {
        self.auth.validated_token()
    }

    fn validated_token_mut(&mut self) -> &mut Option<Arc<ValidatedRequest<Claims>>> {
        self.auth.validated_token_mut()
    }

    fn dpop_nonce_mut(&mut self) -> &mut Option<String> {
        self.auth.dpop_nonce_mut()
    }

    fn strip_credentials(&self) -> bool {
        self.auth.strip_credentials()
    }

    fn set_strip_credentials(&mut self, strip: bool) {
        self.auth.set_strip_credentials(strip);
    }
}

pub struct Upstream {
    pub address: String,
}

#[async_trait]
impl ProxyHttp for Upstream {
    type CTX = AppContext;

    fn new_ctx(&self) -> Self::CTX {
        AppContext::default()
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        Ok(Box::new(HttpPeer::new(&self.address, false, String::new())))
    }
}

pub struct NotFound;

#[async_trait]
impl ProxyHttp for NotFound {
    type CTX = AppContext;

    fn new_ctx(&self) -> Self::CTX {
        AppContext::default()
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        session.respond_error(404).await?;
        Ok(true)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        Err(pingora_error::Error::new(
            pingora_error::ErrorType::HTTPStatus(404),
        ))
    }
}

pub async fn build_validator(issuer: &str, audience: &str) -> Rfc9068Validator {
    let http_client = ReqwestClient::builder()
        .mtls(huskarl_reqwest::mtls::NoMtls)
        .build()
        .await
        .expect("failed to create HTTP client");
    let metadata = AuthorizationServerMetadata::fetch()
        .http_client(&http_client)
        .issuer(issuer)
        .call()
        .await
        .expect("failed to fetch authorization-server metadata");
    let jwks = Arc::new(JwksSource::builder().http_client(http_client).build());

    Rfc9068Validator::builder_from_metadata(&metadata)
        .audience(audience)
        .jws_verifier_factory(jwks)
        .build()
        .await
        .expect("failed to build JWT validator")
}

/// Discover providers on a temporary runtime, then let Pingora own its runtime.
pub fn run<P>(setup: impl std::future::Future<Output = P>)
where
    P: ProxyHttp + Send + Sync + 'static,
    P::CTX: Send + Sync,
{
    env_logger::init();
    let rt = tokio::runtime::Runtime::new().expect("setup runtime");
    let proxy = rt.block_on(setup);
    drop(rt);
    let listen = std::env::var("LISTEN").unwrap_or_else(|_| "127.0.0.1:6188".into());
    let mut server = Server::new(None).expect("create server");
    server.bootstrap();
    let mut service = http_proxy_service(&server.configuration, proxy);
    service.add_tcp(&listen);
    server.add_service(service);
    println!("Listening on {listen}");
    server.run_forever();
}
