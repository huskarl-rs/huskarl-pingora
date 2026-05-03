//! Simple JWT-protected reverse proxy.
//!
//! Forwards all traffic to an upstream service, requiring a valid
//! RFC 9068 JWT access token on every route except `/health`.
//!
//! # Usage
//!
//! ```sh
//! ISSUER=https://auth.example.com \
//! AUDIENCE=my-api \
//! cargo run --example jwt_proxy
//! ```
//!
//! Environment variables:
//!   - `ISSUER`   — Authorization server issuer URL (required)
//!   - `AUDIENCE` — Expected `aud` claim value (required)
//!   - `UPSTREAM` — Upstream host:port (default: `127.0.0.1:3000`)
//!   - `LISTEN`   — Listen address (default: `0.0.0.0:6188`)

use std::sync::Arc;

use async_trait::async_trait;
use pingora_core::server::Server;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::Result;
use pingora_proxy::{http_proxy_service, ProxyHttp, Session};

use huskarl_pingora::resource_server::core::jwk::JwksSource;
use huskarl_pingora::resource_server::core::server_metadata::AuthorizationServerMetadata;
use huskarl_pingora::resource_server::validator::dpop_nonce::NoNonceCheck;
use huskarl_pingora::resource_server::validator::rfc9068::Rfc9068Validator;
use huskarl_pingora::{AuthCtx, AuthProxy, Guard, Rule};
use huskarl_reqwest::ReqwestClient;

type Claims = huskarl_pingora::resource_server::validator::rfc9068::Rfc9068AccessTokenClaims;

/// A simple proxy that forwards every request to a single upstream.
struct Upstream(String);

#[async_trait]
impl ProxyHttp for Upstream {
    type CTX = AuthCtx<(), Claims>;

    fn new_ctx(&self) -> Self::CTX {
        AuthCtx::new(())
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let peer = HttpPeer::new(&*self.0, false, String::new());
        Ok(Box::new(peer))
    }
}

/// Discover authorization server metadata and build an RFC 9068 JWT validator.
async fn build_validator(issuer: &str, audience: &str) -> Rfc9068Validator<NoNonceCheck> {
    let http_client = ReqwestClient::builder()
        .mtls(huskarl_reqwest::mtls::NoMtls)
        .build()
        .await
        .expect("failed to create HTTP client");

    // Fetch authorization server metadata (issuer, jwks_uri, etc.)
    //
    // Uses the RFC 8414 well-known path by default. For OIDC providers
    // (Auth0, Keycloak, etc.), use `.well_known_path("/.well-known/openid-configuration")`
    // or `AuthorizationServerMetadata::oidc_builder()` instead.
    let metadata = AuthorizationServerMetadata::builder()
        .http_client(&http_client)
        .issuer(issuer)
        .build()
        .await
        .expect("failed to fetch authorization server metadata");

    let jwks = Arc::new(JwksSource::builder().http_client(http_client).build());

    Rfc9068Validator::builder_from_metadata(&metadata)
        .audience(audience)
        .jws_verifier_factory(jwks)
        .build()
        .await
        .expect("failed to build JWT validator")
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let issuer = std::env::var("ISSUER").expect("ISSUER env var required");
    let audience = std::env::var("AUDIENCE").expect("AUDIENCE env var required");
    let upstream = std::env::var("UPSTREAM").unwrap_or_else(|_| "127.0.0.1:3000".into());
    let listen = std::env::var("LISTEN").unwrap_or_else(|_| "0.0.0.0:6188".into());

    let validator = build_validator(&issuer, &audience).await;

    let guard = Guard::builder(validator)
        .route("/health", Rule::public())
        .build();

    let proxy = AuthProxy::new(Upstream(upstream.clone()), guard);

    let mut server = Server::new(None).expect("failed to create server");
    server.bootstrap();

    let mut service = http_proxy_service(&server.configuration, proxy);
    service.add_tcp(&listen);
    server.add_service(service);

    println!("Listening on {listen}, forwarding to {upstream}");
    server.run_forever();
}
