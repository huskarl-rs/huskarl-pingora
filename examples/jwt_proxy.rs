//! Lower-level bearer-token proxy with public route exceptions.
//! Start with `resource_proxy` for resource identity and discovery metadata.
//!
//! Forwards all traffic to an upstream service, requiring a valid
//! RFC 9068 JWT access token on every route except `/health` and the
//! `/public` subtree.
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
//!   - `CASE_INSENSITIVE_UPSTREAM` — if set, add case-folding to the
//!     path-confusion model (for a case-insensitive upstream)

use std::sync::Arc;

use async_trait::async_trait;
use huskarl_pingora::{
    resource::{
        AuthCtx, AuthProxy, CaseSensitivity, DecodeDepth, Guard, GuardConfig, ResourcePolicy, Rule,
    },
    resource_server::{
        core::{jwk::JwksSource, server_metadata::AuthorizationServerMetadata},
        validator::rfc9068::Rfc9068Validator,
    },
};
use huskarl_reqwest::ReqwestClient;
use pingora_core::{server::Server, upstreams::peer::HttpPeer};
use pingora_error::Result;
use pingora_proxy::{ProxyHttp, Session, http_proxy_service};

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
async fn build_validator(issuer: &str, audience: &str) -> Rfc9068Validator {
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
    let metadata = AuthorizationServerMetadata::fetch()
        .http_client(&http_client)
        .issuer(issuer)
        .call()
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

fn main() {
    env_logger::init();

    let issuer = std::env::var("ISSUER").expect("ISSUER env var required");
    let audience = std::env::var("AUDIENCE").expect("AUDIENCE env var required");
    let upstream = std::env::var("UPSTREAM").unwrap_or_else(|_| "127.0.0.1:3000".into());
    let listen = std::env::var("LISTEN").unwrap_or_else(|_| "0.0.0.0:6188".into());

    // Complete async provider setup before Pingora starts its own runtimes.
    let rt = tokio::runtime::Runtime::new().expect("setup runtime");
    let proxy = rt.block_on(async {
        let validator = build_validator(&issuer, &audience).await;

        // Path-confusion protection is ON by default (`GuardMode::RejectAmbiguous`):
        // a request carrying a structural byte (`%2F`, `..`, `;`, …) in a route position
        // the table makes able to change which rule matches (`/x/../public/secret`,
        // `/health%2f..%2fadmin`, …) is rejected with 400. Allowed paths are forwarded unchanged. You must declare whether the upstream folds case: if it routes
        // case-insensitively (IIS, some filesystems), `Insensitive` stops `/Health` from
        // dodging a rule (and requires routes to be registered in lowercase).
        let case_sensitivity = if std::env::var("CASE_INSENSITIVE_UPSTREAM").is_ok() {
            CaseSensitivity::Insensitive
        } else {
            CaseSensitivity::Sensitive
        };

        // Everything is protected by default (`Rule::required()`). `subtree` opens
        // up a whole area of the URL space (a path and everything beneath it);
        // `route` opens a single exact path.
        let policy = ResourcePolicy::builder()
            .path_guard(GuardConfig::new(case_sensitivity, DecodeDepth::UpToOne))
            .subtree("/public", Rule::public()) // /public and everything under it
            .route("/health", Rule::public()) // exactly /health
            // RejectAmbiguous is the default; GuardMode::Disabled disables the guard.
            .build()
            .expect("failed to build policy");

        let guard = Guard::builder().validator(validator).policy(policy).build();
        AuthProxy::new(Upstream(upstream.clone()), guard)
    });
    drop(rt);

    let mut server = Server::new(None).expect("failed to create server");
    server.bootstrap();

    let mut service = http_proxy_service(&server.configuration, proxy);
    service.add_tcp(&listen);
    server.add_service(service);

    println!("Listening on {listen}, forwarding to {upstream}");
    server.run_forever();
}
