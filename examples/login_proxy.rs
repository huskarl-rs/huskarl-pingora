//! OAuth 2.0 Authorization Code Grant login proxy.
//!
//! Wraps an upstream service with a browser-facing login wall. Unauthenticated
//! requests are redirected through an Authorization Code Grant flow; once the
//! user completes login they are forwarded to the upstream.
//!
//! # Usage
//!
//! ```sh
//! ISSUER=https://auth.example.com \
//! CLIENT_ID=my-client \
//! REDIRECT_URI=http://localhost:6188/callback \
//! cargo run --example login_proxy --features login
//! ```
//!
//! Then open http://localhost:6188 in your browser. Navigate to
//! http://localhost:6188/logout to log out.
//!
//! Environment variables:
//!   - `ISSUER`        — Authorization server issuer URL (required)
//!   - `CLIENT_ID`     — OAuth2 client ID (required)
//!   - `REDIRECT_URI`  — Callback URL registered with the AS (required)
//!   - `COOKIE_KEY`    — 32-byte AES-256 key, hex-encoded (optional; random if absent)
//!   - `UPSTREAM`      — Upstream host:port (default: `localhost:3000`)
//!   - `UPSTREAM_TLS`  — Set to enable TLS to the upstream (SNI derived from hostname)
//!   - `LISTEN`        — Listen address (default: `0.0.0.0:6188`)

use std::{convert::Infallible, sync::Arc};

use async_trait::async_trait;
use huskarl::{
    core::{
        crypto::cipher::BoxedAeadCipher,
        dpop::NoDPoP,
        jwk::JwksSource,
        secrets::{SecretBytes, SecretOutput},
        server_metadata::AuthorizationServerMetadata,
    },
    grant::authorization_code::{AuthorizationCodeGrant, NoJar},
};
use huskarl_crypto_native::aead::{AesGcmKey, AesGcmKeyType};
use huskarl_pingora::login::{
    CookieSession, CookieSessionStore, LoginConfig, LoginCtx, LoginProxy,
};
use huskarl_reqwest::ReqwestClient;
use huskarl_resource_server::core::client_auth::NoAuth;
use pingora_core::{server::Server, upstreams::peer::HttpPeer};
use pingora_error::Result;
use pingora_http::RequestHeader;
use pingora_proxy::{ProxyHttp, Session, http_proxy_service};

// ── Inner proxy ───────────────────────────────────────────────────────────────

/// Forwards every request to a single upstream host.
struct Upstream {
    address: String,
    tls: bool,
    sni: String,
}

#[async_trait]
impl ProxyHttp for Upstream {
    type CTX = LoginCtx<(), CookieSession>;

    fn new_ctx(&self) -> Self::CTX {
        LoginCtx::new(())
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let mut peer = HttpPeer::new(&*self.address, self.tls, self.sni.clone());
        if self.tls {
            // Negotiate HTTP/2 or fall back to HTTP/1.1.
            peer.options.alpn = pingora_core::protocols::tls::ALPN::H2H1;
        }
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        // Rewrite the Host header to match the upstream, so TLS upstreams
        // see the correct hostname rather than the proxy's listen address.
        if !self.sni.is_empty() {
            upstream_request
                .insert_header(http::header::HOST, &self.sni)
                .map_err(|e| {
                    pingora_error::Error::because(
                        pingora_error::ErrorType::InternalError,
                        "failed to set Host header",
                        e,
                    )
                })?;
        }
        Ok(())
    }
}

// ── Secret helpers ────────────────────────────────────────────────────────────

#[derive(Clone)]
struct StaticBytesSecret(SecretBytes);

impl huskarl::core::secrets::Secret for StaticBytesSecret {
    type Output = SecretBytes;
    type Error = Infallible;

    async fn get_secret_value(&self) -> std::result::Result<SecretOutput<SecretBytes>, Infallible> {
        Ok(SecretOutput {
            value: self.0.clone(),
            identity: None,
        })
    }
}

// ── AES key ───────────────────────────────────────────────────────────────────

/// Loads or generates the 32-byte AES-256 key for cookie encryption.
fn load_or_generate_key_bytes() -> Vec<u8> {
    match std::env::var("COOKIE_KEY") {
        Ok(hex) => hex::decode(hex.trim()).expect("COOKIE_KEY must be valid hex"),
        Err(_) => {
            let bytes: [u8; 32] = rand::random();
            println!("No COOKIE_KEY set — using a random key. Sessions will not survive restarts.");
            println!("To persist sessions across restarts, set:");
            println!("  COOKIE_KEY={}", hex::encode(bytes));
            bytes.to_vec()
        }
    }
}

async fn aes_key_from_bytes(bytes: Vec<u8>) -> AesGcmKey {
    AesGcmKey::from_secret(
        AesGcmKeyType::Aes256,
        StaticBytesSecret(SecretBytes::new(bytes)),
        |_| None,
    )
    .await
    .expect("failed to load AES-256 key (expected 32 bytes)")
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    env_logger::init();

    let issuer = std::env::var("ISSUER").expect("ISSUER env var required");
    let client_id = std::env::var("CLIENT_ID").expect("CLIENT_ID env var required");
    let redirect_uri = std::env::var("REDIRECT_URI").expect("REDIRECT_URI env var required");
    let parsed_redirect = url::Url::parse(&redirect_uri).expect("REDIRECT_URI must be a valid URL");
    let base_url = format!(
        "{}://{}",
        parsed_redirect.scheme(),
        parsed_redirect.authority()
    );
    let upstream = std::env::var("UPSTREAM").unwrap_or_else(|_| "localhost:3000".into());
    let upstream_tls = std::env::var("UPSTREAM_TLS").is_ok();
    let listen = std::env::var("LISTEN").unwrap_or_else(|_| "0.0.0.0:6188".into());

    // Use a temporary runtime for async setup, then drop it before
    // server.run_forever() which creates its own runtime.
    let rt = tokio::runtime::Runtime::new().expect("failed to create setup runtime");
    let proxy = rt.block_on(async {
        let http_client = ReqwestClient::builder()
            .mtls(huskarl_reqwest::mtls::NoMtls)
            .build()
            .await
            .expect("failed to create HTTP client");

        let metadata = AuthorizationServerMetadata::oidc_fetch()
            .http_client(&http_client)
            .issuer(&issuer)
            .call()
            .await
            .expect("failed to fetch authorization server metadata");

        let grant = AuthorizationCodeGrant::builder_from_metadata(&metadata)
            .expect("authorization server does not advertise an authorization endpoint")
            .client_id(client_id)
            .client_auth(NoAuth)
            .redirect_uri(redirect_uri.clone())
            .dpop(NoDPoP)
            .jar(NoJar)
            .jws_verifier_factory(Arc::new(
                JwksSource::builder()
                    .http_client(http_client.clone())
                    .build(),
            ))
            .build()
            .await
            .expect("failed to build authorization code grant");

        let key_bytes = load_or_generate_key_bytes();
        let cipher = BoxedAeadCipher::new(aes_key_from_bytes(key_bytes).await);

        let session_store = CookieSessionStore::new(
            cipher.clone(),
            "huskarl_session",
            parsed_redirect.scheme() == "https",
            "/",
        );

        let login_config = LoginConfig::builder()
            .callback_path(parsed_redirect.path().to_owned())
            .scopes(vec!["openid".to_owned()])
            .secure(parsed_redirect.scheme() == "https")
            .base_url(base_url.parse().expect("valid base URL"))
            .logout_path("/logout")
            .maybe_end_session_endpoint(metadata.end_session_endpoint.map(|e| e.into_uri()))
            .build()
            .expect("failed to build login config");

        let inner = Upstream {
            // Extract the hostname (before the colon) for SNI when using TLS.
            sni: if upstream_tls {
                upstream.split(':').next().unwrap_or(&upstream).to_owned()
            } else {
                String::new()
            },
            address: upstream.clone(),
            tls: upstream_tls,
        };

        LoginProxy::builder()
            .inner(inner)
            .config(login_config)
            .grant(grant)
            .session_store(session_store)
            .cipher(cipher)
            .http_client(http_client)
            .build()
    });
    drop(rt);

    let mut server = Server::new(None).expect("failed to create server");
    server.bootstrap();

    let mut service = http_proxy_service(&server.configuration, proxy);
    service.add_tcp(&listen);
    server.add_service(service);

    println!("Listening on {listen}, forwarding to {upstream}");
    println!("Callback URL: {redirect_uri}");
    println!("Logout URL:   {base_url}/logout");
    server.run_forever();
}
