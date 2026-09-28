//! OAuth 2.0 Authorization Code Grant login proxy.
//!
//! Wraps an upstream service with a browser-facing login wall. Unauthenticated
//! requests are redirected through an Authorization Code Grant flow; once the
//! user completes login they are forwarded to the upstream.
//!
//! # Usage
//!
//! ```sh
//! export COOKIE_KEY="$(openssl rand -hex 32)"
//! ISSUER=https://auth.example.com \
//! CLIENT_ID=my-client \
//! REDIRECT_URI=http://localhost:6188/callback \
//! cargo run --example login_proxy --features login
//! ```
//!
//! First run `python3 examples/login_upstream.py` in another terminal.
//! Open http://localhost:6188/dashboard to sign in, then use its Sign out form.
//! Full walkthrough: `docs/tutorial/browser_login.md`.
//!
//! For rewritten deployments, see examples/README.md (PUBLIC_BASE and INCOMING_PREFIX).
//!
//! Environment variables:
//!   - `PUBLIC_BASE` — Public application base URL (default: REDIRECT_URI origin)
//!   - `INCOMING_PREFIX` — Prefix received by this process (default: `/`)
//!   - `ISSUER`        — Authorization server issuer URL (required)
//!   - `CLIENT_ID`     — OAuth2 client ID (required)
//!   - `REDIRECT_URI`  — Callback URL registered with the AS (required)
//!   - `COOKIE_KEY`    — 32-byte AES-256 key, hex-encoded (required; keep stable across restarts)
//!   - `UPSTREAM`      — Upstream host:port (default: `127.0.0.1:3001`)
//!   - `UPSTREAM_TLS`  — Set to enable TLS to the upstream (SNI derived from hostname)
//!   - `LISTEN`        — Listen address (default: `127.0.0.1:6188`)

use std::sync::Arc;

use async_trait::async_trait;
use huskarl::{
    core::{
        crypto::seal::AeadV1Sealer,
        jwk::OctBytes,
        secrets::{EnvVarSecret, Secret as _, encodings::HexEncoding},
        server_metadata::AuthorizationServerMetadata,
    },
    grant::authorization_code::AuthorizationCodeGrant,
};
use huskarl_crypto_native::{NativeVerifierPlatform, aead::AesGcmKey};
use huskarl_login::Session as _;
use huskarl_pingora::login::{
    CaseSensitivity, CookieSession, CookieSessionStore, DecodeDepth, GuardConfig, HasLoginSession,
    LoginConfig, LoginCtx, LoginEngine, LoginProxy, LoginRule, LogoutConfig, SessionLifetime,
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
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        set_identity_header(upstream_request, ctx)?;
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

// The upstream must accept this assertion only from the trusted proxy.
fn set_identity_header(
    request: &mut RequestHeader,
    ctx: &LoginCtx<(), CookieSession>,
) -> Result<()> {
    request.remove_header("X-Authenticated-Subject");
    if let Some(subject) = ctx.login_state().session.as_ref().and_then(|s| s.sub()) {
        request.insert_header("X-Authenticated-Subject", subject)?;
    }
    Ok(())
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
    let upstream = std::env::var("UPSTREAM").unwrap_or_else(|_| "127.0.0.1:3001".into());
    let upstream_tls = std::env::var("UPSTREAM_TLS").is_ok();
    let mapping = huskarl_login::core::url_mapping::PublicUrlMapping::new(
        &std::env::var("PUBLIC_BASE").unwrap_or(base_url.clone()),
        &std::env::var("INCOMING_PREFIX").unwrap_or_else(|_| "/".into()),
    )
    .expect("invalid public/ingress URL mapping");
    let callback = huskarl_login::url::callback_path(
        &mapping,
        &redirect_uri.parse().expect("invalid redirect URI"),
        None,
    )
    .expect("callback URL must be covered by the mapping");
    // Application route names are relative to the public base; mount them in
    // the coordinates actually received by this process.
    let incoming_path = |path: &str| {
        mapping
            .incoming_uri(&mapping.resource_url(path).expect("valid application path"))
            .expect("application path must round-trip")
            .path()
            .to_owned()
    };
    let listen = std::env::var("LISTEN").unwrap_or_else(|_| "127.0.0.1:6188".into());

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
            .http_client(http_client)
            .redirect_uri(redirect_uri.clone())
            .jws_verifier_platform(Arc::new(NativeVerifierPlatform))
            .build()
            .await
            .expect("failed to build authorization code grant");

        let cipher = AesGcmKey::from_secret(
            EnvVarSecret::new("COOKIE_KEY", &HexEncoding)
                .expect("COOKIE_KEY must contain a hex-encoded 32-byte key")
                .mapped(OctBytes::new("A256GCM")),
        )
        .await
        .expect("failed to load AES-256 cookie key");

        let session_store = CookieSessionStore::builder()
            .sealer(AeadV1Sealer::new(cipher))
            .cookie_name("huskarl_session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build();

        let login_config = LoginConfig::builder()
            .url_mapping(mapping.clone())
            .callback_path(callback.as_str().to_owned())
            .scope(vec!["openid".to_owned()])
            // Cookie sessions carry the refresh token, so bound the session
            // lifetime crate-side rather than delegating to the auth server.
            .session_lifetime(SessionLifetime::Bounded(std::time::Duration::from_hours(8)))
            .logout(
                LogoutConfig::builder()
                    .path(incoming_path("/logout"))
                    .post_logout_redirect_uri(
                        mapping
                            .resource_url("/signed-out")
                            .expect("signed-out URL")
                            .to_string(),
                    )
                    .build()
                    .expect("failed to build logout config"),
            )
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

        let engine = Arc::new(
            LoginEngine::builder()
                .config(login_config)
                .grant(grant)
                .session_store(session_store)
                .build()
                .expect("failed to build login engine"),
        );

        LoginProxy::builder()
            .inner(inner)
            .engine(engine)
            .path_guard(GuardConfig::new(
                CaseSensitivity::Sensitive,
                DecodeDepth::UpToOne,
            ))
            // `subtree` applies a rule to a path and everything beneath it;
            // `route` matches a single exact path.
            //
            // Protect the whole dashboard area — `/dashboard`, `/dashboard/`,
            // and every page under it.
            .subtree(&incoming_path("/dashboard"), LoginRule::required())
            // Liveness probe — exact path, skip session handling entirely.
            .route(incoming_path("/health"), LoginRule::public())
            .route(incoming_path("/signed-out"), LoginRule::public())
            // Landing page — exact path; render publicly but personalize if the
            // user is already signed in.
            .route(incoming_path("/"), LoginRule::optional())
            // Everything else falls through to the default (`required`),
            // redirecting unauthenticated browsers through the auth-code flow.
            //
            // Path-confusion protection is ON by default (`RejectAmbiguous`): a
            // request carrying a structural byte in a route position the table makes
            // able to change which rule matches (e.g. `/x/../dashboard`,
            // `/dashboard/..;/admin`) is rejected with 400. Allowed paths are forwarded unchanged. `GuardMode::RequireCanonical` is a stricter,
            // defense-in-depth alternative; `GuardMode::Disabled` disables it.
            .build()
            .expect("valid LoginProxy configuration")
    });
    drop(rt);

    let mut server = Server::new(None).expect("failed to create server");
    server.bootstrap();

    let mut service = http_proxy_service(&server.configuration, proxy);
    service.add_tcp(&listen);
    server.add_service(service);

    println!("Listening on {listen}, forwarding to {upstream}");
    println!("Callback URL: {redirect_uri}");
    println!(
        "Logout URL:   {}",
        mapping.resource_url("/logout").expect("logout URL")
    );
    server.run_forever();
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use huskarl_login::SessionState;

    use super::*;

    #[test]
    fn forwarded_identity_replaces_all_client_values_and_clears_anonymous_values()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        for subject in [None, Some("provider-subject")] {
            let mut request = RequestHeader::build("GET", b"/dashboard", None)?;
            request.append_header("X-Authenticated-Subject", "forged-one")?;
            request.append_header("x-authenticated-subject", "forged-two")?;
            let mut ctx = LoginCtx::new(());
            if let Some(subject) = subject {
                let now = SystemTime::now();
                ctx.login_state_mut().session = Some(CookieSession::from(
                    SessionState::builder()
                        .created_at(now)
                        .token_expiry(now + Duration::from_secs(3600))
                        .sub(subject.to_owned())
                        .build(),
                ));
            }
            set_identity_header(&mut request, &ctx)?;
            let values: Vec<_> = request
                .headers
                .get_all("X-Authenticated-Subject")
                .iter()
                .collect();
            match subject {
                None => assert!(values.is_empty()),
                Some(subject) => {
                    assert_eq!(values.len(), 1);
                    assert_eq!(
                        request
                            .headers
                            .get("X-Authenticated-Subject")
                            .and_then(|h| h.to_str().ok()),
                        Some(subject)
                    );
                }
            }
        }
        Ok(())
    }
}
