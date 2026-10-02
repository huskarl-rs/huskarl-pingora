# Add token authentication without discovery

Use `Guard` and `AuthProxy` when you want token authentication without a resource
definition or discovery endpoint. For discovery, start with
[resource assembly](crate::_docs::how_to::resource_registration).

This recipe assumes clients already hold RFC 9068 access tokens. You need the
issuer URL, the expected audience, and an upstream service. For a runnable
Pingora server, use `examples/jwt_proxy.rs` with `ISSUER`, `AUDIENCE`, and
`UPSTREAM` set, then run `cargo run --example jwt_proxy --features resource`.
Check that a request without a token receives 401 and one with a valid token
for the configured issuer and audience reaches the upstream. `/health` and the
`/public` subtree bypass token validation in that runnable example.

The integration below shows how to add an `api` scope requirement as well.
The proxy uses an [RFC 9068] validator. Note
how `subtree` protects the whole API while `route` opens a single exact
health endpoint:

[RFC 9068]: https://datatracker.ietf.org/doc/html/rfc9068

```no_run
use std::sync::Arc;

use async_trait::async_trait;
use huskarl_pingora::{
    resource::{AuthCtx, AuthProxy, CaseSensitivity, DecodeDepth, Guard, GuardConfig, ResourcePolicy, Rule},
    resource_server::{
        core::{jwk::JwksSource, server_metadata::AuthorizationServerMetadata},
        validator::rfc9068::Rfc9068Validator,
    },
};
use huskarl_reqwest::ReqwestClient;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::Result;
use pingora_proxy::{ProxyHttp, Session};

type Claims = huskarl_pingora::resource_server::validator::rfc9068::Rfc9068AccessTokenClaims;

struct MyProxy;

#[async_trait]
impl ProxyHttp for MyProxy {
    type CTX = AuthCtx<(), Claims>;
    fn new_ctx(&self) -> Self::CTX {
        AuthCtx::new(())
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let peer = HttpPeer::new("127.0.0.1:3000", false, String::new());
        Ok(Box::new(peer))
    }
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // 1. Create an HTTP client for fetching metadata and JWKS.
    let http_client = ReqwestClient::builder()
        .mtls(huskarl_reqwest::mtls::NoMtls)
        .build()
        .await?;

    // 2. Discover the authorization server's metadata (issuer, jwks_uri, …).
    let metadata = AuthorizationServerMetadata::fetch()
        .http_client(&http_client)
        .issuer("https://auth.example.com")
        .call()
        .await?;

    // 3. Build an RFC 9068 JWT validator.
    let jwks = Arc::new(JwksSource::builder().http_client(http_client).build());
    let validator = Rfc9068Validator::builder_from_metadata(&metadata)
        .audience("my-api")
        .jws_verifier_factory(jwks)
        .build()
        .await?;

    // 4. Wrap your proxy with the auth guard.
    //    `subtree` protects a path and everything beneath it; `route`
    //    matches one exact path. Unmatched paths use the default
    //    (`Rule::required()`), so the whole proxy is closed by default.
    let policy = ResourcePolicy::builder()
        .path_guard(GuardConfig::new(
            CaseSensitivity::Sensitive,
            DecodeDepth::UpToOne,
        ))
        .subtree("/api", Rule::required().scopes(["api"])) // /api and below
        .route("/health", Rule::public()) // exactly /health
        .build()?;

    let guard = Guard::builder().validator(validator).policy(policy).build();
    let proxy = AuthProxy::new(MyProxy, guard);
    // Pass `proxy` to Pingora's http_proxy_service; it implements ProxyHttp.
    let _ = proxy;
    Ok(())
}
```

## Publish discovery metadata

Follow [Publish protected-resource metadata](crate::_docs::how_to::resource_metadata)
to add a public discovery endpoint or host multiple resources on one listener.
