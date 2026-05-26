//! Pingora integration for huskarl.
//!
//! This crate provides two independent feature-gated modules:
//!
//! - **`resource`** — OAuth 2.0 resource-server (bearer token) protection via
//!   [`resource::AuthProxy`] and [`resource::Guard`].
//! - **`login`** — OAuth 2.0 Authorization Code Grant login layer via
//!   [`login::LoginProxy`].
//!
//! Both features are enabled by default.
//!
//! # Resource server example
//!
//! A minimal JWT-protected reverse proxy using an [RFC 9068] validator:
//!
//! [RFC 9068]: https://datatracker.ietf.org/doc/html/rfc9068
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use async_trait::async_trait;
//! use huskarl_pingora::{
//!     resource::{AuthCtx, AuthProxy, Guard, Rule},
//!     resource_server::{
//!         core::{jwk::JwksSource, server_metadata::AuthorizationServerMetadata},
//!         validator::rfc9068::Rfc9068Validator,
//!     },
//! };
//! use huskarl_reqwest::ReqwestClient;
//! use pingora_core::upstreams::peer::HttpPeer;
//! use pingora_error::Result;
//! use pingora_proxy::{ProxyHttp, Session};
//!
//! type Claims = huskarl_pingora::resource_server::validator::rfc9068::Rfc9068AccessTokenClaims;
//!
//! struct MyProxy;
//!
//! #[async_trait]
//! impl ProxyHttp for MyProxy {
//!     type CTX = AuthCtx<(), Claims>;
//!     fn new_ctx(&self) -> Self::CTX {
//!         AuthCtx::new(())
//!     }
//!
//!     async fn upstream_peer(
//!         &self,
//!         _session: &mut Session,
//!         _ctx: &mut Self::CTX,
//!     ) -> Result<Box<HttpPeer>> {
//!         let peer = HttpPeer::new("127.0.0.1:3000", false, String::new());
//!         Ok(Box::new(peer))
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() {
//!     // 1. Create an HTTP client for fetching metadata and JWKS.
//!     let http_client = ReqwestClient::builder()
//!         .mtls(huskarl_reqwest::mtls::NoMtls)
//!         .build()
//!         .await
//!         .expect("HTTP client");
//!
//!     // 2. Discover the authorization server's metadata (issuer, jwks_uri, …).
//!     let metadata = AuthorizationServerMetadata::fetch()
//!         .http_client(&http_client)
//!         .issuer("https://auth.example.com")
//!         .call()
//!         .await
//!         .expect("AS metadata");
//!
//!     // 3. Build an RFC 9068 JWT validator.
//!     let jwks = Arc::new(JwksSource::builder().http_client(http_client).build());
//!     let validator = Rfc9068Validator::builder_from_metadata(&metadata)
//!         .audience("my-api")
//!         .jws_verifier_factory(jwks)
//!         .build()
//!         .await
//!         .expect("validator");
//!
//!     // 4. Wrap your proxy with the auth guard.
//!     let guard = Guard::builder()
//!         .validator(validator)
//!         .route("/health", Rule::public())
//!         .build()
//!         .expect("guard");
//!
//!     let proxy = AuthProxy::new(MyProxy, guard);
//!     // pass `proxy` to pingora — it implements ProxyHttp
//! }
//! ```

#[cfg(feature = "login")]
pub mod login;
#[cfg(feature = "resource")]
pub mod resource;

/// Re-export of [`huskarl_resource_server`] for convenience.
#[cfg(feature = "resource")]
pub use huskarl_resource_server as resource_server;
