//! Pingora integration for huskarl-resource-server.
//!
//! This crate provides [`AuthProxy`], a decorator that wraps a [`ProxyHttp`](pingora_proxy::ProxyHttp)
//! implementation to add OAuth 2.0 token validation via a [`Guard`].
//!
//! # Example
//!
//! ```
//! # use std::sync::Arc;
//! # use async_trait::async_trait;
//! # use huskarl_pingora::resource_server::validator::ValidatedRequest;
//! use huskarl_pingora::{AuthProxy, Guard, HasAuthState, Rule};
//! # use pingora_core::upstreams::peer::HttpPeer;
//! # use pingora_error::Result;
//! # use pingora_proxy::{ProxyHttp, Session};
//!
//! # struct MyClaims;
//! #[derive(Default)]
//! struct MyCtx {
//!     token: Option<Arc<ValidatedRequest<MyClaims>>>,
//!     dpop_nonce: Option<String>,
//!     strip_credentials: bool,
//! }
//!
//! impl HasAuthState<MyClaims> for MyCtx {
//!     fn validated_token_mut(&mut self) -> &mut Option<Arc<ValidatedRequest<MyClaims>>> {
//!         &mut self.token
//!     }
//!     fn dpop_nonce_mut(&mut self) -> &mut Option<String> { &mut self.dpop_nonce }
//!     fn strip_credentials(&self) -> bool { self.strip_credentials }
//!     fn set_strip_credentials(&mut self, strip: bool) { self.strip_credentials = strip; }
//! }
//!
//! struct MyProxy;
//!
//! #[async_trait]
//! impl ProxyHttp for MyProxy {
//!     type CTX = MyCtx;
//!     fn new_ctx(&self) -> MyCtx { MyCtx { strip_credentials: true, ..Default::default() } }
//!
//!     async fn upstream_peer(
//!         &self,
//!         _session: &mut Session,
//!         ctx: &mut MyCtx,
//!     ) -> Result<Box<HttpPeer>> {
//!         if let Some(_token) = ctx.validated_token_mut().as_ref() { /* inspect claims */ }
//!         todo!()
//!     }
//! }
//!
//! # fn build<V>(validator: V)
//! # where
//! #     V: huskarl_pingora::resource_server::validator::AccessTokenValidator<Claims = MyClaims>
//! #         + huskarl_pingora::resource_server::validator::metadata::ProvideValidatorMetadata,
//! # {
//! let guard = Guard::builder()
//!     .validator(validator)
//!     .route("/public/*rest", Rule::public())
//!     .build()
//!     .expect("route");
//! let proxy = AuthProxy::new(MyProxy, guard);
//! // pass `proxy` to pingora — it implements ProxyHttp<CTX = MyCtx>
//! # }
//! ```

mod ctx;
pub(crate) mod error;
mod guard;
mod outcome;
mod proxy;
pub(crate) mod response;
pub mod rule;
pub mod scopes;
pub(crate) mod uri;

pub use ctx::{AuthCtx, HasAuthState};
pub use error::ConfigError;
pub use guard::{ClientCertDer, Guard, GuardBuilder};
/// Re-export of [`huskarl_resource_server`] for convenience.
pub use huskarl_resource_server as resource_server;
pub use outcome::Outcome;
pub use proxy::AuthProxy;
pub use rule::{CheckError, Rule, TokenRequirement};
pub use scopes::HasScopes;
