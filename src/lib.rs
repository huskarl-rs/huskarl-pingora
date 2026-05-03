//! Pingora integration for huskarl-resource-server.
//!
//! This crate provides [`AuthProxy`], a decorator that wraps a [`ProxyHttp`]
//! implementation to add OAuth 2.0 token validation via a [`Guard`].
//!
//! # Example
//!
//! ```ignore
//! use huskarl_pingora::{AuthProxy, AuthCtx, Guard, Rule};
//!
//! struct MyProxy;
//!
//! struct MyCtx { /* user state */ }
//!
//! #[async_trait]
//! impl ProxyHttp for MyProxy {
//!     type CTX = AuthCtx<MyCtx, MyClaims>;
//!     fn new_ctx(&self) -> Self::CTX { AuthCtx::new(MyCtx { /* ... */ }) }
//!
//!     async fn upstream_peer(
//!         &self,
//!         session: &mut Session,
//!         ctx: &mut Self::CTX,
//!     ) -> Result<Box<HttpPeer>> {
//!         if let Some(token) = &ctx.token { /* route based on claims */ }
//!         // ctx.my_field works via Deref
//!         todo!()
//!     }
//! }
//!
//! let guard = Guard::builder(validator)
//!     .route("/public/*rest", Rule::public())
//!     .build();
//! let proxy = AuthProxy::new(my_proxy, guard);
//! // pass `proxy` to pingora — it implements ProxyHttp
//! ```

mod ctx;
mod guard;
mod outcome;
mod proxy;
pub(crate) mod response;
pub mod rule;
pub mod scopes;

pub use ctx::AuthCtx;
pub use guard::{ClientCertDer, Guard, GuardBuilder};
pub use outcome::Outcome;
pub use proxy::AuthProxy;
pub use rule::{CheckError, Rule, TokenRequirement};
pub use scopes::HasScopes;

/// Re-export of [`huskarl_resource_server`] for convenience.
pub use huskarl_resource_server as resource_server;
