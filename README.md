<!-- cargo-reedme: start -->

<!-- cargo-reedme: info-start

    Do not edit this region by hand
    ===============================

    This region was generated from Rust documentation comments by `cargo-reedme` using this command:

        cargo +nightly reedme

    for more info: https://github.com/nik-rev/cargo-reedme

cargo-reedme: info-end -->

Pingora integration for huskarl-resource-server.

This crate provides [`AuthProxy`](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/proxy/struct.AuthProxy.html), a decorator that wraps a [`ProxyHttp`](https://docs.rs/pingora_proxy/latest/pingora_proxy/proxy_trait/trait.ProxyHttp.html)
implementation to add OAuth 2.0 token validation via a [`Guard`](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/guard/struct.Guard.html).

# Example

```rust
use huskarl_pingora::{AuthProxy, Guard, HasAuthState, Rule};

#[derive(Default)]
struct MyCtx {
    token: Option<Arc<ValidatedRequest<MyClaims>>>,
    dpop_nonce: Option<String>,
    strip_credentials: bool,
}

impl HasAuthState<MyClaims> for MyCtx {
    fn validated_token_mut(&mut self) -> &mut Option<Arc<ValidatedRequest<MyClaims>>> {
        &mut self.token
    }
    fn dpop_nonce_mut(&mut self) -> &mut Option<String> { &mut self.dpop_nonce }
    fn strip_credentials(&self) -> bool { self.strip_credentials }
    fn set_strip_credentials(&mut self, strip: bool) { self.strip_credentials = strip; }
}

struct MyProxy;

#[async_trait]
impl ProxyHttp for MyProxy {
    type CTX = MyCtx;
    fn new_ctx(&self) -> MyCtx { MyCtx { strip_credentials: true, ..Default::default() } }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut MyCtx,
    ) -> Result<Box<HttpPeer>> {
        if let Some(_token) = ctx.validated_token_mut().as_ref() { /* inspect claims */ }
        todo!()
    }
}

let guard = Guard::builder()
    .validator(validator)
    .route("/public/*rest", Rule::public())
    .build()
    .expect("route");
let proxy = AuthProxy::new(MyProxy, guard);
// pass `proxy` to pingora — it implements ProxyHttp<CTX = MyCtx>
```

<!-- cargo-reedme: end -->
