//! Two independently authenticated resource servers on one Pingora listener.
//!
//! `/mcp/inventory` and `/mcp/payments` have separate validators, audiences,
//! upstreams, and request contexts. Their RFC 9728 documents are published by
//! a separate router branch at the shared well-known namespace.
//!
//! # Usage
//!
//! ```sh
//! PUBLIC_BASE=https://api.example.com \
//! INVENTORY_ISSUER=https://inventory-auth.example.com \
//! PAYMENTS_ISSUER=https://payments-auth.example.com \
//! cargo run --example multi_resource_proxy
//! ```

use std::sync::Arc;

use async_trait::async_trait;
use huskarl_pingora::{
    resource::{
        AudienceBinding, AuthCtx, AuthProxy, CaseSensitivity, DecodeDepth, Guard, GuardConfig,
        HasAuthState, ResourceMetadataProxy,
    },
    resource_server::{
        core::{jwk::JwksSource, server_metadata::AuthorizationServerMetadata},
        validator::{ValidatedRequest, rfc9068::Rfc9068Validator},
    },
};
use huskarl_reqwest::ReqwestClient;
use pingora_core::{server::Server, upstreams::peer::HttpPeer};
use pingora_error::Result;
use pingora_proxy::{ProxyHttp, Session, http_proxy_service};
use pingora_proxy_router::{RouteSlot, Router, context_lens, route};

type Claims = huskarl_pingora::resource_server::validator::rfc9068::Rfc9068AccessTokenClaims;

const INVENTORY_PATH: &str = "/mcp/inventory";
const PAYMENTS_PATH: &str = "/mcp/payments";

struct AppContext {
    auth: AuthCtx<(), Claims>,
    route: RouteSlot<Self>,
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

struct Upstream {
    address: String,
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

struct NotFound;

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
        unreachable!("the not-found proxy always completes requests in request_filter")
    }
}

fn resource_path_matches(resource: &str, request: &str) -> bool {
    request == resource
        || request
            .strip_prefix(resource)
            .is_some_and(|remainder| remainder.starts_with('/'))
}

fn resource_identifier(base: &str, path: &str) -> String {
    format!("{}{path}", base.trim_end_matches('/'))
}

fn audience_binding(resource: &str, audience: &str) -> AudienceBinding {
    if audience == resource {
        AudienceBinding::ResourceIdentifier
    } else {
        AudienceBinding::mapped([audience])
    }
}

async fn build_validator(issuer: &str, audience: &str) -> Rfc9068Validator {
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

#[tokio::main]
async fn main() {
    env_logger::init();

    let public_base =
        std::env::var("PUBLIC_BASE").unwrap_or_else(|_| "https://api.example.com".into());
    let base_uri: http::Uri = public_base.parse().expect("PUBLIC_BASE must be a URI");
    let inventory_resource = resource_identifier(&public_base, INVENTORY_PATH);
    let payments_resource = resource_identifier(&public_base, PAYMENTS_PATH);
    let inventory_audience =
        std::env::var("INVENTORY_AUDIENCE").unwrap_or_else(|_| inventory_resource.clone());
    let payments_audience =
        std::env::var("PAYMENTS_AUDIENCE").unwrap_or_else(|_| payments_resource.clone());

    let inventory_validator = build_validator(
        &std::env::var("INVENTORY_ISSUER").expect("INVENTORY_ISSUER is required"),
        &inventory_audience,
    )
    .await;
    let payments_validator = build_validator(
        &std::env::var("PAYMENTS_ISSUER").expect("PAYMENTS_ISSUER is required"),
        &payments_audience,
    )
    .await;

    // Both upstreams have the same downstream parsing assumptions.
    let path_guard = GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne);
    let inventory_guard = Guard::builder()
        .validator(inventory_validator)
        .base_uri(base_uri.clone())
        .path_guard(path_guard.clone())
        .build()
        .expect("failed to build inventory guard");
    let (inventory, inventory_metadata) = AuthProxy::new(
        Upstream {
            address: std::env::var("INVENTORY_UPSTREAM")
                .unwrap_or_else(|_| "127.0.0.1:3001".into()),
        },
        inventory_guard,
    )
    .with_protected_resource(
        INVENTORY_PATH,
        audience_binding(&inventory_resource, &inventory_audience),
    )
    .expect("failed to configure inventory resource");

    let payments_guard = Guard::builder()
        .validator(payments_validator)
        .base_uri(base_uri)
        .path_guard(path_guard)
        .build()
        .expect("failed to build payments guard");
    let (payments, payments_metadata) = AuthProxy::new(
        Upstream {
            address: std::env::var("PAYMENTS_UPSTREAM").unwrap_or_else(|_| "127.0.0.1:3002".into()),
        },
        payments_guard,
    )
    .with_protected_resource(
        PAYMENTS_PATH,
        audience_binding(&payments_resource, &payments_audience),
    )
    .expect("failed to configure payments resource");

    let metadata = ResourceMetadataProxy::new(NotFound)
        .publish(inventory_metadata)
        .and_then(|proxy| proxy.publish(payments_metadata))
        .expect("failed to publish resource metadata");
    let metadata = route(metadata);
    let inventory = route(inventory);
    let payments = route(payments);
    let proxy = Router::new(
        move |session: &Session, _ctx: &AppContext| {
            let path = session.req_header().uri.path();
            let selected = if path.starts_with("/.well-known/oauth-protected-resource") {
                Some(Arc::clone(&metadata))
            } else if resource_path_matches(INVENTORY_PATH, path) {
                Some(Arc::clone(&inventory))
            } else if resource_path_matches(PAYMENTS_PATH, path) {
                Some(Arc::clone(&payments))
            } else {
                None
            };
            Ok(selected)
        },
        route(NotFound),
        context_lens!(AppContext, ctx => ctx.route),
    );

    let listen = std::env::var("LISTEN").unwrap_or_else(|_| "0.0.0.0:6188".into());
    let mut server = Server::new(None).expect("failed to create server");
    server.bootstrap();
    let mut service = http_proxy_service(&server.configuration, proxy);
    service.add_tcp(&listen);
    server.add_service(service);

    println!("Listening on {listen}");
    println!("Inventory resource: {inventory_resource}");
    println!("Payments resource:  {payments_resource}");
    server.run_forever();
}
