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
        AudienceBinding, AuthCtx, CaseSensitivity, DecodeDepth, Guard, GuardConfig, HasAuthState,
        assembly::ResourceAssembly,
    },
    resource_server::{
        core::{
            jwk::JwksSource, server_metadata::AuthorizationServerMetadata,
            url_mapping::PublicUrlMapping,
        },
        resource::ResourceDefinition,
        validator::{ValidatedRequest, rfc9068::Rfc9068Validator},
    },
};
use huskarl_reqwest::ReqwestClient;
use pingora_core::{server::Server, upstreams::peer::HttpPeer};
use pingora_error::Result;
use pingora_proxy::{ProxyHttp, Session, http_proxy_service};
use pingora_proxy_router::{RouteSlot, context_lens, route};

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
    let mapping = PublicUrlMapping::new(
        &public_base,
        &std::env::var("INCOMING_PREFIX").unwrap_or_else(|_| "/".into()),
    )
    .expect("invalid public URL mapping");
    let inventory_definition = ResourceDefinition::new(
        mapping.clone(),
        INVENTORY_PATH,
        std::env::var("INVENTORY_AUDIENCE").map_or(AudienceBinding::ResourceIdentifier, |value| {
            AudienceBinding::mapped([value])
        }),
    )
    .expect("invalid inventory resource");
    let payments_definition = ResourceDefinition::new(
        mapping.clone(),
        PAYMENTS_PATH,
        std::env::var("PAYMENTS_AUDIENCE").map_or(AudienceBinding::ResourceIdentifier, |value| {
            AudienceBinding::mapped([value])
        }),
    )
    .expect("invalid payments resource");
    let inventory_resource = inventory_definition.resource();
    let payments_resource = payments_definition.resource();
    let inventory_audience = &inventory_definition.audiences()[0];
    let payments_audience = &payments_definition.audiences()[0];
    let origin = format!(
        "{}://{}",
        mapping.public_base().scheme_str().unwrap(),
        mapping.public_base().authority().unwrap()
    );
    let metadata_mapping = PublicUrlMapping::new(
        &origin,
        &std::env::var("METADATA_INCOMING_PREFIX").unwrap_or_else(|_| "/".into()),
    )
    .expect("invalid metadata mapping");

    let inventory_validator = build_validator(
        &std::env::var("INVENTORY_ISSUER").expect("INVENTORY_ISSUER is required"),
        inventory_audience,
    )
    .await;
    let payments_validator = build_validator(
        &std::env::var("PAYMENTS_ISSUER").expect("PAYMENTS_ISSUER is required"),
        payments_audience,
    )
    .await;

    // Both upstreams have the same downstream parsing assumptions.
    let path_guard = GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne);
    let inventory_guard = Guard::builder()
        .validator(inventory_validator)
        .path_guard(path_guard.clone())
        .build()
        .expect("failed to build inventory guard");

    let payments_guard = Guard::builder()
        .validator(payments_validator)
        .path_guard(path_guard.clone())
        .build()
        .expect("failed to build payments guard");
    let proxy = ResourceAssembly::new(metadata_mapping)
        .register(
            &inventory_definition,
            inventory_guard,
            Upstream {
                address: std::env::var("INVENTORY_UPSTREAM")
                    .unwrap_or_else(|_| "127.0.0.1:3001".into()),
            },
        )
        .expect("failed to register inventory")
        .register(
            &payments_definition,
            payments_guard,
            Upstream {
                address: std::env::var("PAYMENTS_UPSTREAM")
                    .unwrap_or_else(|_| "127.0.0.1:3002".into()),
            },
        )
        .expect("failed to register payments")
        .build(
            route(NotFound),
            context_lens!(AppContext, ctx => ctx.route),
            path_guard,
        )
        .expect("invalid resource assembly");

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
