//! Advanced: integrate bound resources into a server-owned publication router.
//! Start with `resource_proxy` and `multi_resource_proxy` for built-in assembly.
//!
//! `/mcp/inventory` and `/mcp/payments` have separate validators, audiences,
//! upstreams, and request contexts. Their RFC 9728 documents are published by
//! the server-owned router alongside an optional operator-supplied `security.txt`.
//! Set `SECURITY_TXT_FILE` to a UTF-8 file path; publication routes are independent
//! of the authenticated resource branches.
//!
//! # Usage
//!
//! ```sh
//! PUBLIC_BASE=https://api.example.com \
//! INVENTORY_ISSUER=https://inventory-auth.example.com \
//! PAYMENTS_ISSUER=https://payments-auth.example.com \
//! cargo run --example publication_proxy
//! ```

use std::{collections::BTreeSet, sync::Arc};

use async_trait::async_trait;
use bytes::Bytes;
use huskarl_pingora::{
    resource::{
        AudienceBinding, AuthCtx, BoundResource, CaseSensitivity, DecodeDepth, GuardConfig,
        HasAuthState, ResourceMetadataProxy, ResourcePolicy,
    },
    resource_server::{
        core::{
            jwk::JwksSource, server_metadata::AuthorizationServerMetadata,
            url_mapping::PublicUrlMapping,
        },
        resource::{MetadataRouting, ResourceDefinition, ResourceRegistry},
        validator::{ValidatedRequest, rfc9068::Rfc9068Validator},
    },
};
use huskarl_reqwest::ReqwestClient;
use huskarl_route_guard::{PathRegistration, RuleRouter};
use pingora_core::{server::Server, upstreams::peer::HttpPeer};
use pingora_error::Result;
use pingora_proxy::{ProxyHttp, Session, http_proxy_service};
use pingora_proxy_router::{Route, RouteSelector, RouteSlot, Router, context_lens, route};

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
        Err(pingora_error::Error::new(
            pingora_error::ErrorType::HTTPStatus(404),
        ))
    }
}

// This is application-owned composition. Huskarl contributes the auth branch
// and metadata; it does not need to know about the security.txt handler.

struct ServerRoutes(RuleRouter<Route<AppContext>>);

impl RouteSelector<AppContext> for ServerRoutes {
    fn select(&self, session: &Session, _ctx: &AppContext) -> Result<Option<Route<AppContext>>> {
        let req = session.req_header();
        let matched = self
            .0
            .resolve(req.uri.path(), &req.method)
            .map_err(|error| {
                pingora_error::Error::explain(
                    pingora_error::ErrorType::HTTPStatus(
                        huskarl_pingora::path_confusion::resolve_error_status(&error).as_u16(),
                    ),
                    error.to_string(),
                )
            })?;
        Ok(Some(Arc::clone(matched.rule())))
    }
}

type AppRouter = Router<AppContext, ServerRoutes, fn() -> AppContext>;

fn build_router(
    resources: Vec<BoundResource<Route<AppContext>>>,
    metadata_mapping: &PublicUrlMapping,
    security_txt: Option<Bytes>,
    path_guard: GuardConfig,
) -> std::result::Result<AppRouter, Box<dyn std::error::Error>> {
    let fallback = route(NotFound);
    let mut registry = ResourceRegistry::new(MetadataRouting::PathAndQuery);
    let mut publisher = ResourceMetadataProxy::new(NotFound);
    let mut metadata_paths = BTreeSet::new();
    let mut branches = Vec::new();
    for resource in resources {
        let (definition, proxy, metadata) = resource.into_parts();
        let incoming = registry.register(&definition, metadata_mapping)?;
        // These values describe literal paths, never route patterns.
        for path in [definition.incoming_mount(), incoming.path()] {
            if path.contains(['{', '}']) {
                return Err("resource and publication mounts must be literal paths".into());
            }
        }
        metadata_paths.insert(incoming.path().to_owned());
        publisher = publisher.publish(metadata.with_mapping(metadata_mapping)?)?;
        branches.push((definition.incoming_mount().to_owned(), proxy));
    }
    let mut registrations = Vec::new();
    let metadata_route = route(publisher);
    for path in &metadata_paths {
        // Reserve every method at the path. Unknown queries end at NotFound,
        // rather than entering a protected application without authentication.
        registrations.push(PathRegistration::path(path).all(Arc::clone(&metadata_route)));
    }
    let mut public_paths = metadata_paths;
    if let Some(body) = security_txt {
        let public_url = format!(
            "{}://{}/.well-known/security.txt",
            metadata_mapping
                .public_base()
                .scheme_str()
                .ok_or("missing public scheme")?,
            metadata_mapping
                .public_base()
                .authority()
                .ok_or("missing public authority")?,
        )
        .parse()?;
        let incoming = metadata_mapping.incoming_uri(&public_url)?;
        if incoming.path().contains(['{', '}']) || !public_paths.insert(incoming.path().to_owned())
        {
            return Err("security.txt publication path is invalid or already owned".into());
        }
        registrations.push(PathRegistration::path(incoming.path()).all(route(SecurityTxt(body))));
    }
    for (mount, branch) in branches {
        let slash = if mount.ends_with('/') {
            mount.clone()
        } else {
            format!("{mount}/")
        };
        let patterns = [mount, slash.clone(), format!("{slash}{{*rest}}")]
            .into_iter()
            .filter(|path| !public_paths.contains(path))
            .collect::<BTreeSet<_>>();
        registrations.push(PathRegistration::patterns(patterns).all(branch));
    }
    let routes = RuleRouter::from_registrations(Arc::clone(&fallback), path_guard, registrations)?;
    Ok(Router::new(
        ServerRoutes(routes),
        fallback,
        context_lens!(AppContext, ctx => ctx.route),
    ))
}

struct SecurityTxt(Bytes);

#[async_trait]
impl ProxyHttp for SecurityTxt {
    type CTX = AppContext;

    fn new_ctx(&self) -> Self::CTX {
        AppContext::default()
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        let method = &session.req_header().method;
        let allowed = matches!(*method, http::Method::GET | http::Method::HEAD);
        let send_body = *method == http::Method::GET && !self.0.is_empty();
        let mut response =
            pingora_http::ResponseHeader::build(if allowed { 200 } else { 405 }, None)?;
        if allowed {
            response.insert_header("content-type", "text/plain; charset=utf-8")?;
            response.insert_header("content-length", self.0.len().to_string())?;
            response.insert_header("cache-control", "max-age=3600")?;
        } else {
            response.insert_header("allow", "GET, HEAD")?;
            response.insert_header("content-length", "0")?;
            response.insert_header("cache-control", "no-store")?;
        }
        session
            .write_response_header(Box::new(response), !send_body)
            .await?;
        if send_body {
            session
                .write_response_body(Some(self.0.clone()), true)
                .await?;
        }
        Ok(true)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        Err(pingora_error::Error::new(
            pingora_error::ErrorType::HTTPStatus(500),
        ))
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

fn main() {
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

    // Complete async provider setup before Pingora starts its own runtimes.
    let rt = tokio::runtime::Runtime::new().expect("setup runtime");
    let proxy = rt.block_on(async {
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
        let inventory_policy = ResourcePolicy::builder()
            .path_guard(path_guard.clone())
            .build()
            .expect("failed to build inventory policy");

        let payments_policy = ResourcePolicy::builder()
            .path_guard(path_guard.clone())
            .build()
            .expect("failed to build payments policy");
        let inventory = BoundResource::builder()
            .definition(inventory_definition.clone())
            .validator(inventory_validator)
            .policy(inventory_policy)
            .inner(Upstream {
                address: std::env::var("INVENTORY_UPSTREAM")
                    .unwrap_or_else(|_| "127.0.0.1:3001".into()),
            })
            .error_body(())
            .build()
            .expect("failed to bind inventory")
            .into_route();
        let payments = BoundResource::builder()
            .definition(payments_definition.clone())
            .validator(payments_validator)
            .policy(payments_policy)
            .inner(Upstream {
                address: std::env::var("PAYMENTS_UPSTREAM")
                    .unwrap_or_else(|_| "127.0.0.1:3002".into()),
            })
            .error_body(())
            .build()
            .expect("failed to bind payments")
            .into_route();
        let security_txt = std::env::var_os("SECURITY_TXT_FILE").map(|path| {
            Bytes::from(
                std::fs::read_to_string(path).expect("failed to read SECURITY_TXT_FILE as UTF-8"),
            )
        });
        build_router(
            vec![inventory, payments],
            &metadata_mapping,
            security_txt,
            path_guard,
        )
        .expect("invalid server routing")
    });
    drop(rt);

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

#[cfg(test)]
#[path = "support/publication_tests.rs"]
mod tests;
