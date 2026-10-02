//! Start here: one authenticated resource, with public discovery metadata.
//!
//! Supply ISSUER and PUBLIC_BASE (the external origin, e.g. https://api.example.com).
//! AUDIENCE optionally overrides the resource URL accepted as the token audience.
//! UPSTREAM defaults to 127.0.0.1:3000; LISTEN defaults to 127.0.0.1:6188.
//! Run: ISSUER=https://auth.example.com PUBLIC_BASE=https://api.example.com
//!      cargo run --example resource_proxy
//! See examples/README.md for requests and the next examples.
use huskarl_pingora::{
    resource::{
        AudienceBinding, CaseSensitivity, DecodeDepth, GuardConfig, ResourcePolicy,
        assembly::ResourceAssembly,
    },
    resource_server::{core::url_mapping::PublicUrlMapping, resource::ResourceDefinition},
};
use pingora_proxy_router::{context_lens, route};
#[path = "support/resource_server.rs"]
mod support;
use support::{AppContext, NotFound, Upstream, build_validator, run};

fn main() {
    run(async {
        // 1. Name the resource and describe this direct, origin-root deployment.
        let public_base = std::env::var("PUBLIC_BASE").expect("PUBLIC_BASE is required");
        let mapping = PublicUrlMapping::new(&public_base, "/").expect("invalid mapping");
        let audiences = std::env::var("AUDIENCE")
            .map_or(AudienceBinding::ResourceIdentifier, |value| {
                AudienceBinding::mapped([value])
            });
        let definition = ResourceDefinition::builder()
            .mapping(mapping.clone())
            .subpath("/api")
            .audience(audiences)
            .resource_name("Example API")
            .build()
            .expect("invalid resource");

        // 2. Choose who validates tokens. Use the definition's audience so both
        // token validation and resource binding agree. This example accepts one.
        let issuer = std::env::var("ISSUER").expect("ISSUER is required");
        let validator = build_validator(&issuer, &definition.audiences()[0]).await;
        let paths = GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne);
        let policy = ResourcePolicy::builder()
            .path_guard(paths.clone())
            .build()
            .expect("invalid policy"); // Authentication is required by default.
        let upstream = Upstream {
            address: std::env::var("UPSTREAM").unwrap_or_else(|_| "127.0.0.1:3000".into()),
        };

        // 3. Install /api and its descendants plus the derived public metadata
        // endpoint. Other paths return 404. register() performs binding for us.
        ResourceAssembly::new(mapping)
            .register(&definition, validator, policy, upstream)
            .expect("resource registration failed")
            .build(
                route(NotFound),
                context_lens!(AppContext, ctx => ctx.route),
                paths,
            )
            .expect("invalid server routing")
    });
}
