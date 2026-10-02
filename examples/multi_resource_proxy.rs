//! Next: two resources using the same built-in assembly as resource_proxy.
//!
//! Supply PUBLIC_BASE, INVENTORY_ISSUER and PAYMENTS_ISSUER. Optional
//! INVENTORY_AUDIENCE/PAYMENTS_AUDIENCE override the respective resource URLs.
//! INVENTORY_UPSTREAM/PAYMENTS_UPSTREAM default to 127.0.0.1:3001/3002.
//! LISTEN defaults to 127.0.0.1:6188. See examples/README.md for commands.
//! For custom routing, rewrites and security.txt, see publication_proxy.
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
        let public_base = std::env::var("PUBLIC_BASE").expect("PUBLIC_BASE is required");
        let mapping = PublicUrlMapping::new(&public_base, "/").expect("invalid mapping");
        let paths = GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne);
        let mut server = ResourceAssembly::new(mapping.clone());

        // Each row supplies the same resource inputs as the single-resource example.
        for (name, path, default_upstream) in [
            ("INVENTORY", "/mcp/inventory", "127.0.0.1:3001"),
            ("PAYMENTS", "/mcp/payments", "127.0.0.1:3002"),
        ] {
            let audiences = std::env::var(format!("{name}_AUDIENCE"))
                .map_or(AudienceBinding::ResourceIdentifier, |value| {
                    AudienceBinding::mapped([value])
                });
            let definition = ResourceDefinition::new(mapping.clone(), path, audiences)
                .expect("invalid resource");
            let issuer =
                std::env::var(format!("{name}_ISSUER")).expect("resource issuer is required");
            let validator = build_validator(&issuer, &definition.audiences()[0]).await;
            let policy = ResourcePolicy::builder()
                .path_guard(paths.clone())
                .build()
                .expect("invalid policy");
            let upstream = Upstream {
                address: std::env::var(format!("{name}_UPSTREAM"))
                    .unwrap_or_else(|_| default_upstream.into()),
            };
            server = server
                .register()
                .definition(&definition)
                .validator(validator)
                .policy(policy)
                .inner(upstream)
                .call()
                .expect("resource registration failed");
        }
        // The assembly checks overlaps and publishes both metadata contributions.
        server
            .assemble()
            .fallback(route(NotFound))
            .slot(context_lens!(AppContext, ctx => ctx.route))
            .path_guard(paths)
            .call()
            .expect("invalid server routing")
    });
}
