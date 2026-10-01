//! Validated assembly of resource branches and server-level metadata publication.

use std::{collections::BTreeSet, marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use huskarl_route_guard::{GuardConfig, PathRegistration, RuleRouter};
use pingora_proxy::{ProxyHttp, Session};
use pingora_proxy_router::{Lens, Route, RouteSelector, RouteSlot, Router, route};

use super::{
    BoundResource, ConfigError, Guard, HasAuthState, HasScopes, ResourceMetadataEndpoint,
    ResourceMetadataProxy,
};
use crate::resource_server::{
    core::url_mapping::PublicUrlMapping,
    resource::{MetadataRouting, ResourceDefinition, ResourceError, ResourceRegistry},
    validator::{AccessTokenValidator, metadata::ProvideValidatorMetadata},
};

/// Invalid resource relationships or adapter routing configuration.
#[derive(Debug)]
pub enum AssemblyError {
    /// Invalid shared resource registration.
    Registration(ResourceError),
    /// Invalid Pingora guard, route, or metadata publication.
    Configuration(ConfigError),
}
impl std::fmt::Display for AssemblyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Registration(e) => e.fmt(f),
            Self::Configuration(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for AssemblyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Registration(e) => Some(e),
            Self::Configuration(e) => Some(e),
        }
    }
}

/// Collects resource branches and their separately mounted metadata endpoints.
///
/// The resulting router checks path ambiguity before invoking any branch hook.
/// Resources in this assembly must have disjoint incoming mounts and one public
/// origin. Registered metadata paths are public exceptions, including inside a
/// root authentication mount. Unknown queries on those paths return 404.
/// Use the low-level adapters for overlapping authentication policies.
pub struct ResourceAssembly<C> {
    registry: ResourceRegistry,
    metadata_mapping: PublicUrlMapping,
    branches: Vec<(String, Route<C>)>,
    endpoints: Vec<ResourceMetadataEndpoint>,
    metrics_name: Option<String>,
}
impl<C: Send + Sync + 'static> ResourceAssembly<C> {
    /// Creates an assembly with explicit mapping for the metadata namespace.
    #[must_use]
    pub fn new(metadata_mapping: PublicUrlMapping) -> Self {
        Self {
            registry: ResourceRegistry::new(MetadataRouting::PathAndQuery),
            metadata_mapping,
            branches: Vec::new(),
            endpoints: Vec::new(),
            metrics_name: None,
        }
    }
    /// Names this assembly's route-selection metrics when `metrics` is enabled.
    /// Use a stable deployment-configured name; unset emits `name=""`.
    /// Branch guards and shared dependencies retain their own names.
    #[must_use]
    pub fn metrics_name(mut self, name: impl Into<String>) -> Self {
        self.metrics_name = Some(name.into());
        self
    }

    /// Binds authentication and records its incoming mount and metadata endpoint.
    /// # Errors
    /// Rejects inconsistent mappings, overlapping mounts, or metadata conflicts.
    pub fn register<P, V>(
        self,
        definition: &ResourceDefinition,
        guard: Guard<V>,
        inner: P,
    ) -> Result<Self, AssemblyError>
    where
        P: ProxyHttp<CTX = C> + Send + Sync + 'static,
        V: AccessTokenValidator + ProvideValidatorMetadata + Send + Sync + 'static,
        V::Claims: HasScopes + Send + Sync,
        C: HasAuthState<V::Claims>,
    {
        let bound = BoundResource::new(definition.clone(), guard, inner)
            .map_err(AssemblyError::Configuration)?;
        self.register_bound(bound.into_route())
    }

    /// Registers an already bound router branch without preparing metadata again.
    /// Publication remains separate from the authenticated branch.
    /// # Errors
    /// Rejects inconsistent mappings, overlapping mounts, or publication conflicts.
    pub fn register_bound(mut self, bound: BoundResource<Route<C>>) -> Result<Self, AssemblyError> {
        let (definition, proxy, endpoint) = bound.into_parts();
        let incoming = self
            .registry
            .register(&definition, &self.metadata_mapping)
            .map_err(AssemblyError::Registration)?;
        if definition.incoming_mount().contains(['{', '}']) || incoming.path().contains(['{', '}'])
        {
            return Err(AssemblyError::Configuration(ConfigError::Route {
                pattern: definition.incoming_mount().to_owned(),
                reason: "resource mounts must be literal Pingora paths",
            }));
        }
        let endpoint = endpoint
            .with_mapping(&self.metadata_mapping)
            .map_err(|e| AssemblyError::Registration(ResourceError::Mapping { source: e }))?;
        self.branches
            .push((definition.incoming_mount().to_owned(), proxy));
        self.endpoints.push(endpoint);
        Ok(self)
    }
    /// Builds a router using the existing application context and route slot.
    /// `path_guard` must reflect the parsing assumptions of all mounted branches.
    /// # Errors
    /// Rejects noncanonical route patterns or conflicting metadata publication.
    pub fn build(
        self,
        fallback: Route<C>,
        slot: Lens<C, RouteSlot<C>>,
        path_guard: GuardConfig,
    ) -> Result<AssembledResources<C>, AssemblyError>
    where
        C: Default,
    {
        let mut publisher = ResourceMetadataProxy::new(MetadataNotFound::<C>(PhantomData));
        let mut paths = BTreeSet::new();
        for endpoint in self.endpoints {
            paths.insert(endpoint.incoming_uri().path().to_owned());
            publisher = publisher
                .publish(endpoint)
                .map_err(AssemblyError::Configuration)?;
        }
        let mut registrations = Vec::new();
        for (mount, branch) in self.branches {
            // Keep one policy identity for the mount and descendants, but let
            // reserved metadata paths replace exact application mount routes.
            let slash = if mount.ends_with('/') {
                mount.clone()
            } else {
                format!("{mount}/")
            };
            let patterns = [mount, slash.clone(), format!("{slash}{{*rest}}")]
                .into_iter()
                .filter(|path| !paths.contains(path))
                .collect::<BTreeSet<_>>();
            registrations.push(PathRegistration::patterns(patterns).all(branch));
        }
        let metadata_route = route(publisher);
        for path in paths {
            registrations.push(PathRegistration::path(path).all(Arc::clone(&metadata_route)));
        }
        let routes =
            RuleRouter::from_registrations(Arc::clone(&fallback), path_guard, registrations)
                .map_err(|e| AssemblyError::Configuration(e.into()))?;
        Ok(Router::new(
            ResourceSelector {
                routes,
                metrics_name: self.metrics_name,
            },
            fallback,
            slot,
        ))
    }
}

/// Selector produced by [`ResourceAssembly`], retaining path-guard validation.
pub struct ResourceSelector<C> {
    routes: RuleRouter<Route<C>>,
    metrics_name: Option<String>,
}
impl<C: Send + Sync + 'static> RouteSelector<C> for ResourceSelector<C> {
    fn select(&self, session: &Session, _ctx: &C) -> pingora_error::Result<Option<Route<C>>> {
        let req = session.req_header();
        let resolved = self.routes.resolve(req.uri.path(), &req.method);
        crate::metrics::route_outcome(resolved.as_ref().err(), self.metrics_name.as_deref());
        let matched = resolved.map_err(|reason| {
            pingora_error::Error::explain(
                pingora_error::ErrorType::HTTPStatus(
                    crate::path_confusion::resolve_error_status(&reason).as_u16(),
                ),
                reason.to_string(),
            )
        })?;
        Ok(Some(Arc::clone(matched.rule())))
    }
}
// The reserved metadata path may receive an unregistered query. Do not delegate
// that request to the application's fallback, which may assume authentication.
struct MetadataNotFound<C>(PhantomData<fn() -> C>);
#[async_trait]
impl<C: Default + Send + Sync + 'static> ProxyHttp for MetadataNotFound<C> {
    type CTX = C;
    fn new_ctx(&self) -> C {
        C::default()
    }
    async fn request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut C,
    ) -> pingora_error::Result<bool> {
        session.respond_error(404).await?;
        Ok(true)
    }
    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut C,
    ) -> pingora_error::Result<Box<pingora_core::upstreams::peer::HttpPeer>> {
        Err(pingora_error::Error::new(
            pingora_error::ErrorType::HTTPStatus(404),
        ))
    }
}

/// Router produced by a validated resource assembly.
pub type AssembledResources<C> = Router<C, ResourceSelector<C>, fn() -> C>;
