//! A resource binding carried intact to a server's routing boundary.

use pingora_proxy::ProxyHttp;
use pingora_proxy_router::{Route, route};

use super::{
    AuthProxy, ConfigError, ErrorBody, Guard, HasAuthState, HasScopes, ResourceMetadataEndpoint,
};
use crate::resource_server::{
    resource::ResourceDefinition,
    validator::{AccessTokenValidator, metadata::ProvideValidatorMetadata},
};

/// An authenticated proxy and its metadata, prepared from one resource definition.
///
/// Fields are private so independently prepared parts cannot be combined. The
/// consuming server owns routing and publication. Use [`Self::into_parts`] only
/// at that boundary; mounting the resulting proxy at the correct path remains
/// the server's responsibility.
///
/// ```compile_fail
/// use huskarl_pingora::resource::BoundResource;
/// fn replace_definition<P>(bound: &mut BoundResource<P>, other: huskarl_pingora::resource_server::resource::ResourceDefinition) {
///     bound.definition = other;
/// }
/// ```
pub struct BoundResource<P> {
    definition: ResourceDefinition,
    proxy: P,
    metadata: ResourceMetadataEndpoint,
}

impl<P, V> BoundResource<AuthProxy<P, V>>
where
    V: AccessTokenValidator + ProvideValidatorMetadata,
{
    /// Binds authentication and prepares its matching publication contribution.
    /// No HTTP route is installed.
    ///
    /// # Errors
    /// Rejects inconsistent guard mappings or invalid metadata.
    pub fn new(
        definition: ResourceDefinition,
        guard: Guard<V>,
        inner: P,
    ) -> Result<Self, ConfigError> {
        let (proxy, metadata) =
            AuthProxy::new(inner, guard).with_resource_definition(&definition)?;
        Ok(Self {
            definition,
            proxy,
            metadata,
        })
    }
}

impl<P, V, E> BoundResource<AuthProxy<P, V, E>>
where
    V: AccessTokenValidator + ProvideValidatorMetadata,
{
    /// Configures rejection bodies while retaining the resource definition and
    /// prepared metadata. See [`AuthProxy::error_body`] for renderer semantics.
    #[must_use]
    pub fn error_body<NewE: ErrorBody>(
        self,
        error_body: NewE,
    ) -> BoundResource<AuthProxy<P, V, NewE>> {
        BoundResource {
            definition: self.definition,
            proxy: self.proxy.error_body(error_body),
            metadata: self.metadata,
        }
    }

    /// Converts the bound proxy to a router branch while retaining its definition
    /// and publication contribution. This allows heterogeneous resource proxies
    /// to be collected by a consuming server.
    pub fn into_route(self) -> BoundResource<Route<P::CTX>>
    where
        P: ProxyHttp + Send + Sync + 'static,
        P::CTX: HasAuthState<V::Claims> + Send + Sync + 'static,
        V: Send + Sync + 'static,
        V::Claims: HasScopes + Send + Sync,
        E: ErrorBody,
    {
        BoundResource {
            definition: self.definition,
            proxy: route(self.proxy),
            metadata: self.metadata,
        }
    }
}

impl<P> BoundResource<P> {
    /// Definition used to bind this proxy and prepare its metadata.
    pub fn definition(&self) -> &ResourceDefinition {
        &self.definition
    }

    /// Publication contribution prepared during binding. Reading it installs no route.
    pub fn metadata(&self) -> &ResourceMetadataEndpoint {
        &self.metadata
    }

    /// Consumes the validated bundle at the server's routing boundary.
    ///
    /// Mount the proxy using the returned definition; publish the endpoint
    /// separately or export its snapshot. An arbitrary router can still mount
    /// the proxy incorrectly, so its defensive resource checks remain in place.
    pub fn into_parts(self) -> (ResourceDefinition, P, ResourceMetadataEndpoint) {
        (self.definition, self.proxy, self.metadata)
    }
}
