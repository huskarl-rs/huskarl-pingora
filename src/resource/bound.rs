//! A resource binding carried intact to a server's routing boundary.

use pingora_proxy::ProxyHttp;
use pingora_proxy_router::{Route, route};

use super::{
    ConfigError, ErrorBody, HasAuthState, HasScopes, ProtectedResourceProxy,
    ResourceMetadataEndpoint, ResourcePolicy,
};
use crate::resource_server::{
    resource::ResourceDefinition,
    validator::{AccessTokenValidator, metadata::ProvideValidatorMetadata},
};

/// An authenticated proxy and its metadata, prepared from one resource definition.
///
/// Use this when your server owns routing or when customizing a resource before
/// registering it with [`super::assembly::ResourceAssembly`]. For ordinary
/// registration, [`super::assembly::ResourceAssembly::register`] constructs it for you.
///
/// # Example
///
/// Given a resource definition, matching validator, validated policy, and inner proxy:
///
/// ```
/// use huskarl_pingora::resource::{BoundResource, ResourcePolicy};
/// # use huskarl_pingora::resource_server::{resource::ResourceDefinition,
/// #     validator::{AccessTokenValidator, metadata::ProvideValidatorMetadata}};
/// # fn bind<P, V>(definition: ResourceDefinition, validator: V,
/// #     policy: ResourcePolicy<V::Claims>, inner: P) -> Result<(), Box<dyn std::error::Error>>
/// # where V: AccessTokenValidator + ProvideValidatorMetadata {
/// let bound = BoundResource::builder()
///     .definition(definition)
///     .validator(validator)
///     .policy(policy)
///     .inner(inner)
///     .error_body(()) // Empty rejection bodies; protocol headers are still set.
///     .build()?;
/// let (definition, authenticated_proxy, metadata) = bound.into_parts();
/// // Mount authenticated_proxy at definition.incoming_mount().
/// // Publish metadata separately, before authentication hooks run.
/// # let _ = (definition, authenticated_proxy, metadata);
/// # Ok(())
/// # }
/// ```
///
/// For built-in assembly, keep the bundle intact: call [`Self::into_route`] and
/// pass it to [`super::assembly::ResourceAssembly::register_bound`]. For a custom
/// router or external publisher, follow the
/// [publication recipe](crate::_docs::how_to::publication_contributions).
///
/// # Binding guarantees
///
/// Fields are private so independently prepared parts cannot be combined. The
/// consuming server owns routing and publication. Use [`Self::into_parts`] only
/// at that boundary; mounting the resulting proxy at the correct path remains
/// the server's responsibility.
///
/// The definition supplies the only URL mapping. Pass a validated
/// [`ResourcePolicy`], rather than an already configured [`super::Guard`]:
///
/// ```compile_fail,E0308
/// use huskarl_pingora::resource::{BoundResource, Guard};
/// use huskarl_pingora::resource_server::{
///     resource::ResourceDefinition,
///     validator::{AccessTokenValidator, metadata::ProvideValidatorMetadata},
/// };
/// fn bind<P, V>(definition: ResourceDefinition, validator: V, guard: Guard<V>, inner: P)
/// where V: AccessTokenValidator + ProvideValidatorMetadata {
///     let _ = BoundResource::builder()
///         .definition(definition)
///         .validator(validator)
///         .policy(guard)
///         .inner(inner)
///         .error_body(())
///         .build();
/// }
/// ```
///
/// Resource binding is a construction step; the resulting proxy has no rebinding setter:
///
/// ```compile_fail,E0599
/// use huskarl_pingora::resource::ProtectedResourceProxy;
/// use huskarl_pingora::resource_server::{
///     resource::ResourceDefinition,
///     validator::{AccessTokenValidator, metadata::ProvideValidatorMetadata},
/// };
/// fn rebind<P, V>(definition: ResourceDefinition, proxy: ProtectedResourceProxy<P, V>)
/// where V: AccessTokenValidator + ProvideValidatorMetadata {
///     let _ = proxy.with_resource_definition(&definition);
/// }
/// ```
///
/// Independently prepared definitions cannot replace the bundled definition:
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

#[bon::bon]
impl<P, V, E: ErrorBody> BoundResource<ProtectedResourceProxy<P, V, E>>
where
    V: AccessTokenValidator + ProvideValidatorMetadata,
{
    /// Starts a builder for an authenticated proxy and its matching metadata.
    /// Call [`BoundResourceBuilder::build`] to bind authentication and prepare
    /// the publication contribution.
    /// Set [`BoundResourceBuilder::error_body`] to a renderer, or `()` for an
    /// empty rejection body.
    /// No HTTP route is installed. Policy paths use incoming request coordinates,
    /// including the ingress prefix and resource mount. The definition alone
    /// supplies resource identity, accepted audiences and URL reconstruction.
    ///
    /// # Errors
    /// [`BoundResourceBuilder::build`] rejects inconsistent validator metadata
    /// or metadata serialization failures.
    #[builder]
    pub fn new(
        /// Resource identity, accepted audiences, and trusted public URL mapping.
        definition: ResourceDefinition,
        /// Access-token validator for this resource.
        validator: V,
        /// Validated access rules in incoming request coordinates.
        policy: ResourcePolicy<V::Claims>,
        /// Inner proxy to invoke after authentication and authorization succeed.
        inner: P,
        /// Renderer for resource-server rejection bodies. Use `()` for an empty body.
        /// Protocol status and headers remain library-controlled.
        error_body: E,
    ) -> Result<Self, ConfigError> {
        let (proxy, metadata) = ProtectedResourceProxy::new(&definition, validator, policy, inner)?;
        Ok(Self {
            definition,
            proxy: proxy.error_body(error_body),
            metadata,
        })
    }
}

impl<P, V, E> BoundResource<ProtectedResourceProxy<P, V, E>>
where
    V: AccessTokenValidator + ProvideValidatorMetadata,
{
    /// Configures rejection bodies while retaining the resource definition and
    /// prepared metadata. See [`ProtectedResourceProxy::error_body`] for renderer semantics.
    /// Use [`BoundResourceBuilder::error_body`] to choose the renderer during construction.
    #[must_use]
    pub fn error_body<NewE: ErrorBody>(
        self,
        error_body: NewE,
    ) -> BoundResource<ProtectedResourceProxy<P, V, NewE>> {
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
