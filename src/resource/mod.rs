//! Access-token authentication and protected-resource discovery for Pingora.
//!
//! | Task | API | Guide |
//! |---|---|---|
//! | Protect resources and publish discovery on one listener | [`assembly::ResourceAssembly`] | [Assemble resources](crate::_docs::how_to::resource_registration) |
//! | Use your own router or an external metadata publisher | [`BoundResource`] | [Contribute metadata](crate::_docs::how_to::publication_contributions) |
//! | Authenticate tokens without resource discovery | [`Guard`] + [`AuthProxy`] | [Add token authentication](crate::_docs::how_to::resource_proxy) |
//!
//! Start with the [token-protection tutorial](crate::_docs::tutorial::resource_proxy)
//! for a working upstream, proxy, and authenticated request.
//!
//! # Request policy and context
//!
//! A [`ResourcePolicy`] selects a [`Rule`] for the incoming path and method.
//! Unmatched paths require authentication by default. Use
//! [`subtree`](ResourcePolicyBuilder::subtree) for a path and its descendants,
//! or [`route`](ResourcePolicyBuilder::route) for one exact path. Rules can require
//! audiences, scopes, and custom checks after token validation.
//!
//! The inner proxy's context must implement [`HasAuthState`] for the validator's
//! claims type. [`AuthCtx`] supplies this state around your own context.
//! Read [`HasAuthState::validated_token`] in inner request or forwarding hooks.
//! Public rules skip validation; optional rules validate supplied credentials
//! but allow requests without a token. Invalid supplied tokens are rejected.
//!
//! # Forwarding and discovery
//!
//! Authentication removes `Authorization` and `DPoP` before the inner upstream
//! request filter by default. [`Rule::strip_credentials`] controls this behavior.
//! `DPoP` nonces are propagated to responses. For mTLS-bound tokens, supply the
//! handshake certificate through [`ClientCertDer`].
//!
//! Resource assembly binds each resource's identity and audiences and publishes
//! its metadata outside token authentication. Advertising scopes does not enforce
//! them: configure [`Rule::scopes`] for authorization. A custom router must select
//! metadata independently before invoking an authenticated branch's early hooks.
//! See [metadata publication](crate::_docs::how_to::resource_metadata).

mod bound;
mod ctx;
pub(crate) mod error;
pub mod error_body;
mod guard;
mod outcome;
mod policy;
mod proxy;
pub(crate) mod response;
pub mod rule;
pub mod scopes;
#[cfg(test)]
pub(crate) mod test_support;

pub use bound::{BoundResource, BoundResourceBuilder};
pub use ctx::{AuthCtx, HasAuthState};
pub use error::ConfigError;
pub use error_body::{
    ErrorBody, ErrorBodyResponse, ErrorDetails, ErrorDetailsBuilder, FailureDetails,
};
pub use guard::{ClientCertDer, Guard, GuardBuilder};
pub use outcome::Outcome;
pub use policy::{ResourcePolicy, ResourcePolicyBuilder};
pub use proxy::{
    AudienceBinding, AuthProxy, ProtectedResourceProxy, ResourceMetadataEndpoint,
    ResourceMetadataProxy,
};
pub use rule::{CheckError, Rule, TokenRequirement};
pub use scopes::HasScopes;

pub use crate::method::MethodMatch;
#[doc(no_inline)]
pub use crate::path_confusion::{
    CaseSensitivity, DecodeDepth, GuardConfig, GuardMode, ResolveError, ResolveErrorKind,
    StructuralChar, StructuralClass, StructuralClasses, StructuralProbe,
};

/// Validated assembly of independently authenticated resources.
pub mod assembly;
