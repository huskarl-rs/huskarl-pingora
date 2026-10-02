//! Validated access policy, independent of resource identity and token validation.
use std::collections::BTreeSet;

use bon::bon;
use huskarl_route_guard::{GuardConfig, RuleRouter};

use super::{ConfigError, Rule};
use crate::routing::RouteKind;

/// Validated route rules in incoming request coordinates, including the mount prefix.
///
/// A policy owns no validator or URL mapping. Pass it to [`super::BoundResource::new`]
/// for a defined resource, or [`super::Guard::new`] for standalone authentication.
/// Unmatched paths require authentication unless an explicit default overrides it.
pub struct ResourcePolicy<C> {
    pub(crate) routes: RuleRouter<Rule<C>>,
    pub(crate) scopes_supported: Vec<String>,
    pub(crate) metrics_name: Option<String>,
}

#[bon]
impl<C> ResourcePolicy<C> {
    /// Validates access rules in incoming request coordinates.
    ///
    /// Use [`ResourcePolicy::builder`] to set routes and
    /// configuration; this constructor is the builder's terminal `build`
    /// step.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if a route pattern is
    /// invalid, or if a public rule has constraints that can never be enforced.
    #[builder]
    pub fn new(
        // One entry per `route`/`subtree`/`blob_subtree` call, in registration order.
        // Rule-id assignment and subtree-pattern expansion are deferred to
        // `RuleRouter::from_registrations` at build time.
        #[builder(field)] routes: Vec<(RouteKind, String, Rule<C>)>,
        /// The default rule for paths that don't match any route.
        ///
        /// Defaults to [`Rule::required()`].
        #[builder(default)]
        default: Rule<C>,
        /// Path-confusion configuration, including the required downstream case
        /// sensitivity and decode depth. There is no default: declare these
        /// assumptions with [`GuardConfig::new`]. Clone the configuration to share
        /// it with other guards that have the same downstream parsing assumptions.
        path_guard: GuardConfig,
        /// Optional value for the `name` label on emitted metrics (the
        /// `huskarl.resource.check` counter). Set it to tell guard instances apart when
        /// one process runs several; leave unset for `name=""`. Requires the optional
        /// `metrics` feature; naming never wraps the supplied validator.
        #[builder(into)]
        metrics_name: Option<String>,
    ) -> Result<Self, ConfigError> {
        // Reject public rules with audience or scope constraints — they can never
        // be enforced because the token validator is skipped for public routes.
        for (_kind, pattern, rule) in &routes {
            if rule.public_constraints_requested() {
                return Err(ConfigError::PublicRuleWithConstraints(pattern.clone()));
            }
        }
        if default.public_constraints_requested() {
            return Err(ConfigError::PublicRuleWithConstraints("<default>".into()));
        }

        // Collect unique scopes from all route rules and the default rule.
        let mut all_scopes = BTreeSet::new();
        for (_kind, _pattern, rule) in &routes {
            all_scopes.extend(rule.scopes.iter().cloned());
        }
        all_scopes.extend(default.scopes.iter().cloned());
        let scopes_supported: Vec<String> = all_scopes.into_iter().collect();

        let registrations = routes.into_iter().map(|(kind, pattern, rule)| {
            let method = rule.method.clone();
            kind.registration(pattern, method, rule)
        });
        let routes = RuleRouter::from_registrations(default, path_guard, registrations)?;

        Ok(Self {
            routes,
            scopes_supported,
            metrics_name,
        })
    }
}

impl<C, S: resource_policy_builder::State> ResourcePolicyBuilder<C, S> {
    /// Adds a single exact-match route pattern with an associated rule.
    ///
    /// Patterns use `matchit` syntax (e.g. `/users/{id}`, `/public/{*rest}`).
    ///
    /// This matches the given path *exactly* — `route("/admin", …)` does not
    /// cover `/admin/` or `/admin/users`. To protect a path and everything
    /// beneath it (the usual intent, and the safer default for authorization),
    /// prefer [`subtree`](Self::subtree).
    pub fn route(mut self, pattern: impl Into<String>, rule: Rule<C>) -> Self {
        self.routes.push((RouteKind::Exact, pattern.into(), rule));
        self
    }

    /// Applies a rule to a path **and everything beneath it**.
    ///
    /// This is the recommended way to protect an area of the URL space:
    /// matching only an exact path (via [`route`](Self::route)) is a common
    /// source of authorization gaps, because a request to `/admin/` or
    /// `/admin/users` would otherwise fall through to the default rule and skip
    /// the scope/audience checks you attached to `/admin`.
    ///
    /// The path is expanded into the `matchit` patterns that cover the
    /// subtree (each mapping to a clone of `rule`):
    ///
    /// - `subtree("/admin", …)`  covers `/admin`, `/admin/`, and `/admin/...`
    /// - `subtree("/admin/", …)` covers `/admin/` and `/admin/...` — a trailing
    ///   slash means "this directory and its contents, but not the bare
    ///   `/admin`".
    /// - `subtree("/", …)` covers the entire path space.
    ///
    /// A more-specific [`route`](Self::route) still takes precedence over a
    /// subtree's catch-all, so you can layer exceptions:
    ///
    /// ```
    /// # use huskarl_pingora::resource::{CaseSensitivity, DecodeDepth, GuardConfig, ResourcePolicy, Rule};
    /// # fn build<V>(my_validator: V)
    /// # where
    /// #     V: huskarl_pingora::resource_server::validator::AccessTokenValidator
    /// #         + huskarl_pingora::resource_server::validator::metadata::ProvideValidatorMetadata,
    /// # {
    /// let policy = ResourcePolicy::<V::Claims>::builder()
    ///     .path_guard(GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne))
    ///     .subtree("/admin", Rule::required().scopes(["admin"]))
    ///     .route("/admin/health", Rule::public()) // exact carve-out wins
    ///     .build()
    ///     .expect("routes");
    /// # }
    /// ```
    pub fn subtree(mut self, path: &str, rule: Rule<C>) -> Self {
        self.routes
            .push((RouteKind::Subtree, path.to_owned(), rule));
        self
    }

    /// Registers an exclusive subtree, rejecting nested route overrides at build time.
    ///
    /// The same ambiguity checks apply as for [`subtree`](Self::subtree).
    /// Encoded separators and dot-segments can pass only when analysis establishes
    /// that they stay within the same rule. NUL is denied in every active mode.
    pub fn blob_subtree(mut self, path: &str, rule: Rule<C>) -> Self {
        self.routes.push((RouteKind::Blob, path.to_owned(), rule));
        self
    }
}
