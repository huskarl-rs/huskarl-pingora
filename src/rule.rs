use std::sync::Arc;

use huskarl_resource_server::validator::ValidatedRequest;

/// What level of authentication a route requires.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TokenRequirement {
    /// No authentication required. The validator is not called.
    None,
    /// A token is accepted but not required.
    Optional,
    /// A valid token must be present.
    #[default]
    Required,
}

/// An error returned by a custom [`Rule::check`] function.
pub enum CheckError {
    /// 403 — the token is valid but lacks permission for this resource.
    Forbidden(String),
    /// 401 — the token is unsuitable for this resource.
    InvalidToken(String),
}

type CheckFn<C> = Arc<dyn Fn(&ValidatedRequest<C>) -> Result<(), CheckError> + Send + Sync>;

/// A composable rule describing what authentication and authorization a path requires.
///
/// Use the constructor methods [`Rule::public`], [`Rule::optional`], and [`Rule::required`]
/// to create a rule, then chain `.audience()`, `.scopes()`, and `.check()` for further
/// constraints.
pub struct Rule<C> {
    pub(crate) token: TokenRequirement,
    pub(crate) audiences: Vec<String>,
    pub(crate) scopes: Vec<String>,
    pub(crate) check: Option<CheckFn<C>>,
    pub(crate) strip_credentials: bool,
}

impl<C> Rule<C> {
    /// Creates a rule that requires no authentication.
    ///
    /// The validator is not called at all for matching paths.
    pub fn public() -> Self {
        Self {
            token: TokenRequirement::None,
            audiences: Vec::new(),
            scopes: Vec::new(),
            check: None,
            strip_credentials: true,
        }
    }

    /// Creates a rule where a token is accepted but not required.
    ///
    /// If a token is present it is validated; if absent the request proceeds
    /// with `token: None`.
    pub fn optional() -> Self {
        Self {
            token: TokenRequirement::Optional,
            audiences: Vec::new(),
            scopes: Vec::new(),
            check: None,
            strip_credentials: true,
        }
    }

    /// Creates a rule that requires a valid token.
    pub fn required() -> Self {
        Self {
            token: TokenRequirement::Required,
            audiences: Vec::new(),
            scopes: Vec::new(),
            check: None,
            strip_credentials: true,
        }
    }

    /// Requires that the token's `audience` contains at least one of the given values.
    ///
    /// If none match, the request is denied with 401 `invalid_token`.
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audiences.push(audience.into());
        self
    }

    /// Requires that the token's scopes (via [`HasScopes`](crate::HasScopes)) contain
    /// all of the given values.
    ///
    /// If any are missing, the request is denied with 403 `insufficient_scope`.
    pub fn scopes(mut self, scopes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.scopes.extend(scopes.into_iter().map(Into::into));
        self
    }

    /// Adds a custom check function that runs after audience and scope checks.
    ///
    /// Return `Ok(())` to allow the request, or `Err(CheckError)` to deny it.
    pub fn check(
        mut self,
        f: impl Fn(&ValidatedRequest<C>) -> Result<(), CheckError> + Send + Sync + 'static,
    ) -> Self {
        self.check = Some(Arc::new(f));
        self
    }

    /// Controls whether the `Authorization` header is stripped before
    /// forwarding the request to upstream.
    ///
    /// Defaults to `true`. Set to `false` if the upstream service needs to
    /// see the original credentials.
    pub fn strip_credentials(mut self, strip: bool) -> Self {
        self.strip_credentials = strip;
        self
    }
}

impl<C> Default for Rule<C> {
    fn default() -> Self {
        Self::required()
    }
}
