use std::sync::Arc;

use crate::resource_server::validator::ValidatedRequest;

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
#[derive(Debug)]
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
///
/// Rules can be cloned and shared across multiple routes.
#[must_use]
pub struct Rule<C> {
    pub(crate) token: TokenRequirement,
    pub(crate) audiences: Vec<String>,
    pub(crate) scopes: Vec<String>,
    pub(crate) scope_param: Option<String>,
    pub(crate) check: Option<CheckFn<C>>,
    pub(crate) strip_credentials: bool,
}

impl<C> Clone for Rule<C> {
    fn clone(&self) -> Self {
        Self {
            token: self.token,
            audiences: self.audiences.clone(),
            scopes: self.scopes.clone(),
            scope_param: self.scope_param.clone(),
            check: self.check.clone(),
            strip_credentials: self.strip_credentials,
        }
    }
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
            scope_param: None,
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
            scope_param: None,
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
            scope_param: None,
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

    /// Requires that the token's `audience` contains at least one of the given values.
    ///
    /// Convenience method for adding multiple audiences at once.
    /// If none match, the request is denied with 401 `invalid_token`.
    pub fn audiences(mut self, audiences: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.audiences.extend(audiences.into_iter().map(Into::into));
        self
    }

    /// Requires that the token's scopes (via [`HasScopes`](crate::HasScopes)) contain
    /// all of the given values.
    ///
    /// If any are missing, the request is denied with 403 `insufficient_scope`.
    pub fn scopes(mut self, scopes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.scopes.extend(scopes.into_iter().map(Into::into));
        self.scope_param = if self.scopes.is_empty() {
            None
        } else {
            Some(self.scopes.join(" "))
        };
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

impl<C> std::fmt::Debug for Rule<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rule")
            .field("token", &self.token)
            .field("audiences", &self.audiences)
            .field("scopes", &self.scopes)
            .field("strip_credentials", &self.strip_credentials)
            .field("check", &self.check.as_ref().map(|_| ..))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_rule_defaults() {
        let rule = Rule::<()>::public();
        assert_eq!(rule.token, TokenRequirement::None);
        assert!(rule.audiences.is_empty());
        assert!(rule.scopes.is_empty());
        assert!(rule.scope_param.is_none());
        assert!(rule.strip_credentials);
        assert!(rule.check.is_none());
    }

    #[test]
    fn optional_rule_defaults() {
        let rule = Rule::<()>::optional();
        assert_eq!(rule.token, TokenRequirement::Optional);
        assert!(rule.strip_credentials);
    }

    #[test]
    fn required_rule_defaults() {
        let rule = Rule::<()>::required();
        assert_eq!(rule.token, TokenRequirement::Required);
        assert!(rule.strip_credentials);
    }

    #[test]
    fn default_is_required() {
        let rule = Rule::<()>::default();
        assert_eq!(rule.token, TokenRequirement::Required);
    }

    #[test]
    fn scopes_sets_scope_param() {
        let rule = Rule::<()>::required().scopes(["read", "write"]);
        assert_eq!(rule.scopes, vec!["read", "write"]);
        assert_eq!(rule.scope_param.as_deref(), Some("read write"));
    }

    #[test]
    fn scopes_accumulate_across_calls() {
        let rule = Rule::<()>::required().scopes(["read"]).scopes(["write"]);
        assert_eq!(rule.scopes, vec!["read", "write"]);
        assert_eq!(rule.scope_param.as_deref(), Some("read write"));
    }

    #[test]
    fn audience_chaining() {
        let rule = Rule::<()>::required().audience("a").audience("b");
        assert_eq!(rule.audiences, vec!["a", "b"]);
    }

    #[test]
    fn audiences_batch() {
        let rule = Rule::<()>::required().audiences(["a", "b", "c"]);
        assert_eq!(rule.audiences, vec!["a", "b", "c"]);
    }

    #[test]
    fn strip_credentials_override() {
        let rule = Rule::<()>::required().strip_credentials(false);
        assert!(!rule.strip_credentials);
    }

    #[test]
    fn clone_preserves_fields() {
        let rule = Rule::<()>::required().scopes(["read"]).audience("aud");
        let cloned = rule.clone();
        assert_eq!(cloned.token, rule.token);
        assert_eq!(cloned.scopes, rule.scopes);
        assert_eq!(cloned.audiences, rule.audiences);
        assert_eq!(cloned.strip_credentials, rule.strip_credentials);
    }
}
