//! Per-route session policy.
//!
//! [`LoginRule`] describes what session handling a path requires, plus
//! optional authorization checks that run after the session is loaded. Rules
//! are registered on [`LoginProxy`](super::LoginProxy) via
//! `.route(pattern, rule)` using [`matchit`] path-pattern syntax (e.g.
//! `/users/{id}`, `/static/{*rest}`).
//!
//! Use the constructor methods [`LoginRule::public`], [`LoginRule::optional`],
//! and [`LoginRule::required`], then chain `.check(...)` for custom
//! authorization logic.

use std::sync::Arc;

/// What level of session handling a route requires.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SessionRequirement {
    /// No session check — session loading is skipped entirely. The inner
    /// proxy sees no session. Cheapest option for paths that genuinely
    /// don't care (e.g. `/health`, `/static/...`).
    None,
    /// Load the session if a cookie is present, but pass through to the
    /// inner proxy either way. Use this when the path is publicly accessible
    /// but should still render personalized content (e.g. a "Sign in" vs
    /// "Welcome, Alice" header on the landing page).
    Optional,
    /// Load the session and require it. Unauthenticated browser navigation
    /// gets a `302` to the authorization server; XHR/API requests get a
    /// `401`. This is the default for paths with no matching route.
    #[default]
    Required,
}

/// An error returned by a custom [`LoginRule::check`] function.
#[derive(Debug)]
#[non_exhaustive]
pub enum CheckError {
    /// `403 Forbidden` — the session is valid but lacks permission for this
    /// resource.
    Forbidden(String),
    // Future: `StepUp { acr_values: Vec<String>, … }` for step-up authentication
    // (re-authenticate with elevated ACR / max_age / prompt=login). Wiring it
    // up requires the engine to accept these parameters on `redirect_to_login`.
}

impl std::fmt::Display for CheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Forbidden(msg) => write!(f, "forbidden: {msg}"),
        }
    }
}

impl std::error::Error for CheckError {}

type CheckFn<S> = Arc<dyn Fn(&S) -> Result<(), CheckError> + Send + Sync>;

/// Per-path session policy.
///
/// Constructor methods [`LoginRule::public`], [`LoginRule::optional`], and
/// [`LoginRule::required`] cover the session-loading requirement. Chain
/// `.check(|session| …)` to add custom authorization checks that run after
/// the session is loaded (audience, scope, claim, role-based gates).
///
/// The type parameter is the session type produced by your
/// [`SessionDriver`](super::SessionDriver) — usually inferred from context.
/// Rules are cheap to clone.
///
/// ```ignore
/// LoginRule::public();
/// LoginRule::optional();
/// LoginRule::required();
/// LoginRule::required().check(|s: &MySession| {
///     if s.has_role("admin") { Ok(()) }
///     else { Err(CheckError::Forbidden("admin only".into())) }
/// });
/// ```
#[must_use]
pub struct LoginRule<S = ()> {
    pub(crate) requirement: SessionRequirement,
    pub(crate) check: Option<CheckFn<S>>,
}

impl<S> Default for LoginRule<S> {
    fn default() -> Self {
        Self::required()
    }
}

impl<S> Clone for LoginRule<S> {
    fn clone(&self) -> Self {
        Self {
            requirement: self.requirement,
            check: self.check.clone(),
        }
    }
}

impl<S> std::fmt::Debug for LoginRule<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginRule")
            .field("requirement", &self.requirement)
            .field("check", &self.check.as_ref().map(|_| ..))
            .finish()
    }
}

impl<S> LoginRule<S> {
    fn with_requirement(requirement: SessionRequirement) -> Self {
        Self {
            requirement,
            check: None,
        }
    }

    /// A rule that bypasses session handling entirely. The session store is
    /// not called and the inner proxy sees no session.
    ///
    /// `.check()` is meaningless on a public rule (there is no session to
    /// inspect) and is ignored.
    pub fn public() -> Self {
        Self::with_requirement(SessionRequirement::None)
    }

    /// A rule that loads the session if a cookie is present but never gates
    /// the request. The inner proxy can read `ctx.login_session()` to
    /// personalize the response.
    ///
    /// `.check()` runs only when a session is present.
    pub fn optional() -> Self {
        Self::with_requirement(SessionRequirement::Optional)
    }

    /// A rule that requires an authenticated session. Unauthenticated
    /// requests are redirected to the authorization server (browser
    /// navigation) or rejected with `401` (XHR).
    pub fn required() -> Self {
        Self::with_requirement(SessionRequirement::Required)
    }

    /// Adds a custom authorization check that runs after the session is
    /// loaded. Returning `Err(CheckError)` denies the request.
    ///
    /// Use this for general claim checks — audience, scope, role,
    /// org-id matching — or anything that depends on session content.
    ///
    /// On a `public` rule this is ignored; on `optional` it only runs when
    /// a session is present.
    pub fn check(
        mut self,
        f: impl Fn(&S) -> Result<(), CheckError> + Send + Sync + 'static,
    ) -> Self {
        self.check = Some(Arc::new(f));
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_rule() {
        let r: LoginRule = LoginRule::public();
        assert_eq!(r.requirement, SessionRequirement::None);
        assert!(r.check.is_none());
    }

    #[test]
    fn optional_rule() {
        let r: LoginRule = LoginRule::optional();
        assert_eq!(r.requirement, SessionRequirement::Optional);
    }

    #[test]
    fn required_rule() {
        let r: LoginRule = LoginRule::required();
        assert_eq!(r.requirement, SessionRequirement::Required);
    }

    #[test]
    fn default_is_required() {
        let r: LoginRule = LoginRule::default();
        assert_eq!(r.requirement, SessionRequirement::Required);
    }

    #[test]
    fn check_is_attached() {
        let r = LoginRule::<String>::required().check(|_| Ok(()));
        assert!(r.check.is_some());
    }

    #[test]
    fn check_runs() {
        let r = LoginRule::<i32>::required().check(|n| {
            if *n > 0 {
                Ok(())
            } else {
                Err(CheckError::Forbidden("non-positive".into()))
            }
        });
        let check = r.check.as_ref().unwrap();
        assert!(check(&1).is_ok());
        assert!(matches!(check(&0), Err(CheckError::Forbidden(_))));
    }
}
