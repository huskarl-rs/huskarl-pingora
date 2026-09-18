//! Per-route session policy.
//!
//! [`LoginRule`] describes what session handling a path requires, plus
//! optional authorization checks that run after the session is loaded. Rules
//! are registered on [`LoginProxy`](super::LoginProxy) via
//! `.route(pattern, rule)` using `matchit` path-pattern syntax (e.g.
//! `/users/{id}`, `/static/{*rest}`).
//!
//! Use the constructor methods [`LoginRule::public`], [`LoginRule::optional`],
//! and [`LoginRule::required`], then chain `.check(...)` for custom
//! authorization logic.

use std::sync::Arc;

use huskarl_route_guard::MethodMatch;

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
/// [`LoginRule::required`] choose how the session is loaded; chain
/// `.check(|session| …)` on `optional`/`required` to add a custom
/// authorization check that runs after the session is loaded (audience,
/// scope, claim, role-based gates).
///
/// The three cases are modelled as enum variants so the authorization check
/// only runs where a session exists. [`Public`](Self::Public) skips session
/// loading entirely; attaching a check to it is rejected when the proxy is
/// built rather than silently ignored.
///
/// The type parameter is the session type produced by your
/// [`SessionDriver`](super::SessionDriver) — usually inferred from context.
/// Rules are cheap to clone.
///
/// ```
/// use huskarl_pingora::login::{CheckError, LoginRule};
///
/// struct MySession {
///     roles: Vec<String>,
/// }
/// impl MySession {
///     fn has_role(&self, role: &str) -> bool {
///         self.roles.iter().any(|r| r == role)
///     }
/// }
///
/// LoginRule::<MySession>::public();
/// LoginRule::<MySession>::optional();
/// LoginRule::<MySession>::required();
/// LoginRule::<MySession>::required().check(|s: &MySession| {
///     if s.has_role("admin") {
///         Ok(())
///     } else {
///         Err(CheckError::Forbidden("admin only".into()))
///     }
/// });
/// ```
#[must_use]
#[non_exhaustive]
pub enum LoginRule<S = ()> {
    /// No session check — session loading is skipped entirely. The inner
    /// proxy sees no session. Cheapest option for paths that genuinely don't
    /// care (e.g. `/health`, `/static/...`). Carries no authorization check:
    /// there is no session to inspect.
    Public {
        /// Which HTTP method(s) this rule applies to (wildcard by default).
        method: MethodMatch,
        /// Records an invalid `.check(...)` call so proxy construction can
        /// report it with the affected route pattern.
        check_requested: bool,
    },
    /// Load the session if a cookie is present, but pass through to the inner
    /// proxy either way. Use this when the path is publicly accessible but
    /// should still render personalized content (e.g. a "Sign in" vs
    /// "Welcome, Alice" header on the landing page). An attached `check` runs
    /// only when a session is present.
    Optional {
        /// Authorization check, run after the session is loaded when one is
        /// present. Set via [`check`](Self::check).
        check: Option<CheckFn<S>>,
        /// Which HTTP method(s) this rule applies to (wildcard by default).
        method: MethodMatch,
    },
    /// Load the session and require it. Unauthenticated browser navigation
    /// gets a `302` to the authorization server; XHR/API requests get a
    /// `401`. This is the default for paths with no matching route. An
    /// attached `check` gates the request further once a session is present.
    Required {
        /// Authorization check, run after the session is loaded. Set via
        /// [`check`](Self::check).
        check: Option<CheckFn<S>>,
        /// Which HTTP method(s) this rule applies to (wildcard by default).
        method: MethodMatch,
    },
}

impl<S> Default for LoginRule<S> {
    fn default() -> Self {
        Self::required()
    }
}

impl<S> Clone for LoginRule<S> {
    fn clone(&self) -> Self {
        match self {
            Self::Public {
                method,
                check_requested,
            } => Self::Public {
                method: method.clone(),
                check_requested: *check_requested,
            },
            Self::Optional { check, method } => Self::Optional {
                check: check.clone(),
                method: method.clone(),
            },
            Self::Required { check, method } => Self::Required {
                check: check.clone(),
                method: method.clone(),
            },
        }
    }
}

impl<S> std::fmt::Debug for LoginRule<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public {
                method,
                check_requested,
            } => f
                .debug_struct("Public")
                .field("method", method)
                .field("check_requested", check_requested)
                .finish(),
            Self::Optional { check, method } => f
                .debug_struct("Optional")
                .field("check", &check.as_ref().map(|_| ..))
                .field("method", method)
                .finish(),
            Self::Required { check, method } => f
                .debug_struct("Required")
                .field("check", &check.as_ref().map(|_| ..))
                .field("method", method)
                .finish(),
        }
    }
}

impl<S> LoginRule<S> {
    /// A rule that bypasses session handling entirely. The session store is
    /// not called and the inner proxy sees no session.
    ///
    /// [`Public`](Self::Public) carries no authorization check because there is
    /// no session to inspect. Calling [`check`](Self::check) on it makes proxy
    /// construction fail with `RouteConfigError::PublicRuleWithCheck`.
    pub fn public() -> Self {
        Self::Public {
            method: MethodMatch::Any,
            check_requested: false,
        }
    }

    /// A rule that loads the session if a cookie is present but never gates
    /// the request. The inner proxy can read `ctx.login_state().session` to
    /// personalize the response.
    ///
    /// Chain [`check`](Self::check) to run an authorization check when a
    /// session is present.
    pub fn optional() -> Self {
        Self::Optional {
            check: None,
            method: MethodMatch::Any,
        }
    }

    /// A rule that requires an authenticated session. Unauthenticated
    /// requests are redirected to the authorization server (browser
    /// navigation) or rejected with `401` (XHR).
    ///
    /// Chain [`check`](Self::check) to gate the request further on session
    /// content.
    pub fn required() -> Self {
        Self::Required {
            check: None,
            method: MethodMatch::Any,
        }
    }

    /// Adds a custom authorization check that runs after the session is
    /// loaded. Returning `Err(CheckError)` denies the request.
    ///
    /// Use this for general claim checks — audience, scope, role, org-id
    /// matching — or anything that depends on session content.
    ///
    /// Attaches to [`Optional`](Self::Optional) (where it runs only when a
    /// session is present) and [`Required`](Self::Required). On
    /// [`Public`](Self::Public), proxy construction fails because there is no
    /// session to inspect.
    pub fn check(self, f: impl Fn(&S) -> Result<(), CheckError> + Send + Sync + 'static) -> Self {
        let check: Option<CheckFn<S>> = Some(Arc::new(f));
        match self {
            Self::Public { method, .. } => Self::Public {
                method,
                check_requested: true,
            },
            Self::Optional { method, .. } => Self::Optional { check, method },
            Self::Required { method, .. } => Self::Required { check, method },
        }
    }

    /// Restricts this rule to a single HTTP method.
    ///
    /// By default a rule applies to **any** method. Scope it (e.g. `GET` public, `POST`
    /// protected on the same path) by registering one rule per method. The method axis is
    /// orthogonal to the path — it never affects which *path* matches.
    ///
    /// **Default-deny on the method axis:** registering any method-specific rule on a path
    /// makes every *other* method on that path fall to the default rule. Add a wildcard
    /// rule (no `.method()`) on the same path for a fallback policy; it is **not** inherited
    /// from a broader catch-all.
    ///
    /// The guard authorizes on the **request-line** method. If your backend honors method
    /// override headers (`X-HTTP-Method-Override`, …) or folds `HEAD` into `GET`, strip
    /// those at your edge. A CORS preflight (`OPTIONS`, credential-less) is handled above
    /// this layer.
    pub fn method(self, method: http::Method) -> Self {
        let method = MethodMatch::from(method);
        match self {
            Self::Public {
                check_requested, ..
            } => Self::Public {
                method,
                check_requested,
            },
            Self::Optional { check, .. } => Self::Optional { check, method },
            Self::Required { check, .. } => Self::Required { check, method },
        }
    }

    /// The method qualifier — read by the proxy builder when registering the route.
    pub(crate) fn method_match(&self) -> &MethodMatch {
        match self {
            Self::Public { method, .. }
            | Self::Optional { method, .. }
            | Self::Required { method, .. } => method,
        }
    }

    /// Whether a check was attached to a public rule, which cannot run it.
    pub(crate) fn public_check_requested(&self) -> bool {
        matches!(
            self,
            Self::Public {
                check_requested: true,
                ..
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_rule_has_no_check() {
        let r: LoginRule = LoginRule::public();
        assert!(matches!(r, LoginRule::Public { .. }));
    }

    #[test]
    fn optional_rule_starts_without_check() {
        let r: LoginRule = LoginRule::optional();
        assert!(matches!(r, LoginRule::Optional { check: None, .. }));
    }

    #[test]
    fn required_rule_starts_without_check() {
        let r: LoginRule = LoginRule::required();
        assert!(matches!(r, LoginRule::Required { check: None, .. }));
    }

    #[test]
    fn default_is_required() {
        let r: LoginRule = LoginRule::default();
        assert!(matches!(r, LoginRule::Required { check: None, .. }));
    }

    #[test]
    fn check_attaches_to_required() {
        let r = LoginRule::<String>::required().check(|_| Ok(()));
        assert!(matches!(r, LoginRule::Required { check: Some(_), .. }));
    }

    #[test]
    fn check_attaches_to_optional() {
        let r = LoginRule::<String>::optional().check(|_| Ok(()));
        assert!(matches!(r, LoginRule::Optional { check: Some(_), .. }));
    }

    #[test]
    fn check_on_public_is_recorded_for_build_validation() {
        let r = LoginRule::<String>::public().check(|_| Err(CheckError::Forbidden("nope".into())));
        assert!(r.public_check_requested());
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
        assert!(matches!(r, LoginRule::Required { check: Some(_), .. }));
        if let LoginRule::Required {
            check: Some(check), ..
        } = r
        {
            assert!(check(&1).is_ok());
            assert!(matches!(check(&0), Err(CheckError::Forbidden(_))));
        }
    }
}
