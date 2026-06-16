//! Shared rule-id router and path-confusion guard.
//!
//! Both the resource [`Guard`](crate::resource::Guard) and the login
//! [`LoginProxy`](crate::login::LoginProxy) map request paths to per-path rules and need
//! the same two things:
//!
//! - **Rule identity** — every pattern produced by one `route`/`subtree` call shares a
//!   rule id, so the structural guard reasons at rule granularity (movement *within* a
//!   subtree is not a relocation).
//! - **The structural verdict** — deny a request whose path could be routed differently
//!   by a normalizing backend than the rule the raw path matched.
//!
//! [`RuleRouter`] owns the `id → rule` table, the default rule, and a
//! [`StructuralGuard`](crate::route_tree::StructuralGuard) over the
//! [owned segment-tree router](crate::route_tree). Public matchit-style pattern strings
//! are lowered into the owned grammar at build time; whatever the grammar cannot express
//! (in-segment prefix/suffix params) is a build-time error.

use crate::{
    path_confusion::{CaseSensitivity, PathConfusion, StructuralClasses},
    route_tree::{BuildError, LowerError, MethodMatch, Router, StructuralGuard, lower_matchit},
    structural::{classes_present, enabled_classes, enabled_encodings},
};

/// Rule id used when no route matches (the default rule).
const DEFAULT_RULE_ID: u32 = u32::MAX;

/// Error building a [`RuleRouter`]. Callers map this to their own config error.
#[derive(Debug)]
pub(crate) enum RuleRouterError {
    /// A pattern could not be lowered into the route grammar (e.g. an in-segment
    /// prefix/suffix param, a non-final catch-all, or a conflict with another route).
    Route {
        /// The offending pattern.
        pattern: String,
        /// A human-readable reason.
        reason: &'static str,
    },
    /// A registered pattern is itself non-canonical — it carries a structural byte
    /// (`%2F`, `..`, `//`, `;`, or an enabled opt-in form) that the guard treats as
    /// route structure, so a normalizing backend would never present it canonically.
    NonCanonical {
        /// The offending pattern.
        pattern: String,
    },
    /// A registered pattern contains ASCII uppercase under
    /// [`CaseSensitivity::Insensitive`]. A case-folding backend resolves it to lowercase,
    /// so a differently-cased request could reach it without the matched rule's checks.
    NonCanonicalCase {
        /// The offending pattern.
        pattern: String,
    },
}

/// One registered route entry: `(pattern, rule, rule_id, opaque, method)`. Patterns from
/// one `route`/`subtree` call share a `rule_id`; `opaque` marks a blob catch-all; `method`
/// is the rule's method qualifier.
pub(crate) type RouteEntry<R> = (String, R, u32, bool, MethodMatch);

/// The rule id for the next `route`/`subtree` call: one past the last entry's id
/// (ids are contiguous and monotonic across calls).
pub(crate) fn next_rule_id<R>(entries: &[RouteEntry<R>]) -> u32 {
    entries.last().map_or(0, |(_, _, id, _, _)| id + 1)
}

/// A `path → rule` router with rule-granularity identity and the path-confusion guard.
pub(crate) struct RuleRouter<R> {
    rules: Vec<R>,
    default: R,
    guard: StructuralGuard,
}

impl<R> std::fmt::Debug for RuleRouter<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleRouter")
            .field("rules", &self.rules.len())
            .finish_non_exhaustive()
    }
}

impl<R> RuleRouter<R> {
    /// Builds the router from `(pattern, rule, rule_id)` entries (ids assigned by
    /// [`next_rule_id`]; patterns from one call share an id).
    ///
    /// Runs the build-time canonical-pattern checks unless the guard is `Off`: a pattern
    /// that itself carries an enabled structural byte is rejected
    /// ([`RuleRouterError::NonCanonical`]), and under `case_insensitive` an uppercase
    /// pattern is rejected ([`RuleRouterError::NonCanonicalCase`]). Each pattern is then
    /// lowered into the route grammar; an unrepresentable pattern is a
    /// [`RuleRouterError::Route`].
    pub(crate) fn build(
        entries: Vec<RouteEntry<R>>,
        default: R,
        path_confusion: PathConfusion,
        structural_classes: StructuralClasses,
        case_insensitive: bool,
    ) -> Result<Self, RuleRouterError> {
        let byte_enabled = enabled_classes(&structural_classes);
        let enc = enabled_encodings(&structural_classes);

        let mut tree_entries = Vec::new();
        let mut rules: Vec<R> = Vec::new();
        for (pattern, rule, id, opaque, method) in entries {
            // Build-time canonical-pattern check: a registered pattern that itself carries
            // a structural byte (or, under a case-folding backend, uppercase) is
            // non-canonical — the backend would never present it as written.
            if path_confusion != PathConfusion::Off {
                if !classes_present(&pattern, byte_enabled, enc)
                    .intersect(byte_enabled)
                    .is_empty()
                {
                    return Err(RuleRouterError::NonCanonical { pattern });
                }
                if case_insensitive && pattern.bytes().any(|b| b.is_ascii_uppercase()) {
                    return Err(RuleRouterError::NonCanonicalCase { pattern });
                }
            }

            let lowered = lower_matchit(&pattern).map_err(|e| RuleRouterError::Route {
                pattern: pattern.clone(),
                reason: lower_reason(&e),
            })?;
            // Patterns from one call share an id; push the rule on its first occurrence.
            if id as usize == rules.len() {
                rules.push(rule);
            }
            tree_entries.push((lowered, id, opaque, method));
        }

        let router = Router::build(&tree_entries).map_err(map_build_err)?;
        let case = if case_insensitive {
            CaseSensitivity::Insensitive
        } else {
            CaseSensitivity::Sensitive
        };
        let guard = StructuralGuard::new(router, path_confusion, structural_classes, case);

        Ok(Self {
            rules,
            default,
            guard,
        })
    }

    /// Matches `path`, returning its rule id and rule. Unmatched paths use the default
    /// rule and [`DEFAULT_RULE_ID`].
    pub(crate) fn match_rule(&self, path: &str, method: &http::Method) -> (u32, &R) {
        match self.guard.resolve(path, method) {
            Some(id) => (id, &self.rules[id as usize]),
            None => (DEFAULT_RULE_ID, &self.default),
        }
    }

    /// Path-confusion verdict. Returns `Some(reason)` if `path` should be denied. The
    /// verdict re-routes the path internally, so the caller's matched rule id is not needed.
    pub(crate) fn ambiguous(&self, path: &str) -> Option<&'static str> {
        self.guard.verdict(path)
    }
}

/// Map a lowering failure to a stable, human-readable reason.
fn lower_reason(e: &LowerError) -> &'static str {
    match e {
        LowerError::MissingLeadingSlash => "route pattern must begin with '/'",
        LowerError::EmptyInteriorSegment => "route pattern has an empty path segment",
        LowerError::PrefixSuffixParam => {
            "in-segment prefix/suffix parameters (e.g. /v{ver}) are not supported"
        }
        LowerError::CatchAllNotLast => "a catch-all {*…} must be the final path segment",
        LowerError::MalformedParam => "malformed route parameter",
    }
}

/// Map a route-tree build failure to a [`RuleRouterError`]. With no opaque routes
/// declared, only a terminal conflict is reachable.
fn map_build_err(e: BuildError) -> RuleRouterError {
    let reason = match e {
        BuildError::Conflict => "two routes resolve to the same path",
        BuildError::OpaqueTailHasSibling => {
            "a blob_subtree has a nested route under it; remove the nested route or use subtree"
        }
    };
    RuleRouterError::Route {
        pattern: String::new(),
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path_confusion::StructuralClasses;

    fn router(rows: &[(&str, u32)], pc: PathConfusion) -> Result<RuleRouter<u32>, RuleRouterError> {
        let entries: Vec<(String, u32, u32, bool, MethodMatch)> = rows
            .iter()
            .map(|(p, id)| ((*p).to_owned(), *id, *id, false, MethodMatch::Any))
            .collect();
        RuleRouter::build(entries, u32::MAX, pc, StructuralClasses::new(), false)
    }

    fn denied(r: &RuleRouter<u32>, path: &str) -> bool {
        r.ambiguous(path).is_some()
    }

    #[test]
    fn matches_and_defaults() {
        let r = router(
            &[("/admin", 0), ("/admin/", 0), ("/admin/{*rest}", 0)],
            PathConfusion::RejectStructural,
        )
        .expect("build");
        assert_eq!(r.match_rule("/admin", &http::Method::GET).0, 0);
        assert_eq!(r.match_rule("/admin/x", &http::Method::GET).0, 0);
        assert_eq!(r.match_rule("/nope", &http::Method::GET).0, DEFAULT_RULE_ID);
    }

    #[test]
    fn uniform_live_denies_encoded_slash_in_blob() {
        // Under the uniform-live model, a lone blob denies an encoded slash unless it was
        // declared opaque (which the route/subtree builders do not do).
        let r = router(
            &[("/files", 0), ("/files/", 0), ("/files/{*rest}", 0)],
            PathConfusion::RejectStructural,
        )
        .expect("build");
        assert!(denied(&r, "/files/a%2fb"));
        assert!(denied(&r, "/files/a/../b"));
        assert!(!denied(&r, "/files/clean"));
    }

    #[test]
    fn rejects_prefix_suffix_param() {
        let err = router(&[("/v{ver}", 0)], PathConfusion::RejectStructural)
            .expect_err("prefix param rejected");
        assert!(matches!(err, RuleRouterError::Route { .. }));
    }

    #[test]
    fn rejects_non_canonical_pattern() {
        let err = router(&[("/a/../b", 0)], PathConfusion::RejectStructural)
            .expect_err("non-canonical pattern rejected");
        assert!(matches!(err, RuleRouterError::NonCanonical { .. }));
    }

    #[test]
    fn opaque_blob_tolerates_separator_via_entry_flag() {
        // The `opaque` entry flag (set by the builder's blob_subtree) reaches the tree
        // and tolerates a structural byte in the catch-all tail — but not a dot-segment.
        let entries: Vec<(String, u32, u32, bool, MethodMatch)> = vec![
            ("/files".to_owned(), 0, 0, true, MethodMatch::Any),
            ("/files/".to_owned(), 0, 0, true, MethodMatch::Any),
            ("/files/{*rest}".to_owned(), 0, 0, true, MethodMatch::Any),
        ];
        let r = RuleRouter::build(
            entries,
            u32::MAX,
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            false,
        )
        .expect("build");
        assert!(!denied(&r, "/files/a%2fb"));
        assert!(denied(&r, "/files/a/../b"));
    }

    #[test]
    fn opaque_blob_with_sibling_is_build_error() {
        let entries: Vec<(String, u32, u32, bool, MethodMatch)> = vec![
            ("/files".to_owned(), 0, 0, true, MethodMatch::Any),
            ("/files/".to_owned(), 0, 0, true, MethodMatch::Any),
            ("/files/{*rest}".to_owned(), 0, 0, true, MethodMatch::Any),
            ("/files/secret".to_owned(), 1, 1, false, MethodMatch::Any),
        ];
        let err = RuleRouter::build(
            entries,
            u32::MAX,
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            false,
        )
        .expect_err("opaque blob with sibling");
        assert!(matches!(err, RuleRouterError::Route { .. }));
    }
}
