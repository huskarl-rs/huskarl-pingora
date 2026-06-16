//! Owned route grammar + segment-tree matcher.
//!
//! This is the keystone of the path-confusion redesign: a matcher we **own**, so the
//! structural/liveness analysis can read the route structure directly instead of
//! reverse-engineering `matchit`'s opaque parse tree. The grammar is a deliberately
//! small, whole-segment, anonymous subset of `matchit` syntax:
//!
//! - a segment is a **literal** (matched byte-for-byte) or a lone `*` **wildcard**;
//! - `*` matches exactly one non-empty segment, **except** the final `*` in a pattern,
//!   which is a **catch-all** matching the raw remainder (1+ chars, `//` and trailing
//!   slashes included — `matchit` catch-all semantics);
//! - a literal `*` is written by doubling: a segment of `k >= 2` stars is the literal
//!   string of `k - 1` stars (`**` → `*`, `***` → `**`);
//! - a trailing `/` is significant (`/a` and `/a/` are distinct routes, as in `matchit`).
//!
//! Capturing is anonymous — the auth layer never reads captured values, only *which
//! rule* matched and *where* the wildcard/catch-all bytes fell (for the liveness pass).
//!
//! `matchit` is retained **only as a test oracle** (see the proptest below): the runtime
//! matcher has no external dependency. "Lowering equivalence" now lives entirely in the
//! tests — for every pattern in this grammar, the owned matcher must agree with `matchit`
//! on the pattern's lowered form.

use std::{collections::HashMap, sync::Arc};

use crate::{
    path_confusion::{CaseSensitivity, PathConfusion, StructuralClasses, StructuralProbe},
    structural::{ClassSet, Encodings, classes_present, enabled_classes, enabled_encodings},
};

/// Identifier for a registered rule. Patterns from one `route`/`subtree` call share one.
pub(crate) type RuleId = u32;

/// One segment of a parsed pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Segment {
    /// A literal segment, already unescaped; matched byte-for-byte.
    Literal(String),
    /// A `*` in a non-final position: matches exactly one non-empty segment.
    Wildcard,
    /// A `*` in the final position: matches the raw remainder (1+ chars).
    CatchAll,
}

/// A parsed pattern: its segments plus whether it ends in a significant trailing slash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Pattern {
    pub(crate) segments: Vec<Segment>,
    pub(crate) trailing_slash: bool,
}

/// Why a pattern string is not a valid route in this grammar.
///
/// Test-only: production lowers public matchit syntax via [`lower_matchit`]; the native
/// `*`-grammar parser ([`parse_pattern`]) is exercised only by the unit tests and oracle.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PatternError {
    /// The pattern did not begin with `/`.
    MissingLeadingSlash,
    /// An interior `//` (an empty, non-trailing segment) — degenerate.
    EmptyInteriorSegment,
}

/// Why a public matchit-style pattern could not be lowered into this grammar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LowerError {
    /// The pattern did not begin with `/`.
    MissingLeadingSlash,
    /// An interior `//` (an empty, non-trailing segment).
    EmptyInteriorSegment,
    /// A param with a static prefix or suffix in its segment (`/v{ver}`,
    /// `/img-{id}.png`). The whole-segment grammar cannot express these.
    PrefixSuffixParam,
    /// A catch-all `{*rest}` that is not the final segment.
    CatchAllNotLast,
    /// A malformed parameter group (stray or unterminated brace).
    MalformedParam,
}

/// Classify one segment's text into a [`Segment`], applying the star-doubling escape.
#[cfg(test)]
fn classify_segment(seg: &str) -> Segment {
    if !seg.is_empty() && seg.bytes().all(|b| b == b'*') {
        if seg.len() == 1 {
            Segment::Wildcard
        } else {
            // `k >= 2` stars → the literal string of `k - 1` stars.
            Segment::Literal("*".repeat(seg.len() - 1))
        }
    } else {
        Segment::Literal(seg.to_owned())
    }
}

/// Parse a pattern string into a [`Pattern`].
///
/// # Errors
///
/// [`PatternError`] if the pattern lacks a leading slash or contains an interior empty
/// segment.
#[cfg(test)]
pub(crate) fn parse_pattern(pat: &str) -> Result<Pattern, PatternError> {
    if !pat.starts_with('/') {
        return Err(PatternError::MissingLeadingSlash);
    }
    let trailing_slash = pat.len() > 1 && pat.ends_with('/');
    // Body: drop the leading slash and the single significant trailing slash.
    let end = pat.len() - usize::from(trailing_slash);
    let body = &pat[1..end];

    let mut segments = Vec::new();
    if !body.is_empty() {
        for seg in body.split('/') {
            if seg.is_empty() {
                return Err(PatternError::EmptyInteriorSegment);
            }
            segments.push(classify_segment(seg));
        }
    }
    // Positional arity: the final lone `*` (with no significant trailing slash) is the
    // catch-all; interior `*` stay single-segment wildcards.
    if !trailing_slash && matches!(segments.last(), Some(Segment::Wildcard)) {
        let last = segments.len() - 1;
        segments[last] = Segment::CatchAll;
    }
    Ok(Pattern {
        segments,
        trailing_slash,
    })
}

/// Lower a public **matchit-style** pattern string (`/users/{id}`, `/files/{*rest}`)
/// into an owned [`Pattern`]: `{name}` → [`Segment::Wildcard`], `{*name}` →
/// [`Segment::CatchAll`], static text → [`Segment::Literal`] (braces unescaped).
///
/// This is the build-time bridge from the public API's familiar `{name}` syntax to the
/// anonymous whole-segment grammar; the names are discarded (the auth layer never reads
/// captured values).
///
/// # Errors
///
/// [`LowerError`] for a missing leading slash, an empty interior segment, a non-final
/// catch-all, a malformed param, or a **prefix/suffix param** (`/v{ver}`) — which the
/// whole-segment grammar cannot represent.
pub(crate) fn lower_matchit(pat: &str) -> Result<Pattern, LowerError> {
    if !pat.starts_with('/') {
        return Err(LowerError::MissingLeadingSlash);
    }
    let trailing_slash = pat.len() > 1 && pat.ends_with('/');
    let end = pat.len() - usize::from(trailing_slash);
    let body = &pat[1..end];

    let mut segments = Vec::new();
    if !body.is_empty() {
        let parts: Vec<&str> = body.split('/').collect();
        let last = parts.len() - 1;
        for (idx, seg) in parts.iter().enumerate() {
            if seg.is_empty() {
                return Err(LowerError::EmptyInteriorSegment);
            }
            match lower_segment(seg)? {
                SegLower::Literal(s) => segments.push(Segment::Literal(s)),
                SegLower::Wildcard => segments.push(Segment::Wildcard),
                SegLower::CatchAll => {
                    if idx != last {
                        return Err(LowerError::CatchAllNotLast);
                    }
                    segments.push(Segment::CatchAll);
                }
            }
        }
    }
    Ok(Pattern {
        segments,
        trailing_slash,
    })
}

/// The lowering of a single matchit segment.
enum SegLower {
    Literal(String),
    Wildcard,
    CatchAll,
}

/// Lower one matchit segment. A segment is static, or a single `{…}` spanning the whole
/// segment; a `{…}` with surrounding static text is a prefix/suffix param and rejected.
fn lower_segment(seg: &str) -> Result<SegLower, LowerError> {
    let b = seg.as_bytes();
    let mut i = 0;
    // First *unescaped* `{` begins a parameter; `{{`/`}}` are literal braces.
    let open = loop {
        match b.get(i) {
            None => return Ok(SegLower::Literal(unescape_braces(seg))), // fully static
            Some(b'{') if b.get(i + 1) == Some(&b'{') => i += 2,
            Some(b'}') if b.get(i + 1) == Some(&b'}') => i += 2,
            Some(b'{') => break i,
            Some(b'}') => return Err(LowerError::MalformedParam), // stray unescaped `}`
            Some(_) => i += 1,
        }
    };
    // Param names contain no braces, so the next `}` closes the group.
    let close = open
        + 1
        + b[open + 1..]
            .iter()
            .position(|&c| c == b'}')
            .ok_or(LowerError::MalformedParam)?;
    // A whole-segment param spans the entire segment; anything else is prefix/suffix.
    if open != 0 || close != b.len() - 1 {
        return Err(LowerError::PrefixSuffixParam);
    }
    let inner = &seg[open + 1..close];
    if inner.starts_with('*') {
        Ok(SegLower::CatchAll)
    } else {
        Ok(SegLower::Wildcard)
    }
}

/// Unescape matchit's doubled braces (`{{` → `{`, `}}` → `}`) so a literal segment
/// matches the request path byte-for-byte.
fn unescape_braces(s: &str) -> String {
    if !s.contains("{{") && !s.contains("}}") {
        return s.to_owned();
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        out.push(b[i]);
        i += usize::from(
            (b[i] == b'{' && b.get(i + 1) == Some(&b'{'))
                || (b[i] == b'}' && b.get(i + 1) == Some(&b'}')),
        ) + 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_owned())
}

/// Which HTTP method(s) a registration applies to. `Any` (the default) matches every
/// method; `Only` matches one. Method is **orthogonal to path**: it is consulted solely
/// at terminal resolution, never during path traversal or the structural verdict.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum MethodMatch {
    /// Matches any method (the wildcard default).
    #[default]
    Any,
    /// Matches exactly this method.
    Only(http::Method),
}

/// The rules terminating at one path position, keyed by method. A path can carry a
/// method-wildcard rule and any number of method-specific ones; resolution is
/// specific-method → wildcard → none.
#[derive(Default)]
struct MethodSlot {
    /// The method-wildcard rule, if any.
    any: Option<RuleId>,
    /// Method-specific rules.
    exact: Vec<(http::Method, RuleId)>,
}

impl MethodSlot {
    fn is_empty(&self) -> bool {
        self.any.is_none() && self.exact.is_empty()
    }

    /// Resolve a rule. `None` (method-blind) returns a stable **representative** — used
    /// by the structural guard and content-decode, which compare path zones, not
    /// methods. `Some(m)` resolves specific-method → wildcard.
    fn get(&self, method: Option<&http::Method>) -> Option<RuleId> {
        match method {
            None => self.any.or_else(|| self.exact.first().map(|(_, id)| *id)),
            Some(m) => self
                .exact
                .iter()
                .find(|(em, _)| em == m)
                .map(|(_, id)| *id)
                .or(self.any),
        }
    }

    /// Insert a rule for `method`; a duplicate `(position, method)` is a [`BuildError::Conflict`].
    fn insert(&mut self, method: &MethodMatch, id: RuleId) -> Result<(), BuildError> {
        match method {
            MethodMatch::Any => {
                if self.any.is_some() {
                    return Err(BuildError::Conflict);
                }
                self.any = Some(id);
            }
            MethodMatch::Only(m) => {
                if self.exact.iter().any(|(em, _)| em == m) {
                    return Err(BuildError::Conflict);
                }
                self.exact.push((m.clone(), id));
            }
        }
        Ok(())
    }
}

/// A node in the route tree. Structural bytes only ever land in a wildcard/catch-all
/// position (literals match canonical pattern bytes), so the liveness pass annotates
/// *these* nodes — the payoff of owning the matcher.
#[derive(Default)]
struct Node {
    /// Exact-segment children.
    literals: HashMap<String, Node>,
    /// The single `*` child at this depth, if any.
    wildcard: Option<Box<Node>>,
    /// Rules (no trailing slash) terminating here, keyed by method.
    leaf: MethodSlot,
    /// Rules *with* a trailing slash terminating here, keyed by method.
    leaf_slash: MethodSlot,
    /// Trailing catch-all rules rooted here, keyed by method.
    catchall: MethodSlot,
    /// Whether the catch-all was declared opaque (validated sibling-free at build). A
    /// path property, uniform across methods.
    catchall_opaque: bool,
}

/// Why building a [`Router`] failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BuildError {
    /// Two rules claim the same terminal slot.
    Conflict,
    /// An opaque catch-all shares its node with a routing sibling (a literal or wildcard
    /// child), so a boundary-shift byte in the blob could relocate into the sibling.
    OpaqueTailHasSibling,
}

/// A `path -> RuleId` matcher over the owned grammar.
pub(crate) struct Router {
    root: Node,
}

impl Router {
    /// Build a router from `(pattern, rule_id, opaque)` entries.
    ///
    /// `opaque` declares a pattern's trailing catch-all an opaque blob (boundary-shift
    /// bytes in its tail are tolerated by the liveness pass); it is ignored for patterns
    /// without a catch-all.
    ///
    /// # Errors
    ///
    /// [`BuildError`] on a terminal conflict or an opaque catch-all with a routing sibling.
    pub(crate) fn build(
        entries: &[(Pattern, RuleId, bool, MethodMatch)],
    ) -> Result<Self, BuildError> {
        let mut root = Node::default();
        for (pat, id, opaque, method) in entries {
            insert(
                &mut root,
                &pat.segments,
                pat.trailing_slash,
                *id,
                *opaque,
                method,
            )?;
        }
        validate_opaque(&root)?;
        Ok(Self { root })
    }

    /// Match `path`, then resolve the claimed terminal with `method` (`None` = method-blind
    /// representative). A path that claims a terminal but has no rule for `method` returns
    /// `None` — never a fall-back to a less-specific path.
    fn at(&self, path: &str, method: Option<&http::Method>) -> Option<Match> {
        let body = path.strip_prefix('/')?;
        let matched = if body.is_empty() {
            // The bare root path `/` claims the root leaf.
            (!self.root.leaf.is_empty()).then(|| Matched {
                slot: &self.root.leaf,
                caps: Vec::new(),
            })
        } else {
            route(&self.root, body, 1)
        }?;
        // Method resolution happens once, on the claimed terminal — no backtracking.
        let id = matched.slot.get(method)?;
        Some(Match {
            id,
            caps: matched.caps,
        })
    }

    /// The matched rule id, **method-blind** (a stable per-terminal representative) — for
    /// content-decode and the oracle, which compare path zones rather than methods.
    pub(crate) fn route_id(&self, path: &str) -> Option<RuleId> {
        self.at(path, None).map(|m| m.id)
    }

    /// The matched rule id for a specific method (specific → wildcard → none).
    pub(crate) fn resolve(&self, path: &str, method: &http::Method) -> Option<RuleId> {
        self.at(path, Some(method)).map(|m| m.id)
    }

    /// The byte span of the matched rule's catch-all **iff** it is opaque. Method-blind:
    /// blob-ness is a path property. `None` for a non-opaque match, a wildcard-only
    /// match, the default (no match), or the root.
    pub(crate) fn opaque_span(&self, path: &str) -> Option<(usize, usize)> {
        self.at(path, None)?
            .caps
            .into_iter()
            .find_map(|c| match c.kind {
                CapKind::CatchAll { opaque: true } => Some((c.start, c.end)),
                _ => None,
            })
    }

    /// Whether any rule in the table declared an opaque catch-all. When false, the
    /// structural verdict never walks the tree (any structural byte denies outright).
    pub(crate) fn has_opaque(&self) -> bool {
        any_opaque(&self.root)
    }
}

/// Whether `node` or any descendant carries an opaque catch-all.
fn any_opaque(node: &Node) -> bool {
    node.catchall_opaque
        || node.literals.values().any(any_opaque)
        || node.wildcard.as_deref().is_some_and(any_opaque)
}

/// Recursive insert. `matchit`-style catch-all is always the final segment (guaranteed
/// by `parse_pattern` / `lower_matchit`), so its `rest` is empty.
fn insert(
    node: &mut Node,
    segs: &[Segment],
    trailing_slash: bool,
    id: RuleId,
    opaque: bool,
    method: &MethodMatch,
) -> Result<(), BuildError> {
    match segs.split_first() {
        None => {
            let slot = if trailing_slash {
                &mut node.leaf_slash
            } else {
                &mut node.leaf
            };
            slot.insert(method, id)
        }
        Some((Segment::Literal(s), rest)) => insert(
            node.literals.entry(s.clone()).or_default(),
            rest,
            trailing_slash,
            id,
            opaque,
            method,
        ),
        Some((Segment::Wildcard, rest)) => insert(
            node.wildcard.get_or_insert_with(Box::default),
            rest,
            trailing_slash,
            id,
            opaque,
            method,
        ),
        Some((Segment::CatchAll, _rest)) => {
            node.catchall.insert(method, id)?;
            // Blob-ness is a path property: opaque if any registration declares it.
            node.catchall_opaque |= opaque;
            Ok(())
        }
    }
}

/// Reject an opaque catch-all that shares its node with a routing sibling: a
/// boundary-shift byte in the blob could then relocate into that sibling. This is the
/// "surprise-live" footgun, promoted from a debug lint to a hard, fail-closed error on
/// an explicit opt-in.
fn validate_opaque(node: &Node) -> Result<(), BuildError> {
    if !node.catchall.is_empty()
        && node.catchall_opaque
        && (!node.literals.is_empty() || node.wildcard.is_some())
    {
        return Err(BuildError::OpaqueTailHasSibling);
    }
    for child in node.literals.values() {
        validate_opaque(child)?;
    }
    if let Some(w) = &node.wildcard {
        validate_opaque(w)?;
    }
    Ok(())
}

/// What a recovered capture is — drives the opaque-span exemption in the liveness pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CapKind {
    /// A single-segment `*`.
    Wildcard,
    /// A trailing catch-all, carrying whether it was declared opaque.
    CatchAll { opaque: bool },
}

/// A recovered capture: its byte span in the request path and its kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Capture {
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) kind: CapKind,
}

/// The result of a match: the rule and the capture spans, in pattern order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Match {
    pub(crate) id: RuleId,
    pub(crate) caps: Vec<Capture>,
}

/// Match `s` (a non-empty path body, offset `off` bytes into the full path) against
/// `node`. Precedence is literal > wildcard > catch-all, **with backtracking**: a
/// higher-priority branch that dead-ends falls through to the next.
/// The terminal a path **claims**, found method-blind: its method-slot (resolved later)
/// and the recovered capture spans.
struct Matched<'a> {
    slot: &'a MethodSlot,
    caps: Vec<Capture>,
}

/// Find the terminal `s` claims under `node`. Traversal is **method-blind** — a position
/// is "matched" iff *some* rule terminates there (`!slot.is_empty()`), so method never
/// drives path backtracking. Precedence is literal > wildcard > catch-all, with
/// backtracking on genuine *path* dead-ends.
fn route<'a>(node: &'a Node, s: &str, off: usize) -> Option<Matched<'a>> {
    let (seg, after) = match s.find('/') {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    };
    let seg_start = off;
    let seg_end = off + seg.len();

    // 1. literal child — highest priority.
    if let Some(child) = node.literals.get(seg)
        && let Some(m) = descend(child, after, seg_end)
    {
        return Some(m);
    }
    // 2. single-segment wildcard — requires a non-empty segment.
    if !seg.is_empty()
        && let Some(child) = node.wildcard.as_deref()
        && let Some(mut m) = descend(child, after, seg_end)
    {
        m.caps.insert(
            0,
            Capture {
                start: seg_start,
                end: seg_end,
                kind: CapKind::Wildcard,
            },
        );
        return Some(m);
    }
    // 3. catch-all — lowest priority; consumes the whole raw remainder `s` (>= 1 char).
    if !node.catchall.is_empty() {
        return Some(Matched {
            slot: &node.catchall,
            caps: vec![Capture {
                start: off,
                end: off + s.len(),
                kind: CapKind::CatchAll {
                    opaque: node.catchall_opaque,
                },
            }],
        });
    }
    None
}

/// After matching a segment against `child`, either terminate (leaf / leaf-with-trailing-
/// slash, by method-blind presence) or recurse on the remaining body.
fn descend<'a>(child: &'a Node, after: Option<&str>, seg_end: usize) -> Option<Matched<'a>> {
    match after {
        // No `/` followed the segment: path ended here → a leaf match.
        None => (!child.leaf.is_empty()).then(|| Matched {
            slot: &child.leaf,
            caps: Vec::new(),
        }),
        // A `/` followed, with nothing after it: a trailing-slash match.
        Some("") => (!child.leaf_slash.is_empty()).then(|| Matched {
            slot: &child.leaf_slash,
            caps: Vec::new(),
        }),
        // More path remains after the `/`.
        Some(rest) => route(child, rest, seg_end + 1),
    }
}

/// Length cap for a *suspicious* path: once a structural byte is flagged, a path over
/// this length is denied. Clean paths bypass it (they cannot be ambiguous). Defense in
/// depth — Pingora bounds the request line well below this.
const MAX_PATH_LEN: usize = 8192;

/// The runtime path-confusion verdict, driven by the owned [`Router`].
///
/// This is the liveness runtime built on the **uniform-live** model: every wildcard /
/// catch-all position is live (any enabled structural byte there denies), *except* a
/// catch-all explicitly declared opaque, which tolerates boundary-shift bytes (`/`, `;`,
/// `\`) inside its span — but never dot-segment, truncation, or case. Because registered
/// patterns are canonical, any structural byte in a matched path necessarily falls in a
/// capture, so the no-opaque case needs no tree walk at all.
///
/// Two checks compose, mirroring the existing guard: the **positional** verdict above and
/// a **content-decode** verdict that decodes the path, re-routes it through the same
/// [`Router`], and denies a relocation onto a different rule (`/%61dmin` → `/admin`).
///
/// Not yet ported from the legacy `RuleRouter` (deferred to integration): custom
/// break-glass probes, and the build-time non-canonical-pattern / uppercase-pattern
/// rejection.
pub(crate) struct StructuralGuard {
    router: Router,
    mode: PathConfusion,
    /// Byte classes that deny, derived from the configured classes plus (when the backend
    /// folds case) [`ClassSet::CASE`].
    enabled: ClassSet,
    /// Which alternate encodings the scanner recognises.
    enc: Encodings,
    /// Whether the backend folds ASCII case (drives the content-decode lowercasing).
    case_insensitive: bool,
    /// Whether any rule declared an opaque catch-all (else the positional check never
    /// walks the tree).
    has_opaque: bool,
    /// Custom break-glass probes — a structural form the built-in alphabet doesn't ship,
    /// denied on whole-path presence.
    probes: Vec<Arc<dyn StructuralProbe>>,
}

impl StructuralGuard {
    /// Build a guard over `router` for the given mode and structural configuration.
    pub(crate) fn new(
        router: Router,
        mode: PathConfusion,
        classes: StructuralClasses,
        case: CaseSensitivity,
    ) -> Self {
        let mut enabled = enabled_classes(&classes);
        if case.is_insensitive() {
            enabled.insert(ClassSet::CASE);
        }
        let has_opaque = router.has_opaque();
        Self {
            router,
            mode,
            enabled,
            enc: enabled_encodings(&classes),
            case_insensitive: case.is_insensitive(),
            has_opaque,
            probes: classes.probes,
        }
    }

    /// The deny reason for `path`, or `None` to allow — the message-returning core used
    /// by the router. Mirrors the legacy guard's static reason strings.
    pub(crate) fn verdict(&self, path: &str) -> Option<&'static str> {
        match self.mode {
            PathConfusion::Off => None,
            PathConfusion::RejectStructural => self
                .positional_deny(path)
                .or_else(|| self.content_decode_deny(path))
                .or_else(|| self.custom_probe_deny(path)),
            // Strict: every position live (opaque ignored) and any percent-escape is
            // itself non-canonical.
            PathConfusion::RejectNonCanonical => self
                .noncanonical_deny(path)
                .or_else(|| escape_present(path).then_some("Non-canonical request path"))
                .or_else(|| self.custom_probe_deny(path)),
        }
    }

    /// Break-glass verdict: deny if any registered custom probe recognises its form
    /// anywhere in `path`. A no-op (one `is_empty`) when no probe is registered.
    fn custom_probe_deny(&self, path: &str) -> Option<&'static str> {
        if self.probes.is_empty() || !self.probes.iter().any(|p| p.matches(path)) {
            return None;
        }
        if path.len() > MAX_PATH_LEN {
            Some("Request path too long")
        } else {
            Some("Ambiguous request path")
        }
    }

    /// Whether `path` must be denied — `verdict(path).is_some()`. Test-only: production
    /// calls `verdict` directly (it needs the deny *reason*, not just the boolean).
    #[cfg(test)]
    pub(crate) fn ambiguous(&self, path: &str) -> bool {
        self.verdict(path).is_some()
    }

    /// The method-resolved rule id — for the router's `match_rule`.
    pub(crate) fn resolve(&self, path: &str, method: &http::Method) -> Option<RuleId> {
        self.router.resolve(path, method)
    }

    /// Positional verdict for [`PathConfusion::RejectStructural`] (uniform-live + opaque
    /// exemption). A clean path (no enabled structural byte) is the fast path and never
    /// walks the tree.
    fn positional_deny(&self, path: &str) -> Option<&'static str> {
        let present = classes_present(path, self.enabled, self.enc).intersect(self.enabled);
        if present.is_empty() {
            return None;
        }
        if path.len() > MAX_PATH_LEN {
            return Some("Request path too long");
        }
        if !self.has_opaque {
            // No opaque routes: every structural byte denies, no routing needed.
            return Some("Ambiguous request path");
        }
        // dot-segment / truncation / case deny anywhere — even inside an opaque blob.
        let uniform = ClassSet::DOT_SEGMENT | ClassSet::TRUNCATION | ClassSet::CASE;
        match self.router.opaque_span(path) {
            None => Some("Ambiguous request path"), // matched a non-opaque rule, or the default
            Some((start, end)) => {
                if !present.intersect(uniform).is_empty() {
                    return Some("Ambiguous request path");
                }
                // Boundary-shift bytes deny only *outside* the opaque span.
                let outside = classes_present(&blank(path, start, end), self.enabled, self.enc)
                    .intersect(self.enabled)
                    .intersect(ClassSet::BOUNDARY_SHIFT);
                if outside.is_empty() {
                    None
                } else {
                    Some("Ambiguous request path")
                }
            }
        }
    }

    /// Positional verdict for [`PathConfusion::RejectNonCanonical`]: every position live,
    /// opaque declarations ignored, so any enabled structural byte denies.
    fn noncanonical_deny(&self, path: &str) -> Option<&'static str> {
        let present = classes_present(path, self.enabled, self.enc).intersect(self.enabled);
        if present.is_empty() {
            return None;
        }
        if path.len() > MAX_PATH_LEN {
            return Some("Request path too long");
        }
        Some("Non-canonical request path")
    }

    /// Content-decode verdict: model a backend percent-decoding the path and deny if that
    /// **relocates** it to a different rule than the raw path matched. Precise — a decode
    /// that lands on the same rule (`/foo%20bar`) is allowed, so opaque content flows.
    fn content_decode_deny(&self, path: &str) -> Option<&'static str> {
        if !path.contains('%') {
            return None;
        }
        if path.len() > MAX_PATH_LEN {
            return Some("Request path too long");
        }
        let passes = if self.enc.double_decode { 2 } else { 1 };
        let mut decoded = path.to_owned();
        for _ in 0..passes {
            let Some(next) = percent_decode_once(&decoded) else {
                return None; // undecodable (e.g. raw overlong) — not a modeled relocation
            };
            decoded = next;
        }
        if self.case_insensitive {
            decoded.make_ascii_lowercase();
        }
        if decoded == path {
            return None; // decoding changed nothing routable
        }
        (self.router.route_id(&decoded) != self.router.route_id(path))
            .then_some("Ambiguous request path")
    }
}

/// Blank a byte span to a non-structural filler, so only bytes *outside* it are judged.
///
/// A `//` may straddle the span boundary: the catch-all can capture a remainder that
/// itself begins with `/` (e.g. `/files//x` against `/files/*` captures `/x`), so the
/// byte just inside `start` is sometimes a slash whose partner sits just outside. Blanking
/// the inside slash breaks that `//`, which is sound here: a `//` at the span's leading
/// edge collapses (under slash-merging) to the single separator the router already used to
/// reach the catch-all, so it never relocates *out* of the opaque rule. Every other `//`
/// lies wholly inside the span (tolerated) or wholly outside (still seen).
fn blank(path: &str, start: usize, end: usize) -> String {
    let mut bytes = path.as_bytes().to_vec();
    if let Some(slice) = bytes.get_mut(start..end) {
        slice.fill(b'a');
    }
    String::from_utf8(bytes).unwrap_or_else(|_| path.to_owned())
}

/// Whether `path` carries any complete `%XX` escape — the [`PathConfusion::RejectNonCanonical`]
/// "any escape is non-canonical" rule.
fn escape_present(path: &str) -> bool {
    let b = path.as_bytes();
    (0..b.len()).any(|i| crate::percent::byte_at(b, i).is_some())
}

/// Percent-decode every complete `%XX` escape once (one pass: `%252F` → `%2F`). `None`
/// if the decoded bytes are not valid UTF-8. Borrows-then-owns; only the `%` path allocates.
fn percent_decode_once(path: &str) -> Option<String> {
    if !path.contains('%') {
        return Some(path.to_owned());
    }
    let b = path.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if let Some(byte) = crate::percent::byte_at(b, i) {
            out.push(byte);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    // Test-only conveniences: small rule-id casts, by-value helpers, and a wide config
    // struct don't warrant the production-grade pedantic lints.
    #![allow(
        clippy::cast_possible_truncation,
        clippy::needless_pass_by_value,
        clippy::struct_excessive_bools
    )]

    use super::*;

    /// Lower a [`Pattern`] to the equivalent `matchit` pattern string (oracle side only).
    /// Literal braces are escaped; wildcards get unique synthetic names.
    fn lower(p: &Pattern) -> String {
        let mut s = String::new();
        for (i, seg) in p.segments.iter().enumerate() {
            s.push('/');
            match seg {
                Segment::Literal(t) => s.push_str(&t.replace('{', "{{").replace('}', "}}")),
                Segment::Wildcard => {
                    s.push_str("{w");
                    s.push_str(&i.to_string());
                    s.push('}');
                }
                Segment::CatchAll => s.push_str("{*rest}"),
            }
        }
        if p.trailing_slash {
            s.push('/');
        }
        if s.is_empty() {
            s.push('/');
        }
        s
    }

    fn router(rows: &[(&str, RuleId)]) -> Router {
        let entries: Vec<_> = rows
            .iter()
            .map(|(p, id)| {
                (
                    parse_pattern(p).expect("parse"),
                    *id,
                    false,
                    MethodMatch::Any,
                )
            })
            .collect();
        Router::build(&entries).expect("build")
    }

    // ── parsing ──────────────────────────────────────────────────────────────

    #[test]
    fn parse_basic_shapes() {
        assert_eq!(parse_pattern("/").expect("root").segments, vec![]);
        assert_eq!(
            parse_pattern("/admin").expect("lit").segments,
            vec![Segment::Literal("admin".into())]
        );
        assert_eq!(
            parse_pattern("/a/*/b").expect("interior wildcard").segments,
            vec![
                Segment::Literal("a".into()),
                Segment::Wildcard,
                Segment::Literal("b".into())
            ]
        );
        // The final `*` is a catch-all, not a single-segment wildcard.
        assert_eq!(
            parse_pattern("/files/*").expect("catchall").segments,
            vec![Segment::Literal("files".into()), Segment::CatchAll]
        );
        // Bare root catch-all.
        assert_eq!(
            parse_pattern("/*").expect("root catchall").segments,
            vec![Segment::CatchAll]
        );
    }

    #[test]
    fn parse_star_escaping() {
        // `**` → literal `*`, `***` → literal `**`.
        assert_eq!(
            parse_pattern("/**").expect("escaped").segments,
            vec![Segment::Literal("*".into())]
        );
        assert_eq!(
            parse_pattern("/***").expect("escaped").segments,
            vec![Segment::Literal("**".into())]
        );
        // A `*` inside a mixed segment is a literal byte, not a wildcard.
        assert_eq!(
            parse_pattern("/v*").expect("mixed").segments,
            vec![Segment::Literal("v*".into())]
        );
    }

    #[test]
    fn parse_trailing_slash_is_significant() {
        let a = parse_pattern("/admin").expect("a");
        let b = parse_pattern("/admin/").expect("b");
        assert!(!a.trailing_slash);
        assert!(b.trailing_slash);
        assert_eq!(a.segments, b.segments);
    }

    #[test]
    fn parse_rejects_bad_patterns() {
        assert_eq!(
            parse_pattern("no-slash"),
            Err(PatternError::MissingLeadingSlash)
        );
        assert_eq!(
            parse_pattern("/a//b"),
            Err(PatternError::EmptyInteriorSegment)
        );
    }

    // ── matchit-syntax lowering (the public-API bridge) ───────────────────────

    #[test]
    fn lower_matchit_maps_params() {
        assert_eq!(lower_matchit("/").expect("root").segments, vec![]);
        // Trailing single-segment param stays a single-segment Wildcard (not a catch-all).
        assert_eq!(
            lower_matchit("/users/{id}").expect("param").segments,
            vec![Segment::Literal("users".into()), Segment::Wildcard]
        );
        assert_eq!(
            lower_matchit("/files/{*rest}").expect("catchall").segments,
            vec![Segment::Literal("files".into()), Segment::CatchAll]
        );
        assert_eq!(
            lower_matchit("/a/{x}/b").expect("interior").segments,
            vec![
                Segment::Literal("a".into()),
                Segment::Wildcard,
                Segment::Literal("b".into())
            ]
        );
        // Escaped braces are a literal segment.
        assert_eq!(
            lower_matchit("/{{cfg}}").expect("escaped").segments,
            vec![Segment::Literal("{cfg}".into())]
        );
    }

    #[test]
    fn lower_matchit_rejects_unrepresentable() {
        // Prefix/suffix params — the dropped feature.
        assert_eq!(lower_matchit("/v{ver}"), Err(LowerError::PrefixSuffixParam));
        assert_eq!(
            lower_matchit("/img-{id}.png"),
            Err(LowerError::PrefixSuffixParam)
        );
        // Catch-all must be final.
        assert_eq!(
            lower_matchit("/files/{*rest}/x"),
            Err(LowerError::CatchAllNotLast)
        );
        assert_eq!(
            lower_matchit("no-slash"),
            Err(LowerError::MissingLeadingSlash)
        );
        assert_eq!(
            lower_matchit("/a//b"),
            Err(LowerError::EmptyInteriorSegment)
        );
    }

    // ── build gates ──────────────────────────────────────────────────────────

    #[test]
    fn build_rejects_terminal_conflict() {
        let entries = vec![
            (parse_pattern("/a").expect("p"), 0, false, MethodMatch::Any),
            (parse_pattern("/a").expect("p"), 1, false, MethodMatch::Any),
        ];
        assert!(matches!(Router::build(&entries), Err(BuildError::Conflict)));
    }

    #[test]
    fn build_rejects_opaque_with_sibling() {
        let entries = vec![
            (
                parse_pattern("/files/*").expect("blob"),
                0,
                true,
                MethodMatch::Any,
            ),
            (
                parse_pattern("/files/secret").expect("sib"),
                1,
                false,
                MethodMatch::Any,
            ),
        ];
        assert!(matches!(
            Router::build(&entries),
            Err(BuildError::OpaqueTailHasSibling)
        ));
    }

    #[test]
    fn build_accepts_lone_opaque_blob() {
        let entries = vec![(
            parse_pattern("/files/*").expect("blob"),
            0,
            true,
            MethodMatch::Any,
        )];
        let r = Router::build(&entries).expect("lone opaque builds");
        // "/files/a/b": catch-all span is the raw tail "a/b" at bytes 7..10.
        assert_eq!(r.opaque_span("/files/a/b"), Some((7, 10)));
        // A non-opaque blob yields no opaque span.
        let plain = router(&[("/files/*", 0)]);
        assert_eq!(plain.opaque_span("/files/a/b"), None);
    }

    // ── matching: precedence + backtracking (the load-bearing behavior) ───────

    #[test]
    fn literal_beats_wildcard_and_catchall() {
        let r = router(&[("/files/secret", 0), ("/files/*", 1)]);
        assert_eq!(r.route_id("/files/secret"), Some(0)); // literal wins
        assert_eq!(r.route_id("/files/other"), Some(1)); // catch-all fallback
        assert_eq!(r.route_id("/files/x/y"), Some(1)); // catch-all spans segments
    }

    #[test]
    fn backtracks_from_literal_into_wildcard() {
        // The case that a non-backtracking trie gets wrong: `/a/b` shadows the literal
        // `a` branch, but `/a/c` must still reach `/*/c`.
        let r = router(&[("/a/b", 0), ("/*/c", 1)]);
        assert_eq!(r.route_id("/a/b"), Some(0));
        assert_eq!(r.route_id("/a/c"), Some(1));
    }

    #[test]
    fn trailing_slash_and_empty_segments() {
        let r = router(&[("/users", 0), ("/users/", 1), ("/users/*", 2)]);
        assert_eq!(r.route_id("/users"), Some(0)); // leaf
        assert_eq!(r.route_id("/users/"), Some(1)); // leaf_slash — distinct route
        assert_eq!(r.route_id("/users/x"), Some(2)); // catch-all
    }

    #[test]
    fn single_segment_wildcard_requires_one_segment() {
        let r = router(&[("/a/*/b", 0)]);
        assert_eq!(r.route_id("/a/x/b"), Some(0));
        assert_eq!(r.route_id("/a/b"), None); // wildcard needs a segment
        assert_eq!(r.route_id("/a/x/y/b"), None); // and exactly one
    }

    // ── matchit equivalence (the oracle) ──────────────────────────────────────

    /// Catalog of patterns in the owned grammar. Chosen to coexist (no conflicts) and to
    /// exercise literals, siblings, catch-alls, interior wildcards, and trailing slashes.
    const CATALOG: &[&str] = &[
        "/",
        "/health",
        "/admin",
        "/admin/",
        "/admin/*",
        "/admin/super",
        "/public",
        "/public/*",
        "/users/*",
        "/a/*/edit",
        "/files/*",
    ];

    /// Instantiate a pattern into a path that matches it (each `*` → "x").
    fn fill(pat: &str) -> String {
        if pat == "/" {
            return "/".to_owned();
        }
        pat.split('/')
            .map(|s| if s == "*" { "x" } else { s })
            .collect::<Vec<_>>()
            .join("/")
    }

    /// Derive a probe path from a base pattern by one of several perturbations — the ways
    /// a request bends around the route boundaries where matcher bugs hide.
    fn perturbation(pat: &str, kind: u8, extra: &str) -> String {
        let base = fill(pat);
        match kind {
            0 => base,                        // exact match
            1 => format!("{base}/{extra}"),   // extra trailing segment
            2 => format!("{base}/"),          // trailing slash
            3 => base.replacen('/', "//", 1), // injected empty segment
            4 => format!("/{extra}"),         // unrelated short path
            _ => base // last segment dropped
                .rsplit_once('/')
                .map_or(base.clone(), |(head, _)| head.to_owned()),
        }
    }

    proptest::proptest! {
        #[test]
        fn matches_matchit(
            include in proptest::collection::vec(proptest::prelude::any::<bool>(), CATALOG.len()),
            base_idx in 0..CATALOG.len(),
            kind in 0u8..6,
            extra in "[a-z]{1,3}",
        ) {
            // Build both routers from the same accepted subset. matchit is the oracle, so
            // its acceptance gates the subset (the clean catalog never conflicts anyway).
            let mut ours_entries = Vec::new();
            let mut oracle = matchit::Router::new();
            for (i, pat) in CATALOG.iter().enumerate() {
                if !include[i] {
                    continue;
                }
                let parsed = parse_pattern(pat).expect("catalog parses");
                if oracle.insert(lower(&parsed), i as RuleId).is_err() {
                    continue; // keep ours in lockstep with the oracle
                }
                ours_entries.push((parsed, i as RuleId, false, MethodMatch::Any));
            }
            let ours = Router::build(&ours_entries).expect("ours builds");

            let probe = perturbation(CATALOG[base_idx], kind, &extra);
            let our_id = ours.route_id(&probe);
            let their_id = oracle.at(&probe).ok().map(|m| *m.value);
            proptest::prop_assert_eq!(our_id, their_id, "diverged on {:?}", probe);
        }
    }

    /// Catalog in the **public matchit syntax**, lowered via [`lower_matchit`]. Crucially
    /// includes a trailing single-segment param (`/users/{id}`) and a deeper route under
    /// it (`/users/{id}/posts`) — the case the `*`-grammar catalog can't express, where a
    /// trailing wildcard must match exactly one segment and not swallow deeper paths.
    const MATCHIT_CATALOG: &[&str] = &[
        "/",
        "/health",
        "/admin",
        "/admin/",
        "/admin/{*rest}",
        "/admin/super",
        "/users/{id}",
        "/users/{id}/posts",
        "/a/{x}/edit",
        "/files/{*rest}",
    ];

    /// Instantiate a matchit-syntax pattern into a matching path (`{…}` → "x").
    fn fill_matchit(pat: &str) -> String {
        if pat == "/" {
            return "/".to_owned();
        }
        pat.split('/')
            .map(|s| if s.starts_with('{') { "x" } else { s })
            .collect::<Vec<_>>()
            .join("/")
    }

    proptest::proptest! {
        #[test]
        fn matches_matchit_syntax(
            include in proptest::collection::vec(proptest::prelude::any::<bool>(), MATCHIT_CATALOG.len()),
            base_idx in 0..MATCHIT_CATALOG.len(),
            kind in 0u8..6,
            extra in "[a-z]{1,3}",
        ) {
            let mut ours_entries = Vec::new();
            let mut oracle = matchit::Router::new();
            for (i, pat) in MATCHIT_CATALOG.iter().enumerate() {
                if !include[i] {
                    continue;
                }
                // The catalog *is* matchit syntax, so the oracle takes it verbatim.
                if oracle.insert(*pat, i as RuleId).is_err() {
                    continue;
                }
                let lowered = lower_matchit(pat).expect("catalog lowers");
                ours_entries.push((lowered, i as RuleId, false, MethodMatch::Any));
            }
            let ours = Router::build(&ours_entries).expect("ours builds");

            let probe = perturbation_matchit(MATCHIT_CATALOG[base_idx], kind, &extra);
            let our_id = ours.route_id(&probe);
            let their_id = oracle.at(&probe).ok().map(|m| *m.value);
            proptest::prop_assert_eq!(our_id, their_id, "diverged on {:?}", probe);
        }
    }

    /// As [`perturbation`], but over a matchit-syntax base pattern.
    fn perturbation_matchit(pat: &str, kind: u8, extra: &str) -> String {
        let base = fill_matchit(pat);
        match kind {
            0 => base,
            1 => format!("{base}/{extra}"),
            2 => format!("{base}/"),
            3 => base.replacen('/', "//", 1),
            4 => format!("/{extra}"),
            _ => base
                .rsplit_once('/')
                .map_or(base.clone(), |(head, _)| head.to_owned()),
        }
    }

    // ── fuzz target: owned matcher vs `matchit` (engine-agnostic body) ─────────
    //
    // The differential the existing oracle proptest runs over a fixed perturbation scheme,
    // re-expressed as a `fn(&[u8])` so a coverage-guided fuzzer can drive *arbitrary* probe
    // paths against the matcher. A divergence from `matchit` is exactly where a relocation
    // bug would hide, so this is the highest-value target — and one Kani could never reach,
    // since it walks the router. Wire later via bolero/cargo-fuzz; the body is the engine.

    /// Engine-agnostic fuzz body: build the owned matcher and `matchit` from the same
    /// included subset of [`MATCHIT_CATALOG`], then assert they resolve an arbitrary probe
    /// to the same rule. Input layout: `[include_mask, probe bytes…]`.
    pub(crate) fn fuzz_matcher_differential(data: &[u8]) {
        let include = data.first().copied().unwrap_or(0xFF);
        let probe = String::from_utf8_lossy(data.get(1..).unwrap_or(&[]));

        let mut ours_entries = Vec::new();
        let mut oracle = matchit::Router::new();
        for (i, pat) in MATCHIT_CATALOG.iter().enumerate() {
            // The first 8 entries are mask-controlled; any beyond are always included.
            if i < 8 && include & (1 << i) == 0 {
                continue;
            }
            if oracle.insert(*pat, i as RuleId).is_err() {
                continue; // keep ours in lockstep with the oracle
            }
            let lowered = lower_matchit(pat).expect("catalog lowers");
            ours_entries.push((lowered, i as RuleId, false, MethodMatch::Any));
        }
        let ours = Router::build(&ours_entries).expect("ours builds");

        let our_id = ours.route_id(&probe);
        let their_id = oracle.at(&probe).ok().map(|m| *m.value);
        assert_eq!(
            our_id, their_id,
            "matcher diverged from matchit on {probe:?}"
        );
    }

    /// Bolero harness for [`fuzz_matcher_differential`]. Runs under `cargo test` and as a
    /// coverage-guided fuzzer under `cargo bolero test matcher_differential`.
    #[test]
    fn matcher_differential() {
        bolero::check!().for_each(|data: &[u8]| fuzz_matcher_differential(data));
    }

    // ── liveness runtime ──────────────────────────────────────────────────────

    use crate::path_confusion::{CaseSensitivity, PathConfusion, StructuralClasses};

    fn guard(
        rows: &[(&str, RuleId, bool)],
        mode: PathConfusion,
        classes: StructuralClasses,
        case: CaseSensitivity,
    ) -> StructuralGuard {
        let entries: Vec<_> = rows
            .iter()
            .map(|(p, id, op)| (parse_pattern(p).expect("parse"), *id, *op, MethodMatch::Any))
            .collect();
        StructuralGuard::new(Router::build(&entries).expect("build"), mode, classes, case)
    }

    /// L1: a path with no enabled structural byte is never denied.
    #[test]
    fn clean_paths_allowed() {
        let g = guard(
            &[("/admin/*", 0, false), ("/users/*", 1, false)],
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(!g.ambiguous("/admin/users"));
        assert!(!g.ambiguous("/users/42"));
        assert!(!g.ambiguous("/nope/clean"));
    }

    /// Opaque exemption relaxes boundary-shift inside the blob but never dot-segment.
    #[test]
    fn opaque_blob_allows_separator_denies_dotdot() {
        let g = guard(
            &[("/files/*", 0, true)],
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(!g.ambiguous("/files/a%2fb"), "encoded slash in opaque blob");
        assert!(!g.ambiguous("/files/a;b"), "matrix param in opaque blob");
        assert!(g.ambiguous("/files/a/../b"), "dot-segment is never relaxed");
        assert!(
            g.ambiguous("/files/a/%2e%2e/b"),
            "encoded dot-segment denied"
        );
    }

    /// An *encoded* matrix param that reveals a dot-segment (`..%3bx` — a `;`-stripping
    /// servlet backend climbs out of the blob) is denied just like the literal `..;x`.
    /// The blob tolerates a `;` as a boundary-shift byte, but never the traversal it hides.
    #[test]
    fn opaque_blob_denies_encoded_param_traversal() {
        let g = guard(
            &[
                ("/files", 0, false),
                ("/files/", 0, false),
                ("/files/*", 0, true),
            ],
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        // A plain matrix param on a real segment stays tolerated.
        assert!(
            !g.ambiguous("/files/a;b/c"),
            "matrix param on a real key segment"
        );
        // The literal Tomcat `..;` vector is denied even in the blob.
        assert!(g.ambiguous("/files/..;x/secret"), "literal `..;x`");
        // The encoded equivalents must be denied too — the bug this closes.
        assert!(g.ambiguous("/files/..%3bx/secret"), "encoded `..%3bx`");
        assert!(g.ambiguous("/files/..%3Bx/secret"), "encoded `..%3Bx`");
    }

    /// Opaque relaxes only bytes *inside* the blob span — a boundary-shift byte in a
    /// preceding wildcard still denies.
    #[test]
    fn opaque_blob_denies_outside_span() {
        let g = guard(
            &[("/files/*/*", 0, true)],
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(!g.ambiguous("/files/ab/c%2fd"), "%2f only in the blob tail");
        assert!(
            g.ambiguous("/files/a%2fb/c"),
            "%2f in the preceding wildcard"
        );
    }

    /// Strict mode ignores opaque declarations and treats any escape as non-canonical.
    #[test]
    fn noncanonical_ignores_opaque_and_denies_escapes() {
        let g = guard(
            &[("/files/*", 0, true)],
            PathConfusion::RejectNonCanonical,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(g.ambiguous("/files/a%2fb"), "opaque ignored when strict");
        assert!(g.ambiguous("/files/a%20b"), "any escape is non-canonical");
        assert!(!g.ambiguous("/files/ab"), "clean path still allowed");
    }

    /// Case is structural only under a case-folding backend.
    #[test]
    fn case_sensitivity_gates_uppercase() {
        let rows = &[("/admin", 0, false)];
        let sensitive = guard(
            rows,
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(
            !sensitive.ambiguous("/Admin"),
            "case ignored when sensitive"
        );

        let insensitive = guard(
            rows,
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            CaseSensitivity::Insensitive,
        );
        assert!(insensitive.ambiguous("/Admin"), "/Admin folds onto /admin");
        assert!(
            !insensitive.ambiguous("/admin"),
            "lowercase clean path allowed"
        );
    }

    /// Regression (found by the `guard_relocation` fuzz target): under a NUL-truncating
    /// backend, a *raw* NUL must be denied — `/a\0junk` matched the default rule and was
    /// allowed, while the backend truncates it to `/a` (a different rule). Raw and encoded
    /// NUL are now treated alike, mirroring raw vs encoded `;`/`\`.
    #[test]
    fn raw_nul_truncation_denied() {
        let g = guard(
            &[("/a", 0, false), ("/a/", 0, false), ("/a/*", 0, false)],
            PathConfusion::RejectStructural,
            StructuralClasses::new().with_null_truncation(),
            CaseSensitivity::Sensitive,
        );
        assert!(g.ambiguous("/a\u{0}b"), "raw NUL truncates to /a");
        assert!(g.ambiguous("/a%00b"), "encoded NUL truncates to /a");
        assert!(!g.ambiguous("/a"), "clean path allowed");
        // Without the truncation class declared, NUL is not a modeled transform.
        let no_trunc = guard(
            &[("/a", 0, false)],
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(
            !no_trunc.ambiguous("/a\u{0}b"),
            "NUL inert when truncation off"
        );
    }

    /// Content-decode catches a relocation the positional scan cannot see.
    #[test]
    fn content_decode_relocation_denied() {
        let g = guard(
            &[
                ("/admin", 0, false),
                ("/admin/", 0, false),
                ("/admin/*", 0, false),
            ],
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(g.ambiguous("/%61dmin"), "/%61dmin decodes to /admin");
        // Precise: a same-rule decode (opaque content) is allowed.
        assert!(!g.ambiguous("/admin/a%20b"), "encoded space under /admin");
        assert!(!g.ambiguous("/admin/x"), "clean path allowed");
    }

    /// The other half of the detection-table audit's CASE row: *encoded* uppercase is not a
    /// positional concern (the byte scan flags only raw `A-Z`) — it is the content-decode
    /// check's job under a case-folding backend. `/%41dmin` → `/Admin` → `/admin` relocates.
    #[test]
    fn content_decode_catches_encoded_uppercase() {
        let g = guard(
            &[
                ("/admin", 0, false),
                ("/admin/", 0, false),
                ("/admin/*", 0, false),
            ],
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            CaseSensitivity::Insensitive,
        );
        assert!(
            g.ambiguous("/%41dmin"),
            "/%41dmin → /Admin → /admin under case folding"
        );
        // A case-sensitive backend distinguishes /Admin from /admin, so it is not a relocation.
        let sensitive = guard(
            &[
                ("/admin", 0, false),
                ("/admin/", 0, false),
                ("/admin/*", 0, false),
            ],
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(
            !sensitive.ambiguous("/%41dmin"),
            "/%41dmin → /Admin, a distinct path when case-sensitive"
        );
    }

    /// `Off` disables the guard entirely.
    #[test]
    fn off_allows_everything() {
        let g = guard(
            &[("/files/*", 0, false)],
            PathConfusion::Off,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(!g.ambiguous("/files/a/../b"));
    }

    // ── metamorphic laws ──────────────────────────────────────────────────────
    //
    // The matcher has an oracle (matchit); the liveness verdict has none, so these are
    // invariants the verdict must satisfy for *all* inputs, plus a CVE ground-truth
    // corpus. The generators are constructive (a vocabulary mixing clean segments and
    // structural payloads, biased to hit the route prefixes) — random strings would pass
    // every law vacuously by never being denied.

    use proptest::prelude::*;

    use crate::path_confusion::StructuralChar;

    /// A structural configuration, with a monotone `tighten` for the L2 law.
    #[derive(Clone, Debug)]
    struct Cfg {
        mode: PathConfusion,
        insensitive: bool,
        backslash: bool,
        truncation: bool,
        double_decode: bool,
        unicode: bool,
        overlong: bool,
    }

    impl Cfg {
        /// The default-config baseline: positional reject, standard alphabet, sensitive.
        fn structural() -> Self {
            Self {
                mode: PathConfusion::RejectStructural,
                insensitive: false,
                backslash: false,
                truncation: false,
                double_decode: false,
                unicode: false,
                overlong: false,
            }
        }

        fn classes(&self) -> StructuralClasses {
            let mut c = StructuralClasses::new();
            if self.backslash {
                c = c.with_backslash();
            }
            if self.truncation {
                c = c.with_null_truncation();
            }
            if self.double_decode {
                c = c.with_double_decode();
            }
            if self.unicode {
                c = c.with_unicode_normalization();
            }
            if self.overlong {
                c = c.with_overlong([StructuralChar::Slash, StructuralChar::Dot]);
            }
            c
        }

        fn case(&self) -> CaseSensitivity {
            if self.insensitive {
                CaseSensitivity::Insensitive
            } else {
                CaseSensitivity::Sensitive
            }
        }
    }

    /// One knob, in its safe (deny-more) direction — the L2 monotonicity steps.
    #[derive(Clone, Copy, Debug)]
    enum Tighten {
        Insensitive,
        Backslash,
        Truncation,
        DoubleDecode,
        Unicode,
        Overlong,
        NonCanonical,
    }

    impl Tighten {
        fn apply(self, base: &Cfg) -> Cfg {
            let mut c = base.clone();
            match self {
                Tighten::Insensitive => c.insensitive = true,
                Tighten::Backslash => c.backslash = true,
                Tighten::Truncation => c.truncation = true,
                Tighten::DoubleDecode => c.double_decode = true,
                Tighten::Unicode => c.unicode = true,
                Tighten::Overlong => c.overlong = true,
                Tighten::NonCanonical => c.mode = PathConfusion::RejectNonCanonical,
            }
            c
        }
    }

    /// Segment vocabulary mixing clean names (hitting the tables) with structural
    /// payloads across every class — including opt-in forms that stay inert unless the
    /// matching toggle is on, so config tightening visibly changes the verdict.
    const SEG_VOCAB: &[&str] = &[
        "a", "b", "x", "admin", "users", "files", "edit", "super", "secret", "a%2fb", "..",
        "%2e%2e", "a;b", "..;x", "a%5cb", "a%00b", "a%252fb", "a%c0%afb", "Abc",
    ];

    fn arb_cfg() -> impl Strategy<Value = Cfg> {
        (
            prop_oneof![
                Just(PathConfusion::RejectStructural),
                Just(PathConfusion::RejectNonCanonical)
            ],
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
        )
            .prop_map(
                |(mode, insensitive, backslash, truncation, double_decode, unicode, overlong)| {
                    Cfg {
                        mode,
                        insensitive,
                        backslash,
                        truncation,
                        double_decode,
                        unicode,
                        overlong,
                    }
                },
            )
    }

    fn arb_tighten() -> impl Strategy<Value = Tighten> {
        prop_oneof![
            Just(Tighten::Insensitive),
            Just(Tighten::Backslash),
            Just(Tighten::Truncation),
            Just(Tighten::DoubleDecode),
            Just(Tighten::Unicode),
            Just(Tighten::Overlong),
            Just(Tighten::NonCanonical),
        ]
    }

    /// A request path of vocab segments — mixes clean and structural, hits the prefixes.
    fn arb_request_path() -> impl Strategy<Value = String> {
        proptest::collection::vec(0..SEG_VOCAB.len(), 1..4).prop_map(|idxs| {
            let segs: Vec<&str> = idxs.iter().map(|&i| SEG_VOCAB[i]).collect();
            format!("/{}", segs.join("/"))
        })
    }

    /// A clean path: lowercase alphanumerics, no escape, no structural byte — clean under
    /// every config, including `Insensitive` and `RejectNonCanonical`.
    fn arb_clean_path() -> impl Strategy<Value = String> {
        proptest::collection::vec("[a-z][a-z0-9]{0,4}", 1..4)
            .prop_map(|segs| format!("/{}", segs.join("/")))
    }

    /// A path under `/files` carrying a dot-segment in one of its forms — for L4.
    fn arb_dotty_path() -> impl Strategy<Value = String> {
        const DOTS: &[&str] = &[
            "..",
            "%2e%2e",
            "%2E%2e",
            ".%2e",
            "..;x",
            "..%3bx",
            "..%3Bx",
            "a%2f..%2fb",
        ];
        const TAILS: &[&str] = &["", "/x", "/admin"];
        (0..DOTS.len(), 0..TAILS.len()).prop_map(|(d, t)| format!("/files/{}{}", DOTS[d], TAILS[t]))
    }

    const GENERAL: &[(&str, RuleId, bool)] = &[
        ("/admin", 0, false),
        ("/admin/", 0, false),
        ("/admin/*", 0, false),
        ("/admin/super", 1, false),
        ("/users/*", 2, false),
        ("/a/*/edit", 3, false),
    ];

    fn guard_cfg(rows: &[(&str, RuleId, bool)], cfg: &Cfg) -> StructuralGuard {
        guard(rows, cfg.mode, cfg.classes(), cfg.case())
    }

    fn files_rows(opaque: bool) -> Vec<(&'static str, RuleId, bool)> {
        vec![
            ("/files", 0, false),
            ("/files/", 0, false),
            ("/files/*", 0, opaque),
        ]
    }

    proptest! {
        /// L1: a path with no enabled structural byte is never denied, under any config.
        #[test]
        fn l1_clean_never_denied(cfg in arb_cfg(), path in arb_clean_path()) {
            let g = guard_cfg(GENERAL, &cfg);
            prop_assert!(!g.ambiguous(&path), "clean path denied: {:?}", path);
        }

        /// L2: tightening the config (a class on, case-fold on, or strict mode) only ever
        /// turns allows into denies — every knob's unsafe direction is the same direction.
        #[test]
        fn l2_monotone(cfg in arb_cfg(), step in arb_tighten(), path in arb_request_path()) {
            let base = guard_cfg(GENERAL, &cfg);
            let stricter = guard_cfg(GENERAL, &step.apply(&cfg));
            prop_assert!(
                !base.ambiguous(&path) || stricter.ambiguous(&path),
                "{:?} via {:?} turned a deny into an allow",
                path,
                step
            );
        }

        /// L3: opaque never denies *more* than the non-opaque blob; and when it saves a
        /// path the non-opaque blob denies, the relaxation is *exactly* boundary-shift
        /// bytes inside the opaque span — never dot-segment / truncation / case.
        #[test]
        fn l3_opaque_relaxation_is_exact(path in arb_request_path()) {
            let cfg = Cfg::structural();
            let normal = guard_cfg(&files_rows(false), &cfg);
            let blob = guard_cfg(&files_rows(true), &cfg);
            let dn = normal.ambiguous(&path);
            let db = blob.ambiguous(&path);

            prop_assert!(!db || dn, "opaque denied MORE on {:?}", path);

            if dn && !db {
                let enabled = enabled_classes(&StructuralClasses::new());
                let enc = enabled_encodings(&StructuralClasses::new());
                let present = classes_present(&path, enabled, enc).intersect(enabled);
                let uniform = ClassSet::DOT_SEGMENT | ClassSet::TRUNCATION | ClassSet::CASE;
                prop_assert!(present.intersect(uniform).is_empty(), "a uniform class was relaxed: {:?}", path);
                prop_assert!(
                    !present.intersect(ClassSet::BOUNDARY_SHIFT).is_empty(),
                    "relaxation with no boundary-shift byte to explain it: {:?}", path
                );
                let entries: Vec<_> = files_rows(true)
                    .iter()
                    .map(|(p, id, op)| (parse_pattern(p).expect("p"), *id, *op, MethodMatch::Any))
                    .collect();
                let r = Router::build(&entries).expect("build");
                prop_assert!(r.opaque_span(&path).is_some(), "saved path did not match the opaque span: {:?}", path);
            }
        }

        /// L4: a dot-segment is denied under RejectStructural regardless of placement —
        /// opaque cannot reopen traversal.
        #[test]
        fn l4_dot_segment_inviolable(path in arb_dotty_path()) {
            let cfg = Cfg::structural();
            prop_assert!(guard_cfg(&files_rows(false), &cfg).ambiguous(&path), "normal: {:?}", path);
            prop_assert!(guard_cfg(&files_rows(true), &cfg).ambiguous(&path), "blob: {:?}", path);
        }

        /// L5: RejectNonCanonical denies a superset of RejectStructural (same classes).
        #[test]
        fn l5_noncanonical_dominates(cfg in arb_cfg(), path in arb_request_path()) {
            let rs = guard_cfg(GENERAL, &Cfg { mode: PathConfusion::RejectStructural, ..cfg.clone() });
            let rn = guard_cfg(GENERAL, &Cfg { mode: PathConfusion::RejectNonCanonical, ..cfg });
            prop_assert!(!rs.ambiguous(&path) || rn.ambiguous(&path), "{:?}", path);
        }

        /// L6: an opaque catch-all with a routing sibling is unconstructable.
        #[test]
        fn l6_opaque_with_sibling_rejected(leaf in "[a-z]{1,4}") {
            let entries = vec![
                (parse_pattern("/p/*").expect("blob"), 0, true, MethodMatch::Any),
                (
                    parse_pattern(&format!("/p/{leaf}")).expect("sibling"),
                    1,
                    false,
                    MethodMatch::Any,
                ),
            ];
            prop_assert!(matches!(Router::build(&entries), Err(BuildError::OpaqueTailHasSibling)));
        }
    }

    /// L7: CVE ground truth — known-bad inputs must deny, and declaring the public prefix
    /// an opaque blob must not reopen any of them.
    #[test]
    fn cve_corpus_denied() {
        let classes = StructuralClasses::new();
        // CVE-2019-9901 (Envoy): `/public/../admin` climbs into a protected route.
        let envoy = |opaque| {
            guard(
                &[
                    ("/public", 0, false),
                    ("/public/", 0, false),
                    ("/public/*", 0, opaque),
                    ("/admin", 1, false),
                ],
                PathConfusion::RejectStructural,
                classes.clone(),
                CaseSensitivity::Sensitive,
            )
        };
        assert!(envoy(false).ambiguous("/public/../admin"));
        assert!(
            envoy(true).ambiguous("/public/../admin"),
            "opaque blob must not reopen the traversal"
        );

        // CVE-2021-31920 (Istio): `//admin` and `%2f`-escaped slashes bypass policy.
        let istio = guard(
            &[("/admin", 0, false)],
            PathConfusion::RejectStructural,
            classes.clone(),
            CaseSensitivity::Sensitive,
        );
        assert!(istio.ambiguous("//admin"));
        assert!(istio.ambiguous("/x%2fadmin"));

        // CVE-2021-41773 (Apache): encoded `%2e%2e` dot-segments escape an alias.
        let apache = guard(
            &[
                ("/cgi-bin", 0, false),
                ("/cgi-bin/", 0, false),
                ("/cgi-bin/*", 0, false),
                ("/secret", 1, false),
            ],
            PathConfusion::RejectStructural,
            classes,
            CaseSensitivity::Sensitive,
        );
        assert!(apache.ambiguous("/cgi-bin/%2e%2e/secret"));
    }
}
