//! Property-based bypass fuzzing for the path-confusion guard.
//!
//! This tests the guard's *security claim* directly, not its parsing: the guard
//! forwards the **raw** path or denies, so a bypass is a parser differential —
//! the proxy authorizes a request as one rule while a backend, after normalizing
//! the path, would route it to a *different* rule. The soundness invariant:
//!
//! > For a route table + structural config, and for **every backend in the
//! > modeled transform family**, if normalizing the request path relocates it to
//! > a different rule than the raw path matched, the guard **must deny**.
//!
//! A violation (relocation exists, guard allowed) is a real authorization
//! bypass — a false *negative*. Over-denial (a false positive) is only an
//! availability issue, so the hard assertion here is one-sided.
//!
//! The oracle's value is that the reference backend ([`normalize`]) is a
//! **concrete, executable** model — it actually decodes `%2F`→`/`, resolves
//! `..`, strips `;`-params, folds case, etc., then re-routes through the same
//! table — whereas the guard is an *abstract positional analysis that never
//! transforms a byte*. Two independent implementations of "what could happen to
//! this path"; when they disagree it means something.
//!
//! The one rule that keeps it honest: the reference backend's transforms are
//! **gated by the same [`StructuralClasses`]/[`CaseSensitivity`]** the guard was
//! built with. A relocation via a transform the config does not enable (e.g.
//! `\`→`/` with `with_backslash()` off) is operator under-declaration, not a
//! guard bug, so those transforms stay off in the sampled backends too.

use proptest::prelude::*;

use crate::{
    path_confusion::{CaseSensitivity, PathConfusion, StructuralChar, StructuralClasses},
    path_router::{RuleRouter, RuleRouterError},
    route_tree::MethodMatch,
    subtree_patterns,
};

// ── Route-table catalog ────────────────────────────────────────────────────

/// `(kind, path)` route specs the generator samples from. `kind` is `'s'` for a
/// `subtree` (expanded via [`subtree_patterns`]) or `'e'` for an exact route.
/// All lowercase, all canonical, and chosen to mostly coexist in `matchit` — a
/// subset that conflicts just fails to build and is skipped.
const CATALOG: &[(char, &str)] = &[
    ('s', "/admin"),
    ('s', "/public"),
    ('s', "/api"),
    ('e', "/health"),
    ('e', "/admin/super"),
    ('e', "/users/{id}"),
    ('s', "/a"),
    ('e', "/a/b"),
];

/// Path-segment vocabulary, mixing names that hit the catalog with structural
/// mutators (literal and encoded separators, dot-segments, matrix-params,
/// backslashes, NULs, overlong/double-encoded forms, and case variants).
const VOCAB: &[&str] = &[
    "admin",
    "public",
    "api",
    "health",
    "super",
    "secret",
    "users",
    "a",
    "b",
    "42",
    "id",
    "v1",
    "img-1.png",
    "",
    "..",
    ".",
    "%2e",
    "%2e%2e",
    "a%2fb",
    "%2fadmin",
    "..%2fadmin",
    ";x",
    "..;",
    "admin;jsessionid=1",
    "a\\b",
    "%5cadmin",
    "..%5cadmin",
    "a%00b",
    "admin%00",
    "%252e%252e",
    "%252fadmin",
    "%c0%afadmin",
    "%c0%ae%c0%ae",
    "ADMIN",
    "Admin",
    "PUBLIC",
    // Content-encoded forms that decode onto a catalog literal — exercise the
    // content-decode relocation path (`%61dmin` → `admin`, `%41dmin` → `Admin`).
    "%61dmin",
    "%41dmin",
    "%73uper",
    "%70ublic",
    "%68ealth",
    "%61pi",
    "v%31",
    // Fullwidth structural confusables (raw and percent-encoded) — exercise the
    // `with_unicode_normalization` path (`／` folds to `/`, `．` to `.`).
    "a／b",
    "／admin",
    "..／admin",
    "．．",
    "a；b",
    "%ef%bc%8fadmin",
];

fn build_router(
    specs: &[(char, &str)],
    classes: StructuralClasses,
    case: CaseSensitivity,
) -> Result<RuleRouter<u32>, RuleRouterError> {
    let mut entries: Vec<(String, u32, u32, bool, MethodMatch)> = Vec::new();
    for (id, (kind, path)) in specs.iter().enumerate() {
        let id = u32::try_from(id).expect("catalog is small");
        let patterns = if *kind == 's' {
            subtree_patterns(path)
        } else {
            vec![(*path).to_owned()]
        };
        for p in patterns {
            entries.push((p, id, id, false, MethodMatch::Any));
        }
    }
    RuleRouter::build(
        entries,
        u32::MAX,
        PathConfusion::RejectStructural,
        classes,
        case.is_insensitive(),
    )
}

// ── Reference backend (the executable normalization model) ──────────────────

/// One sampled backend: which modeled transforms it performs. Each toggle is
/// only ever set when the corresponding structural class/encoding is enabled in
/// the config the guard was built with.
// Each field is an independent transform toggle — a flat set of booleans is the
// clearest representation (mirroring `StructuralClasses`).
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug)]
struct Backend {
    decode_sep: bool,        // `%2F` (and `\`/`%5C` when backslash is enabled) → `/`
    decode_dot: bool,        // `%2E` → `.`
    decode_unreserved: bool, // every other `%XX` (content) → its byte
    fold_unicode: bool,      // fullwidth `／`·`．`·`；`·`＼` → `/`·`.`·`;`·`\`
    strip_params: bool,      // drop `;…` in each segment
    merge_slashes: bool,     // `//` → `/`
    resolve_dots: bool,      // RFC 3986 §5.2.4 dot-segment removal
    case_fold: bool,         // ASCII lowercase
    truncate_nul: bool,      // cut at the first NUL (`%00`)
}

/// Every backend in the modeled family for `classes`/`case`: the power set of
/// the available transforms. A transform is available only where the matching
/// class is enabled (case folding under `Insensitive`, NUL truncation under
/// `with_null_truncation()`); the always-on trio's transforms are always
/// available.
fn modeled_backends(classes: &StructuralClasses, case: CaseSensitivity) -> Vec<Backend> {
    let case_avail = case.is_insensitive();
    let trunc_avail = classes.truncation;
    let uni_avail = classes.unicode;
    let mut backends = Vec::new();
    for mask in 0u32..(1 << 9) {
        let case_fold = mask & (1 << 5) != 0;
        let truncate_nul = mask & (1 << 6) != 0;
        let fold_unicode = mask & (1 << 8) != 0;
        if (case_fold && !case_avail)
            || (truncate_nul && !trunc_avail)
            || (fold_unicode && !uni_avail)
        {
            continue; // out of model for this config
        }
        backends.push(Backend {
            decode_sep: mask & 1 != 0,
            decode_dot: mask & (1 << 1) != 0,
            strip_params: mask & (1 << 2) != 0,
            merge_slashes: mask & (1 << 3) != 0,
            resolve_dots: mask & (1 << 4) != 0,
            case_fold,
            truncate_nul,
            // Generic content-decode is always available — every backend percent-
            // decodes the path (the always-on case for the guard's content check).
            decode_unreserved: mask & (1 << 7) != 0,
            fold_unicode,
        });
    }
    backends
}

/// Normalize `path` as `backend` would, to a fixpoint. Independent of the
/// guard's own scanner by construction — it rewrites bytes and routing follows.
fn normalize(
    path: &str,
    backend: Backend,
    classes: &StructuralClasses,
    case_insensitive: bool,
) -> String {
    let mut s = path.to_owned();
    for _ in 0..24 {
        let mut t = s.clone();
        if backend.truncate_nul && classes.truncation {
            t = truncate_at_nul(&t);
        }
        if backend.decode_sep || backend.decode_dot {
            t = decode_pass(&t, backend, classes);
        }
        if backend.decode_unreserved {
            t = decode_unreserved(&t);
        }
        if backend.fold_unicode {
            t = fold_unicode(&t);
        }
        if backend.strip_params {
            t = strip_params(&t);
        }
        if backend.merge_slashes {
            t = merge_slashes(&t);
        }
        if backend.resolve_dots {
            t = remove_dot_segments(&t);
        }
        if backend.case_fold && case_insensitive {
            t = t.to_ascii_lowercase();
        }
        if t == s {
            break;
        }
        s = t;
    }
    s
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn pct(b: &[u8], i: usize) -> Option<u8> {
    if *b.get(i)? != b'%' {
        return None;
    }
    Some(hex_val(*b.get(i + 1)?)? * 16 + hex_val(*b.get(i + 2)?)?)
}

/// Case-insensitive ASCII prefix match of `pat` (lowercase) at `b[i..]`.
fn starts_ci(b: &[u8], i: usize, pat: &[u8]) -> bool {
    pat.iter()
        .enumerate()
        .all(|(k, &p)| b.get(i + k).is_some_and(|c| c.to_ascii_lowercase() == p))
}

/// One percent-decoding pass for the modeled structural bytes only (never
/// general unreserved octets — see the module-level discussion of why that is a
/// deliberate scope line). Double-encoding is peeled one `%25` layer per pass;
/// the fixpoint loop re-runs the decode.
fn decode_pass(t: &str, backend: Backend, c: &StructuralClasses) -> String {
    let b = t.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            // Double-encoding: peel `%25` → `%`, let the next pass decode it.
            if c.double_decode && starts_ci(b, i, b"%25") {
                out.push(b'%');
                i += 3;
                continue;
            }
            // Overlong UTF-8 (2-byte canonical forms `%C0%AF` / `%C0%AE`).
            if backend.decode_sep && c.overlong_slash && starts_ci(b, i, b"%c0%af") {
                out.push(b'/');
                i += 6;
                continue;
            }
            if backend.decode_dot && c.overlong_dot && starts_ci(b, i, b"%c0%ae") {
                out.push(b'.');
                i += 6;
                continue;
            }
            if let Some(byte) = pct(b, i) {
                let decoded = match byte {
                    b'/' if backend.decode_sep => Some(b'/'),
                    b'\\' if backend.decode_sep && c.backslash => Some(b'/'),
                    b'.' if backend.decode_dot => Some(b'.'),
                    _ => None,
                };
                if let Some(d) = decoded {
                    out.push(d);
                    i += 3;
                    continue;
                }
            }
            out.push(b[i]);
            i += 1;
        } else if b[i] == b'\\' && backend.decode_sep && c.backslash {
            out.push(b'/');
            i += 1;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| t.to_owned())
}

/// Percent-decode the *content* escapes — every complete `%XX` except those that
/// decode to a structural byte (`/ . ; \ NUL`) or to the `%` double-encode wrapper.
/// Single pass and idempotent (it produces no new `%`), so it composes safely inside
/// the normalization fixpoint; the structural and double-decode forms are handled by
/// their own steps so this never implies them.
fn decode_unreserved(t: &str) -> String {
    if !t.contains('%') {
        return t.to_owned();
    }
    let b = t.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && let Some(byte) = pct(b, i)
            && !matches!(byte, b'/' | b'.' | b';' | b'\\' | 0 | b'%')
        {
            out.push(byte);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| t.to_owned())
}

/// NFKC-fold the fullwidth structural confusables to their ASCII byte — the Phase-1
/// `with_unicode_normalization` set. Letters and other compatibility forms are *not*
/// folded (Phase 1 is structural only), so the oracle never generates a content
/// relocation the structural class cannot catch.
fn fold_unicode(t: &str) -> String {
    if t.is_ascii() {
        return t.to_owned();
    }
    t.replace('／', "/")
        .replace('．', ".")
        .replace('；', ";")
        .replace('＼', "\\")
}

fn truncate_at_nul(t: &str) -> String {
    let cut = [t.find("%00"), t.find('\0')].into_iter().flatten().min();
    match cut {
        Some(i) => t[..i].to_owned(),
        None => t.to_owned(),
    }
}

fn strip_params(t: &str) -> String {
    t.split('/')
        .map(|seg| seg.split(';').next().unwrap_or(seg))
        .collect::<Vec<_>>()
        .join("/")
}

fn merge_slashes(t: &str) -> String {
    let mut out = String::with_capacity(t.len());
    let mut prev_slash = false;
    for ch in t.chars() {
        if ch == '/' {
            if prev_slash {
                continue;
            }
            prev_slash = true;
        } else {
            prev_slash = false;
        }
        out.push(ch);
    }
    out
}

/// RFC 3986 §5.2.4 `remove_dot_segments`.
fn remove_dot_segments(path: &str) -> String {
    let mut input = path.to_owned();
    let mut output = String::new();
    while !input.is_empty() {
        if let Some(rest) = input.strip_prefix("../") {
            input = rest.to_owned();
        } else if let Some(rest) = input.strip_prefix("./") {
            input = rest.to_owned();
        } else if let Some(rest) = input.strip_prefix("/./") {
            input = format!("/{rest}");
        } else if input == "/." {
            input = "/".to_owned();
        } else if let Some(rest) = input.strip_prefix("/../") {
            input = format!("/{rest}");
            pop_last_segment(&mut output);
        } else if input == "/.." {
            input = "/".to_owned();
            pop_last_segment(&mut output);
        } else if input == "." || input == ".." {
            input.clear();
        } else {
            // Move the first path segment (leading `/` plus up to the next `/`).
            let after = if let Some(idx) = input[1..].find('/') {
                idx + 1
            } else {
                input.len()
            };
            output.push_str(&input[..after]);
            input = input[after..].to_owned();
        }
    }
    output
}

fn pop_last_segment(output: &mut String) {
    if let Some(idx) = output.rfind('/') {
        output.truncate(idx);
    } else {
        output.clear();
    }
}

// ── Strategies ──────────────────────────────────────────────────────────────

fn config_strategy() -> impl Strategy<Value = (StructuralClasses, CaseSensitivity)> {
    (
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(|(back, trunc, over_s, over_d, double, uni, ci)| {
            let mut c = StructuralClasses::new();
            if back {
                c = c.with_backslash();
            }
            if trunc {
                c = c.with_null_truncation();
            }
            let mut overlong = Vec::new();
            if over_s {
                overlong.push(StructuralChar::Slash);
            }
            if over_d {
                overlong.push(StructuralChar::Dot);
            }
            if !overlong.is_empty() {
                c = c.with_overlong(overlong);
            }
            if double {
                c = c.with_double_decode();
            }
            if uni {
                c = c.with_unicode_normalization();
            }
            let case = if ci {
                CaseSensitivity::Insensitive
            } else {
                CaseSensitivity::Sensitive
            };
            (c, case)
        })
}

fn specs_strategy() -> impl Strategy<Value = Vec<(char, &'static str)>> {
    proptest::sample::subsequence(CATALOG.to_vec(), 1..=CATALOG.len())
}

fn path_strategy() -> impl Strategy<Value = String> {
    proptest::collection::vec(proptest::sample::select(VOCAB), 1..5)
        .prop_map(|segs| format!("/{}", segs.join("/")))
}

// ── Fuzz target: the guard's soundness claim (engine-agnostic body) ──────────
//
// `guard_denies_every_modeled_relocation` re-expressed as a `fn(&[u8])` so a coverage-
// guided fuzzer can drive arbitrary (table, config, path) triples at the *executable
// backend model*. This is the security boundary — router + verdict together — and the
// reason fuzzing earns its keep over the bounded model checker, which couldn't get past
// the router's `HashMap`. Wire later via bolero/cargo-fuzz; the body is the engine.

/// Decode a config from one byte's bits (mirrors [`config_strategy`]).
fn config_from_bits(bits: u8) -> (StructuralClasses, CaseSensitivity) {
    let mut c = StructuralClasses::new();
    if bits & 1 != 0 {
        c = c.with_backslash();
    }
    if bits & 2 != 0 {
        c = c.with_null_truncation();
    }
    let mut overlong = Vec::new();
    if bits & 4 != 0 {
        overlong.push(StructuralChar::Slash);
    }
    if bits & 8 != 0 {
        overlong.push(StructuralChar::Dot);
    }
    if !overlong.is_empty() {
        c = c.with_overlong(overlong);
    }
    if bits & 16 != 0 {
        c = c.with_double_decode();
    }
    if bits & 32 != 0 {
        c = c.with_unicode_normalization();
    }
    let case = if bits & 64 != 0 {
        CaseSensitivity::Insensitive
    } else {
        CaseSensitivity::Sensitive
    };
    (c, case)
}

/// Engine-agnostic fuzz body: if the guard *allows* the path, assert no modeled backend
/// relocates it to a different rule. A failure is a real authorization bypass. Input
/// layout: `[specs_mask, config_bits, path bytes…]`.
pub(crate) fn fuzz_guard_relocation(data: &[u8]) {
    let specs_mask = data.first().copied().unwrap_or(0xFF);
    let (classes, case) = config_from_bits(data.get(1).copied().unwrap_or(0));
    // The guard only ever sees `uri.path()`, which is origin-form (a leading `/`). Model
    // that so the fuzzer explores realistic inputs — and so the reference backend's
    // dot-segment resolver, which assumes a rooted path, is never handed an impossible one.
    // A bare `/` prepend preserves `//` and every structural byte; it only roots the path.
    let raw = String::from_utf8_lossy(data.get(2..).unwrap_or(&[]));
    let path = if raw.starts_with('/') {
        raw.into_owned()
    } else {
        format!("/{raw}")
    };

    let specs: Vec<(char, &str)> = CATALOG
        .iter()
        .enumerate()
        .filter(|(i, _)| specs_mask & (1 << i) != 0)
        .map(|(_, s)| *s)
        .collect();
    if specs.is_empty() {
        return;
    }
    let Ok(router) = build_router(&specs, classes.clone(), case) else {
        return; // unbuildable subset (matchit conflict) — skip
    };

    let raw_rule = router.match_rule(&path, &http::Method::GET).0;
    if router.ambiguous(&path).is_some() {
        return; // denied — sound regardless of any backend
    }
    for backend in modeled_backends(&classes, case) {
        let normalized = normalize(&path, backend, &classes, case.is_insensitive());
        if normalized == path {
            continue;
        }
        let reloc_rule = router.match_rule(&normalized, &http::Method::GET).0;
        assert_eq!(
            reloc_rule, raw_rule,
            "BYPASS: guard allowed {path:?} (rule {raw_rule}) but backend {backend:?} \
             normalizes it to {normalized:?}, which routes to rule {reloc_rule}"
        );
    }
}

// ── Properties ──────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig { cases: 2048, ..ProptestConfig::default() })]

    /// Soundness: if the guard *allows* a path, no modeled backend may relocate
    /// it to a different rule.
    #[test]
    fn guard_denies_every_modeled_relocation(
        specs in specs_strategy(),
        (classes, case) in config_strategy(),
        path in path_strategy(),
    ) {
        // Under a case-folding backend the catalog (lowercase) builds fine; an
        // unbuildable subset (matchit conflict) is simply skipped.
        let Ok(router) = build_router(&specs, classes.clone(), case) else {
            return Ok(());
        };

        let raw_rule = router.match_rule(&path, &http::Method::GET).0;
        if router.ambiguous(&path).is_some() {
            return Ok(()); // denied — sound regardless of any backend
        }

        // Guard allowed `path`: assert it is genuinely unambiguous across the
        // whole modeled backend family.
        for backend in modeled_backends(&classes, case) {
            let normalized = normalize(&path, backend, &classes, case.is_insensitive());
            if normalized == path {
                continue;
            }
            let reloc_rule = router.match_rule(&normalized, &http::Method::GET).0;
            prop_assert_eq!(
                reloc_rule,
                raw_rule,
                "BYPASS: guard allowed {:?} (rule {}) but backend {:?} normalizes it to \
                 {:?}, which routes to rule {} — table {:?}, classes {:?}, case {:?}",
                path, raw_rule, backend, normalized, reloc_rule, specs, classes, case
            );
        }
    }

    /// Robustness: building with an arbitrary pattern, and matching/judging an
    /// arbitrary path against a fixed table, must never panic or hang (the crate
    /// is `deny(clippy::panic)`, but that cannot see runtime slicing/UTF-8 edges).
    #[test]
    fn never_panics_on_arbitrary_input(pattern in ".*", path in ".*") {
        let entries = vec![(pattern, 0u32, 0u32, false, MethodMatch::Any)];
        let _ = RuleRouter::build(
            entries,
            u32::MAX,
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            false,
        );

        let router = build_router(
            &[('s', "/admin"), ('e', "/users/{id}")],
            StructuralClasses::new().with_backslash().with_double_decode(),
            CaseSensitivity::Insensitive,
        )
        .expect("fixed table builds");
        let _ = router.match_rule(&path, &http::Method::GET);
        let _ = router.ambiguous(&path);
    }
}

/// Bolero harness for [`fuzz_guard_relocation`] — the guard's soundness claim against the
/// executable backend model. Runs under `cargo test` and as a coverage-guided fuzzer under
/// `cargo bolero test guard_relocation`.
#[test]
fn guard_relocation() {
    bolero::check!().for_each(|data: &[u8]| fuzz_guard_relocation(data));
}

#[cfg(test)]
mod reference_backend_tests {
    use super::*;

    #[test]
    fn remove_dot_segments_matches_rfc_examples() {
        // RFC 3986 §5.2.4 worked examples.
        assert_eq!(remove_dot_segments("/a/b/c/./../../g"), "/a/g");
        assert_eq!(remove_dot_segments("/a/../admin"), "/admin");
        assert_eq!(remove_dot_segments("/admin/../.."), "/");
        assert_eq!(remove_dot_segments("/public/file.txt"), "/public/file.txt");
    }

    #[test]
    fn decode_pass_is_scoped_to_structural_bytes() {
        let c = StructuralClasses::new();
        let all_decode = Backend {
            decode_sep: true,
            decode_dot: true,
            decode_unreserved: false,
            fold_unicode: false,
            strip_params: false,
            merge_slashes: false,
            resolve_dots: false,
            case_fold: false,
            truncate_nul: false,
        };
        assert_eq!(decode_pass("/a%2fb", all_decode, &c), "/a/b");
        assert_eq!(decode_pass("/a%2eb", all_decode, &c), "/a.b");
        // A non-structural unreserved escape is left intact — by design.
        assert_eq!(decode_pass("/%61dmin", all_decode, &c), "/%61dmin");
        // Backslash only decodes when the class is enabled.
        assert_eq!(decode_pass("/a\\b", all_decode, &c), "/a\\b");
        let with_back = StructuralClasses::new().with_backslash();
        assert_eq!(decode_pass("/a\\b", all_decode, &with_back), "/a/b");
    }

    #[test]
    fn decode_unreserved_decodes_content_not_structure() {
        // Content escapes decode to their byte…
        assert_eq!(decode_unreserved("/%61dmin"), "/admin");
        assert_eq!(decode_unreserved("/a%20b"), "/a b");
        // …but structural bytes and the %25 double-encode wrapper are left to their
        // own steps, so this never produces `/`, `.`, `;`, `\`, NUL, or a fresh `%`.
        assert_eq!(decode_unreserved("/a%2fb"), "/a%2fb");
        assert_eq!(decode_unreserved("/a%2eb"), "/a%2eb");
        assert_eq!(decode_unreserved("/a%252fb"), "/a%252fb");
        // Idempotent (no new escapes appear).
        assert_eq!(decode_unreserved(&decode_unreserved("/%61%20b")), "/a b");
    }

    #[test]
    fn fold_unicode_folds_structural_confusables_only() {
        assert_eq!(fold_unicode("/api／secret"), "/api/secret");
        assert_eq!(fold_unicode("/a／..／b"), "/a/../b");
        assert_eq!(fold_unicode("/a．b；c"), "/a.b;c");
        // Fullwidth *letters* are content (Phase 2), not folded by the Phase-1 model.
        assert_eq!(fold_unicode("/ＡＤＭＩＮ"), "/ＡＤＭＩＮ");
        // ASCII fast-path is a no-op.
        assert_eq!(fold_unicode("/plain/path"), "/plain/path");
    }

    #[test]
    fn strip_and_merge_helpers() {
        assert_eq!(strip_params("/a;x=1/b;y/c"), "/a/b/c");
        assert_eq!(merge_slashes("/a//b///c"), "/a/b/c");
        assert_eq!(truncate_at_nul("/public%00/admin"), "/public");
    }
}

/// Regenerate the committed fuzz **seed corpus** under `fuzz-corpus/<bolero-dir>/`.
///
/// `#[ignore]` because it writes files; run it explicitly when the seed set changes, then
/// commit the result:
///
/// ```text
/// cargo test --features resource regenerate_fuzz_corpus -- --ignored --nocapture
/// ```
///
/// Seeds are the security-relevant inputs we want every fuzz run to start *warm* on — CVE
/// traversal shapes, the encoded-`;` and raw-NUL regressions, and the matcher's
/// backtracking edges — so a cold/evicted cache still reaches the interesting branches
/// immediately. Each file is the raw `&[u8]` a target's `fuzz_*` body decodes; the dir
/// names match bolero's live corpus dirs (`::` → `__`) so priming a run is a plain copy.
#[test]
#[ignore = "side-effecting: regenerates committed seed files on demand"]
fn regenerate_fuzz_corpus() {
    use std::{fs, path::Path};

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz-corpus");
    let write = |dir: &str, name: &str, bytes: &[u8]| {
        let d = root.join(dir);
        fs::create_dir_all(&d).expect("create seed dir");
        fs::write(d.join(name), bytes).expect("write seed");
    };

    // Each closure prepends the fixed control-byte prefix its `fuzz_*` body decodes.
    let scanner = |path: &str| {
        // [enabled = 0x3f (all classes), e2_extra = 0, enc1 = 0x0f (all encodings), enc2_extra = 0]
        [&[0x3f, 0x00, 0x0f, 0x00], path.as_bytes()].concat()
    };
    let matcher = |probe: &str| [&[0xFFu8], probe.as_bytes()].concat(); // [include = all routes]
    let guard = |path: &str| {
        // [specs_mask = 0xFF (all routes), config_bits = 0x7F (every class + case-insensitive)]
        [&[0xFFu8, 0x7F], path.as_bytes()].concat()
    };

    // scanner — one of each structural form, incl. the `..%3b` and raw-NUL regressions.
    for (name, path) in [
        ("dot_segment", "/a/../b"),
        ("encoded_sep_dot", "/a%2f..%2fb"),
        ("encoded_param_dot", "/files/..%3bx/secret"),
        ("raw_nul", "/a\u{0}b"),
        ("encoded_nul", "/a%00b"),
        ("overlong", "/a%c0%afb"),
        ("double_encoded", "/a%252fb"),
        ("fullwidth", "/a／b"),
        ("uppercase", "/Admin"),
        ("clean", "/admin/users"),
    ] {
        write("structural__tests__scanner", name, &scanner(path));
    }

    // matcher — backtracking, trailing slash, catch-all, empty segments, the default.
    for (name, probe) in [
        ("exact", "/health"),
        ("trailing_slash", "/admin/"),
        ("catchall", "/admin/x/y"),
        ("nested_param", "/users/42/posts"),
        ("interior_wildcard", "/a/x/edit"),
        ("empty_segment", "//admin"),
        ("backtrack", "/a/b"),
        ("default", "/nope"),
    ] {
        write(
            "route_tree__tests__matcher_differential",
            name,
            &matcher(probe),
        );
    }

    // guard — CVE traversal shapes + the regressions, against the lowercase catalog.
    for (name, path) in [
        ("traversal", "/public/../admin"),
        ("encoded_traversal", "/api/%2e%2e/admin"),
        ("raw_nul_trunc", "/a\u{0}b"),
        ("encoded_nul_trunc", "/a%00b"),
        ("encoded_sep_dot", "/public/..%2fadmin"),
        ("empty_segment", "//admin"),
        ("trailing_encoded_sep", "/admin%2f"),
        ("fullwidth", "/api／secret"),
        ("double_traversal", "/public/%252e%252e/admin"),
    ] {
        write(
            "path_confusion_proptest__guard_relocation",
            name,
            &guard(path),
        );
    }

    eprintln!("seed corpus written under {}", root.display());
}
