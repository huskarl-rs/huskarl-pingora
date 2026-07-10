//! Path-confusion configuration **and the algorithm it drives**.
//!
//! Rules are matched on the request path, but the **raw** path is forwarded upstream
//! unchanged. If the proxy and the upstream disagree about what a path *means* — a
//! parser differential — a request can be authorized as one path while the upstream
//! acts on another (`/x/../admin/secret`, `/admin%2fsecret`, `/%61dmin`, …). The
//! guard's whole job is to deny such requests; it never rewrites what is forwarded.
//!
//! # The differential is in the topology, not this crate
//!
//! That gap exists only because **two systems parse the path** — this proxy makes the
//! authorization decision, a separate backend serves the resource — and the two can
//! disagree. The safest deployment *removes* the gap rather than guarding it: when the
//! authorization checks and the backend code they protect are the **same system acting
//! on the same parsed path**, there is no second parser to differ and nothing here to
//! defend. Read everything below as making the *split* topology — the one this crate
//! exists for — as safe as a split can be; it is a mitigation, not a reason to split
//! when colocation is an option.
//!
//! Colocation only helps if the authorization decision and the request dispatch share
//! **one** path interpretation: an in-process filter that checks the raw path while the
//! framework routes the decoded one has reintroduced the very same differential inside
//! a single process. The guarantee is "one parser," not "one binary."
//!
//! # The guard never rewrites the path — and that is the point
//!
//! The guard only ever *denies* or *forwards the raw bytes unchanged*; it never
//! normalizes the path it sends upstream. This is not a missing feature — normalizing
//! would be **actively worse**, and for the same reason the topology is hard to reason
//! about in the first place.
//!
//! Forwarding raw keeps the differential surface at exactly **one parser pair**: *how
//! this layer routed these bytes* versus *how the backend parses these bytes*. Normalize
//! before forwarding and you get **two**: *client bytes → your normalization*, then *your
//! output → the backend's parse*. You have not removed the differential, you have added
//! one — and the new one is between your normalizer and a backend you have already
//! conceded you cannot fully characterize (that is why, e.g.,
//! [`with_double_decode`](StructuralClasses::with_double_decode) is a declaration, not an
//! inference). Picking a normalization is choosing how many times to decode *on the
//! backend's behalf* without knowing how many decoders sit downstream; get it wrong by
//! one and you have *built* the CVE-2025-0108 chain rather than detected it. The honest
//! response to "I cannot count the layers" is to refuse ambiguous input
//! ([`reject_non_canonical`](PathConfusion::reject_non_canonical)), never to guess a
//! rewrite and hope it matches.
//!
//! Rewriting is also **non-local**: a guard that forwards raw is byte-transparent, so
//! every other element in the chain — a downstream WAF, a cache keying on the URL, the
//! origin's own path defenses, the audit log — reasons about exactly what the client
//! sent, and this layer's presence is invisible to their analysis. The moment it
//! normalizes, it becomes a transform every neighbour must now model: a downstream WAF
//! tuned against client traffic sees a changed input distribution, a cache's key space
//! shifts (the machinery of cache deception), and forensics logs the laundered path
//! instead of the probe. Identity-on-the-bytes is the one transform that composes safely
//! across an arbitrary chain — N transparent hops still equal one canonical input, rather
//! than an N-deep pipeline whose every seam is a candidate bypass. (This is why a
//! security parser must reject [Postel's law](https://en.wikipedia.org/wiki/Robustness_principle):
//! being "helpful" by canonicalizing is the source of the bug class, not a mitigation.)
//!
//! Finally, detection preserves the lattice. Every knob here is safe in one direction —
//! tightening can only ever deny *more* (see [the monotonicity note](#making-the-decision)).
//! A rewrite breaks that: it can *change* which bytes reach the backend, not merely gate
//! them, so it cannot sit anywhere on the deny-more axis. There is deliberately no rung
//! that says "transform it for them."
//!
//! This module holds the *configuration*:
//!
//! - [`PathConfusion`] selects the mode (the default positional reject, the strict
//!   all-positions reject, or off);
//! - [`CaseSensitivity`] declares whether the upstream folds ASCII case — **required**,
//!   with no default, because the library cannot infer it;
//! - [`StructuralClasses`] selects which structural classes and encodings beyond the
//!   always-on default the guard recognises, plus any [`StructuralProbe`] break-glass
//!   detectors.
//!
//! # How the guard decides
//!
//! For every request the guard matches the **raw** path to a rule, then runs the
//! following checks against that raw path. Each can only ever *deny* (`400`); if none
//! fires, the raw path is forwarded untouched.
//!
//! Two things to fix first. A *rule* here is one `route`/`subtree` registration —
//! **identity, not policy**: two separate registrations are different rules even if
//! their policies are identical, and movement *within* a single `subtree` is never a
//! relocation (its patterns share one rule). And the checks run on
//! **every** request, whatever rule the raw path matched — a `public` or `optional`
//! route is guarded exactly like a protected one. That is the whole point: the danger
//! is a path the proxy authorizes under a *permissive* rule but the backend serves
//! under a *stricter* one (or the reverse). When a relocation is found the guard
//! **denies** rather than re-routing to the other rule — it cannot know which rule the
//! backend will actually resolve to, so refusing the ambiguous request is the only
//! sound response.
//!
//! 1. **Positional structural reject** — deny a *structural byte* (encoded separator,
//!    dot-segment, matrix-param, …) sitting anywhere a wildcard or catch-all captures
//!    it. Models **no backend**.
//! 2. **Case-fold reject** (under [`CaseSensitivity::Insensitive`] only) — lowercase
//!    the path, re-route the folded form, and deny if it lands on a *different* rule.
//!    Models the declared case-folding backend, precisely: `/files/ReadMe.TXT` folds
//!    within its own rule and is allowed; `/ADMIN` folding onto a distinct `/admin`
//!    rule is denied.
//! 3. **Content-decode reject** — percent-decode the path (lowercasing the result when
//!    the backend folds case), re-route the decoded form, and deny if it lands on a
//!    *different* rule. Models the one near-universal backend behaviour: RFC 3986
//!    percent-decoding.
//! 4. **Custom probes** — any [`StructuralProbe`] you registered, denied on presence.
//!
//! The checks are complementary along a principled line. The positional check covers
//! relocations that **shift segment boundaries or climb** the tree — there *where* a
//! byte lands decides the outcome, not its value; it over-approximates because those
//! transforms (slash-merging, `;`-strip, dot-resolution) are an open-ended *family*
//! the guard cannot enumerate per request. Case-fold and content-decode cover
//! relocations that **change which literal matches** — each models a *deterministic
//! declared transform* (fold, decode), so the guard simply applies it, re-routes, and
//! compares rules: precise, never an over-approximation. No single check is
//! sufficient; together they cover both axes.
//!
//! ## 1. Positional structural reject
//!
//! Rather than model what a backend *does* to a path, this asks a weaker,
//! backend-independent question. Registered patterns are **canonical** — a pattern that
//! itself carries a structural byte is a build error — so the literal parts of a matched
//! path match the pattern byte-for-byte, which means any structural byte in the request
//! necessarily lands inside a **wildcard or catch-all** capture. The default therefore
//! denies on the *presence* of such a byte: there is no per-table liveness to compute and
//! no backend parser to guess.
//!
//! - `..` / encoded-dot (dot-segment) and a `%00` NUL are denied **everywhere**: they
//!   climb or truncate onto another rule from any position.
//! - The **boundary-shifting** bytes — encoded separator (`%2F`, `//`), matrix-param
//!   (`;`), and (opt-in) backslash — are denied in any capture, because a decoded one
//!   could split the captured segment off its rule.
//!
//! ASCII case is **not** part of the positional check: under a case-folding backend it
//! is handled by the precise case-fold reject above, so uppercase content that folds
//! within its own rule is never denied.
//!
//! **Opaque key spaces.** A prefix that legitimately proxies opaque identifiers whose
//! keys contain encoded separators (object-store keys, …) opts its catch-all tail out of
//! the *boundary-shift* denial by registering it with `blob_subtree` instead of
//! `subtree`. Inside such a blob `%2F`/`;`/`\` are tolerated — but `..` and NUL are
//! **still** denied, so traversal cannot escape the blob (and the case-fold reject
//! still denies a fold that would relocate *out* of it, while a mixed-case key that
//! folds within the blob is fine). The opt-in is
//! **explicit and local**, never inferred from table shape: registering a more-specific
//! route *under* a `blob_subtree` is a build error (a structural byte could then relocate
//! into it), so the tolerance cannot be silently widened by an unrelated route.
//!
//! The check is a **sound over-approximation**: it denies `/users/4%2F2` on principle —
//! the encoded slash *could* split the `{id}` segment — even though that exact value
//! reaches no other route.
//!
//! ## 2. Content-decode reject
//!
//! A backend that percent-decodes the path (essentially all do) sees different
//! *content* in a segment, so `/%61dmin` is served as `/admin`. No boundary moved, so
//! the positional check cannot see it. The guard therefore decodes the path once
//! (twice when [`StructuralClasses::with_double_decode`] is set), lowercases it when the
//! backend is [`CaseSensitivity::Insensitive`] (a decoded escape can reveal an uppercase
//! byte — `/%41dmin` → `/Admin` → `/admin`), re-routes the result, and denies **only if
//! the matched rule changes**. This is **precise**, not an over-approximation:
//! `/foo%20bar` decodes to a same-rule path and is allowed, so opaque encoded content
//! keeps flowing.
//!
//! # What is covered
//!
//! | Backend behaviour | Coverage | Enable with |
//! |---|---|---|
//! | encoded slash `%2F`, empty segment `//` | **default** | — |
//! | dot-segments `.`/`..`, encoded `%2E` | **default** | — |
//! | matrix params `;` / `%3B` (servlet strip) | **default** | — |
//! | percent-decoding to a different literal (`/%61dmin`) | **default** | — |
//! | `\` / `%5C` as a separator (Windows / IIS) | opt-in | [`StructuralClasses::with_backslash`] |
//! | `%00` NUL truncation (C-string backends) | opt-in | [`StructuralClasses::with_null_truncation`] |
//! | overlong UTF-8 `%C0%AF` / `%C0%AE` (legacy decoders) | opt-in | [`StructuralClasses::with_overlong`] |
//! | double percent-decoding `%252F` (CDN/WAF → origin) | opt-in | [`StructuralClasses::with_double_decode`] / [`behind_decoding_proxy`](StructuralClasses::behind_decoding_proxy) |
//! | fullwidth/NFKC structural confusables (`／`→`/`, …) | opt-in | [`StructuralClasses::with_unicode_normalization`] |
//! | case folding `/ADMIN` ≡ `/admin` | **required** declaration | [`CaseSensitivity::Insensitive`] |
//! | a novel structural form (fresh CVE, vendor quirk) | break-glass | [`StructuralClasses::with_probe`] |
//!
//! # What is *not* covered
//!
//! The default alphabet is sound for a **conventional, standards-conforming backend**.
//! The guard models your backend's router as *the route matcher plus the transforms you
//! declare*, so it is only as complete as that configuration — and behaviours **outside
//! that envelope** are not seen at all. The residual risks — the things you, not the
//! library, are responsible for — are:
//!
//! - **Undeclared backend quirks.** If your backend treats `\` as a separator, folds
//!   case, truncates at NUL, or sits behind a second decoder and you have **not**
//!   enabled the matching toggle, that relocation is invisible to the guard. Each toggle
//!   is you asserting "my backend considers these paths equivalent"; the library cannot
//!   infer it and will not guess.
//! - **Unicode *content* confusables and non-NFKC look-alikes.** The structural NFKC
//!   confusables (`／`→`/`, `．`→`.`, `；`→`;`, `＼`→`\`) *are* covered, opt-in, by
//!   [`with_unicode_normalization`](StructuralClasses::with_unicode_normalization). What
//!   remains uncovered: fullwidth *letters* that NFKC-fold onto a different literal route
//!   (`/ＡＤＭＩＮ` → `/ADMIN` → `/admin` — a content relocation with no built-in class),
//!   and visual look-alikes NFKC does **not** decompose (U+2044 fraction slash, U+2215
//!   division slash). For these, deny non-ASCII paths with a [`StructuralProbe`] — blunt
//!   but sound, since a probe can only ever deny *more*:
//!
//!   ```
//!   use huskarl_pingora::path_confusion::{StructuralClasses, StructuralProbe};
//!
//!   struct RejectNonAscii;
//!   impl StructuralProbe for RejectNonAscii {
//!       fn name(&self) -> &'static str {
//!           "reject-non-ascii"
//!       }
//!       // Whole-path presence check. Scope it tighter (the specific confusables your
//!       // backend folds) if you must serve legitimate non-ASCII paths.
//!       fn matches(&self, path: &str) -> bool {
//!           !path.is_ascii()
//!       }
//!   }
//!
//!   let classes = StructuralClasses::new().with_probe(RejectNonAscii);
//!   ```
//! - **Trailing-slash / segment-presence equivalence.** A backend that treats
//!   `/admin/` ≡ `/admin` is not caught — `/admin/` carries no structural byte — so an
//!   exact `route("/admin", …)` lets `/admin/` fall through to the default rule while the
//!   backend still serves the admin resource. The defense here is rule *registration*,
//!   not detection: use `subtree` (one rule covering `/admin`, `/admin/`, and below)
//!   rather than `route` for anything you mean to protect.
//! - **Partial / selective decoding.** The content-decode check models a backend that
//!   decodes the whole path (the universal case). A backend that decodes only *some*
//!   escapes, or in an order all its own, is not modelled.
//! - **Forms with no class and no probe.** A structural form outside the built-in
//!   alphabet — including a future CVE — is invisible until you add a
//!   [`StructuralClasses::with_probe`] for it or a release ships it.
//! - **Path only.** Query and fragment are never examined; rules match on the path.
//! - **Detection, not sanitisation.** The guard denies or forwards the **raw** bytes; it
//!   never normalises the path it sends upstream. This is deliberate and load-bearing,
//!   not a gap — see [The guard never rewrites the path](#the-guard-never-rewrites-the-path--and-that-is-the-point).
//! - **Not a WAF.** The guard equalises *routing* — it ensures the rule you authorized
//!   is the rule the backend serves. It does not inspect content for injection, and it
//!   does not protect the backend from its *own* path-handling bugs beyond denying the
//!   confusable input: fronting CVE-2021-41773 stops the request reaching the vulnerable
//!   mapping, but the underlying traversal-to-file bug remains the backend's to fix.
//!
//! # Making the decision
//!
//! Three per-deployment choices, in order of importance:
//!
//! 1. **Declare [`CaseSensitivity`]** — required, no default. Pick
//!    [`Insensitive`](CaseSensitivity::Insensitive) for IIS / ASP.NET, servlet
//!    containers on Windows, or files served from a Windows/macOS filesystem;
//!    [`Sensitive`](CaseSensitivity::Sensitive) for a typical Unix-style backend.
//! 2. **Enable the [`StructuralClasses`] that match your stack.** Reach for
//!    [`with_backslash`](StructuralClasses::with_backslash) on Windows/IIS,
//!    [`with_null_truncation`](StructuralClasses::with_null_truncation) for a C-string
//!    backend, [`with_overlong`](StructuralClasses::with_overlong) for a decoder that
//!    accepts non-shortest-form UTF-8, and
//!    [`with_double_decode`](StructuralClasses::with_double_decode) /
//!    [`behind_decoding_proxy`](StructuralClasses::behind_decoding_proxy) whenever **two
//!    layers each decode** (a CDN or WAF in front of an origin, or proxy-in-front-of-proxy
//!    — the CVE-2025-0108 shape), and
//!    [`with_unicode_normalization`](StructuralClasses::with_unicode_normalization) for a
//!    backend you have **confirmed** Unicode-normalizes the path before routing. Leave a
//!    toggle off only when you are sure the backend does not do it.
//! 3. **Pick the [`PathConfusion`] mode.**
//!    [`reject_structural`](PathConfusion::reject_structural) (the default) is the
//!    positional reject described above and what almost everyone wants — pair it with
//!    `blob_subtree` where you serve opaque keys;
//!    [`reject_non_canonical`](PathConfusion::reject_non_canonical) is strict
//!    defense-in-depth that denies *any* non-canonical path — **including opaque blob
//!    keys and any percent-escape** — so opt in only where you serve no such content;
//!    [`off`](PathConfusion::off) disables the guard, appropriate only when the upstream
//!    fully normalises the path before authorising and you trust it to.
//!
//! **When you can't characterise the backend, err strict.** Every knob has a safe
//! direction: the stricter setting can only ever deny *more*, never fewer, so an
//! over-declaration costs false-positive `400`s but never a missed relocation. If you
//! can't confirm the case behaviour, declare
//! [`Insensitive`](CaseSensitivity::Insensitive) (it catches more — the cost is that
//! route patterns must then be lowercase). If there is *any* chance a CDN, WAF, or
//! second proxy fronts the origin, enable
//! [`with_double_decode`](StructuralClasses::with_double_decode). And if you can't
//! characterise the backend at all *and* serve no opaque or deliberately-encoded path
//! content, [`reject_non_canonical`](PathConfusion::reject_non_canonical) is the safe
//! default — it refuses every non-canonical path outright, trading availability for
//! certainty.
//!
//! # One configuration, because this layer cannot see the upstream
//!
//! The structural configuration is set once, for the whole guard, and that is a
//! consequence of *where this layer sits*, not a missing knob. The guard runs at
//! authorization time — **before** upstream selection, which happens lower down (the inner
//! proxy's peer choice) and may key on the host, headers, or its own routing, not just the
//! path. So this layer has an *authz* route table; it does **not** have, and cannot verify,
//! the binding from a request to the backend that will actually serve it.
//!
//! That is exactly why a single configuration is the safe one: the global profile is
//! correct over **every** upstream a request might reach — it is the worst case across all
//! of them, and the worst case holds no matter where the request is routed. The required
//! [`CaseSensitivity`] declaration and the [`StructuralClasses`] toggles are facts you
//! assert about *the backends behind you, collectively*; the guard then applies them
//! everywhere because it cannot tell which one any given request will hit.
//!
//! It is tempting to want per-route (≈ per-upstream) profiles — "stop applying IIS rules to
//! my Unix zone" — but the line between safe and unsafe refinement is the line between
//! tightening and relaxing, and it is drawn by this layer's blindness to the upstream:
//!
//! - **Tightening a specific rule is always sound.** Attaching *extra* strictness (or a
//!   custom check) to one rule, as an approximate stand-in for "I think this area talks to
//!   a nastier backend," can only ever deny more — so a wrong approximation costs
//!   false-positive `400`s, never a bypass, whatever upstream the traffic truly hits.
//! - **Relaxing a specific rule is the dangerous direction**, because it is the only one
//!   that *depends* on the rule→upstream binding being what you assumed — and this layer
//!   cannot confirm it. "This zone is Unix, stop checking `\`" becomes a clean relocation
//!   bypass the moment any of that zone's traffic is routed to a Windows backend. Unlike
//!   `blob_subtree` — whose relaxation is **bounded** (it still denies `..`, NUL, and any
//!   fold that relocates out of the blob, so even misuse cannot escape it) — a
//!   structural-class relaxation has no residual floor: a wrong guess is a straight hole.
//!
//! So the global strict profile is not a limitation to be refined away; it is the only
//! setting that does not rest on something this layer structurally cannot know. Refine
//! *upward* per rule if you must (it stays within the deny-more lattice); never refine
//! downward on the strength of an upstream you cannot see.
//!
//! Whether you register a rule with `subtree`, `blob_subtree`, or `route` is a related
//! security decision, documented at [the crate root](crate) and on the builder methods.

use std::sync::Arc;

/// Which path-confusion guard is active.
///
/// Defaults to [`RejectStructural`](PathConfusion::RejectStructural) — denies
/// structural bytes only where the route table makes them able to change which rule
/// matches.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PathConfusion {
    /// Deny (`400`) a request carrying a structural byte (`%2F`, `..`, `;`, …) wherever a
    /// wildcard or catch-all captures it — *positional structural reject*. Models **no
    /// backend**: because route patterns are canonical, any structural byte necessarily
    /// lands in a capture, so it denies on *presence* alone — no backend parser to guess.
    /// To tolerate encoded separators inside a genuine opaque key space, register the
    /// prefix with `blob_subtree` (an explicit, validated opt-in); `..` and NUL are
    /// denied even there, so traversal cannot escape the blob. **The default.**
    #[default]
    RejectStructural,
    /// Deny (`400`) any request carrying a structural byte (`%2F`, `..`, `//`, `;`)
    /// **anywhere** in the path — the strictest point on the same axis as
    /// [`RejectStructural`](Self::RejectStructural), with *every* position treated as
    /// live (the table is not consulted). Strict hygiene / defense in depth: refuses
    /// `..`, `//`, encoded separators, etc. outright, even where they wouldn't change
    /// the matched rule — so it also rejects legitimate encoded content (e.g. blob
    /// keys). Opt in deliberately. Honors the configured [`StructuralClasses`].
    RejectNonCanonical,
    /// Disable the guard entirely.
    Off,
}

impl PathConfusion {
    /// Deny structural bytes in route-relevant positions, without modeling the
    /// backend (positional structural reject; see
    /// [`RejectStructural`](Self::RejectStructural)). **The default.**
    #[must_use]
    pub fn reject_structural() -> Self {
        Self::RejectStructural
    }

    /// Deny any path carrying a structural byte anywhere — strict hygiene, the
    /// all-positions-live point of structural reject (see
    /// [`RejectNonCanonical`](Self::RejectNonCanonical)).
    #[must_use]
    pub fn reject_non_canonical() -> Self {
        Self::RejectNonCanonical
    }

    /// Disable the path-confusion guard.
    #[must_use]
    pub fn off() -> Self {
        Self::Off
    }
}

/// Whether the upstream resolves paths case-sensitively — a **required** declaration
/// on the `Guard` / `LoginProxy` builder. (Plain code spans, not links: this module
/// compiles under either feature alone, and each builder lives behind its own.)
///
/// Path matching here is case-sensitive (so is the route matcher). Whether that matches the
/// upstream is a security fact the library cannot infer and will not guess: a
/// case-folding backend (IIS, ASP.NET, servlet containers on Windows, files on a
/// Windows/macOS filesystem) routes `/ADMIN` and `/admin` identically, so a
/// differently-cased request can reach a rule *without its checks*. You must state
/// which world you are in; there is no default.
///
/// - [`Sensitive`](Self::Sensitive) — the upstream distinguishes case. Routes that
///   differ only by ASCII case are treated as genuinely distinct and allowed.
/// - [`Insensitive`](Self::Insensitive) — the upstream folds ASCII case. The guard runs
///   the **precise case-fold check**: it lowercases the request path, re-routes it, and
///   denies only if the folded path lands on a *different* rule — so mixed-case content
///   that folds within its own rule (`/files/ReadMe.TXT`) keeps flowing, while `/ADMIN`
///   folding onto a distinct `/admin` rule is denied. Route patterns must be registered
///   in lowercase (uppercase is a build error — it is the form the backend resolves
///   to), and two routes that differ only by case become a **hard config error** — the
///   table would otherwise be ambiguous on that backend. Models ASCII case only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaseSensitivity {
    /// The upstream distinguishes ASCII case (the typical Unix-style backend).
    Sensitive,
    /// The upstream folds ASCII case (IIS/ASP.NET, Windows/macOS filesystems).
    Insensitive,
}

impl CaseSensitivity {
    /// Whether this is [`Insensitive`](Self::Insensitive).
    pub(crate) fn is_insensitive(self) -> bool {
        matches!(self, Self::Insensitive)
    }
}

/// A structural character whose alternate (overlong-UTF-8) encodings a backend may
/// decode and then honor as path structure — the selector for
/// [`StructuralClasses::with_overlong`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructuralChar {
    /// `/` — the path separator (`%C0%AF`, …).
    Slash,
    /// `.` — feeds dot-segment (`.`/`..`) resolution (`%C0%AE`, …).
    Dot,
}

/// A user-defined structural detector — the **break-glass** for teaching the
/// structural modes a path form the built-in alphabet doesn't ship.
///
/// The built-in alphabet knows `%2F`, `..`, `;`, and the opt-in classes/encodings.
/// A backend that treats some *other* byte or encoding as path structure — a fresh
/// path-confusion CVE, a vendor quirk — is invisible to the structural modes until a
/// release adds the form. Wrap a detector in [`StructuralClasses::with_probe`] and it
/// is consulted on every request: return `true` and the request is denied as
/// ambiguous.
///
/// # Contract
///
/// `matches` must be **pure, deterministic, and ~O(n)** — it runs on every request.
/// The check is **whole-path**: presence *anywhere* denies, even inside an opaque
/// `blob_subtree` tail that tolerates the built-in boundary-shift bytes. That is the
/// sound, blunt semantics of a break-glass lever — by construction it can only
/// ever deny *more*, never fewer, so a probe cannot open an authorization hole, at the
/// cost of also rejecting legitimate content that carries the form. Scope the
/// predicate as tightly as you can (match the dangerous *sequence*, not a lone byte)
/// to limit that collateral, and fold the form into the alphabet proper once there is
/// time for a release.
pub trait StructuralProbe: Send + Sync {
    /// A short static identifier for this probe, used in `Debug` output.
    fn name(&self) -> &'static str;
    /// Whether `path` carries this probe's structural form. See the trait docs for
    /// the whole-path, all-positions-live contract.
    fn matches(&self, path: &str) -> bool;
}

/// The structural alphabet the guard recognises **beyond the always-on default
/// trio** (encoded-slash, dot-segment, matrix-param).
///
/// [`new`](Self::new) (the default) enables just that trio — the standard RFC 3986
/// path-resolution surface, sound for a conventional standards-conforming backend.
/// Turn on the opt-in classes and encodings to match a backend that considers *more*
/// paths equivalent:
///
/// ```
/// # use huskarl_pingora::path_confusion::{StructuralClasses, StructuralChar};
/// // A Windows/IIS-style backend that also decodes overlong UTF-8.
/// let classes = StructuralClasses::new()
///     .with_backslash()
///     .with_overlong([StructuralChar::Slash, StructuralChar::Dot]);
/// ```
///
/// Each toggle is a per-deployment **security** decision: enabling a class makes the
/// guard treat that form as route-structure (so it denies it wherever a capture holds
/// it); leaving it off assumes the backend does not. Case is **not** here — it is a
/// required, separate declaration on the builder
/// ([`CaseSensitivity`]) rather than an opt-in, because every deployment must answer it.
// Each field is an independent, orthogonal class/encoding toggle — a flat set of
// booleans is the clearest representation, not a code smell here.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Default)]
pub struct StructuralClasses {
    /// `\`/`%5C` as a path separator (Windows/IIS).
    pub(crate) backslash: bool,
    /// `%00` NUL truncation (C-string backends).
    pub(crate) truncation: bool,
    /// Recognise overlong UTF-8 `/` (`%C0%AF`, …).
    pub(crate) overlong_slash: bool,
    /// Recognise overlong UTF-8 `.` (`%C0%AE`, …).
    pub(crate) overlong_dot: bool,
    /// Recognise double-percent-encoded forms (`%252F`, …).
    pub(crate) double_decode: bool,
    /// Recognise fullwidth-form structural confusables (`／`/`．`/`；`/`＼`).
    pub(crate) unicode: bool,
    /// Custom break-glass detectors ([`StructuralProbe`]).
    pub(crate) probes: Vec<Arc<dyn StructuralProbe>>,
}

impl StructuralClasses {
    /// The default set: just the always-on trio (encoded-slash, dot-segment,
    /// matrix-param), no opt-in classes, encodings, or probes.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Treat `\`/`%5C` as a path separator — for Windows/IIS backends.
    #[must_use]
    pub fn with_backslash(mut self) -> Self {
        self.backslash = true;
        self
    }

    /// Treat `%00` (decoded NUL) as a path terminator — for a backend that reads the
    /// path as a C string, where `/public%00/admin` is seen as `/public`.
    #[must_use]
    pub fn with_null_truncation(mut self) -> Self {
        self.truncation = true;
        self
    }

    /// Recognise overlong (non-shortest-form) UTF-8 encodings of the given
    /// structural characters — `%C0%AF` → `/`, `%C0%AE` → `.`, plus their 3- and
    /// 4-byte forms — as their class. Standards-conforming decoders reject overlong
    /// forms, so this is off unless a backend that accepts them (the classic
    /// legacy-IIS Unicode traversal vector) is being modeled.
    #[must_use]
    pub fn with_overlong(mut self, chars: impl IntoIterator<Item = StructuralChar>) -> Self {
        for c in chars {
            match c {
                StructuralChar::Slash => self.overlong_slash = true,
                StructuralChar::Dot => self.overlong_dot = true,
            }
        }
        self
    }

    /// Recognise double-percent-encoded structural bytes (`%252F` → `/`, `%253B` →
    /// `;`, …) — for a declared double-decoding chain (a proxy decodes, then the app
    /// decodes again). Off by default: a single backend pass leaves `%252F` as `%2F`.
    ///
    /// Enable this whenever **two layers each decode** — a CDN/WAF in front of an
    /// origin, or one proxy in front of another. That layering is exactly
    /// **CVE-2025-0108** (Palo Alto PAN-OS): nginx decoded `%252e%252e` once to
    /// `%2e%2e` and let it past a no-auth prefix, then Apache decoded *again* to `..`
    /// and traversed into a protected script. The default catches the single-encoded
    /// `%2e%2e`; this option is what catches the double-encoded evasion that slips a
    /// single-pass front.
    ///
    /// Scope: this models the **canonical** double-encoding, where the `%` itself is
    /// encoded (`%25` + `2e` = `%252e`) — the form *any* double-decoder resolves.
    /// Apache **CVE-2021-42013** used a narrower variant, `%%32%65` (a bare `%` plus
    /// encoded *digits*), which resolves to `.` only on a decoder that *also* treats a
    /// malformed `%` as a literal and keeps going — a quirk beyond "decodes twice", and
    /// one a strict double-decoder would reject. That decoder-leniency form is a
    /// [`with_probe`](Self::with_probe) (custom break-glass) case, not something this
    /// option implies.
    #[must_use]
    pub fn with_double_decode(mut self) -> Self {
        self.double_decode = true;
        self
    }

    /// Recognise the **fullwidth-form** structural confusables — `／` (U+FF0F), `．`
    /// (U+FF0E), `；` (U+FF1B), and (when [`with_backslash`](Self::with_backslash) is also
    /// set) `＼` (U+FF3C) — that NFKC compatibility normalization folds to `/`, `.`, `;`,
    /// `\`, in both raw and percent-encoded (`%EF%BC%8F`) form. Enable this for a backend
    /// that Unicode-normalizes the path before routing: such a backend treats
    /// `/api／secret` as `/api/secret`, so the fullwidth solidus is a separator the guard
    /// must account for.
    ///
    /// Scope is **NFKC structural** confusables only — the handful of fullwidth forms
    /// that fold to a delimiter. Two related things are deliberately *not* covered:
    /// fullwidth *letters* that fold onto a different literal route (`/ＡＤＭＩＮ` →
    /// `/admin`, a content relocation), and visual look-alikes NFKC does not decompose
    /// (U+2044 fraction slash, U+2215 division slash). For either, use a
    /// [`with_probe`](Self::with_probe) — e.g. one that denies non-ASCII paths.
    #[must_use]
    pub fn with_unicode_normalization(mut self) -> Self {
        self.unicode = true;
        self
    }

    /// Add a custom break-glass [`StructuralProbe`] — for a structural form the
    /// built-in alphabet doesn't ship (e.g. an incident mitigation). See
    /// [`StructuralProbe`] for the whole-path, all-positions-live semantics.
    #[must_use]
    pub fn with_probe(mut self, probe: impl StructuralProbe + 'static) -> Self {
        self.probes.push(Arc::new(probe));
        self
    }

    /// **Preset.** The structural set for a deployment with a **decoding layer in
    /// front** of the backend — a CDN, WAF, or proxy-in-front-of-proxy — where the
    /// path is percent-decoded more than once before it is finally routed.
    ///
    /// Named for the *topology* that calls for it (the CVE-2025-0108 / CVE-2021-42013
    /// double-decode shape) so the reason to enable it is discoverable, and as the
    /// home for any future layered-decode forms. Equivalent to
    /// [`with_double_decode`](Self::with_double_decode) today.
    ///
    /// Models the canonical `%252e` double-encoding; the decoder-leniency variant
    /// `%%32%65` (Apache CVE-2021-42013) still needs a custom
    /// [`with_probe`](Self::with_probe) — see [`with_double_decode`](Self::with_double_decode).
    #[must_use]
    pub fn behind_decoding_proxy(self) -> Self {
        self.with_double_decode()
    }
}

impl std::fmt::Debug for StructuralClasses {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let probes: Vec<&'static str> = self.probes.iter().map(|p| p.name()).collect();
        f.debug_struct("StructuralClasses")
            .field("backslash", &self.backslash)
            .field("truncation", &self.truncation)
            .field("overlong_slash", &self.overlong_slash)
            .field("overlong_dot", &self.overlong_dot)
            .field("double_decode", &self.double_decode)
            .field("unicode", &self.unicode)
            .field("probes", &probes)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_trio_only() {
        let c = StructuralClasses::new();
        assert!(!c.backslash);
        assert!(!c.truncation);
        assert!(!c.overlong_slash);
        assert!(!c.overlong_dot);
        assert!(!c.double_decode);
        assert!(!c.unicode);
        assert!(c.probes.is_empty());
    }

    #[test]
    fn builders_toggle_their_field() {
        assert!(StructuralClasses::new().with_backslash().backslash);
        assert!(StructuralClasses::new().with_null_truncation().truncation);
        assert!(StructuralClasses::new().with_double_decode().double_decode);
        assert!(
            StructuralClasses::new()
                .with_unicode_normalization()
                .unicode
        );

        let both =
            StructuralClasses::new().with_overlong([StructuralChar::Slash, StructuralChar::Dot]);
        assert!(both.overlong_slash && both.overlong_dot);
        let slash_only = StructuralClasses::new().with_overlong([StructuralChar::Slash]);
        assert!(slash_only.overlong_slash && !slash_only.overlong_dot);
    }

    #[test]
    fn behind_decoding_proxy_preset_enables_double_decode() {
        // The topology-named preset is the canonical double-decode toggle.
        assert!(
            StructuralClasses::new()
                .behind_decoding_proxy()
                .double_decode
        );
    }

    #[test]
    fn probe_registered_and_named() {
        struct P;
        impl StructuralProbe for P {
            fn name(&self) -> &'static str {
                "p"
            }
            fn matches(&self, path: &str) -> bool {
                path.contains('~')
            }
        }
        let c = StructuralClasses::new().with_probe(P);
        assert_eq!(c.probes.len(), 1);
        assert!(c.probes[0].matches("/a~b"));
        assert!(!c.probes[0].matches("/ab"));
        // probe does not flip any class field
        assert!(!c.backslash && !c.truncation);
    }
}
