# Path-guard configuration

Both `LoginProxy::builder()` and `Guard::builder()` require
`.path_guard(GuardConfig::new(case_sensitivity, decode_depth))`. Configure the
mode, additional structural classes, and analysis budget on that `GuardConfig`
with `with_mode`, `with_structural_classes`, and `with_max_analysis_path_len`.
These replace the separate `case_sensitivity`, `decode_depth`, `guard_mode`,
`structural_classes`, and `max_analysis_path_len` builder setters.

`GuardConfig` is re-exported by both `login` and `resource`, and is also
available in `path_confusion`. Clone one configuration for guards with the same
downstream parsing assumptions, or pass it directly to a
`huskarl_route_guard::RuleRouter`. Sharing configuration does not share route
rules: each layer still needs its own authorization boundaries; see
[Path confusion](crate::_docs::explanation::path_confusion).
Decode depth can differ by layer, so only reuse a configuration where its
assumptions hold.

## Opt-in classes and encodings

The always-on alphabet is encoded slash, dot-segments, `;`-matrix-params, and
`%00`/raw-NUL truncation — the forms whose legitimate-traffic cost is near nil. A
backend that considers *more* paths equivalent needs the matching toggle on
[`StructuralClasses`](crate::path_confusion::StructuralClasses), passed via
`GuardConfig::with_structural_classes`:

- [`with_backslash()`](crate::path_confusion::StructuralClasses::with_backslash) — `\`/`%5C`
  as a separator (Windows/IIS);
- [`with_overlong([…])`](crate::path_confusion::StructuralClasses::with_overlong) —
  recognise overlong-UTF-8 forms (`%C0%AF`) accepted by legacy decoders;
- [`with_probe(p)`](crate::path_confusion::StructuralClasses::with_probe) — a custom
  [`StructuralProbe`](crate::path_confusion::StructuralProbe) **break-glass** for a structural
  form the built-in alphabet doesn't ship (e.g. a fresh CVE), denied on presence
  anywhere in the path.

Each toggle is a per-deployment security decision: it is how you tell the guard
which paths your backend considers equivalent. Example:
`StructuralClasses::new().with_backslash()`. (Case and decode depth are **not**
here — they are required arguments to `GuardConfig::new`; see below.)

## Decode depth

`GuardConfig::new` requires [`DecodeDepth`](crate::path_confusion::DecodeDepth), with no default.
Declare `UpToOne` when downstream performs at most one whole-path percent decode,
or `UpToTwo` when it may perform up to two. Count actual decoding passes across
intermediaries and the origin, rather than the number of processes. More than
two passes are outside the supported model.

## Case-insensitive backends

Path matching here is **case-sensitive** (and so is the route matcher), but whether that
matches your upstream is a security fact the library cannot infer — so `GuardConfig::new`
**requires** you to declare it with
[`CaseSensitivity`](crate::path_confusion::CaseSensitivity); there is no default. A case-folding
upstream — IIS, ASP.NET, servlet containers on Windows, or anything serving files
from a Windows/macOS filesystem — routes `/ADMIN` and `/admin` to the same resource,
so a differently-cased request can reach a route *without that route's checks*
(`/ADMIN` falling through to a weaker rule, then served as `/admin`).

- [`Sensitive`](crate::path_confusion::CaseSensitivity::Sensitive) — the upstream distinguishes
  case; routes differing only by case are genuinely distinct and allowed.
- [`Insensitive`](crate::path_confusion::CaseSensitivity::Insensitive) — the upstream folds
  case. The guard then runs a **precise case-fold check**: it lowercases the request
  path, re-routes it, and denies only if the folded path lands on a *different* rule
  — mixed-case content that folds within its own rule (`/files/ReadMe.TXT`) keeps
  flowing, while `/ADMIN` folding onto a distinct `/admin` rule is denied. **Route
  patterns must be registered in lowercase** (an uppercase pattern is a build error —
  it is the form the backend resolves to), and two routes differing only by case are
  rejected at build. Only ASCII case is modeled.

## Strict mode, disabled mode, and analysis budget

[`GuardMode::RequireCanonical`](crate::path_confusion::GuardMode::RequireCanonical)
rejects recognized structural forms and complete percent escapes even within a
uniform subtree. [`GuardMode::Disabled`](crate::path_confusion::GuardMode::Disabled)
disables ambiguity analysis, but still validates path input and denies unlisted
methods. Select the mode with `GuardConfig::with_mode(...)`.

`GuardConfig::with_max_analysis_path_len(...)` sets the analysis budget in original path bytes
(default: 8,192). With custom probes it applies to every path; disabled mode
bypasses the budget. This is not an overall request-size limit.

Active modes reject non-canonical route patterns at construction time.
