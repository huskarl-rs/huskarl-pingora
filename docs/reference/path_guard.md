# Path-guard configuration

Both `LoginProxy::builder()` and `ResourcePolicy::builder()` require
`.path_guard(GuardConfig::new(case_sensitivity, decode_depth))`. Configure the
mode, additional structural classes, and analysis budget on that `GuardConfig`
with `with_mode`, `with_structural_classes`, and `with_max_analysis_path_len`.

| Setting | Required/default | Meaning |
|---|---|---|
| Case sensitivity | Required: `Sensitive` or `Insensitive` | Whether downstream routing folds ASCII case |
| Decode depth | Required: `UpToOne` or `UpToTwo` | Maximum whole-path percent-decoding passes downstream |
| Mode | `RejectAmbiguous` | Reject supported interpretations that select different rules |
| Backslash separators | Enabled | Model raw and percent-encoded backslashes as separators |
| Additional encodings/probes | None | Opt in to overlong encodings, fullwidth structural forms, or custom probes |
| Maximum analysis path length | 8,192 original path bytes | Analysis budget, separate from request-size limits |

For a configuration sequence, follow [Configure the path guard](crate::_docs::how_to::path_guard).

`GuardConfig` is re-exported by both `login` and `resource`, and is also
available in `path_confusion`. Clone one configuration for guards with the same
downstream parsing assumptions, or pass it directly to a
`huskarl_route_guard::RuleRouter`. Sharing configuration does not share route
rules: each layer still needs its own authorization boundaries; see
[Path confusion](crate::_docs::explanation::path_confusion).
Decode depth can differ by layer, so only reuse a configuration where its
assumptions hold.

## Structural classes and encodings

The default alphabet includes encoded slash, dot-segments, matrix parameters,
NUL truncation, and backslash separators. Backslashes are included conservatively:
URL parsers can treat them as separators even on Unix. `StructuralClasses::new()`
uses this default set.

Configure additional forms through
[`StructuralClasses`](crate::path_confusion::StructuralClasses), then pass the
result to `GuardConfig::with_structural_classes`:

| Method | Effect |
|---|---|
| [`without_backslash()`](crate::path_confusion::StructuralClasses::without_backslash) | Treat backslashes as content; use only when every downstream component preserves them |
| [`with_backslash()`](crate::path_confusion::StructuralClasses::with_backslash) | Restore default backslash handling |
| [`with_overlong(...)`](crate::path_confusion::StructuralClasses::with_overlong) | Model overlong UTF-8 slash/dot encodings accepted by a legacy decoder |
| [`with_fullwidth_structure()`](crate::path_confusion::StructuralClasses::with_fullwidth_structure) | Model fullwidth structural characters that NFKC normalization maps to delimiters |
| [`with_probe(p)`](crate::path_confusion::StructuralClasses::with_probe) | Reject paths matched by an application-supplied structural detector |

These settings declare actual downstream behavior. Unicode support covers the
specified structural forms, not all Unicode route equivalences; consult the
method's contract before enabling it. A custom probe sees the original path and
must account for relevant escaped spellings. See
[`StructuralProbe`](crate::path_confusion::StructuralProbe) for its execution contract.
Case sensitivity and decode depth are separate required settings.

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
upstream, such as a service using a case-insensitive filesystem, routes `/ADMIN` and `/admin` to the same resource,
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
