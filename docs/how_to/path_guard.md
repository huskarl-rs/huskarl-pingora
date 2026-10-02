# Configure the path guard

Use this when constructing a login or resource proxy. First establish how the
upstream and every intermediary parse paths; the guard cannot infer that from
their product names.

## 1. Declare case sensitivity and decode depth

Choose `Sensitive` if your complete downstream routing pipeline distinguishes
case, or `Insensitive` if it folds ASCII case. Count whole-path percent-decoding
passes across the pipeline: declare `UpToOne` or `UpToTwo`. More than two passes
are outside the supported model.

For a case-sensitive upstream with at most one decoding pass:

```rust
use huskarl_pingora::path_confusion::{CaseSensitivity, DecodeDepth, GuardConfig};

let path_guard = GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne);
```

Pass this value to `.path_guard(path_guard)` on `LoginProxy::builder()` or
`ResourcePolicy::builder()`. The tutorial's small Python upstream compares the path
without decoding or case folding, so these declarations cover it.

## 2. Add structural forms your downstream accepts

If a downstream component treats backslashes as separators, enable
`StructuralClasses::new().with_backslash()` through
`GuardConfig::with_structural_classes`. Declare any other supported equivalents
that apply. See the [configuration reference](crate::_docs::reference::path_guard)
for overlong encodings and custom probes.

## 3. Select a mode and budget

Keep `RejectAmbiguous` to reject paths whose supported downstream
interpretations select different rules. Choose `RequireCanonical` when you
intend to reject recognized structural forms even inside a uniform subtree.
`Disabled` skips ambiguity analysis but still validates input and enforces
method policy. Set `with_max_analysis_path_len` to your analysis budget; this is
separate from the proxy's general request-size limits.

## 4. Exercise the actual route boundaries

Use a fixture upstream and `curl --path-as-is` to check encoded separators,
dot segments, case variants, and disallowed methods. Include the full rewrite
pipeline. Confirm that accepted requests reach only resources covered by the
selected policy. A uniform rule table cannot protect finer permissions enforced
elsewhere; read [Path confusion](crate::_docs::explanation::path_confusion).
