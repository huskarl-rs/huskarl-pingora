//! Metrics emitted by the resource [`Guard`](crate::resource::Guard) through the
//! [`metrics`] facade. Install a recorder (e.g. `metrics-exporter-prometheus`) to
//! collect them; without one they are no-ops. All are counters, incremented inline on
//! the request path.
//!
//! | Counter | Labels |
//! |---------|--------|
//! | `huskarl.resource.check` | `outcome`: [`CheckOutcome`] values (`forward`, `path_confusion`, `unauthenticated`, `invalid_token`, `insufficient_scope`, `invalid_request`) |
//!
//! One counter is emitted per [`Guard::check_request`](crate::resource::Guard::check_request)
//! call, so `forward` counts successes and every other value is a denial broken out by
//! reason. `path_confusion` is the path-confusion guard's ambiguous-path `400` — kept
//! distinct from `invalid_request` so a spike in confusable-path probing is visible on
//! its own, independent of routine malformed requests.
//!
//! **Cardinality.** The `outcome` label is a fixed, closed enum — the request path (which
//! an attacker fully controls) is **never** used as a label, so no input can inflate the
//! series count. When `metrics_name` is set on the [`Guard`](crate::resource::Guard)
//! builder, every counter additionally carries a `name` label with that value, telling
//! guard instances apart when one process runs several.

/// Increments counter `name` with `labels`, appending the instance `name` label when
/// `metrics_name` is set.
pub(crate) fn emit_counter(
    name: &'static str,
    mut labels: Vec<metrics::Label>,
    metrics_name: Option<&str>,
) {
    if let Some(v) = metrics_name {
        labels.push(metrics::Label::new("name", v.to_owned()));
    }
    metrics::counter!(name, labels).increment(1);
}

/// The name of the per-request outcome counter.
pub(crate) const CHECK_COUNTER: &str = "huskarl.resource.check";

/// The outcome of one [`Guard::check_request`](crate::resource::Guard::check_request)
/// call; the `outcome` label on [`CHECK_COUNTER`]. A closed set so it is safe to use as a
/// metric label (never the attacker-controlled path).
#[derive(strum::IntoStaticStr, Clone, Copy, Debug, PartialEq, Eq)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum CheckOutcome {
    /// The request was forwarded upstream (public, authenticated, or optional-no-token).
    Forward,
    /// Denied `400` by the path-confusion guard: the path is ambiguous under the modeled
    /// backend transforms.
    PathConfusion,
    /// Denied `401`: authentication is required but no token was presented.
    Unauthenticated,
    /// Denied `401`: a token was presented but is invalid (bad token, or wrong audience).
    InvalidToken,
    /// Denied `403`: the token is valid but lacks a required scope (or failed a custom
    /// forbidden check).
    InsufficientScope,
    /// Denied `400` for a malformed request other than path confusion (e.g. an
    /// unreconstructable request URI).
    InvalidRequest,
}

impl CheckOutcome {
    /// The `snake_case` label value.
    pub(crate) fn as_str(self) -> &'static str {
        self.into()
    }

    /// Emit [`CHECK_COUNTER`] for this outcome, carrying the optional instance name.
    pub(crate) fn emit(self, metrics_name: Option<&str>) {
        emit_counter(
            CHECK_COUNTER,
            vec![metrics::Label::new("outcome", self.as_str())],
            metrics_name,
        );
    }
}
