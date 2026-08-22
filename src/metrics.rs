//! Metrics emitted by the resource [`Guard`](crate::resource::Guard) through the
//! [`metrics`] facade. Install a recorder (e.g. `metrics-exporter-prometheus`) to
//! collect them; without one they are no-ops. All are counters, incremented inline on
//! the request path.
//!
//! | Counter | Labels |
//! |---------|--------|
//! | `huskarl.resource.check` | `outcome`: [`CheckOutcome`] values (`forward`, `path_confusion`, `unauthenticated`, `invalid_token`, `expired`, `unrecognized_issuer`, `binding_error`, `nonce_required`, `insufficient_scope`, `invalid_request`, `server_error`) |
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

use crate::resource_server::validator::observe::ValidationOutcome;

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
    /// Denied `401`: a token was presented but is invalid — bad signature, wrong
    /// audience, inactive, or an `iss` the validator rejected on its own terms.
    /// Distinct from [`UnrecognizedIssuer`](Self::UnrecognizedIssuer), which is a
    /// multi-issuer routing miss rather than a verdict on the token.
    InvalidToken,
    /// Denied `401`: the token was rejected for being expired. Split from
    /// [`InvalidToken`](Self::InvalidToken) because late-refreshing clients make expiry
    /// the highest-volume benign rejection; folding it in would mask signature-failure
    /// spikes, the classic broken-key-rotation signal.
    Expired,
    /// Denied `401`: the token's `iss` was missing, unparseable, or not registered with
    /// a multi-issuer validator — a client pointed at the wrong authorization server, or
    /// someone probing which issuers this resource accepts.
    ///
    /// Split from [`InvalidToken`](Self::InvalidToken) for the same reason
    /// [`PathConfusion`](Self::PathConfusion) is split from
    /// [`InvalidRequest`](Self::InvalidRequest): it is normally flat at zero, so movement
    /// is legible on its own and would be invisible inside the routine-rejection bucket.
    UnrecognizedIssuer,
    /// Denied `401`: a sender-constraint binding check failed (`DPoP` or mTLS) — the
    /// possible-stolen-token bucket (RFC 9449 §7.1), and the one worth alerting on.
    BindingError,
    /// Denied `401`: a `DPoP` nonce is required and was supplied, so the client retries
    /// (RFC 9449 §8). Routine protocol churn under server-side nonce enforcement, kept
    /// out of [`BindingError`](Self::BindingError) so that bucket stays a clean signal.
    NonceRequired,
    /// Denied `403`: the token is valid but lacks a required scope (or failed a custom
    /// forbidden check).
    InsufficientScope,
    /// Denied `400` for a malformed request other than path confusion — an
    /// unreconstructable request URI, or credentials that could not be parsed out of the
    /// request headers.
    InvalidRequest,
    /// Denied `5xx`: the resource server itself failed — a backing call broke
    /// (introspection endpoint, replay store, nonce checker) or the deployment is
    /// misintegrated. The token was never judged, so this is **not** a token rejection;
    /// it mirrors the 5xx response and belongs in an availability alert, not a security
    /// one.
    ServerError,
}

impl CheckOutcome {
    /// Classifies a validator rejection for the `outcome` label.
    ///
    /// The validator knows *why* it rejected — whether the token was merely expired, a
    /// binding check failed, or the resource server could not reach a backing service at
    /// all. Folding all of that into [`InvalidToken`](Self::InvalidToken) would both hide
    /// the alertable buckets and mislabel a 5xx as a token rejection, so each
    /// distinguishable reason gets its own label.
    ///
    /// [`ValidationOutcome`] is `#[non_exhaustive]`; a future outcome this crate does not
    /// yet model falls back to [`InvalidToken`](Self::InvalidToken), the coarse
    /// classification callers got before the split. `Success` and `NoToken` reach the
    /// same arm but are unreachable in practice — this runs only on the error path, and a
    /// credential-less request is counted [`Unauthenticated`](Self::Unauthenticated)
    /// before it gets here.
    pub(crate) fn from_validation(outcome: ValidationOutcome) -> Self {
        match outcome {
            ValidationOutcome::CallError => Self::ServerError,
            ValidationOutcome::BindingError => Self::BindingError,
            ValidationOutcome::NonceRequired => Self::NonceRequired,
            ValidationOutcome::Expired => Self::Expired,
            ValidationOutcome::UnrecognizedIssuer => Self::UnrecognizedIssuer,
            // The token could not be parsed out of the request at all — a malformed
            // request (`400`), not a judged-and-rejected token.
            ValidationOutcome::ExtractError => Self::InvalidRequest,
            _ => Self::InvalidToken,
        }
    }

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
