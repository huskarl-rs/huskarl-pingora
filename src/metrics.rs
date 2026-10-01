//! Private emission helpers. See the telemetry reference for metric contracts.

#[cfg(feature = "resource")]
use crate::resource_server::validator::observe::ValidationOutcome;

/// Closed call-site labels only; allocation and recorder calls compile out entirely.
#[inline]
pub(crate) fn emit_counter(metric: &'static str, outcome: &'static str, name: Option<&str>) {
    #[cfg(feature = "metrics")]
    metrics::counter!(metric, "outcome" => outcome, "name" => name.unwrap_or_default().to_owned())
        .increment(1);
    #[cfg(not(feature = "metrics"))]
    let _ = (metric, outcome, name);
}

/// Counts one route selection, including fallback and metadata selection.
#[cfg(feature = "resource")]
pub(crate) fn route_outcome(
    error: Option<&crate::path_confusion::ResolveError>,
    name: Option<&str>,
) {
    emit_counter(
        "huskarl.pingora.resource.route",
        error.map_or("selected", route_denial),
        name,
    );
}

pub(crate) fn route_denial(error: &crate::path_confusion::ResolveError) -> &'static str {
    use crate::path_confusion::ResolveErrorKind;
    match error.kind() {
        ResolveErrorKind::InvalidInput => "path_confusion",
        ResolveErrorKind::PolicyDenied => "policy_denied",
        ResolveErrorKind::Internal => "server_error",
    }
}

#[cfg(feature = "login")]
pub(crate) fn login_operation(
    operation: crate::login::SessionOperation,
    phase: crate::login::LoginPhase,
    success: bool,
    name: Option<&str>,
) {
    #[cfg(feature = "metrics")]
    metrics::counter!(
        "huskarl.pingora.login.session_operation",
        "operation" => operation.as_str(),
        "phase" => phase.as_str(),
        "outcome" => if success { "success" } else { "error" },
        "name" => name.unwrap_or_default().to_owned(),
    )
    .increment(1);
    #[cfg(not(feature = "metrics"))]
    let _ = (operation, phase, success, name);
}

#[cfg(feature = "login")]
pub(crate) fn stranded_cookies(count: usize, name: Option<&str>) {
    #[cfg(feature = "metrics")]
    metrics::counter!("huskarl.pingora.login.stranded_cookies", "name" => name.unwrap_or_default().to_owned()).increment(count as u64);
    #[cfg(not(feature = "metrics"))]
    let _ = (count, name);
}

/// The name of the per-request outcome counter.
#[cfg(feature = "resource")]
pub(crate) const CHECK_COUNTER: &str = "huskarl.resource.check";

/// The outcome of one [`Guard::check_request`](crate::resource::Guard::check_request)
/// call; the `outcome` label on [`CHECK_COUNTER`]. A closed set so it is safe to use as a
/// metric label (never the attacker-controlled path).
#[cfg(feature = "resource")]
#[derive(strum::IntoStaticStr, Clone, Copy, Debug, PartialEq, Eq)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum CheckOutcome {
    /// Policy permits continuation (public, authenticated, or optional-no-token).
    Forward,
    /// Denied `400` by the path-confusion guard: the path is ambiguous under the modeled
    /// backend transforms.
    PathConfusion,
    /// The request method has no configured authorization policy.
    PolicyDenied,
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

#[cfg(feature = "resource")]
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
        emit_counter(CHECK_COUNTER, self.as_str(), metrics_name);
    }
}
