//! Optional diagnostics for failures handled inside the login adapter.

use huskarl_login::SessionError;

/// Adapter phase in which session work was attempted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LoginPhase {
    /// Request session loading.
    Request,
    /// Persistence before serving an authorization denial.
    Denied,
    /// Final downstream response-header preparation, including local responses.
    Response,
    /// Cleanup after a direct response or proxy failure.
    Logging,
}

/// Session operation invoked by the adapter, not the engine's internal steps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SessionOperation {
    /// Load the request's session.
    Load,
    /// Retry an owed session persist.
    Persist,
    /// Terminate the local session using the driver's revocation operation.
    Revoke,
}

impl LoginPhase {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Denied => "denied",
            Self::Response => "response",
            Self::Logging => "logging",
        }
    }
}

impl SessionOperation {
    #[cfg(feature = "metrics")]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Load => "load",
            Self::Persist => "persist",
            Self::Revoke => "revoke",
        }
    }
}

/// Diagnostic detail that would otherwise be consumed inside the adapter.
///
/// Configure with [`LoginProxy::diagnostics`](super::LoginProxy::diagnostics).
/// These are operational notifications, not session lifecycle or durable audit
/// events. Error context and sources may contain sensitive or untrusted values;
/// redact them before export and never use them as metric labels. No cookie,
/// token, subject, or request path is added by the adapter.
#[derive(Debug)]
#[non_exhaustive]
pub enum LoginDiagnostic<'a> {
    /// An adapter-owned operation failed. The error is borrowed for this call.
    SessionFailure {
        /// Operation that failed.
        operation: SessionOperation,
        /// Where the adapter invoked it.
        phase: LoginPhase,
        /// Original error, including its source chain.
        error: &'a SessionError,
    },
    /// Prepared cookie headers could not be attached in the logging fallback.
    /// This does not assert anything about the browser's current session state.
    StrandedCookies {
        /// Number of discarded `Set-Cookie` headers in this batch.
        count: usize,
    },
}

pub(super) type DiagnosticHandler = std::sync::Arc<dyn Fn(LoginDiagnostic<'_>) + Send + Sync>;
