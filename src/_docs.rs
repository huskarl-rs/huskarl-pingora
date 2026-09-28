//! Guides for learning and operating a huskarl Pingora proxy.
//!
//! Choose [tutorial] for a guided first run, [how_to] for a task, or
//! [explanation] for design reasoning. Public API modules are the reference.

/// Guided first runs. Available pages depend on enabled features.
#[cfg_attr(
    feature = "login",
    doc = "Start with [Browser login](tutorial::browser_login)."
)]
pub mod tutorial {
    #[cfg(feature = "login")]
    #[doc = include_str!("../docs/tutorial/browser_login.md")]
    pub mod browser_login {}
}

/// Complete an integration or deployment task.
/// Start with [Deploy a proxy](how_to::deployment) before exposing it beyond localhost.
#[cfg_attr(
    any(feature = "login", feature = "resource"),
    doc = "Choose [route policies](how_to::routes), [configure the path guard](how_to::path_guard), [customize error responses](how_to::error_responses), or [troubleshoot a proxy](how_to::troubleshooting)."
)]
#[cfg_attr(
    feature = "login",
    doc = "[Forward session identity](how_to::identity) to an upstream service."
)]
#[cfg_attr(
    feature = "resource",
    doc = "[Build a bearer-token proxy](how_to::resource_proxy)."
)]
pub mod how_to {
    #[cfg(any(feature = "login", feature = "resource"))]
    #[doc = include_str!("../docs/how_to/error_responses.md")]
    pub mod error_responses {}
    #[doc = include_str!("../docs/how_to/deployment.md")]
    pub mod deployment {}
    #[cfg(any(feature = "login", feature = "resource"))]
    #[doc = include_str!("../docs/how_to/routes.md")]
    pub mod routes {}
    #[cfg(any(feature = "login", feature = "resource"))]
    #[doc = include_str!("../docs/how_to/path_guard.md")]
    pub mod path_guard {}
    #[cfg(any(feature = "login", feature = "resource"))]
    #[doc = include_str!("../docs/how_to/troubleshooting.md")]
    pub mod troubleshooting {}
    #[cfg(feature = "login")]
    #[doc = include_str!("../docs/how_to/identity.md")]
    pub mod identity {}
    #[cfg(feature = "resource")]
    #[doc = include_str!("../docs/how_to/resource_proxy.md")]
    pub mod resource_proxy {}
}

/// Design, lifecycle, and security boundaries.
#[cfg_attr(
    any(feature = "login", feature = "resource"),
    doc = "Read [Path confusion](explanation::path_confusion)."
)]
#[cfg_attr(
    feature = "login",
    doc = "Read [Login proxy lifecycle](explanation::login_lifecycle)."
)]
pub mod explanation {
    #[cfg(any(feature = "login", feature = "resource"))]
    #[doc = include_str!("../docs/explanation/path_confusion.md")]
    pub mod path_confusion {}
    #[cfg(feature = "login")]
    #[doc = include_str!("../docs/explanation/login_lifecycle.md")]
    pub mod login_lifecycle {}
}

/// Configuration details complementing the public API reference.
#[cfg_attr(
    any(feature = "login", feature = "resource"),
    doc = "Look up [path-guard configuration](reference::path_guard)."
)]
pub mod reference {
    #[cfg(any(feature = "login", feature = "resource"))]
    #[doc = include_str!("../docs/reference/path_guard.md")]
    pub mod path_guard {}
}
