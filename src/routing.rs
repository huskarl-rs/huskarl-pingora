//! Route registration shared by the resource and login builders.

use huskarl_route_guard::PathRegistration;

use crate::method::MethodMatch;

pub(crate) enum RouteKind {
    Exact,
    Subtree,
    Blob,
}

impl RouteKind {
    pub(crate) fn registration<R>(
        self,
        pattern: String,
        method: MethodMatch,
        rule: R,
    ) -> PathRegistration<R> {
        let registration = match self {
            Self::Exact => PathRegistration::path(pattern),
            Self::Subtree => PathRegistration::subtree(&pattern),
            Self::Blob => PathRegistration::exclusive_subtree(&pattern),
        };
        match method {
            MethodMatch::Any => registration.all(rule),
            MethodMatch::OneOf(methods) => registration.methods(methods, rule),
        }
    }
}
