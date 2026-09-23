/// HTTP methods selected by a proxy rule.
///
/// Method-specific rules override an all-method rule at the same path. Without
/// an all-method rule, unlisted methods are denied before authentication.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum MethodMatch {
    /// Applies to every method without a specific override.
    #[default]
    Any,
    /// Applies to these methods. An empty set is a configuration error.
    OneOf(Vec<http::Method>),
}

impl From<http::Method> for MethodMatch {
    fn from(method: http::Method) -> Self {
        Self::OneOf(vec![method])
    }
}

impl<const N: usize> From<[http::Method; N]> for MethodMatch {
    fn from(methods: [http::Method; N]) -> Self {
        Self::OneOf(methods.into())
    }
}

impl From<Vec<http::Method>> for MethodMatch {
    fn from(methods: Vec<http::Method>) -> Self {
        Self::OneOf(methods)
    }
}
