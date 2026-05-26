use crate::{
    resource::scopes::HasScopes,
    resource_server::{
        error::{ToRfc6750Error, TokenErrorCode, TokenValidationError},
        validator::{extract::TokenType, metadata::ValidatorMetadata},
    },
};

#[derive(Debug, Clone)]
pub(crate) struct MockClaims {
    pub scopes: Option<String>,
}

impl HasScopes for MockClaims {
    fn has_scope(&self, scope: &str) -> bool {
        self.scopes
            .as_ref()
            .is_some_and(|s| s.split_whitespace().any(|t| t == scope))
    }
}

#[derive(Debug)]
pub(crate) struct MockError;

impl ToRfc6750Error for MockError {
    fn attempted_scheme(&self) -> Option<TokenType> {
        None
    }
    fn token_error(&self) -> TokenValidationError {
        TokenValidationError::Client(TokenErrorCode::InvalidToken)
    }
    fn error_description(&self) -> Option<String> {
        Some("mock invalid token".into())
    }
}

/// Convenience implementation for any validator built on [`MockClaims`]/[`MockError`].
pub(crate) fn mock_validator_metadata(resource: Option<&str>) -> ValidatorMetadata {
    ValidatorMetadata {
        realm: None,
        authorization_servers: None,
        dpop_signing_alg_values_supported: None,
        dpop_bound_access_tokens_required: None,
        resource: resource.map(String::from),
        bearer_methods_supported: None,
    }
}
