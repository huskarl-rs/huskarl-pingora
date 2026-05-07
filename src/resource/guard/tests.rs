use std::sync::Mutex;

use super::*;
use crate::{
    resource::test_support::{MockClaims, MockError, mock_validator_metadata},
    resource_server::validator::{ValidationResult, metadata::ValidatorMetadata},
};

enum MockOutcome {
    Missing,
    Valid {
        claims: MockClaims,
        audience: Vec<String>,
    },
    Invalid,
}

struct MockValidator {
    outcome: MockOutcome,
    captured_uri: Mutex<Option<http::Uri>>,
}

impl MockValidator {
    fn no_token() -> Self {
        Self {
            outcome: MockOutcome::Missing,
            captured_uri: Mutex::new(None),
        }
    }

    fn valid(claims: MockClaims) -> Self {
        Self {
            outcome: MockOutcome::Valid {
                claims,
                audience: vec![],
            },
            captured_uri: Mutex::new(None),
        }
    }

    fn valid_with_audience(claims: MockClaims, audience: Vec<String>) -> Self {
        Self {
            outcome: MockOutcome::Valid { claims, audience },
            captured_uri: Mutex::new(None),
        }
    }

    fn invalid() -> Self {
        Self {
            outcome: MockOutcome::Invalid,
            captured_uri: Mutex::new(None),
        }
    }
}

impl AccessTokenValidator for MockValidator {
    type Claims = MockClaims;
    type Error = MockError;

    async fn validate_request(
        &self,
        _headers: &http::HeaderMap,
        _method: &http::Method,
        uri: &http::Uri,
        _client_cert_der: Option<&[u8]>,
    ) -> ValidationResult<MockClaims, MockError> {
        *self.captured_uri.lock().unwrap() = Some(uri.clone());

        let outcome = match &self.outcome {
            MockOutcome::Missing => Ok(None),
            MockOutcome::Valid { claims, audience } => Ok(Some(ValidatedRequest {
                issuer: None,
                subject: None,
                audience: audience.clone(),
                jti: None,
                issued_at: None,
                expiration: None,
                cnf: None,
                claims: claims.clone(),
                introspection_jwt: None,
            })),
            MockOutcome::Invalid => Err(MockError),
        };

        ValidationResult {
            outcome,
            dpop_nonce: None,
        }
    }
}

impl ProvideValidatorMetadata for MockValidator {
    fn validator_metadata(&self, resource: Option<&str>) -> ValidatorMetadata {
        mock_validator_metadata(resource)
    }
}

// --- Helpers ---

fn build_guard(
    validator: MockValidator,
    routes: Vec<(&str, Rule<MockClaims>)>,
) -> Guard<MockValidator> {
    let mut builder = Guard::builder().validator(validator);
    for (pattern, rule) in routes {
        builder = builder.route(pattern, rule);
    }
    builder.build().unwrap()
}

fn build_guard_with_resource(
    validator: MockValidator,
    routes: Vec<(&str, Rule<MockClaims>)>,
    resource: &str,
    strip_prefix: Option<&str>,
) -> Guard<MockValidator> {
    let mut builder = Guard::builder()
        .validator(validator)
        .resource(resource.parse().unwrap())
        .maybe_strip_prefix(strip_prefix);
    for (pattern, rule) in routes {
        builder = builder.route(pattern, rule);
    }
    builder.build().unwrap()
}

async fn check(
    guard: &Guard<MockValidator>,
    method: &http::Method,
    uri: &str,
) -> Outcome<MockClaims> {
    guard
        .check_request(&http::HeaderMap::new(), method, &uri.parse().unwrap(), None)
        .await
}

// --- resource_metadata tests ---

#[test]
fn resource_metadata_default_path() {
    let guard = build_guard(MockValidator::no_token(), vec![]);
    let (path, _) = guard.resource_metadata().unwrap();
    assert_eq!(path, "/.well-known/oauth-protected-resource");
}

#[test]
fn resource_metadata_with_resource_path() {
    let guard = build_guard_with_resource(
        MockValidator::no_token(),
        vec![],
        "https://api.example.com/tenant1",
        None,
    );
    let (path, _) = guard.resource_metadata().unwrap();
    assert_eq!(path, "/.well-known/oauth-protected-resource/tenant1");
}

#[test]
fn resource_metadata_root_path_no_suffix() {
    let guard = build_guard_with_resource(
        MockValidator::no_token(),
        vec![],
        "https://api.example.com/",
        None,
    );
    let (path, _) = guard.resource_metadata().unwrap();
    assert_eq!(path, "/.well-known/oauth-protected-resource");
}

#[test]
fn resource_metadata_includes_scopes() {
    let guard = build_guard(
        MockValidator::no_token(),
        vec![
            ("/admin", Rule::required().scopes(["admin", "write"])),
            ("/read", Rule::required().scopes(["read"])),
        ],
    );
    let (_, json) = guard.resource_metadata().unwrap();
    let value: serde_json::Value = serde_json::from_slice(&json).unwrap();
    let scopes = value["scopes_supported"].as_array().unwrap();
    let scope_strs: Vec<&str> = scopes.iter().map(|v| v.as_str().unwrap()).collect();
    // BTreeSet orders alphabetically
    assert_eq!(scope_strs, vec!["admin", "read", "write"]);
}

#[test]
fn resource_metadata_no_scopes_omits_field() {
    let guard = build_guard(MockValidator::no_token(), vec![]);
    let (_, json) = guard.resource_metadata().unwrap();
    let value: serde_json::Value = serde_json::from_slice(&json).unwrap();
    assert!(value.get("scopes_supported").is_none());
}

// --- check_request: routing and token requirement ---

#[tokio::test]
async fn public_route_skips_validation() {
    let guard = build_guard(MockValidator::no_token(), vec![("/health", Rule::public())]);
    let outcome = check(&guard, &http::Method::GET, "/health").await;
    assert!(matches!(outcome, Outcome::Forward { token: None, .. }));
    // Validator must not have been called.
    assert!(guard.validator.captured_uri.lock().unwrap().is_none());
}

#[tokio::test]
async fn required_route_no_token_denies_401() {
    let guard = build_guard(MockValidator::no_token(), vec![]);
    let outcome = check(&guard, &http::Method::GET, "/api").await;
    assert!(matches!(
        outcome,
        Outcome::Deny { status, .. } if status == http::StatusCode::UNAUTHORIZED
    ));
}

#[tokio::test]
async fn required_route_valid_token_forwards() {
    let claims = MockClaims { scopes: None };
    let guard = build_guard(MockValidator::valid(claims), vec![]);
    let outcome = check(&guard, &http::Method::GET, "/api").await;
    assert!(matches!(outcome, Outcome::Forward { token: Some(_), .. }));
}

#[tokio::test]
async fn required_route_invalid_token_denies() {
    let guard = build_guard(MockValidator::invalid(), vec![]);
    let outcome = check(&guard, &http::Method::GET, "/api").await;
    assert!(matches!(outcome, Outcome::Deny { .. }));
}

#[tokio::test]
async fn optional_route_no_token_forwards() {
    let guard = build_guard(MockValidator::no_token(), vec![("/api", Rule::optional())]);
    let outcome = check(&guard, &http::Method::GET, "/api").await;
    assert!(matches!(outcome, Outcome::Forward { token: None, .. }));
}

#[tokio::test]
async fn optional_route_valid_token_forwards_with_token() {
    let claims = MockClaims { scopes: None };
    let guard = build_guard(
        MockValidator::valid(claims),
        vec![("/api", Rule::optional())],
    );
    let outcome = check(&guard, &http::Method::GET, "/api").await;
    assert!(matches!(outcome, Outcome::Forward { token: Some(_), .. }));
}

#[tokio::test]
async fn default_rule_applies_to_unmatched_paths() {
    let guard = Guard::builder()
        .validator(MockValidator::no_token())
        .route("/health", Rule::public())
        .default(Rule::optional())
        .build()
        .unwrap();

    let outcome = check(&guard, &http::Method::GET, "/health").await;
    assert!(matches!(outcome, Outcome::Forward { token: None, .. }));

    // Unmatched path uses the default Optional rule; no token → Forward.
    let outcome = check(&guard, &http::Method::GET, "/other").await;
    assert!(matches!(outcome, Outcome::Forward { token: None, .. }));
}

// --- check_request: scope enforcement ---

#[tokio::test]
async fn scope_check_passes() {
    let claims = MockClaims {
        scopes: Some("admin read".into()),
    };
    let guard = build_guard(
        MockValidator::valid(claims),
        vec![("/admin", Rule::required().scopes(["admin"]))],
    );
    let outcome = check(&guard, &http::Method::GET, "/admin").await;
    assert!(matches!(outcome, Outcome::Forward { token: Some(_), .. }));
}

#[tokio::test]
async fn scope_check_failure_denies_403() {
    let claims = MockClaims {
        scopes: Some("read".into()),
    };
    let guard = build_guard(
        MockValidator::valid(claims),
        vec![("/admin", Rule::required().scopes(["admin"]))],
    );
    let outcome = check(&guard, &http::Method::GET, "/admin").await;
    assert!(matches!(
        outcome,
        Outcome::Deny { status, .. } if status == http::StatusCode::FORBIDDEN
    ));
}

#[tokio::test]
async fn multiple_scopes_all_required() {
    let claims = MockClaims {
        scopes: Some("read".into()),
    };
    let guard = build_guard(
        MockValidator::valid(claims),
        vec![("/api", Rule::required().scopes(["read", "write"]))],
    );
    // Has "read" but not "write" → denied.
    let outcome = check(&guard, &http::Method::GET, "/api").await;
    assert!(matches!(
        outcome,
        Outcome::Deny { status, .. } if status == http::StatusCode::FORBIDDEN
    ));
}

// --- check_request: audience enforcement ---

#[tokio::test]
async fn audience_check_passes() {
    let claims = MockClaims { scopes: None };
    let guard = build_guard(
        MockValidator::valid_with_audience(claims, vec!["my-api".into()]),
        vec![("/api", Rule::required().audience("my-api"))],
    );
    let outcome = check(&guard, &http::Method::GET, "/api").await;
    assert!(matches!(outcome, Outcome::Forward { token: Some(_), .. }));
}

#[tokio::test]
async fn audience_mismatch_denies_401() {
    let claims = MockClaims { scopes: None };
    let guard = build_guard(
        MockValidator::valid_with_audience(claims, vec!["other-api".into()]),
        vec![("/api", Rule::required().audience("my-api"))],
    );
    let outcome = check(&guard, &http::Method::GET, "/api").await;
    assert!(matches!(
        outcome,
        Outcome::Deny { status, .. } if status == http::StatusCode::UNAUTHORIZED
    ));
}

// --- check_request: custom checks ---

#[tokio::test]
async fn custom_check_forbidden_denies_403() {
    let claims = MockClaims { scopes: None };
    let guard = build_guard(
        MockValidator::valid(claims),
        vec![(
            "/api",
            Rule::required().check(|_| Err(CheckError::Forbidden("nope".into()))),
        )],
    );
    let outcome = check(&guard, &http::Method::GET, "/api").await;
    assert!(matches!(
        outcome,
        Outcome::Deny { status, .. } if status == http::StatusCode::FORBIDDEN
    ));
}

#[tokio::test]
async fn custom_check_invalid_token_denies_401() {
    let claims = MockClaims { scopes: None };
    let guard = build_guard(
        MockValidator::valid(claims),
        vec![(
            "/api",
            Rule::required().check(|_| Err(CheckError::InvalidToken("bad".into()))),
        )],
    );
    let outcome = check(&guard, &http::Method::GET, "/api").await;
    assert!(matches!(
        outcome,
        Outcome::Deny { status, .. } if status == http::StatusCode::UNAUTHORIZED
    ));
}

#[tokio::test]
async fn custom_check_ok_forwards() {
    let claims = MockClaims { scopes: None };
    let guard = build_guard(
        MockValidator::valid(claims),
        vec![("/api", Rule::required().check(|_| Ok(())))],
    );
    let outcome = check(&guard, &http::Method::GET, "/api").await;
    assert!(matches!(outcome, Outcome::Forward { token: Some(_), .. }));
}

// --- check_request: strip_credentials ---

#[tokio::test]
async fn strip_credentials_propagated() {
    let claims = MockClaims { scopes: None };
    let guard = build_guard(
        MockValidator::valid(claims),
        vec![("/api", Rule::required().strip_credentials(false))],
    );
    let outcome = check(&guard, &http::Method::GET, "/api").await;
    match outcome {
        Outcome::Forward {
            strip_credentials, ..
        } => assert!(!strip_credentials),
        other => panic!("expected Forward, got {other:?}"),
    }
}

// --- request_uri reconstruction ---

#[tokio::test]
async fn request_uri_without_base_passes_original() {
    let guard = build_guard(MockValidator::no_token(), vec![]);
    let _ = check(&guard, &http::Method::GET, "/api/data?q=1").await;
    let captured = guard
        .validator
        .captured_uri
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(captured.to_string(), "/api/data?q=1");
}

#[tokio::test]
async fn request_uri_with_base_prepends_path() {
    let guard = build_guard_with_resource(
        MockValidator::no_token(),
        vec![],
        "https://api.example.com/v1",
        None,
    );
    let _ = check(&guard, &http::Method::GET, "/users").await;
    let captured = guard
        .validator
        .captured_uri
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(captured.to_string(), "https://api.example.com/v1/users");
}

#[tokio::test]
async fn request_uri_with_strip_prefix() {
    let guard = build_guard_with_resource(
        MockValidator::no_token(),
        vec![],
        "https://api.example.com",
        Some("/proxy"),
    );
    let _ = check(&guard, &http::Method::GET, "/proxy/users").await;
    let captured = guard
        .validator
        .captured_uri
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(captured.to_string(), "https://api.example.com/users");
}

#[tokio::test]
async fn request_uri_strip_prefix_no_match_denies() {
    let guard = build_guard_with_resource(
        MockValidator::no_token(),
        vec![],
        "https://api.example.com",
        Some("/proxy"),
    );
    let outcome = check(&guard, &http::Method::GET, "/other/users").await;

    // Validation should not have been called
    assert!(guard.validator.captured_uri.lock().unwrap().is_none());

    assert!(matches!(
        outcome,
        Outcome::Deny { status, .. } if status == http::StatusCode::BAD_REQUEST
    ));
}

#[tokio::test]
async fn request_uri_preserves_query_string() {
    let guard = build_guard_with_resource(
        MockValidator::no_token(),
        vec![],
        "https://api.example.com",
        None,
    );
    let _ = check(&guard, &http::Method::GET, "/users?page=2").await;
    let captured = guard
        .validator
        .captured_uri
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(captured.to_string(), "https://api.example.com/users?page=2");
}
