// Mock trait impls satisfy `async fn` signatures without awaiting.
#![allow(clippy::unused_async_trait_impl)]

use std::sync::Mutex;

use super::*;
use crate::{
    path_confusion::DecodeDepth,
    resource::test_support::{
        ChallengeCounter, CountingError, MockClaims, MockError, MockErrorKind,
        mock_validator_metadata,
    },
    resource_server::validator::{ValidationResult, metadata::ValidatorMetadata},
};

enum MockOutcome {
    Missing,
    Valid {
        claims: MockClaims,
        audience: Vec<String>,
    },
    Invalid(MockErrorKind),
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
        Self::rejecting(MockErrorKind::InvalidToken)
    }

    /// A validator that rejects with a specific kind, so the guard's outcome
    /// classification can be driven one branch at a time.
    fn rejecting(kind: MockErrorKind) -> Self {
        Self {
            outcome: MockOutcome::Invalid(kind),
            captured_uri: Mutex::new(None),
        }
    }
}

impl AccessTokenValidator for MockValidator {
    type Claims = MockClaims;
    type Error = MockError;

    fn validate_request<'a>(
        &'a self,
        _headers: &'a http::HeaderMap,
        _method: &'a http::Method,
        uri: &'a http::Uri,
        _client_cert_der: Option<&'a [u8]>,
    ) -> crate::resource_server::core::platform::MaybeSendBoxFuture<
        'a,
        ValidationResult<MockClaims, MockError>,
    > {
        *self.captured_uri.lock().unwrap() = Some(uri.clone());

        let outcome = match &self.outcome {
            MockOutcome::Missing => Ok(None),
            MockOutcome::Valid { claims, audience } => Ok(Some(ValidatedRequest {
                iss: None,
                sub: None,
                aud: audience.clone(),
                jti: None,
                iat: None,
                exp: None,
                cnf: None,
                claims: claims.clone(),
                introspection_jwt: None,
            })),
            MockOutcome::Invalid(kind) => Err(MockError(*kind)),
        };

        Box::pin(async move {
            ValidationResult {
                outcome,
                dpop_nonce: None,
            }
        })
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
    let mut builder = ResourcePolicy::builder().path_guard(crate::resource::GuardConfig::new(
        crate::resource::CaseSensitivity::Sensitive,
        crate::resource::DecodeDepth::UpToOne,
    ));
    for (pattern, rule) in routes {
        builder = builder.route(pattern, rule);
    }
    Guard::new(validator, builder.build().unwrap(), None)
}

fn build_guard_with_base_uri(
    validator: MockValidator,
    routes: Vec<(&str, Rule<MockClaims>)>,
    base_uri: &str,
    strip_prefix: Option<&str>,
) -> Guard<MockValidator> {
    let mut builder = ResourcePolicy::builder().path_guard(crate::resource::GuardConfig::new(
        crate::resource::CaseSensitivity::Sensitive,
        DecodeDepth::UpToOne,
    ));
    for (pattern, rule) in routes {
        builder = builder.route(pattern, rule);
    }
    Guard::new(
        validator,
        builder.build().unwrap(),
        Some(PublicUrlMapping::new(base_uri, strip_prefix.unwrap_or("/")).unwrap()),
    )
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

async fn check_with_metadata(
    guard: &Guard<MockValidator>,
    method: &http::Method,
    uri: &str,
    metadata: &ValidatorMetadata,
) -> Outcome<MockClaims> {
    guard
        .check_request_with_metadata(
            &http::HeaderMap::new(),
            method,
            &uri.parse().unwrap(),
            None,
            metadata,
            None,
        )
        .await
}

/// Builds a guard with a single `subtree` route, case-sensitive backend, and the
/// default path-confusion guard — the shape most path-confusion tests need.
fn subtree_guard(
    validator: MockValidator,
    pattern: &str,
    rule: Rule<MockClaims>,
) -> Guard<MockValidator> {
    crate::resource::ResourcePolicy::builder()
        .path_guard(crate::resource::GuardConfig::new(
            crate::resource::CaseSensitivity::Sensitive,
            DecodeDepth::UpToOne,
        ))
        .subtree(pattern, rule)
        .build()
        .map(|policy| Guard::new(validator, policy, None))
        .unwrap()
}

fn bind_guard<V: AccessTokenValidator + ProvideValidatorMetadata>(
    guard: Guard<V>,
    resource: &str,
) -> Result<(Guard<V>, ResourceMetadataConfig), ConfigError> {
    use crate::resource_server::resource::{AudienceBinding, ResourceDefinition};
    let uri: http::Uri = resource.parse().unwrap();
    let origin = format!(
        "{}://{}",
        uri.scheme_str().unwrap(),
        uri.authority().unwrap()
    );
    let definition = ResourceDefinition::new(
        PublicUrlMapping::new(&origin, "/").unwrap(),
        uri.path_and_query()
            .map_or("/", http::uri::PathAndQuery::as_str),
        AudienceBinding::ResourceIdentifier,
    )
    .unwrap();
    Guard::for_resource(guard.validator, guard.policy, &definition)
}

// --- Outcome assertions ---

/// Asserts `outcome` is a `Deny` carrying `status`.
#[track_caller]
fn assert_deny(outcome: &Outcome<MockClaims>, status: http::StatusCode) {
    assert!(
        matches!(outcome, Outcome::Deny { status: s, .. } if *s == status),
        "expected Deny {status}, got {outcome:?}",
    );
}

/// Asserts `outcome` forwards **without** a token (public or optional-no-token).
#[track_caller]
fn assert_forward(outcome: &Outcome<MockClaims>) {
    assert!(
        matches!(outcome, Outcome::Forward { token: None, .. }),
        "expected Forward without a token, got {outcome:?}",
    );
}

/// Asserts `outcome` forwards carrying a validated token.
#[track_caller]
fn assert_forward_authed(outcome: &Outcome<MockClaims>) {
    assert!(
        matches!(outcome, Outcome::Forward { token: Some(_), .. }),
        "expected Forward with a token, got {outcome:?}",
    );
}

// --- resource_metadata tests ---

#[test]
fn resource_metadata_with_resource_path() {
    let guard = build_guard(MockValidator::no_token(), vec![]);
    let (guard, config) = bind_guard(guard, "https://api.example.com/tenant1?version=1").unwrap();
    assert_eq!(
        config.endpoint_uri.path_and_query().unwrap().as_str(),
        "/.well-known/oauth-protected-resource/tenant1?version=1"
    );
    assert_eq!(
        guard.metadata.resource_metadata.as_deref(),
        Some("https://api.example.com/.well-known/oauth-protected-resource/tenant1?version=1")
    );
    let value: serde_json::Value = serde_json::from_slice(&config.body).unwrap();
    assert_eq!(
        value["resource"],
        "https://api.example.com/tenant1?version=1"
    );
}

#[test]
fn resource_metadata_root_path_no_suffix() {
    let guard = build_guard(MockValidator::no_token(), vec![]);
    let (_guard, config) = bind_guard(guard, "https://api.example.com/").unwrap();
    assert_eq!(
        config.endpoint_uri.path(),
        "/.well-known/oauth-protected-resource"
    );
}

/// The `WWW-Authenticate` values from a denial, or `None` if the request was forwarded.
fn deny_challenges(outcome: &Outcome<MockClaims>) -> Option<&[String]> {
    match outcome {
        Outcome::Deny { challenges, .. } => Some(challenges),
        Outcome::Forward { .. } => None,
    }
}

/// The `resource_metadata` parameter value from whichever challenge carries it.
fn advertised_metadata_url(challenges: &[String]) -> Option<&str> {
    challenges.iter().find_map(|c| {
        c.split("resource_metadata=\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
    })
}

/// Do not advertise a local metadata URL when no endpoint has been enabled.
#[tokio::test]
async fn challenge_does_not_advertise_disabled_local_metadata() {
    let guard = build_guard(MockValidator::no_token(), vec![("/api", Rule::required())]);

    let outcome = check(&guard, &http::Method::GET, "/api").await;
    let challenges = deny_challenges(&outcome).expect("expected a denial");
    assert_eq!(
        advertised_metadata_url(challenges),
        None,
        "challenges: {challenges:?}",
    );
}

/// The URL the challenge advertises and the path the guard serves the document at are
/// two derivations of one fact. If they drift, clients follow the advertised URL to a
/// 404 — so pin them together, including the tenant-path case where the well-known
/// segment is *inserted* rather than appended (RFC 9728 §3.1).
#[tokio::test]
async fn advertised_metadata_url_matches_the_served_path() {
    for resource in [
        "https://api.example.com",
        "https://api.example.com/",
        "https://api.example.com/tenant1",
    ] {
        let guard = build_guard(MockValidator::no_token(), vec![("/api", Rule::required())]);
        let (guard, config) = bind_guard(guard, resource).unwrap();

        let outcome =
            check_with_metadata(&guard, &http::Method::GET, "/api", &guard.metadata).await;
        let challenges = deny_challenges(&outcome).expect("expected a denial");
        let advertised = advertised_metadata_url(challenges)
            .unwrap_or_else(|| unreachable!("no metadata URL for {resource}: {challenges:?}"));
        let advertised_uri = advertised.parse::<http::Uri>().unwrap();

        assert_eq!(
            advertised_uri.path_and_query(),
            config.endpoint_uri.path_and_query(),
            "{resource}: advertised {advertised} but the document is served at {}",
            config.endpoint_uri,
        );
    }
}

#[tokio::test]
async fn one_origin_can_back_distinct_resource_guards() {
    for resource_path in ["payments", "inventory"] {
        let resource = format!("https://api.example.com/{resource_path}");
        let request_path = format!("/{resource_path}/item");
        let guard = crate::resource::ResourcePolicy::builder()
            .path_guard(crate::resource::GuardConfig::new(
                crate::resource::CaseSensitivity::Sensitive,
                DecodeDepth::UpToOne,
            ))
            .route(&request_path, Rule::required())
            .build()
            .map(|policy| {
                Guard::new(
                    MockValidator::no_token(),
                    policy,
                    Some(
                        crate::resource_server::core::url_mapping::PublicUrlMapping::new(
                            "https://api.example.com",
                            "/",
                        )
                        .unwrap(),
                    ),
                )
            })
            .unwrap();
        let (guard, config) = bind_guard(guard, &resource).unwrap();
        assert_eq!(
            config.endpoint_uri.path(),
            format!("/.well-known/oauth-protected-resource/{resource_path}")
        );

        let outcome =
            check_with_metadata(&guard, &http::Method::GET, &request_path, &guard.metadata).await;
        let challenges = deny_challenges(&outcome).expect("expected a denial");
        assert_eq!(
            advertised_metadata_url(challenges),
            Some(format!(
                "https://api.example.com/.well-known/oauth-protected-resource/{resource_path}"
            ))
            .as_deref()
        );
        let captured_uri = guard
            .validator
            .captured_uri
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(
            captured_uri.to_string(),
            format!("https://api.example.com/{resource_path}/item")
        );
    }
}

/// A validator configured with its own metadata URL is pointing clients at a document
/// served elsewhere. That is a deliberate choice, so the derived value must not
/// overwrite it.
#[tokio::test]
async fn explicit_validator_metadata_url_is_not_overwritten() {
    struct CustomUrlValidator(MockValidator);

    impl AccessTokenValidator for CustomUrlValidator {
        type Claims = MockClaims;
        type Error = MockError;

        fn validate_request<'a>(
            &'a self,
            headers: &'a http::HeaderMap,
            method: &'a http::Method,
            uri: &'a http::Uri,
            client_cert_der: Option<&'a [u8]>,
        ) -> crate::resource_server::core::platform::MaybeSendBoxFuture<
            'a,
            ValidationResult<MockClaims, MockError>,
        > {
            self.0
                .validate_request(headers, method, uri, client_cert_der)
        }
    }

    impl ProvideValidatorMetadata for CustomUrlValidator {
        fn validator_metadata(&self, resource: Option<&str>) -> ValidatorMetadata {
            let mut metadata = mock_validator_metadata(resource);
            metadata.resource_metadata = Some("https://meta.example.com/prm".to_owned());
            metadata
        }
    }

    let guard = crate::resource::ResourcePolicy::builder()
        .path_guard(crate::resource::GuardConfig::new(
            crate::resource::CaseSensitivity::Sensitive,
            DecodeDepth::UpToOne,
        ))
        .route("/api", Rule::required())
        .build()
        .map(|policy| Guard::new(CustomUrlValidator(MockValidator::no_token()), policy, None))
        .unwrap();

    // Called directly: the shared `check` helper is typed to `Guard<MockValidator>`.
    let outcome = guard
        .check_request(
            &http::HeaderMap::new(),
            &http::Method::GET,
            &"/api".parse().unwrap(),
            None,
        )
        .await;
    let challenges = deny_challenges(&outcome).expect("expected a denial");
    assert_eq!(
        advertised_metadata_url(challenges),
        Some("https://meta.example.com/prm"),
        "the explicit URL was overwritten: {challenges:?}",
    );

    assert!(matches!(
        bind_guard(guard, "https://api.example.com"),
        Err(ConfigError::ResourceMetadataUrlMismatch { .. })
    ));
}

#[test]
fn invalid_public_mapping_is_a_build_error() {
    for base in [
        "/api",
        "ftp://api.example.com",
        "https://api.example.com/base?tenant=one",
    ] {
        assert!(PublicUrlMapping::new(base, "/").is_err());
    }
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
    let (_guard, config) = bind_guard(guard, "https://api.example.com").unwrap();
    let value: serde_json::Value = serde_json::from_slice(&config.body).unwrap();
    assert_eq!(value["resource"], "https://api.example.com/");
    let scopes = value["scopes_supported"].as_array().unwrap();
    let scope_strs: Vec<&str> = scopes.iter().map(|v| v.as_str().unwrap()).collect();
    // BTreeSet orders alphabetically
    assert_eq!(scope_strs, vec!["admin", "read", "write"]);
}

#[test]
fn resource_metadata_no_scopes_omits_field() {
    let guard = build_guard(MockValidator::no_token(), vec![]);
    let (_guard, config) = bind_guard(guard, "https://api.example.com").unwrap();
    let value: serde_json::Value = serde_json::from_slice(&config.body).unwrap();
    assert!(value.get("scopes_supported").is_none());
}

// --- check_request: routing and token requirement ---

#[tokio::test]
async fn public_route_skips_validation() {
    let guard = build_guard(MockValidator::no_token(), vec![("/health", Rule::public())]);
    let outcome = check(&guard, &http::Method::GET, "/health").await;
    assert_forward(&outcome);
    // Validator must not have been called.
    assert!(guard.validator.captured_uri.lock().unwrap().is_none());
}

#[tokio::test]
async fn required_route_no_token_denies_401() {
    let guard = build_guard(MockValidator::no_token(), vec![]);
    let outcome = check(&guard, &http::Method::GET, "/api").await;
    assert_deny(&outcome, http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn required_route_valid_token_forwards() {
    let claims = MockClaims { scopes: None };
    let guard = build_guard(MockValidator::valid(claims), vec![]);
    let outcome = check(&guard, &http::Method::GET, "/api").await;
    assert_forward_authed(&outcome);
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
    assert_forward(&outcome);
}

#[tokio::test]
async fn optional_route_valid_token_forwards_with_token() {
    let claims = MockClaims { scopes: None };
    let guard = build_guard(
        MockValidator::valid(claims),
        vec![("/api", Rule::optional())],
    );
    let outcome = check(&guard, &http::Method::GET, "/api").await;
    assert_forward_authed(&outcome);
}

#[tokio::test]
async fn default_rule_applies_to_unmatched_paths() {
    let guard = crate::resource::ResourcePolicy::builder()
        .path_guard(crate::resource::GuardConfig::new(
            crate::resource::CaseSensitivity::Sensitive,
            DecodeDepth::UpToOne,
        ))
        .route("/health", Rule::public())
        .default(Rule::optional())
        .build()
        .map(|policy| Guard::new(MockValidator::no_token(), policy, None))
        .unwrap();

    let outcome = check(&guard, &http::Method::GET, "/health").await;
    assert_forward(&outcome);

    // Unmatched path uses the default Optional rule; no token → Forward.
    let outcome = check(&guard, &http::Method::GET, "/other").await;
    assert_forward(&outcome);
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
    assert_forward_authed(&outcome);
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
    assert_deny(&outcome, http::StatusCode::FORBIDDEN);
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
    assert_deny(&outcome, http::StatusCode::FORBIDDEN);
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
    assert_forward_authed(&outcome);
}

#[tokio::test]
async fn audience_mismatch_denies_401() {
    let claims = MockClaims { scopes: None };
    let guard = build_guard(
        MockValidator::valid_with_audience(claims, vec!["other-api".into()]),
        vec![("/api", Rule::required().audience("my-api"))],
    );
    let outcome = check(&guard, &http::Method::GET, "/api").await;
    assert_deny(&outcome, http::StatusCode::UNAUTHORIZED);
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
    assert_deny(&outcome, http::StatusCode::FORBIDDEN);
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
    assert_deny(&outcome, http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn custom_check_ok_forwards() {
    let claims = MockClaims { scopes: None };
    let guard = build_guard(
        MockValidator::valid(claims),
        vec![("/api", Rule::required().check(|_| Ok(())))],
    );
    let outcome = check(&guard, &http::Method::GET, "/api").await;
    assert_forward_authed(&outcome);
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
    assert!(matches!(
        outcome,
        Outcome::Forward {
            strip_credentials: false,
            ..
        }
    ));
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
    let guard = build_guard_with_base_uri(
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
    let guard = build_guard_with_base_uri(
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
    let guard = build_guard_with_base_uri(
        MockValidator::no_token(),
        vec![],
        "https://api.example.com",
        Some("/proxy"),
    );
    let outcome = check(&guard, &http::Method::GET, "/other/users").await;

    // Validation should not have been called
    assert!(guard.validator.captured_uri.lock().unwrap().is_none());

    assert_deny(&outcome, http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn request_uri_preserves_query_string() {
    let guard = build_guard_with_base_uri(
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

// --- subtree matching ---

#[tokio::test]
async fn subtree_covers_path_and_descendants() {
    // Token is valid but lacks the "admin" scope; the subtree rule must enforce
    // the scope on the bare path, the trailing-slash form, and every descendant.
    let claims = MockClaims {
        scopes: Some("read".into()),
    };
    let guard = subtree_guard(
        MockValidator::valid(claims),
        "/admin",
        Rule::required().scopes(["admin"]),
    );

    for path in ["/admin", "/admin/", "/admin/users", "/admin/users/1"] {
        let outcome = check(&guard, &http::Method::GET, path).await;
        assert!(
            matches!(outcome, Outcome::Deny { status, .. } if status == http::StatusCode::FORBIDDEN),
            "path {path} should be denied for missing scope, got {outcome:?}"
        );
    }
}

#[tokio::test]
async fn subtree_exact_route_carve_out_wins() {
    let guard = crate::resource::ResourcePolicy::builder()
        .path_guard(crate::resource::GuardConfig::new(
            crate::resource::CaseSensitivity::Sensitive,
            DecodeDepth::UpToOne,
        ))
        .subtree("/admin", Rule::required())
        .route("/admin/health", Rule::public())
        .build()
        .map(|policy| Guard::new(MockValidator::no_token(), policy, None))
        .unwrap();

    // The more-specific exact route is public — no token still forwards.
    let outcome = check(&guard, &http::Method::GET, "/admin/health").await;
    assert_forward(&outcome);

    // Everything else under the subtree requires a token.
    let outcome = check(&guard, &http::Method::GET, "/admin/secret").await;
    assert_deny(&outcome, http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn subtree_trailing_slash_excludes_bare_path() {
    // A trailing slash means "this directory and its contents, but not the bare
    // name". `/admin/` and descendants are public; bare `/admin` falls through
    // to the default (required) rule.
    let guard = subtree_guard(MockValidator::no_token(), "/admin/", Rule::public());

    assert!(matches!(
        check(&guard, &http::Method::GET, "/admin/").await,
        Outcome::Forward { .. }
    ));
    assert!(matches!(
        check(&guard, &http::Method::GET, "/admin/x").await,
        Outcome::Forward { .. }
    ));
    assert_deny(
        &check(&guard, &http::Method::GET, "/admin").await,
        http::StatusCode::UNAUTHORIZED,
    );
}

// --- path-confusion guard ---

#[tokio::test]
async fn guard_denies_normalizations_that_relocate_the_rule() {
    // Each raw path matches the default rule (or `/admin` raw), but a normalizing
    // backend would resolve it onto — or off — the protected `/admin` subtree. The
    // path→rule binding is ambiguous, so the guard refuses it pre-auth with a 400.
    let guard = subtree_guard(MockValidator::no_token(), "/admin", Rule::required());
    // (attack path, why a normalizing backend relocates the rule)
    let cases: &[(&str, &str)] = &[
        // `..` resolves into the scoped subtree.
        ("/x/../admin/secret", "dot-segment traversal"),
        // `%2F` decoded + slash-merged routes to `/admin` (raw has no literal `/`).
        ("/%2f/admin", "decoded, merged double slash"),
        // `%2e%2e` decodes to `..` → traversal.
        ("/%2e%2e/admin", "encoded dot traversal"),
        // `;`-strip-then-resolve escapes `/admin` to `/secret` (the default rule).
        ("/admin/..;/secret", "path-parameter vector"),
    ];
    for (uri, why) in cases {
        let outcome = check(&guard, &http::Method::GET, uri).await;
        assert!(
            matches!(outcome, Outcome::Deny { status, .. } if status == http::StatusCode::BAD_REQUEST),
            "{uri} ({why}) must be denied 400, got {outcome:?}",
        );
    }
}

#[tokio::test]
async fn guard_400_challenges_carry_no_scope_hint() {
    // The pre-auth 400s (ambiguous path, unreconstructable URI) are rule-independent
    // refusals: the guard has just declined to trust the path→rule binding, so the
    // matched rule's scope must not be advertised — no token will make the request
    // acceptable, and the hint hands a prober the route table's policy layout. The
    // scope hint belongs to post-routing denials, pinned here against the 403.
    fn deny_parts(outcome: Outcome<MockClaims>) -> (Option<http::StatusCode>, Vec<String>) {
        match outcome {
            Outcome::Deny {
                status, challenges, ..
            } => (Some(status), challenges),
            Outcome::Forward { .. } => (None, Vec::new()),
        }
    }

    // Ambiguous path: the raw path matches the scoped /admin subtree, so a leak
    // would surface as `scope="admin"` in the invalid_request challenge.
    let guard = subtree_guard(
        MockValidator::no_token(),
        "/admin",
        Rule::required().scopes(["admin"]),
    );
    let (status, challenges) =
        deny_parts(check(&guard, &http::Method::GET, "/admin/..;/secret").await);
    assert_eq!(status, Some(http::StatusCode::BAD_REQUEST));
    assert!(!challenges.is_empty(), "400 still carries challenges");
    assert!(
        challenges.iter().all(|c| !c.contains("scope=")),
        "ambiguous-path 400 must not advertise the matched rule's scope: {challenges:?}"
    );

    // Unreconstructable URI (strip_prefix mismatch): same rule-independent 400.
    let guard = crate::resource::ResourcePolicy::builder()
        .path_guard(crate::resource::GuardConfig::new(
            crate::resource::CaseSensitivity::Sensitive,
            DecodeDepth::UpToOne,
        ))
        .default(Rule::required().scopes(["admin"]))
        .build()
        .map(|policy| {
            Guard::new(
                MockValidator::no_token(),
                policy,
                Some(
                    crate::resource_server::core::url_mapping::PublicUrlMapping::new(
                        "https://api.example.com",
                        "/proxy",
                    )
                    .unwrap(),
                ),
            )
        })
        .unwrap();
    let (status, challenges) = deny_parts(check(&guard, &http::Method::GET, "/other/users").await);
    assert_eq!(status, Some(http::StatusCode::BAD_REQUEST));
    assert!(
        challenges.iter().all(|c| !c.contains("scope=")),
        "invalid-URI 400 must not advertise the rule's scope: {challenges:?}"
    );

    // Contrast: a post-routing insufficient-scope 403 keeps the hint — that is the
    // attribute's canonical use (RFC 6750 §3), telling the client what to request.
    let guard = subtree_guard(
        MockValidator::valid(MockClaims { scopes: None }),
        "/admin",
        Rule::required().scopes(["admin"]),
    );
    let (status, challenges) = deny_parts(check(&guard, &http::Method::GET, "/admin/x").await);
    assert_eq!(status, Some(http::StatusCode::FORBIDDEN));
    assert!(
        challenges.iter().any(|c| c.contains(r#"scope="admin""#)),
        "insufficient-scope 403 keeps its scope hint: {challenges:?}"
    );
}

#[tokio::test]
async fn guard_allows_non_structural_encoded_content() {
    // Non-structural encoded content (`%20`) decodes to a deeper path under the same
    // `/files/{*rest}` rule — no route change → allowed by the content-decode precision.
    let guard = subtree_guard(MockValidator::no_token(), "/files", Rule::public());

    let outcome = check(&guard, &http::Method::GET, "/files/a%20b").await;
    assert_forward(&outcome);
}

#[tokio::test]
async fn blob_subtree_tolerates_structural_byte_in_key() {
    // `blob_subtree` declares the tail an opaque key space. Tolerance is scoped to the
    // subtree: an encoded slash in the key forwards, as does a climb that resolves
    // inside the blob — but a climb that escapes it still denies.
    let guard = crate::resource::ResourcePolicy::builder()
        .path_guard(crate::resource::GuardConfig::new(
            crate::resource::CaseSensitivity::Sensitive,
            DecodeDepth::UpToOne,
        ))
        .blob_subtree("/files", Rule::public())
        .build()
        .map(|policy| Guard::new(MockValidator::no_token(), policy, None))
        .unwrap();

    let forwarded = check(&guard, &http::Method::GET, "/files/a%2fb").await;
    assert_forward(&forwarded);

    let within = check(&guard, &http::Method::GET, "/files/a/../b").await;
    assert_forward(&within);

    let escapes = check(&guard, &http::Method::GET, "/files/../b").await;
    assert_deny(&escapes, http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn method_specific_rule_closes_other_methods_no_backtrack() {
    // A method gap denies rather than escaping into a broader public catch-all.
    let guard = crate::resource::ResourcePolicy::builder()
        .path_guard(crate::resource::GuardConfig::new(
            crate::resource::CaseSensitivity::Sensitive,
            DecodeDepth::UpToOne,
        ))
        .route("/{*rest}", Rule::public()) // catch-all, any method, public
        .route("/admin", Rule::public().method(http::Method::GET)) // GET /admin public
        .build()
        .map(|policy| Guard::new(MockValidator::no_token(), policy, None))
        .unwrap();

    // GET /admin → its GET rule → public.
    assert_forward(&check(&guard, &http::Method::GET, "/admin").await);
    // Missing policy is a 403, before token validation.
    assert_deny(
        &check(&guard, &http::Method::POST, "/admin").await,
        http::StatusCode::FORBIDDEN,
    );
    // POST /other → matches the catch-all (any method) → public.
    assert_forward(&check(&guard, &http::Method::POST, "/other").await);
}

#[tokio::test]
async fn method_wildcard_fallback_is_per_terminal() {
    // A wildcard-method rule on the *same path* is the fallback for unlisted methods —
    // and it is not inherited from a broader catch-all (see the test above).
    let guard = crate::resource::ResourcePolicy::builder()
        .path_guard(crate::resource::GuardConfig::new(
            crate::resource::CaseSensitivity::Sensitive,
            DecodeDepth::UpToOne,
        ))
        .route("/admin", Rule::public().method(http::Method::GET)) // GET public
        .route("/admin", Rule::required()) // every other method requires a token
        .build()
        .map(|policy| Guard::new(MockValidator::no_token(), policy, None))
        .unwrap();

    assert_forward(&check(&guard, &http::Method::GET, "/admin").await);
    assert_deny(
        &check(&guard, &http::Method::POST, "/admin").await,
        http::StatusCode::UNAUTHORIZED,
    );
}

#[tokio::test]
async fn method_gap_denies_with_public_default() {
    // An unlisted method denies even when the default policy is public.
    let guard = crate::resource::ResourcePolicy::builder()
        .path_guard(crate::resource::GuardConfig::new(
            crate::resource::CaseSensitivity::Sensitive,
            DecodeDepth::UpToOne,
        ))
        .default(Rule::public()) // permissive fallback
        .route("/admin", Rule::required().method(http::Method::POST)) // only POST is protected
        .build()
        .map(|policy| Guard::new(MockValidator::no_token(), policy, None))
        .unwrap();

    // POST /admin → its method rule → required → 401 without a token.
    assert_deny(
        &check(&guard, &http::Method::POST, "/admin").await,
        http::StatusCode::UNAUTHORIZED,
    );
    assert_deny(
        &check(&guard, &http::Method::GET, "/admin").await,
        http::StatusCode::FORBIDDEN,
    );
}

#[test]
fn blob_subtree_with_nested_route_is_build_error() {
    // A more-specific route under the blob would let a structural byte relocate into it.
    let result = crate::resource::ResourcePolicy::builder()
        .path_guard(crate::resource::GuardConfig::new(
            crate::resource::CaseSensitivity::Sensitive,
            DecodeDepth::UpToOne,
        ))
        .blob_subtree("/files", Rule::public())
        .route("/files/secret", Rule::required())
        .build()
        .map(|policy| Guard::new(MockValidator::no_token(), policy, None));
    assert!(matches!(
        result,
        Err(crate::resource::ConfigError::Route { .. })
    ));
}

#[tokio::test]
async fn plain_subtree_scopes_structural_byte_to_its_uniformity() {
    // Runtime tolerance follows the subtree's *uniformity*, not the `blob_subtree`
    // declaration: while `/files` is a single-rule subtree, every path a structural
    // byte could reach past the anchor carries the matched rule, so an encoded slash
    // in the tail forwards. A climb out of the subtree still denies.
    let guard = subtree_guard(MockValidator::no_token(), "/files", Rule::public());

    let outcome = check(&guard, &http::Method::GET, "/files/a%2fb").await;
    assert_forward(&outcome);

    let escapes = check(&guard, &http::Method::GET, "/files/../b").await;
    assert_deny(&escapes, http::StatusCode::BAD_REQUEST);

    // Registering a distinct rule under the subtree breaks that uniformity — the byte
    // could now relocate the path across a rule boundary, so it goes back to denying.
    let nested = crate::resource::ResourcePolicy::builder()
        .path_guard(crate::resource::GuardConfig::new(
            crate::resource::CaseSensitivity::Sensitive,
            DecodeDepth::UpToOne,
        ))
        .subtree("/files", Rule::public())
        .route("/files/secret", Rule::required())
        .build()
        .map(|policy| Guard::new(MockValidator::no_token(), policy, None))
        .unwrap();

    let denied = check(&nested, &http::Method::GET, "/files/a%2fb").await;
    assert_deny(&denied, http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn guard_inert_for_double_encoding() {
    // Double-encoded dots are inert in a single pass (no `.` produced), so no
    // route change: the request falls through to the default rule (401 for the
    // missing token), not a 400 from the guard.
    let guard = subtree_guard(MockValidator::no_token(), "/admin", Rule::required());

    let outcome = check(&guard, &http::Method::GET, "/%252e%252e/admin").await;
    assert_deny(&outcome, http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn guard_allows_long_clean_path() {
    // A very long but canonical path (no `%`/`;`/`//`/`/.`) can't be ambiguous,
    // so the length cap must not reject it — it routes under its rule normally.
    let guard = subtree_guard(MockValidator::no_token(), "/files", Rule::public());

    let path = format!("/files/{}", "a".repeat(16_384));
    let outcome = check(&guard, &http::Method::GET, &path).await;
    assert_forward(&outcome);
}

#[tokio::test]
async fn guard_rejects_long_suspicious_path() {
    // A suspicious path (contains `%`) over the cap is denied: once the first
    // normalization shows the path can change, the length cap rejects it before
    // the remaining normalizations run.
    let guard = subtree_guard(MockValidator::no_token(), "/files", Rule::public());

    let path = format!("/files/{}%2e", "a".repeat(16_384));
    let outcome = check(&guard, &http::Method::GET, &path).await;
    assert_deny(&outcome, http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn guard_off_allows_traversal() {
    // With the guard disabled, `/x/../admin/secret` falls to the default
    // (required) rule and is denied for the missing token (401), not 400.
    let guard = crate::resource::ResourcePolicy::builder()
        .path_guard(
            crate::resource::GuardConfig::new(
                crate::resource::CaseSensitivity::Sensitive,
                DecodeDepth::UpToOne,
            )
            .with_mode(crate::resource::GuardMode::Disabled),
        )
        .subtree("/admin", Rule::required().scopes(["admin"]))
        .build()
        .map(|policy| Guard::new(MockValidator::no_token(), policy, None))
        .unwrap();

    let outcome = check(&guard, &http::Method::GET, "/x/../admin/secret").await;
    assert_deny(&outcome, http::StatusCode::UNAUTHORIZED);
}

// --- build-time non-canonical-pattern detection ---

#[test]
fn build_rejects_pattern_with_empty_segment() {
    // An interior empty segment is not representable in the route grammar.
    let result = crate::resource::ResourcePolicy::builder()
        .path_guard(crate::resource::GuardConfig::new(
            crate::resource::CaseSensitivity::Sensitive,
            DecodeDepth::UpToOne,
        ))
        .route("/a/b", Rule::public())
        .route("/a//b", Rule::required())
        .build()
        .map(|policy| Guard::new(MockValidator::no_token(), policy, None));
    assert!(matches!(
        result,
        Err(crate::resource::ConfigError::Route { pattern, reason })
            if pattern == "/a//b" && reason == "route pattern has an empty path segment"
    ));
}

#[test]
fn build_rejects_traversal_pattern() {
    // `/x/../b` carries a `..` dot-segment → non-canonical.
    let result = crate::resource::ResourcePolicy::builder()
        .path_guard(crate::resource::GuardConfig::new(
            crate::resource::CaseSensitivity::Sensitive,
            DecodeDepth::UpToOne,
        ))
        .route("/x/../b", Rule::required())
        .build()
        .map(|policy| Guard::new(MockValidator::no_token(), policy, None));
    assert!(matches!(
        result,
        Err(crate::resource::ConfigError::NonCanonicalPattern { .. })
    ));
}

#[test]
fn build_allows_noncanonical_pattern_when_guard_off() {
    // With the guard off, the build-time non-canonical-pattern check is skipped, so a
    // pattern carrying a structural byte (here `%2f`) is accepted as a literal route.
    let result = crate::resource::ResourcePolicy::builder()
        .path_guard(
            crate::resource::GuardConfig::new(
                crate::resource::CaseSensitivity::Sensitive,
                DecodeDepth::UpToOne,
            )
            .with_mode(crate::resource::GuardMode::Disabled),
        )
        .route("/a/b", Rule::public())
        .route("/a%2fb", Rule::required())
        .build()
        .map(|policy| Guard::new(MockValidator::no_token(), policy, None));
    assert!(result.is_ok());
}

#[test]
fn build_rejects_public_rule_with_check() {
    // A check function on a public rule can never run — the validator is skipped
    // for public routes. Reject it at build time rather than store a dead check.
    let result = crate::resource::ResourcePolicy::builder()
        .path_guard(crate::resource::GuardConfig::new(
            crate::resource::CaseSensitivity::Sensitive,
            DecodeDepth::UpToOne,
        ))
        .route("/health", Rule::public().check(|_| Ok(())))
        .build()
        .map(|policy| Guard::new(MockValidator::no_token(), policy, None));
    assert!(matches!(
        result,
        Err(crate::resource::ConfigError::PublicRuleWithConstraints(p)) if p == "/health"
    ));
}

#[test]
fn build_rejects_public_default_rule_with_check() {
    let result = crate::resource::ResourcePolicy::builder()
        .path_guard(crate::resource::GuardConfig::new(
            crate::resource::CaseSensitivity::Sensitive,
            DecodeDepth::UpToOne,
        ))
        .default(Rule::public().check(|_| Ok(())))
        .build()
        .map(|policy| Guard::new(MockValidator::no_token(), policy, None));
    assert!(matches!(
        result,
        Err(crate::resource::ConfigError::PublicRuleWithConstraints(p)) if p == "<default>"
    ));
}

#[test]
fn build_allows_distinct_canonical_trailing_slash_routes() {
    // Both `/admin` and `/admin/` are canonical (no structural bytes) → no conflict.
    let result = crate::resource::ResourcePolicy::builder()
        .path_guard(crate::resource::GuardConfig::new(
            crate::resource::CaseSensitivity::Sensitive,
            DecodeDepth::UpToOne,
        ))
        .route("/admin", Rule::public())
        .route("/admin/", Rule::required())
        .build()
        .map(|policy| Guard::new(MockValidator::no_token(), policy, None));
    assert!(result.is_ok());
}

// --- opt-in classes via the structural API ---

#[tokio::test]
async fn structural_case_opt_in_catches_relocation() {
    let guard = crate::resource::ResourcePolicy::builder()
        .path_guard(crate::resource::GuardConfig::new(
            crate::resource::CaseSensitivity::Insensitive,
            DecodeDepth::UpToOne,
        ))
        .subtree("/admin", Rule::required())
        .build()
        .map(|policy| Guard::new(MockValidator::no_token(), policy, None))
        .unwrap();

    // `/Admin/x` carries uppercase a case-insensitive backend would fold onto the
    // protected `/admin` rule → denied 400.
    let outcome = check(&guard, &http::Method::GET, "/Admin/x").await;
    assert_deny(&outcome, http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn structural_case_not_flagged_by_default() {
    // Without with_case, a mixed-case path is not structural → falls to the
    // default (required) rule → 401 for the missing token, not a 400.
    let guard = subtree_guard(MockValidator::no_token(), "/admin", Rule::required());

    let outcome = check(&guard, &http::Method::GET, "/Admin/x").await;
    assert_deny(&outcome, http::StatusCode::UNAUTHORIZED);
}

// --- strict hygiene (RejectNonCanonical) ---

#[tokio::test]
async fn hygiene_rejects_noncanonical_even_when_same_rule() {
    use crate::resource::GuardMode;
    // `/files/a%2fb` stays in the same `/files` rule (no relocation), so the default
    // RejectStructural allows it (inert blob key) — but strict hygiene rejects it.
    let guard = crate::resource::ResourcePolicy::builder()
        .path_guard(
            crate::resource::GuardConfig::new(
                crate::resource::CaseSensitivity::Sensitive,
                DecodeDepth::UpToOne,
            )
            .with_mode(GuardMode::RequireCanonical),
        )
        .subtree("/files", Rule::public())
        .build()
        .map(|policy| Guard::new(MockValidator::no_token(), policy, None))
        .unwrap();

    let outcome = check(&guard, &http::Method::GET, "/files/a%2fb").await;
    assert_deny(&outcome, http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn hygiene_allows_canonical_path() {
    use crate::resource::GuardMode;
    let guard = crate::resource::ResourcePolicy::builder()
        .path_guard(
            crate::resource::GuardConfig::new(
                crate::resource::CaseSensitivity::Sensitive,
                DecodeDepth::UpToOne,
            )
            .with_mode(GuardMode::RequireCanonical),
        )
        .subtree("/files", Rule::public())
        .build()
        .map(|policy| Guard::new(MockValidator::no_token(), policy, None))
        .unwrap();

    // A clean path is canonical → allowed (public → forward).
    let outcome = check(&guard, &http::Method::GET, "/files/a/b").await;
    assert_forward(&outcome);
}

// --- custom break-glass probe ---

struct DangerPrefixProbe;

impl crate::resource::StructuralProbe for DangerPrefixProbe {
    fn name(&self) -> &'static str {
        "danger-prefix"
    }
    fn matches(&self, path: &str) -> bool {
        // A backend that aliases `/danger/...` onto `/admin/...`: a structural form
        // the built-in alphabet doesn't model, blocked via the break-glass hook.
        path.starts_with("/danger")
    }
}

#[tokio::test]
async fn custom_probe_denies_aliased_prefix() {
    use crate::resource::StructuralClasses;
    let guard = crate::resource::ResourcePolicy::builder()
        .path_guard(
            crate::resource::GuardConfig::new(
                crate::resource::CaseSensitivity::Sensitive,
                DecodeDepth::UpToOne,
            )
            .with_structural_classes(StructuralClasses::new().with_probe(DangerPrefixProbe)),
        )
        .subtree("/admin", Rule::required().scopes(["admin"]))
        .build()
        .map(|policy| Guard::new(MockValidator::no_token(), policy, None))
        .unwrap();

    // `/danger/secret` carries the probe's form → denied 400 (break-glass).
    let outcome = check(&guard, &http::Method::GET, "/danger/secret").await;
    assert_deny(&outcome, http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn structural_overlong_opt_in_catches_relocation() {
    use crate::resource::{StructuralChar, StructuralClasses};
    // A backend that decodes overlong UTF-8 reads `/x%c0%af..%c0%afadmin/secret`
    // as `/x/../admin/secret` → `/admin/secret`; with the overlong forms recognised
    // the structural scan reveals the `..` and denies it.
    let guard = crate::resource::ResourcePolicy::builder()
        .path_guard(
            crate::resource::GuardConfig::new(
                crate::resource::CaseSensitivity::Sensitive,
                DecodeDepth::UpToOne,
            )
            .with_structural_classes(
                StructuralClasses::new()
                    .with_overlong([StructuralChar::Slash, StructuralChar::Dot]),
            ),
        )
        .subtree("/admin", Rule::required())
        .build()
        .map(|policy| Guard::new(MockValidator::no_token(), policy, None))
        .unwrap();

    let outcome = check(&guard, &http::Method::GET, "/x%c0%af..%c0%afadmin/secret").await;
    assert_deny(&outcome, http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn structural_overlong_not_flagged_by_default() {
    // Without the opt-in, overlong bytes are inert (the default scan only handles
    // single-byte %2F/%2E), so the path falls to the default (required) rule → 401
    // for the missing token, not a 400.
    let guard = subtree_guard(MockValidator::no_token(), "/admin", Rule::required());

    let outcome = check(&guard, &http::Method::GET, "/x%c0%af..%c0%afadmin/secret").await;
    assert_deny(&outcome, http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn structural_null_truncation_denied_by_default() {
    // A NUL-terminating backend reads `/admin%00/secret` as `/admin`. The truncation
    // class is always-on in huskarl-route-guard (a NUL has no legitimate use in a
    // path), so the default configuration denies the `%00` — no opt-in needed.
    let guard = crate::resource::ResourcePolicy::builder()
        .path_guard(crate::resource::GuardConfig::new(
            crate::resource::CaseSensitivity::Sensitive,
            DecodeDepth::UpToOne,
        ))
        .subtree("/admin", Rule::required())
        .build()
        .map(|policy| Guard::new(MockValidator::no_token(), policy, None))
        .unwrap();

    let outcome = check(&guard, &http::Method::GET, "/admin%00/secret").await;
    assert_deny(&outcome, http::StatusCode::BAD_REQUEST);
}

// ── CVE regression casebook: scoping (architecture, not the structural guard) ──
// oauth2-proxy's recent bypasses came from authorizing on more than the request
// path. huskarl decides on `uri.path()` alone, so they cannot arise.
// See docs/path-confusion-cve-casebook.md (group C).

#[tokio::test]
async fn cve_query_string_cannot_widen_a_rule() {
    // CVE-2025-54576 / GHSA-7rh7-c77v-6434 (oauth2-proxy): skip_auth matched
    // path + query. huskarl matches on the path only, so a query can neither reach
    // nor exempt a rule.
    let guard = build_guard(MockValidator::no_token(), vec![("/public", Rule::public())]);
    // A protected path stays protected even when the query names a public one.
    let outcome = check(&guard, &http::Method::GET, "/admin?next=/public").await;
    assert_deny(&outcome, http::StatusCode::UNAUTHORIZED);
    // A public path matches on its path regardless of the query.
    let outcome = check(&guard, &http::Method::GET, "/public?next=/admin").await;
    assert_forward(&outcome);
}

#[tokio::test]
async fn cve_raw_fragment_is_stripped_to_base_path() {
    // GHSA-pxq7-h93f-9jrg (oauth2-proxy): the CVE's enabler is oauth2-proxy rewriting/
    // normalizing the path around `#` before matching. huskarl never rewrites. Raw `#`
    // is stripped by uri.path(), so `/admin#/anything` is evaluated as the protected base
    // `/admin` — protected, not bypassed. (The encoded `%23` form is forwarded raw and
    // never decoded to `#`, so huskarl can't manufacture the delimiter either; see
    // docs/path-confusion-cve-casebook.md.)
    let guard = build_guard(
        MockValidator::no_token(),
        vec![("/admin", Rule::required())],
    );
    let outcome = check(&guard, &http::Method::GET, "/admin#/public").await;
    assert_deny(&outcome, http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn cve_forwarded_uri_header_is_not_trusted() {
    // GHSA-7x63-xv5r-3p2x (oauth2-proxy): trusted a client X-Forwarded-Uri for the
    // auth path. huskarl authorizes on the real request URI and reads no
    // forwarded-path header, so a spoofed header cannot relax the decision.
    let guard = build_guard(MockValidator::no_token(), vec![("/public", Rule::public())]);
    let mut headers = http::HeaderMap::new();
    headers.insert("x-forwarded-uri", "/public".parse().unwrap());
    let outcome = guard
        .check_request(
            &headers,
            &http::Method::GET,
            &"/admin".parse().unwrap(),
            None,
        )
        .await;
    assert_deny(&outcome, http::StatusCode::UNAUTHORIZED);
}

// --- metrics: the `huskarl.resource.check` outcome counter ---

use crate::metrics_test_support::{assert_counter, with_metrics};

#[test]
fn metrics_forward_on_public_route() {
    let (_, counters) = with_metrics(async {
        let guard = build_guard(MockValidator::no_token(), vec![("/health", Rule::public())]);
        check(&guard, &http::Method::GET, "/health").await
    });
    assert_counter(
        &counters,
        "huskarl.resource.check",
        &[("name", ""), ("outcome", "forward")],
        1,
    );
    assert_counter(
        &counters,
        "huskarl.resource.check",
        &[("name", ""), ("outcome", "unauthenticated")],
        0,
    );
}

#[test]
fn metrics_unauthenticated_on_required_no_token() {
    let (_, counters) = with_metrics(async {
        let guard = build_guard(MockValidator::no_token(), vec![]);
        check(&guard, &http::Method::GET, "/api").await
    });
    assert_counter(
        &counters,
        "huskarl.resource.check",
        &[("name", ""), ("outcome", "unauthenticated")],
        1,
    );
    assert_counter(
        &counters,
        "huskarl.resource.check",
        &[("name", ""), ("outcome", "forward")],
        0,
    );
}

#[test]
fn metrics_path_confusion_on_ambiguous_path() {
    let (_, counters) = with_metrics(async {
        let guard = build_guard(
            MockValidator::no_token(),
            vec![("/admin", Rule::required())],
        );
        // `/x/../admin` climbs onto the protected rule under a normalizing backend.
        check(&guard, &http::Method::GET, "/x/../admin").await
    });
    assert_counter(
        &counters,
        "huskarl.resource.check",
        &[("name", ""), ("outcome", "path_confusion")],
        1,
    );
}

#[test]
fn metrics_invalid_token_on_bad_token() {
    let (_, counters) = with_metrics(async {
        let guard = build_guard(MockValidator::invalid(), vec![("/api", Rule::required())]);
        check(&guard, &http::Method::GET, "/api").await
    });
    assert_counter(
        &counters,
        "huskarl.resource.check",
        &[("name", ""), ("outcome", "invalid_token")],
        1,
    );
}

/// A validator that could not reach a backing service produces a 5xx, and must be
/// counted as a server error — not as `invalid_token`. Labelling an outage as a token
/// rejection both overstates rejections and hides the outage from availability alerts.
#[test]
fn metrics_server_error_not_counted_as_invalid_token() {
    let (outcome, counters) = with_metrics(async {
        let guard = build_guard(
            MockValidator::rejecting(MockErrorKind::ServerError),
            vec![("/api", Rule::required())],
        );
        check(&guard, &http::Method::GET, "/api").await
    });
    assert_deny(&outcome, http::StatusCode::SERVICE_UNAVAILABLE);
    assert_counter(
        &counters,
        "huskarl.resource.check",
        &[("name", ""), ("outcome", "server_error")],
        1,
    );
    assert_counter(
        &counters,
        "huskarl.resource.check",
        &[("name", ""), ("outcome", "invalid_token")],
        0,
    );
}

/// A server-side failure's `Retry-After` interval must survive the guard. Dropping it
/// leaves clients with no backoff signal against an authorization server that is already
/// failing — the retry storm arrives exactly when it does the most harm.
#[tokio::test]
async fn server_error_carries_retry_after_through_the_guard() {
    let guard = build_guard(
        MockValidator::rejecting(MockErrorKind::ServerError),
        vec![("/api", Rule::required())],
    );

    let outcome = check(&guard, &http::Method::GET, "/api").await;
    assert!(
        matches!(
            &outcome,
            Outcome::Deny {
                status,
                retry_after: Some(after),
                challenges,
                ..
            } if *status == http::StatusCode::SERVICE_UNAVAILABLE
                && *after == MockError::RETRY_AFTER
                // RFC 6750: a 5xx carries no challenge — re-authenticating would not help.
                && challenges.is_empty()
        ),
        "expected a 503 carrying the retry interval and no challenge, got {outcome:?}",
    );
}

/// A client-side rejection has no interval to report: waiting does not fix a bad token.
#[tokio::test]
async fn client_error_carries_no_retry_after() {
    let guard = build_guard(MockValidator::invalid(), vec![("/api", Rule::required())]);

    let outcome = check(&guard, &http::Method::GET, "/api").await;
    assert!(
        matches!(
            &outcome,
            Outcome::Deny {
                retry_after: None,
                ..
            }
        ),
        "expected no retry interval, got {outcome:?}",
    );
}

/// A failed sender-constraint check is the possible-stolen-token bucket (RFC 9449 §7.1),
/// and a nonce challenge is routine churn — they must not share a label, or the
/// alertable signal drowns in the routine one.
#[test]
fn metrics_binding_error_and_nonce_required_are_distinct() {
    let (_, counters) = with_metrics(async {
        let guard = build_guard(
            MockValidator::rejecting(MockErrorKind::BindingError),
            vec![("/api", Rule::required())],
        );
        check(&guard, &http::Method::GET, "/api").await
    });
    assert_counter(
        &counters,
        "huskarl.resource.check",
        &[("name", ""), ("outcome", "binding_error")],
        1,
    );
    assert_counter(
        &counters,
        "huskarl.resource.check",
        &[("name", ""), ("outcome", "invalid_token")],
        0,
    );
    assert_counter(
        &counters,
        "huskarl.resource.check",
        &[("name", ""), ("outcome", "nonce_required")],
        0,
    );

    let (_, counters) = with_metrics(async {
        let guard = build_guard(
            MockValidator::rejecting(MockErrorKind::NonceRequired),
            vec![("/api", Rule::required())],
        );
        check(&guard, &http::Method::GET, "/api").await
    });
    assert_counter(
        &counters,
        "huskarl.resource.check",
        &[("name", ""), ("outcome", "nonce_required")],
        1,
    );
    assert_counter(
        &counters,
        "huskarl.resource.check",
        &[("name", ""), ("outcome", "binding_error")],
        0,
    );
}

/// Credentials that cannot be parsed out of the request are a malformed request, not a
/// judged-and-rejected token — same bucket as any other `400`.
#[test]
fn metrics_extract_error_counts_as_invalid_request() {
    let (outcome, counters) = with_metrics(async {
        let guard = build_guard(
            MockValidator::rejecting(MockErrorKind::ExtractError),
            vec![("/api", Rule::required())],
        );
        check(&guard, &http::Method::GET, "/api").await
    });
    assert_deny(&outcome, http::StatusCode::BAD_REQUEST);
    assert_counter(
        &counters,
        "huskarl.resource.check",
        &[("name", ""), ("outcome", "invalid_request")],
        1,
    );
    assert_counter(
        &counters,
        "huskarl.resource.check",
        &[("name", ""), ("outcome", "invalid_token")],
        0,
    );
}

/// The rejection path must build exactly one `Challenge`. Status, retry interval,
/// `WWW-Authenticate` values, and the metric classification all derive from it, and each
/// rebuild would re-clone the owned description and parameters — on a path whose rate an
/// attacker chooses. Regressions here are silent, so pin the count.
#[tokio::test]
async fn rejection_builds_exactly_one_challenge() {
    struct CountingValidator(std::sync::Arc<ChallengeCounter>);

    impl AccessTokenValidator for CountingValidator {
        type Claims = MockClaims;
        type Error = CountingError;

        fn validate_request<'a>(
            &'a self,
            _headers: &'a http::HeaderMap,
            _method: &'a http::Method,
            _uri: &'a http::Uri,
            _client_cert_der: Option<&'a [u8]>,
        ) -> crate::resource_server::core::platform::MaybeSendBoxFuture<
            'a,
            ValidationResult<MockClaims, CountingError>,
        > {
            let error = CountingError(std::sync::Arc::clone(&self.0));
            Box::pin(async move {
                ValidationResult {
                    outcome: Err(error),
                    dpop_nonce: None,
                }
            })
        }
    }

    impl ProvideValidatorMetadata for CountingValidator {
        fn validator_metadata(&self, resource: Option<&str>) -> ValidatorMetadata {
            mock_validator_metadata(resource)
        }
    }

    let counter = std::sync::Arc::new(ChallengeCounter::default());
    let guard = crate::resource::ResourcePolicy::builder()
        .path_guard(crate::resource::GuardConfig::new(
            crate::resource::CaseSensitivity::Sensitive,
            DecodeDepth::UpToOne,
        ))
        .route("/api", Rule::required())
        .build()
        .map(|policy| {
            Guard::new(
                CountingValidator(std::sync::Arc::clone(&counter)),
                policy,
                None,
            )
        })
        .unwrap();

    let outcome = guard
        .check_request(
            &http::HeaderMap::new(),
            &http::Method::GET,
            &"/api".parse().unwrap(),
            None,
        )
        .await;

    assert!(matches!(&outcome, Outcome::Deny { .. }), "{outcome:?}");
    assert_eq!(
        counter.get(),
        1,
        "the rejection path rebuilt the challenge instead of reusing it",
    );
}

#[test]
fn route_denial_preserves_challenges_and_metrics() {
    let metadata = mock_validator_metadata(None);
    for (error, expected_metric, has_challenges) in [
        (
            ResolveError::InvalidPathInput,
            CheckOutcome::PathConfusion,
            true,
        ),
        (
            ResolveError::MethodNotConfigured,
            CheckOutcome::PolicyDenied,
            false,
        ),
        (
            ResolveError::InvalidRuleId,
            CheckOutcome::ServerError,
            false,
        ),
    ] {
        let (outcome, metric) = Guard::<MockValidator>::route_denial(&metadata, &error);
        assert_eq!(metric, expected_metric);
        assert_deny(&outcome, resolve_error_status(&error));
        if let Outcome::Deny {
            challenges,
            dpop_nonce,
            retry_after,
            ..
        } = outcome
        {
            assert_eq!(!challenges.is_empty(), has_challenges);
            assert!(dpop_nonce.is_none());
            assert!(retry_after.is_none());
        }
    }
}

/// The full classification table. `Expired` is unreachable through a challenge (it is
/// RFC 6750 `invalid_token` on the wire), so only a validator that overrides
/// `validation_outcome` reports it — covered here rather than end-to-end.
#[test]
fn validation_outcome_classification_table() {
    use crate::{metrics::CheckOutcome, resource_server::validator::observe::ValidationOutcome};

    for (outcome, expected) in [
        (ValidationOutcome::CallError, CheckOutcome::ServerError),
        (ValidationOutcome::BindingError, CheckOutcome::BindingError),
        (
            ValidationOutcome::NonceRequired,
            CheckOutcome::NonceRequired,
        ),
        (ValidationOutcome::Expired, CheckOutcome::Expired),
        (
            ValidationOutcome::ExtractError,
            CheckOutcome::InvalidRequest,
        ),
        (ValidationOutcome::InvalidToken, CheckOutcome::InvalidToken),
        (
            ValidationOutcome::UnrecognizedIssuer,
            CheckOutcome::UnrecognizedIssuer,
        ),
        // Unreachable on the error path, but floored to the coarse bucket rather than
        // silently counted as a success.
        (ValidationOutcome::NoToken, CheckOutcome::InvalidToken),
    ] {
        assert_eq!(
            CheckOutcome::from_validation(outcome),
            expected,
            "{outcome:?} should classify as {expected:?}",
        );
    }
}

#[test]
fn metrics_insufficient_scope_on_missing_scope() {
    let (_, counters) = with_metrics(async {
        let guard = build_guard(
            MockValidator::valid(MockClaims { scopes: None }),
            vec![("/admin", Rule::required().scopes(["admin"]))],
        );
        check(&guard, &http::Method::GET, "/admin").await
    });
    assert_counter(
        &counters,
        "huskarl.resource.check",
        &[("name", ""), ("outcome", "insufficient_scope")],
        1,
    );
}

#[test]
#[cfg(feature = "metrics")]
fn metrics_name_label_present_when_configured() {
    let (_, counters) = with_metrics(async {
        let guard = crate::resource::ResourcePolicy::builder()
            .path_guard(crate::resource::GuardConfig::new(
                crate::resource::CaseSensitivity::Sensitive,
                DecodeDepth::UpToOne,
            ))
            .metrics_name("edge")
            .route("/health", Rule::public())
            .build()
            .map(|policy| Guard::new(MockValidator::no_token(), policy, None))
            .unwrap();
        check(&guard, &http::Method::GET, "/health").await
    });
    // The counter carries both the `outcome` and the instance `name` label.
    let hit = counters
        .iter()
        .find(|(name, _, _)| name == "huskarl.resource.check");
    let (_, labels, count) = hit.expect("counter emitted");
    assert_eq!(*count, 1);
    assert_eq!(
        labels.as_slice(),
        [
            ("name".to_owned(), "edge".to_owned()),
            ("outcome".to_owned(), "forward".to_owned()),
        ]
    );
}

#[tokio::test]
async fn disabled_guard_still_denies_method_gaps() {
    let guard = crate::resource::ResourcePolicy::builder()
        .path_guard(
            crate::resource::GuardConfig::new(
                crate::resource::CaseSensitivity::Sensitive,
                DecodeDepth::UpToOne,
            )
            .with_mode(crate::resource::GuardMode::Disabled),
        )
        .default(Rule::public())
        .route("/admin", Rule::public().method(http::Method::GET))
        .build()
        .map(|policy| Guard::new(MockValidator::no_token(), policy, None))
        .unwrap();
    assert_deny(
        &check(&guard, &http::Method::POST, "/admin").await,
        http::StatusCode::FORBIDDEN,
    );
    assert_forward(&check(&guard, &http::Method::GET, "/admin").await);
}

#[tokio::test]
async fn configured_analysis_budget_applies_to_encoded_paths() {
    for (budget, allowed) in [(8, false), (64, true)] {
        let guard = crate::resource::ResourcePolicy::builder()
            .path_guard(
                crate::resource::GuardConfig::new(
                    crate::resource::CaseSensitivity::Sensitive,
                    DecodeDepth::UpToOne,
                )
                .with_max_analysis_path_len(budget),
            )
            .subtree("/files", Rule::public())
            .build()
            .map(|policy| Guard::new(MockValidator::no_token(), policy, None))
            .unwrap();
        let outcome = check(&guard, &http::Method::GET, "/files/a%2Fb").await;
        if allowed {
            assert_forward(&outcome);
        } else {
            assert_deny(&outcome, http::StatusCode::BAD_REQUEST);
        }
    }
}

#[tokio::test]
async fn body_details_hide_server_errors_and_untrusted_route_policy() {
    for (validator, path) in [
        (MockValidator::rejecting(MockErrorKind::ServerError), "/api"),
        (MockValidator::no_token(), "/api"),
        (MockValidator::no_token(), "/api/../api"),
    ] {
        let guard = build_guard(
            validator,
            vec![("/api", Rule::required().scopes(["secret"]))],
        );
        let Outcome::Deny {
            status, details, ..
        } = check(&guard, &http::Method::GET, path).await
        else {
            panic!("expected denial")
        };
        if status.is_server_error() || status == http::StatusCode::UNAUTHORIZED {
            assert!(details.error_code.is_none());
            assert!(details.error_description.is_none());
        }
        assert!(details.required_scopes.is_none());
    }
}

#[tokio::test]
async fn custom_check_body_details_preserve_description_without_parsing_headers() {
    let message = "denied \"quoted\" <script>";
    let guard = build_guard(
        MockValidator::valid(MockClaims { scopes: None }),
        vec![(
            "/api",
            Rule::required()
                .check(move |_| Err(crate::resource::rule::CheckError::Forbidden(message.into()))),
        )],
    );
    let Outcome::Deny { details, .. } = check(&guard, &http::Method::GET, "/api").await else {
        panic!("expected denial")
    };
    assert_eq!(
        details.error_code,
        Some(crate::resource_server::error::TokenErrorCode::InsufficientScope)
    );
    assert_eq!(details.error_description.as_deref(), Some(message));
    assert!(details.required_scopes.is_none());
}
