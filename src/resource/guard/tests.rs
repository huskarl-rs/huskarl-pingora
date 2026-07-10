// Mock trait impls satisfy `async fn` signatures without awaiting.
#![allow(clippy::unused_async_trait_impl)]

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
    let mut builder = Guard::builder()
        .validator(validator)
        .case_sensitivity(crate::resource::CaseSensitivity::Sensitive);
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
        .case_sensitivity(crate::resource::CaseSensitivity::Sensitive)
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
        .case_sensitivity(crate::resource::CaseSensitivity::Sensitive)
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

// --- subtree matching ---

#[tokio::test]
async fn subtree_covers_path_and_descendants() {
    // Token is valid but lacks the "admin" scope; the subtree rule must enforce
    // the scope on the bare path, the trailing-slash form, and every descendant.
    let claims = MockClaims {
        scopes: Some("read".into()),
    };
    let guard = Guard::builder()
        .validator(MockValidator::valid(claims))
        .case_sensitivity(crate::resource::CaseSensitivity::Sensitive)
        .subtree("/admin", Rule::required().scopes(["admin"]))
        .build()
        .unwrap();

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
    let guard = Guard::builder()
        .validator(MockValidator::no_token())
        .case_sensitivity(crate::resource::CaseSensitivity::Sensitive)
        .subtree("/admin", Rule::required())
        .route("/admin/health", Rule::public())
        .build()
        .unwrap();

    // The more-specific exact route is public — no token still forwards.
    let outcome = check(&guard, &http::Method::GET, "/admin/health").await;
    assert!(matches!(outcome, Outcome::Forward { token: None, .. }));

    // Everything else under the subtree requires a token.
    let outcome = check(&guard, &http::Method::GET, "/admin/secret").await;
    assert!(matches!(
        outcome,
        Outcome::Deny { status, .. } if status == http::StatusCode::UNAUTHORIZED
    ));
}

#[tokio::test]
async fn subtree_trailing_slash_excludes_bare_path() {
    // A trailing slash means "this directory and its contents, but not the bare
    // name". `/admin/` and descendants are public; bare `/admin` falls through
    // to the default (required) rule.
    let guard = Guard::builder()
        .validator(MockValidator::no_token())
        .case_sensitivity(crate::resource::CaseSensitivity::Sensitive)
        .subtree("/admin/", Rule::public())
        .build()
        .unwrap();

    assert!(matches!(
        check(&guard, &http::Method::GET, "/admin/").await,
        Outcome::Forward { .. }
    ));
    assert!(matches!(
        check(&guard, &http::Method::GET, "/admin/x").await,
        Outcome::Forward { .. }
    ));
    assert!(matches!(
        check(&guard, &http::Method::GET, "/admin").await,
        Outcome::Deny { status, .. } if status == http::StatusCode::UNAUTHORIZED
    ));
}

// --- path-confusion guard ---

#[tokio::test]
async fn guard_denies_traversal_into_scoped_subtree() {
    // Raw `/x/../admin/secret` matches the default rule; a backend that resolves
    // `..` would route it into `/admin`. Route changes → 400.
    let guard = Guard::builder()
        .validator(MockValidator::no_token())
        .case_sensitivity(crate::resource::CaseSensitivity::Sensitive)
        .subtree("/admin", Rule::required().scopes(["admin"]))
        .build()
        .unwrap();

    let outcome = check(&guard, &http::Method::GET, "/x/../admin/secret").await;
    assert!(matches!(
        outcome,
        Outcome::Deny { status, .. } if status == http::StatusCode::BAD_REQUEST
    ));
}

#[tokio::test]
async fn guard_denies_decoded_double_slash() {
    // Raw `/%2f/admin` has no literal `/` after the encoded byte, so it matches
    // the default rule; a backend that decodes `%2F` and merges slashes routes
    // it to `/admin`. Route change → 400. (Without slash-merging in the decode
    // strategy the decoded form is `//admin`, which would slip through.)
    let guard = Guard::builder()
        .validator(MockValidator::no_token())
        .case_sensitivity(crate::resource::CaseSensitivity::Sensitive)
        .subtree("/admin", Rule::required().scopes(["admin"]))
        .build()
        .unwrap();

    let outcome = check(&guard, &http::Method::GET, "/%2f/admin").await;
    assert!(matches!(
        outcome,
        Outcome::Deny { status, .. } if status == http::StatusCode::BAD_REQUEST
    ));
}

#[tokio::test]
async fn guard_denies_encoded_dot_traversal() {
    let guard = Guard::builder()
        .validator(MockValidator::no_token())
        .case_sensitivity(crate::resource::CaseSensitivity::Sensitive)
        .subtree("/admin", Rule::required())
        .build()
        .unwrap();

    let outcome = check(&guard, &http::Method::GET, "/%2e%2e/admin").await;
    assert!(matches!(
        outcome,
        Outcome::Deny { status, .. } if status == http::StatusCode::BAD_REQUEST
    ));
}

#[tokio::test]
async fn guard_denies_path_param_vector() {
    // `/admin/..;/secret` matches `/admin` raw, but `;`-strip-then-resolve escapes
    // to `/secret` (default) — route change → 400.
    let guard = Guard::builder()
        .validator(MockValidator::no_token())
        .case_sensitivity(crate::resource::CaseSensitivity::Sensitive)
        .subtree("/admin", Rule::required())
        .build()
        .unwrap();

    let outcome = check(&guard, &http::Method::GET, "/admin/..;/secret").await;
    assert!(matches!(
        outcome,
        Outcome::Deny { status, .. } if status == http::StatusCode::BAD_REQUEST
    ));
}

#[tokio::test]
async fn guard_allows_non_structural_encoded_content() {
    // Non-structural encoded content (`%20`) decodes to a deeper path under the same
    // `/files/{*rest}` rule — no route change → allowed by the content-decode precision.
    let guard = Guard::builder()
        .validator(MockValidator::no_token())
        .case_sensitivity(crate::resource::CaseSensitivity::Sensitive)
        .subtree("/files", Rule::public())
        .build()
        .unwrap();

    let outcome = check(&guard, &http::Method::GET, "/files/a%20b").await;
    assert!(matches!(outcome, Outcome::Forward { token: None, .. }));
}

#[tokio::test]
async fn blob_subtree_tolerates_structural_byte_in_key() {
    // `blob_subtree` opts the catch-all tail into opaque-key handling: an encoded slash
    // in the key is forwarded, but a dot-segment still denies (no traversal escape).
    let guard = Guard::builder()
        .validator(MockValidator::no_token())
        .case_sensitivity(crate::resource::CaseSensitivity::Sensitive)
        .blob_subtree("/files", Rule::public())
        .build()
        .unwrap();

    let forwarded = check(&guard, &http::Method::GET, "/files/a%2fb").await;
    assert!(matches!(forwarded, Outcome::Forward { token: None, .. }));

    let denied = check(&guard, &http::Method::GET, "/files/a/../b").await;
    assert!(matches!(
        denied,
        Outcome::Deny { status, .. } if status == http::StatusCode::BAD_REQUEST
    ));
}

#[tokio::test]
async fn method_specific_rule_closes_other_methods_no_backtrack() {
    // The canonical method case. `GET /admin` is public; a root catch-all is public for
    // *any* method. A `POST /admin` must NOT escape its `/admin` claim into the permissive
    // catch-all — it falls to the default rule (required) and denies. (The no-backtrack
    // invariant: a method miss never re-broadens the path.)
    let guard = Guard::builder()
        .validator(MockValidator::no_token())
        .case_sensitivity(crate::resource::CaseSensitivity::Sensitive)
        .route("/{*rest}", Rule::public()) // catch-all, any method, public
        .route("/admin", Rule::public().method(http::Method::GET)) // GET /admin public
        .build()
        .unwrap();

    // GET /admin → its GET rule → public.
    assert!(matches!(
        check(&guard, &http::Method::GET, "/admin").await,
        Outcome::Forward { token: None, .. }
    ));
    // POST /admin → no POST rule at /admin, no wildcard there → default (required) → 401.
    // Crucially NOT the public catch-all.
    assert!(matches!(
        check(&guard, &http::Method::POST, "/admin").await,
        Outcome::Deny { status, .. } if status == http::StatusCode::UNAUTHORIZED
    ));
    // POST /other → matches the catch-all (any method) → public.
    assert!(matches!(
        check(&guard, &http::Method::POST, "/other").await,
        Outcome::Forward { token: None, .. }
    ));
}

#[tokio::test]
async fn method_wildcard_fallback_is_per_terminal() {
    // A wildcard-method rule on the *same path* is the fallback for unlisted methods —
    // and it is not inherited from a broader catch-all (see the test above).
    let guard = Guard::builder()
        .validator(MockValidator::no_token())
        .case_sensitivity(crate::resource::CaseSensitivity::Sensitive)
        .route("/admin", Rule::public().method(http::Method::GET)) // GET public
        .route("/admin", Rule::required()) // every other method requires a token
        .build()
        .unwrap();

    assert!(matches!(
        check(&guard, &http::Method::GET, "/admin").await,
        Outcome::Forward { token: None, .. }
    ));
    assert!(matches!(
        check(&guard, &http::Method::POST, "/admin").await,
        Outcome::Deny { status, .. } if status == http::StatusCode::UNAUTHORIZED
    ));
}

#[tokio::test]
async fn method_axis_falls_to_default_rule_not_the_method_rule() {
    // Documented sharp edge (see `Rule::method`): a method-specific rule does NOT protect
    // other methods on its path — they fall to the *default* rule, never inheriting the
    // method rule's policy. Here the default is permissive, so scoping the protection to
    // POST silently leaves GET open. This pins the fall-through target as the default (the
    // dangerous direction the catch-all tests above don't exercise, since their default is
    // the implicit `required`).
    let guard = Guard::builder()
        .validator(MockValidator::no_token())
        .case_sensitivity(crate::resource::CaseSensitivity::Sensitive)
        .default(Rule::public()) // permissive fallback
        .route("/admin", Rule::required().method(http::Method::POST)) // only POST is protected
        .build()
        .unwrap();

    // POST /admin → its method rule → required → 401 without a token.
    assert!(matches!(
        check(&guard, &http::Method::POST, "/admin").await,
        Outcome::Deny { status, .. } if status == http::StatusCode::UNAUTHORIZED
    ));
    // GET /admin → no GET rule at /admin → the *default* (public), NOT the POST rule.
    // The protection scoped to POST does not extend to GET.
    assert!(matches!(
        check(&guard, &http::Method::GET, "/admin").await,
        Outcome::Forward { token: None, .. }
    ));
}

#[test]
fn blob_subtree_with_nested_route_is_build_error() {
    // A more-specific route under the blob would let a structural byte relocate into it.
    let result = Guard::builder()
        .validator(MockValidator::no_token())
        .case_sensitivity(crate::resource::CaseSensitivity::Sensitive)
        .blob_subtree("/files", Rule::public())
        .route("/files/secret", Rule::required())
        .build();
    assert!(matches!(
        result,
        Err(crate::resource::ConfigError::Route { .. })
    ));
}

#[tokio::test]
async fn guard_denies_structural_byte_in_plain_blob() {
    // Under the uniform-live model, a plain `subtree` blob denies an encoded slash in
    // its tail (a structural byte). Tolerating it is an explicit opt-in (opaque blob),
    // not the default.
    let guard = Guard::builder()
        .validator(MockValidator::no_token())
        .case_sensitivity(crate::resource::CaseSensitivity::Sensitive)
        .subtree("/files", Rule::public())
        .build()
        .unwrap();

    let outcome = check(&guard, &http::Method::GET, "/files/a%2fb").await;
    assert!(matches!(
        outcome,
        Outcome::Deny { status, .. } if status == http::StatusCode::BAD_REQUEST
    ));
}

#[tokio::test]
async fn guard_inert_for_double_encoding() {
    // Double-encoded dots are inert in a single pass (no `.` produced), so no
    // route change: the request falls through to the default rule (401 for the
    // missing token), not a 400 from the guard.
    let guard = Guard::builder()
        .validator(MockValidator::no_token())
        .case_sensitivity(crate::resource::CaseSensitivity::Sensitive)
        .subtree("/admin", Rule::required())
        .build()
        .unwrap();

    let outcome = check(&guard, &http::Method::GET, "/%252e%252e/admin").await;
    assert!(matches!(
        outcome,
        Outcome::Deny { status, .. } if status == http::StatusCode::UNAUTHORIZED
    ));
}

#[tokio::test]
async fn guard_allows_long_clean_path() {
    // A very long but canonical path (no `%`/`;`/`//`/`/.`) can't be ambiguous,
    // so the length cap must not reject it — it routes under its rule normally.
    let guard = Guard::builder()
        .validator(MockValidator::no_token())
        .case_sensitivity(crate::resource::CaseSensitivity::Sensitive)
        .subtree("/files", Rule::public())
        .build()
        .unwrap();

    let path = format!("/files/{}", "a".repeat(16_384));
    let outcome = check(&guard, &http::Method::GET, &path).await;
    assert!(matches!(outcome, Outcome::Forward { token: None, .. }));
}

#[tokio::test]
async fn guard_rejects_long_suspicious_path() {
    // A suspicious path (contains `%`) over the cap is denied: once the first
    // normalization shows the path can change, the length cap rejects it before
    // the remaining normalizations run.
    let guard = Guard::builder()
        .validator(MockValidator::no_token())
        .case_sensitivity(crate::resource::CaseSensitivity::Sensitive)
        .subtree("/files", Rule::public())
        .build()
        .unwrap();

    let path = format!("/files/{}%2e", "a".repeat(16_384));
    let outcome = check(&guard, &http::Method::GET, &path).await;
    assert!(matches!(
        outcome,
        Outcome::Deny { status, .. } if status == http::StatusCode::BAD_REQUEST
    ));
}

#[tokio::test]
async fn guard_off_allows_traversal() {
    // With the guard disabled, `/x/../admin/secret` falls to the default
    // (required) rule and is denied for the missing token (401), not 400.
    let guard = Guard::builder()
        .validator(MockValidator::no_token())
        .case_sensitivity(crate::resource::CaseSensitivity::Sensitive)
        .subtree("/admin", Rule::required().scopes(["admin"]))
        .path_confusion(crate::resource::PathConfusion::off())
        .build()
        .unwrap();

    let outcome = check(&guard, &http::Method::GET, "/x/../admin/secret").await;
    assert!(matches!(
        outcome,
        Outcome::Deny { status, .. } if status == http::StatusCode::UNAUTHORIZED
    ));
}

// --- build-time non-canonical-pattern detection ---

#[test]
fn build_rejects_noncanonical_pattern_with_double_slash() {
    // `/a//b` carries a `//` the guard treats as route structure → non-canonical.
    let result = Guard::builder()
        .validator(MockValidator::no_token())
        .case_sensitivity(crate::resource::CaseSensitivity::Sensitive)
        .route("/a/b", Rule::public())
        .route("/a//b", Rule::required())
        .build();
    assert!(matches!(
        result,
        Err(crate::resource::ConfigError::NonCanonicalPattern { .. })
    ));
}

#[test]
fn build_rejects_traversal_pattern() {
    // `/x/../b` carries a `..` dot-segment → non-canonical.
    let result = Guard::builder()
        .validator(MockValidator::no_token())
        .case_sensitivity(crate::resource::CaseSensitivity::Sensitive)
        .route("/x/../b", Rule::required())
        .build();
    assert!(matches!(
        result,
        Err(crate::resource::ConfigError::NonCanonicalPattern { .. })
    ));
}

#[test]
fn build_allows_noncanonical_pattern_when_guard_off() {
    // With the guard off, the build-time non-canonical-pattern check is skipped, so a
    // pattern carrying a structural byte (here `%2f`) is accepted as a literal route.
    let result = Guard::builder()
        .validator(MockValidator::no_token())
        .case_sensitivity(crate::resource::CaseSensitivity::Sensitive)
        .route("/a/b", Rule::public())
        .route("/a%2fb", Rule::required())
        .path_confusion(crate::resource::PathConfusion::off())
        .build();
    assert!(result.is_ok());
}

#[test]
fn build_rejects_public_rule_with_check() {
    // A check function on a public rule can never run — the validator is skipped
    // for public routes. Reject it at build time rather than store a dead check.
    let result = Guard::builder()
        .validator(MockValidator::no_token())
        .case_sensitivity(crate::resource::CaseSensitivity::Sensitive)
        .route("/health", Rule::public().check(|_| Ok(())))
        .build();
    assert!(matches!(
        result,
        Err(crate::resource::ConfigError::PublicRuleWithConstraints(p)) if p == "/health"
    ));
}

#[test]
fn build_rejects_public_default_rule_with_check() {
    let result = Guard::builder()
        .validator(MockValidator::no_token())
        .case_sensitivity(crate::resource::CaseSensitivity::Sensitive)
        .default(Rule::public().check(|_| Ok(())))
        .build();
    assert!(matches!(
        result,
        Err(crate::resource::ConfigError::PublicRuleWithConstraints(p)) if p == "<default>"
    ));
}

#[test]
fn build_allows_distinct_canonical_trailing_slash_routes() {
    // Both `/admin` and `/admin/` are canonical (no structural bytes) → no conflict.
    let result = Guard::builder()
        .validator(MockValidator::no_token())
        .case_sensitivity(crate::resource::CaseSensitivity::Sensitive)
        .route("/admin", Rule::public())
        .route("/admin/", Rule::required())
        .build();
    assert!(result.is_ok());
}

// --- opt-in classes via the structural API ---

#[tokio::test]
async fn structural_case_opt_in_catches_relocation() {
    let guard = Guard::builder()
        .validator(MockValidator::no_token())
        .case_sensitivity(crate::resource::CaseSensitivity::Insensitive)
        .subtree("/admin", Rule::required())
        .build()
        .unwrap();

    // `/Admin/x` carries uppercase a case-insensitive backend would fold onto the
    // protected `/admin` rule → denied 400.
    let outcome = check(&guard, &http::Method::GET, "/Admin/x").await;
    assert!(matches!(
        outcome,
        Outcome::Deny { status, .. } if status == http::StatusCode::BAD_REQUEST
    ));
}

#[tokio::test]
async fn structural_case_not_flagged_by_default() {
    // Without with_case, a mixed-case path is not structural → falls to the
    // default (required) rule → 401 for the missing token, not a 400.
    let guard = Guard::builder()
        .validator(MockValidator::no_token())
        .case_sensitivity(crate::resource::CaseSensitivity::Sensitive)
        .subtree("/admin", Rule::required())
        .build()
        .unwrap();

    let outcome = check(&guard, &http::Method::GET, "/Admin/x").await;
    assert!(matches!(
        outcome,
        Outcome::Deny { status, .. } if status == http::StatusCode::UNAUTHORIZED
    ));
}

// --- strict hygiene (RejectNonCanonical) ---

#[tokio::test]
async fn hygiene_rejects_noncanonical_even_when_same_rule() {
    use crate::resource::PathConfusion;
    // `/files/a%2fb` stays in the same `/files` rule (no relocation), so the default
    // RejectStructural allows it (inert blob key) — but strict hygiene rejects it.
    let guard = Guard::builder()
        .validator(MockValidator::no_token())
        .case_sensitivity(crate::resource::CaseSensitivity::Sensitive)
        .subtree("/files", Rule::public())
        .path_confusion(PathConfusion::reject_non_canonical())
        .build()
        .unwrap();

    let outcome = check(&guard, &http::Method::GET, "/files/a%2fb").await;
    assert!(matches!(
        outcome,
        Outcome::Deny { status, .. } if status == http::StatusCode::BAD_REQUEST
    ));
}

#[tokio::test]
async fn hygiene_allows_canonical_path() {
    use crate::resource::PathConfusion;
    let guard = Guard::builder()
        .validator(MockValidator::no_token())
        .case_sensitivity(crate::resource::CaseSensitivity::Sensitive)
        .subtree("/files", Rule::public())
        .path_confusion(PathConfusion::reject_non_canonical())
        .build()
        .unwrap();

    // A clean path is canonical → allowed (public → forward).
    let outcome = check(&guard, &http::Method::GET, "/files/a/b").await;
    assert!(matches!(outcome, Outcome::Forward { token: None, .. }));
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
    let guard = Guard::builder()
        .validator(MockValidator::no_token())
        .case_sensitivity(crate::resource::CaseSensitivity::Sensitive)
        .subtree("/admin", Rule::required().scopes(["admin"]))
        .structural_classes(StructuralClasses::new().with_probe(DangerPrefixProbe))
        .build()
        .unwrap();

    // `/danger/secret` carries the probe's form → denied 400 (break-glass).
    let outcome = check(&guard, &http::Method::GET, "/danger/secret").await;
    assert!(matches!(
        outcome,
        Outcome::Deny { status, .. } if status == http::StatusCode::BAD_REQUEST
    ));
}

#[tokio::test]
async fn structural_overlong_opt_in_catches_relocation() {
    use crate::resource::{StructuralChar, StructuralClasses};
    // A backend that decodes overlong UTF-8 reads `/x%c0%af..%c0%afadmin/secret`
    // as `/x/../admin/secret` → `/admin/secret`; with the overlong forms recognised
    // the structural scan reveals the `..` and denies it.
    let guard = Guard::builder()
        .validator(MockValidator::no_token())
        .case_sensitivity(crate::resource::CaseSensitivity::Sensitive)
        .subtree("/admin", Rule::required())
        .structural_classes(
            StructuralClasses::new().with_overlong([StructuralChar::Slash, StructuralChar::Dot]),
        )
        .build()
        .unwrap();

    let outcome = check(&guard, &http::Method::GET, "/x%c0%af..%c0%afadmin/secret").await;
    assert!(matches!(
        outcome,
        Outcome::Deny { status, .. } if status == http::StatusCode::BAD_REQUEST
    ));
}

#[tokio::test]
async fn structural_overlong_not_flagged_by_default() {
    // Without the opt-in, overlong bytes are inert (the default scan only handles
    // single-byte %2F/%2E), so the path falls to the default (required) rule → 401
    // for the missing token, not a 400.
    let guard = Guard::builder()
        .validator(MockValidator::no_token())
        .case_sensitivity(crate::resource::CaseSensitivity::Sensitive)
        .subtree("/admin", Rule::required())
        .build()
        .unwrap();

    let outcome = check(&guard, &http::Method::GET, "/x%c0%af..%c0%afadmin/secret").await;
    assert!(matches!(
        outcome,
        Outcome::Deny { status, .. } if status == http::StatusCode::UNAUTHORIZED
    ));
}

#[tokio::test]
async fn structural_null_truncation_opt_in_catches() {
    use crate::resource::StructuralClasses;
    // A NUL-terminating backend reads `/admin%00/secret` as `/admin`; the truncation
    // class denies the `%00`.
    let guard = Guard::builder()
        .validator(MockValidator::no_token())
        .case_sensitivity(crate::resource::CaseSensitivity::Sensitive)
        .subtree("/admin", Rule::required())
        .structural_classes(StructuralClasses::new().with_null_truncation())
        .build()
        .unwrap();

    let outcome = check(&guard, &http::Method::GET, "/admin%00/secret").await;
    assert!(matches!(
        outcome,
        Outcome::Deny { status, .. } if status == http::StatusCode::BAD_REQUEST
    ));
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
    assert!(matches!(
        outcome,
        Outcome::Deny { status, .. } if status == http::StatusCode::UNAUTHORIZED
    ));
    // A public path matches on its path regardless of the query.
    let outcome = check(&guard, &http::Method::GET, "/public?next=/admin").await;
    assert!(matches!(outcome, Outcome::Forward { token: None, .. }));
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
    assert!(matches!(
        outcome,
        Outcome::Deny { status, .. } if status == http::StatusCode::UNAUTHORIZED
    ));
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
    assert!(matches!(
        outcome,
        Outcome::Deny { status, .. } if status == http::StatusCode::UNAUTHORIZED
    ));
}
