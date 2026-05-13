use std::borrow::Cow;
use std::collections::BTreeSet;
use std::sync::{Arc, LazyLock};

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde_json::Value;
use vector_lib::configurable::configurable_component;
use vector_lib::event::Event;
use vrl::path::{parse_target_path, OwnedTargetPath};

/// Pre-parsed path for the `auth_field_name` log/trace metadata field.
pub(crate) static AUTH_FIELD_NAME_PATH: LazyLock<OwnedTargetPath> =
    LazyLock::new(|| parse_target_path("auth_field_name").expect("valid static path"));

/// Pre-parsed path for the `auth_field_value` log/trace metadata field.
pub(crate) static AUTH_FIELD_VALUE_PATH: LazyLock<OwnedTargetPath> =
    LazyLock::new(|| parse_target_path("auth_field_value").expect("valid static path"));

/// Metric tag key for the auth field name (metrics use plain string keys).
pub(crate) const AUTH_FIELD_NAME_TAG: &str = "auth_field_name";

/// Metric tag key for the auth field value.
pub(crate) const AUTH_FIELD_VALUE_TAG: &str = "auth_field_value";

/// Errors returned by [`Auth::authenticate`] (request-level).
#[derive(Debug, PartialEq)]
pub enum AuthError {
    /// The `authorization` header was present but the token is invalid, malformed, expired,
    /// or failed signature verification.
    ///
    /// Maps to HTTP 401 / gRPC `Unauthenticated`. Reject the entire request.
    InvalidToken(&'static str),
}

/// Errors produced by [`EventValidator::check`] (per-event).
///
/// Named after the equivalent HTTP status codes so the mapping to gRPC response
/// codes and metric outcome labels is unambiguous.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthEventError {
    /// The configured auth field was absent from the event or held a non-string value.
    ///
    /// The request JWT itself was valid — only the per-event authorization field is missing.
    AuthorizationMissing,

    /// The field value was present but is not listed in the token's membership claim.
    ///
    /// Equivalent to HTTP 403 — identity is known but not permitted.
    /// Maps to gRPC `PermissionDenied`.
    Forbidden,
}

impl AuthEventError {
    /// Short label used as a metric tag value for the `outcome` dimension.
    pub fn label(&self) -> &'static str {
        match self {
            AuthEventError::AuthorizationMissing => "authorization_missing",
            AuthEventError::Forbidden => "forbidden",
        }
    }
}

/// Source of the RSA public key PEM used to verify auth token signatures.
///
/// Exactly one variant must be configured.
///
/// ## Examples
///
/// Inline PEM (use Vector's `${VAR}` interpolation for env vars):
/// ```toml
/// public_key.type = "inline"
/// public_key.value = "${RSA_PUBLIC_KEY}"
/// ```
///
/// File path (preferred for Kubernetes ConfigMap mounts — key is read once at startup):
/// ```toml
/// public_key.type = "file"
/// public_key.path = "/etc/certs/auth.pem"
/// ```
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(rename_all = "snake_case", tag = "type", deny_unknown_fields)]
pub enum AuthPublicKey {
    /// Inline PEM value.
    ///
    /// Supports Vector's `${ENV_VAR}` interpolation. The value is read once at startup.
    Inline {
        /// RSA public key in PEM format.
        value: String,
    },

    /// Path to a file containing the RSA public key in PEM format.
    ///
    /// Preferred for Kubernetes ConfigMap or secret volume mounts.
    /// The file is read once at source startup.
    File {
        /// Path to the PEM file.
        path: String,
    },
}

/// Event field paths used to extract the membership value for per-event auth.
///
/// The `default` path is used for all event types unless a more specific override is set.
/// For metric events, `metric_tag` is a tag key rather than a field path.
///
/// ## Example
///
/// ```toml
/// [sources.my_source.auth.value_path]
/// default    = "tenant_id"
/// metric_tag = "tenant_id"
/// ```
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct AuthValuePath {
    /// Field path (or metric tag key) used for all event types unless a type-specific
    /// override is configured.
    pub default: String,

    /// Field path for log events. Overrides `default` when set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log: Option<String>,

    /// Tag key for metric events. Overrides `default` when set.
    ///
    /// Note: for metrics `default` is also interpreted as a tag key if this field is absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metric_tag: Option<String>,

    /// Field path for trace events. Overrides `default` when set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace: Option<String>,
}

impl AuthValuePath {
    /// Returns the effective field path for a log event.
    pub fn for_log(&self) -> &str {
        self.log.as_deref().unwrap_or(&self.default)
    }

    /// Returns the effective tag key for a metric event.
    pub fn for_metric(&self) -> &str {
        self.metric_tag.as_deref().unwrap_or(&self.default)
    }

    /// Returns the effective field path for a trace event.
    pub fn for_trace(&self) -> &str {
        self.trace.as_deref().unwrap_or(&self.default)
    }
}

/// A pre-parsed event path paired with the original user-configured name.
///
/// The `name` is what gets stamped onto authorized events as the
/// `auth_field_name` metadata. The `path` is the parsed form used for the
/// per-event lookup — built once at config load so the hot path skips the
/// VRL path parser.
#[derive(Debug)]
pub struct CompiledPath {
    pub(crate) name: String,
    pub(crate) path: OwnedTargetPath,
}

/// Runtime form of [`AuthValuePath`] with paths pre-parsed.
///
/// Built once by [`AuthConfig::build`]; held inside the `Arc<Inner>` so every
/// `EventValidator` borrows it for free.
#[derive(Debug)]
pub struct CompiledValuePath {
    pub(crate) log: CompiledPath,
    /// Metric tag keys are plain strings, not paths — no parse step.
    pub(crate) metric_tag: String,
    pub(crate) trace: CompiledPath,
}

impl TryFrom<&AuthValuePath> for CompiledValuePath {
    type Error = vrl::path::PathParseError;

    fn try_from(vp: &AuthValuePath) -> Result<Self, Self::Error> {
        let log_str = vp.log.as_deref().unwrap_or(&vp.default);
        let metric_str = vp.metric_tag.as_deref().unwrap_or(&vp.default);
        let trace_str = vp.trace.as_deref().unwrap_or(&vp.default);
        Ok(Self {
            log: CompiledPath {
                name: log_str.to_string(),
                path: parse_target_path(log_str)?,
            },
            metric_tag: metric_str.to_string(),
            trace: CompiledPath {
                name: trace_str.to_string(),
                path: parse_target_path(trace_str)?,
            },
        })
    }
}

/// Stamp the auth field name/value onto an authorized event.
///
/// Uses pre-parsed [`OwnedTargetPath`]s for log/trace inserts so the hot path
/// avoids re-parsing `"auth_field_name"` / `"auth_field_value"` per event.
pub fn add_auth_metadata(event: &mut Event, name: &str, value: &str) {
    match event {
        Event::Log(log) => {
            log.insert(&*AUTH_FIELD_NAME_PATH, name);
            log.insert(&*AUTH_FIELD_VALUE_PATH, value);
        }
        Event::Metric(metric) => {
            metric.replace_tag(AUTH_FIELD_NAME_TAG.to_owned(), name.to_owned());
            metric.replace_tag(AUTH_FIELD_VALUE_TAG.to_owned(), value.to_owned());
        }
        Event::Trace(trace) => {
            trace.insert(&*AUTH_FIELD_NAME_PATH, name);
            trace.insert(&*AUTH_FIELD_VALUE_PATH, value);
        }
    }
}

/// JWT signing algorithm.
///
/// All variants verify against an RSA public key, so a single configured
/// PEM works for any combination of these.
#[configurable_component]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthAlgorithm {
    /// RSASSA-PKCS1-v1_5 using SHA-256.
    #[serde(rename = "RS256")]
    Rs256,
    /// RSASSA-PKCS1-v1_5 using SHA-384.
    #[serde(rename = "RS384")]
    Rs384,
    /// RSASSA-PKCS1-v1_5 using SHA-512.
    #[serde(rename = "RS512")]
    Rs512,
    /// RSASSA-PSS using SHA-256.
    #[serde(rename = "PS256")]
    Ps256,
    /// RSASSA-PSS using SHA-384.
    #[serde(rename = "PS384")]
    Ps384,
    /// RSASSA-PSS using SHA-512.
    #[serde(rename = "PS512")]
    Ps512,
}

impl From<AuthAlgorithm> for Algorithm {
    fn from(a: AuthAlgorithm) -> Self {
        match a {
            AuthAlgorithm::Rs256 => Algorithm::RS256,
            AuthAlgorithm::Rs384 => Algorithm::RS384,
            AuthAlgorithm::Rs512 => Algorithm::RS512,
            AuthAlgorithm::Ps256 => Algorithm::PS256,
            AuthAlgorithm::Ps384 => Algorithm::PS384,
            AuthAlgorithm::Ps512 => Algorithm::PS512,
        }
    }
}

/// Default allowlist: full RSA family.
///
/// All six algorithms verify against the same RSA public key. Including all
/// of them lets a single source config accept tokens from any IdP using
/// RSA-based signing (RSxxx for PKCS1-v1_5, PSxxx for PSS). Excludes:
/// - HMAC (`HS*`): wrong key type, plus the well-known RS↔HS confusion attack
/// - ECDSA (`ES*`) and EdDSA: incompatible with the RSA-only PEM loader
/// - `none`: never accepted by jsonwebtoken regardless
pub(crate) fn default_algorithms() -> Vec<AuthAlgorithm> {
    vec![
        AuthAlgorithm::Rs256,
        AuthAlgorithm::Rs384,
        AuthAlgorithm::Rs512,
        AuthAlgorithm::Ps256,
        AuthAlgorithm::Ps384,
        AuthAlgorithm::Ps512,
    ]
}

/// Auth configuration for sources.
///
/// The RSA public key is parsed once at source startup; per-request validation is
/// purely in-process with no network calls. When the `authorization` header is
/// absent, [`Auth::authenticate`] returns `Ok(None)` and the request is accepted
/// without per-event filtering.
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// Source of the RSA public key PEM used to verify auth token signatures.
    pub public_key: AuthPublicKey,

    /// JWT signing algorithms accepted for token verification.
    ///
    /// Tokens whose `alg` header is not in this list are rejected. Pinning
    /// the algorithm at the validator is critical: a token's own `alg` claim
    /// is not trusted alone, which is what prevents `alg: none` and
    /// RS↔HS key-confusion attacks.
    ///
    /// Defaults to the full RSA family
    /// (`RS256`/`RS384`/`RS512` + `PS256`/`PS384`/`PS512`), which covers
    /// effectively all real-world IdPs using RSA public keys.
    #[serde(default = "default_algorithms")]
    pub algorithms: Vec<AuthAlgorithm>,

    /// Expected `iss` (issuer) claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,

    /// Expected `aud` (audience) claim values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Vec<String>>,

    /// Name of the JWT claim whose array value is checked for membership.
    ///
    /// Defaults to `"site_ids"`.
    #[serde(default = "default_membership_claim")]
    pub membership_claim: String,

    /// Event field paths used to extract the membership value for per-event auth.
    ///
    /// When set, each event's field at the configured path is looked up and checked
    /// against the token's membership claim. Events without a matching value are
    /// filtered out. When absent, no per-event filtering is applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_path: Option<AuthValuePath>,

    /// When `true`, requests without an `authorization` header are rejected
    /// with `Unauthenticated`. Defaults to `true` (secure by default).
    ///
    /// Set to `false` to opt into the legacy fallback that accepts requests
    /// without a token (useful during a staged migration where older agents
    /// haven't been updated yet).
    ///
    /// Applies to both `push_events` and `health_check` RPCs so a sink with
    /// auth misconfigured fails its healthcheck rather than silently
    /// bypassing token validation.
    #[serde(default = "default_require_token")]
    pub require_token: bool,
}

fn default_require_token() -> bool {
    true
}

fn default_membership_claim() -> String {
    "site_ids".to_string()
}

impl AuthConfig {
    /// Builds the runtime [`Auth`] by loading and parsing the RSA public key.
    ///
    /// All I/O and PEM parsing happen here — once at startup.
    /// The resulting [`Auth`] is cheap to clone and holds no file handles.
    pub fn build(&self) -> crate::Result<Auth> {
        let pem = self.load_pem()?;

        let decoding_key = DecodingKey::from_rsa_pem(pem.as_bytes())
            .map_err(|e| format!("Failed to parse RSA public key PEM: {e}"))?;

        if self.algorithms.is_empty() {
            return Err("auth.algorithms must contain at least one algorithm".into());
        }

        // Seed `Validation` with the first algorithm, then overwrite with the
        // full allowlist. jsonwebtoken's verifier checks the token's `alg`
        // header against `validation.algorithms` and rejects anything not on
        // the list, regardless of which one was used to seed `new`.
        let mut validation = Validation::new(self.algorithms[0].into());
        validation.algorithms = self.algorithms.iter().copied().map(Algorithm::from).collect();

        if let Some(issuer) = &self.issuer {
            validation.set_issuer(&[issuer]);
        }

        if let Some(audiences) = &self.audience {
            validation.set_audience(audiences);
        } else {
            validation.validate_aud = false;
        }

        let value_path = self
            .value_path
            .as_ref()
            .map(CompiledValuePath::try_from)
            .transpose()
            .map_err(|e| format!("Failed to parse auth value_path: {e}"))?;

        Ok(Auth(Arc::new(Inner {
            decoding_key,
            validation,
            membership_claim: self.membership_claim.clone(),
            value_path,
            require_token: self.require_token,
        })))
    }

    fn load_pem(&self) -> crate::Result<String> {
        match &self.public_key {
            AuthPublicKey::Inline { value } => Ok(value.clone()),
            AuthPublicKey::File { path } => std::fs::read_to_string(path)
                .map_err(|e| format!("Failed to read auth public key from '{path}': {e}").into()),
        }
    }
}

// Private — holds the parsed key and validation config behind Arc so Auth is
// cheap to clone across tokio tasks without copying the RSA key bytes.
struct Inner {
    decoding_key: DecodingKey,
    validation: Validation,
    membership_claim: String,
    value_path: Option<CompiledValuePath>,
    require_token: bool,
}

/// Per-request auth context returned by a successful [`Auth::authenticate`] call.
///
/// Holds the list of allowed membership values extracted from the JWT claim.
/// Pass to per-event validation helpers in the source's event-processing loop.
pub struct AuthContext {
    pub(crate) allowed_values: BTreeSet<String>,
}

impl AuthContext {
    /// Returns `true` if `value` is present in the token's membership claim array.
    pub fn is_authorized(&self, value: &str) -> bool {
        self.allowed_values.contains(value)
    }

    /// Bind this context to a [`CompiledValuePath`], producing an [`EventValidator`]
    /// that can be used directly in `.filter_map()` or `.map()` iterator chains.
    pub fn into_validator<'a>(
        &'a self,
        value_path: &'a CompiledValuePath,
    ) -> EventValidator<'a> {
        EventValidator {
            context: self,
            value_path,
        }
    }
}

/// Per-event validator produced by [`AuthContext::into_validator`].
///
/// Encapsulates the allowed-values list and the field-path configuration so
/// it can be used as a self-contained predicate in event-processing pipelines.
///
/// # Example
///
/// ```ignore
/// let validator = ctx.into_validator(value_path);
/// let authorized: Vec<Event> = events
///     .into_iter()
///     .filter_map(|mut event| {
///         match validator.check(&event) {
///             Ok((name, value)) => {
///                 add_auth_metadata(&mut event, &name, &value);
///                 Some(event)
///             }
///             Err(_) => None,
///         }
///     })
///     .collect();
/// ```
pub struct EventValidator<'a> {
    context: &'a AuthContext,
    value_path: &'a CompiledValuePath,
}

impl<'a> EventValidator<'a> {
    /// Validate a single event.
    ///
    /// # Returns
    ///
    /// * `Ok((field_name, field_value))` — the event is authorized. `field_name`
    ///   borrows the user-configured path string from the validator;
    ///   `field_value` is the value extracted from the event.
    /// * `Err(AuthEventError::AuthorizationMissing)` — the configured field is absent or
    ///   holds a non-string value; the event's identity cannot be determined.
    /// * `Err(AuthEventError::Forbidden)` — the field value is present but not listed
    ///   in the token's membership claim.
    pub fn check<'e>(
        &self,
        event: &'e Event,
    ) -> Result<(&'a str, Cow<'e, str>), AuthEventError> {
        let (field_name, field_value) = self.read_field(event);
        match field_value {
            Some(value) if self.context.is_authorized(&value) => Ok((field_name, value)),
            Some(_) => Err(AuthEventError::Forbidden),
            None => Err(AuthEventError::AuthorizationMissing),
        }
    }

    fn read_field<'e>(&self, event: &'e Event) -> (&'a str, Option<Cow<'e, str>>) {
        match event {
            Event::Log(log) => {
                let value = log.get(&self.value_path.log.path).and_then(|v| v.as_str());
                (self.value_path.log.name.as_str(), value)
            }
            Event::Metric(metric) => {
                let value = metric
                    .tag_value(&self.value_path.metric_tag)
                    .map(Cow::Owned);
                (self.value_path.metric_tag.as_str(), value)
            }
            Event::Trace(trace) => {
                let value = trace
                    .get(&self.value_path.trace.path)
                    .and_then(|v| v.as_str());
                (self.value_path.trace.name.as_str(), value)
            }
        }
    }
}

/// Runtime auth handle built from [`AuthConfig`].
///
/// Cheap to clone — all state is held behind an [`Arc`].
#[derive(Clone)]
pub struct Auth(Arc<Inner>);

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Auth")
            .field("membership_claim", &self.0.membership_claim)
            .finish_non_exhaustive()
    }
}

impl Auth {
    /// Returns the configured event field path config, if any.
    pub fn value_path(&self) -> Option<&CompiledValuePath> {
        self.0.value_path.as_ref()
    }

    /// Validate the request-level JWT and return an [`AuthContext`] for per-event validation.
    ///
    /// # Parameters
    ///
    /// * `authorization` — value of the `authorization` / `Authorization` header, if present.
    ///   Expected format: `"Bearer <jwt>"`.
    ///
    /// # Returns
    ///
    /// * `Ok(None)` — `authorization` was absent; request is from a legacy sender and is
    ///   allowed through for backwards compatibility.
    /// * `Ok(Some(ctx))` — token is valid. Use [`AuthContext::is_authorized`] for per-event
    ///   membership checks against the extracted allowed-values list.
    /// * `Err(AuthError::InvalidToken)` — token is malformed, expired, has a bad signature,
    ///   wrong issuer/audience, or the membership claim is missing.
    pub fn authenticate(
        &self,
        authorization: Option<&str>,
    ) -> Result<Option<AuthContext>, AuthError> {
        let Some(auth_value) = authorization else {
            if self.0.require_token {
                return Err(AuthError::InvalidToken(
                    "authorization header is required",
                ));
            }
            debug!(message = "No authorization header; allowing request.");
            return Ok(None);
        };

        let token = strip_bearer_prefix(auth_value)
            .ok_or(AuthError::InvalidToken("authorization must use Bearer scheme"))?;

        let inner = &self.0;

        let token_data =
            decode::<serde_json::Map<String, Value>>(token, &inner.decoding_key, &inner.validation)
                .map_err(|err| {
                    warn!(message = "Token validation failed.", error = %err);
                    AuthError::InvalidToken("invalid or expired token")
                })?;

        let allowed = token_data
            .claims
            .get(&inner.membership_claim)
            .and_then(Value::as_array)
            .ok_or(AuthError::InvalidToken("token missing membership claim"))?;

        let allowed_values: BTreeSet<String> = allowed
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();

        Ok(Some(AuthContext { allowed_values }))
    }
}

/// Strip the `Bearer` auth scheme from a header value, case-insensitively and
/// tolerant of any whitespace between the scheme and the token.
fn strip_bearer_prefix(value: &str) -> Option<&str> {
    let trimmed = value.trim_start();
    if trimmed.len() < 6 || !trimmed.as_bytes()[..6].eq_ignore_ascii_case(b"Bearer") {
        return None;
    }
    let rest = &trimmed[6..];
    // require at least one whitespace separator between the scheme and the token
    if !rest.starts_with(|c: char| c.is_whitespace()) {
        return None;
    }
    let token = rest.trim_start();
    if token.is_empty() {
        return None;
    }
    Some(token)
}

#[cfg(all(test, feature = "sources-vector"))]
mod tests {
    use std::collections::HashMap;
    use std::io::Write;

    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

    use super::*;
    use crate::test_util::jwt_auth::{
        bearer, build_auth, make_token, now_secs, TEST_PRIVATE_KEY, TEST_PUBLIC_KEY,
    };

    // ── AuthConfig::build ────────────────────────────────────────────────────

    #[test]
    fn build_from_inline_pem_succeeds() {
        let cfg = AuthConfig {
            public_key: AuthPublicKey::Inline {
                value: TEST_PUBLIC_KEY.to_string(),
            },
            issuer: None,
            audience: None,
            membership_claim: "site_ids".to_string(),
            value_path: None,
            algorithms: default_algorithms(),
            require_token: false,
        };
        assert!(cfg.build().is_ok());
    }

    #[test]
    fn build_from_file_pem_succeeds() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(TEST_PUBLIC_KEY.as_bytes()).unwrap();

        let cfg = AuthConfig {
            public_key: AuthPublicKey::File {
                path: f.path().to_str().unwrap().into(),
            },
            issuer: None,
            audience: None,
            membership_claim: "site_ids".to_string(),
            value_path: None,
            algorithms: default_algorithms(),
            require_token: false,
        };
        assert!(cfg.build().is_ok());
    }

    #[test]
    fn build_with_invalid_pem_fails() {
        let cfg = AuthConfig {
            public_key: AuthPublicKey::Inline {
                value: "this is not a PEM".to_string(),
            },
            issuer: None,
            audience: None,
            membership_claim: "site_ids".to_string(),
            value_path: None,
            algorithms: default_algorithms(),
            require_token: false,
        };
        assert!(cfg.build().is_err());
    }

    #[test]
    fn build_with_missing_pem_file_fails() {
        let cfg = AuthConfig {
            public_key: AuthPublicKey::File {
                path: "/nonexistent/path/key.pem".to_string(),
            },
            issuer: None,
            audience: None,
            membership_claim: "site_ids".to_string(),
            value_path: None,
            algorithms: default_algorithms(),
            require_token: false,
        };
        assert!(cfg.build().is_err());
    }

    // ── Auth::authenticate ───────────────────────────────────────────────────

    #[test]
    fn no_auth_header_allows_legacy_client_when_require_token_false() {
        // The shared `build_auth` helper now matches production default
        // (require_token = true), so explicitly opt out to test legacy mode.
        let auth = build_auth_with_require_token(false);
        let result = auth.authenticate(None);
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn valid_token_returns_allowed_values() {
        let auth = build_auth(None, None);
        let token = make_token(HashMap::new());
        let ctx = auth.authenticate(Some(&bearer(&token))).unwrap().unwrap();
        assert!(ctx.is_authorized("site-123"));
        assert!(ctx.is_authorized("site-456"));
        assert!(!ctx.is_authorized("site-other"));
    }

    #[test]
    fn non_bearer_scheme_rejected() {
        let auth = build_auth(None, None);
        let token = make_token(HashMap::new());
        let result = auth.authenticate(Some(&format!("Basic {token}")));
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    #[test]
    fn malformed_token_rejected() {
        let auth = build_auth(None, None);
        let result = auth.authenticate(Some("Bearer not.a.jwt"));
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    #[test]
    fn expired_token_rejected() {
        let auth = build_auth(None, None);
        let mut extra = HashMap::new();
        extra.insert("exp", serde_json::json!(now_secs() - 3600));
        let token = make_token(extra);
        let result = auth.authenticate(Some(&bearer(&token)));
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    #[test]
    fn wrong_issuer_rejected() {
        let auth = build_auth(Some("https://expected.example.com/"), None);
        let mut extra = HashMap::new();
        extra.insert("iss", serde_json::json!("https://other.example.com/"));
        let token = make_token(extra);
        let result = auth.authenticate(Some(&bearer(&token)));
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    #[test]
    fn matching_issuer_passes() {
        let auth = build_auth(Some("https://expected.example.com/"), None);
        let mut extra = HashMap::new();
        extra.insert("iss", serde_json::json!("https://expected.example.com/"));
        let token = make_token(extra);
        let result = auth.authenticate(Some(&bearer(&token)));
        assert!(result.is_ok());
    }

    #[test]
    fn wrong_audience_rejected() {
        let auth = build_auth(None, Some(vec!["https://expected-api/"]));
        let mut extra = HashMap::new();
        extra.insert("aud", serde_json::json!(["https://other-api/"]));
        let token = make_token(extra);
        let result = auth.authenticate(Some(&bearer(&token)));
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    #[test]
    fn matching_audience_passes() {
        let auth = build_auth(None, Some(vec!["https://expected-api/"]));
        let mut extra = HashMap::new();
        extra.insert("aud", serde_json::json!(["https://expected-api/"]));
        let token = make_token(extra);
        let result = auth.authenticate(Some(&bearer(&token)));
        assert!(result.is_ok());
    }

    #[test]
    fn missing_membership_claim_in_token_rejected() {
        let auth = build_auth(None, None);
        // Token has no site_ids claim at all.
        let mut claims = serde_json::Map::new();
        claims.insert("sub".into(), serde_json::json!("user"));
        claims.insert("exp".into(), serde_json::json!(now_secs() + 3600));
        let key = EncodingKey::from_rsa_pem(TEST_PRIVATE_KEY.as_bytes()).unwrap();
        let token = encode(&Header::new(Algorithm::RS256), &claims, &key).unwrap();
        let result = auth.authenticate(Some(&bearer(&token)));
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    #[test]
    fn custom_membership_claim_is_checked() {
        let cfg = AuthConfig {
            public_key: AuthPublicKey::Inline {
                value: TEST_PUBLIC_KEY.to_string(),
            },
            issuer: None,
            audience: None,
            membership_claim: "allowed_tenants".to_string(),
            value_path: None,
            algorithms: default_algorithms(),
            require_token: false,
        };
        let auth = cfg.build().unwrap();

        let mut extra = HashMap::new();
        extra.insert("allowed_tenants", serde_json::json!(["tenant-abc"]));
        let token = make_token(extra);

        let ctx = auth.authenticate(Some(&bearer(&token))).unwrap().unwrap();
        assert!(ctx.is_authorized("tenant-abc"));
        assert!(!ctx.is_authorized("site-123")); // site-123 is in site_ids, not allowed_tenants
    }

    // ── algorithm allowlist ──────────────────────────────────────────────────

    #[test]
    fn empty_algorithms_list_fails_build() {
        let cfg = AuthConfig {
            public_key: AuthPublicKey::Inline {
                value: TEST_PUBLIC_KEY.to_string(),
            },
            issuer: None,
            audience: None,
            membership_claim: "site_ids".to_string(),
            value_path: None,
            algorithms: vec![],
            require_token: false,
        };
        assert!(cfg.build().is_err());
    }

    #[test]
    fn token_with_algorithm_not_in_allowlist_is_rejected() {
        // Allowlist only RS512; sign the token with RS256 → must be rejected.
        let cfg = AuthConfig {
            public_key: AuthPublicKey::Inline {
                value: TEST_PUBLIC_KEY.to_string(),
            },
            issuer: None,
            audience: None,
            membership_claim: "site_ids".to_string(),
            value_path: None,
            algorithms: vec![AuthAlgorithm::Rs512],
            require_token: false,
        };
        let auth = cfg.build().unwrap();
        let token = make_token(HashMap::new()); // signed with RS256 by helper
        let result = auth.authenticate(Some(&bearer(&token)));
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    #[test]
    fn token_with_algorithm_in_allowlist_is_accepted() {
        let cfg = AuthConfig {
            public_key: AuthPublicKey::Inline {
                value: TEST_PUBLIC_KEY.to_string(),
            },
            issuer: None,
            audience: None,
            membership_claim: "site_ids".to_string(),
            value_path: None,
            algorithms: vec![AuthAlgorithm::Rs256, AuthAlgorithm::Rs512],
            require_token: false,
        };
        let auth = cfg.build().unwrap();
        let token = make_token(HashMap::new()); // signed with RS256
        assert!(auth.authenticate(Some(&bearer(&token))).is_ok());
    }

    // ── require_token enforcement ────────────────────────────────────────────

    fn build_auth_with_require_token(require: bool) -> Auth {
        AuthConfig {
            public_key: AuthPublicKey::Inline {
                value: TEST_PUBLIC_KEY.to_string(),
            },
            issuer: None,
            audience: None,
            membership_claim: "site_ids".to_string(),
            value_path: None,
            algorithms: default_algorithms(),
            require_token: require,
        }
        .build()
        .unwrap()
    }

    #[test]
    fn require_token_false_allows_missing_authorization() {
        let auth = build_auth_with_require_token(false);
        assert!(matches!(auth.authenticate(None), Ok(None)));
    }

    #[test]
    fn require_token_true_rejects_missing_authorization() {
        let auth = build_auth_with_require_token(true);
        let result = auth.authenticate(None);
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    #[test]
    fn require_token_true_accepts_valid_token() {
        let auth = build_auth_with_require_token(true);
        let token = make_token(HashMap::new());
        assert!(auth.authenticate(Some(&bearer(&token))).is_ok());
    }

    #[test]
    fn require_token_true_still_rejects_invalid_token() {
        let auth = build_auth_with_require_token(true);
        let result = auth.authenticate(Some("Bearer not.a.jwt"));
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    #[test]
    fn default_algorithms_covers_rs_and_ps_family() {
        let algos = default_algorithms();
        assert!(algos.contains(&AuthAlgorithm::Rs256));
        assert!(algos.contains(&AuthAlgorithm::Rs384));
        assert!(algos.contains(&AuthAlgorithm::Rs512));
        assert!(algos.contains(&AuthAlgorithm::Ps256));
        assert!(algos.contains(&AuthAlgorithm::Ps384));
        assert!(algos.contains(&AuthAlgorithm::Ps512));
        assert_eq!(algos.len(), 6);
    }

    // ── AuthContext::is_authorized ───────────────────────────────────────────

    #[test]
    fn auth_context_is_authorized_checks_membership() {
        let ctx = AuthContext {
            allowed_values: ["foo", "bar"].into_iter().map(String::from).collect(),
        };
        assert!(ctx.is_authorized("foo"));
        assert!(ctx.is_authorized("bar"));
        assert!(!ctx.is_authorized("baz"));
    }

    // ── strip_bearer_prefix ──────────────────────────────────────────────────

    #[test]
    fn strip_bearer_prefix_exact() {
        assert_eq!(strip_bearer_prefix("Bearer abc.def.ghi"), Some("abc.def.ghi"));
    }

    #[test]
    fn strip_bearer_prefix_case_insensitive() {
        assert_eq!(strip_bearer_prefix("bearer abc"), Some("abc"));
        assert_eq!(strip_bearer_prefix("BEARER abc"), Some("abc"));
        assert_eq!(strip_bearer_prefix("BeArEr abc"), Some("abc"));
    }

    #[test]
    fn strip_bearer_prefix_multi_whitespace() {
        assert_eq!(strip_bearer_prefix("Bearer   abc"), Some("abc"));
        assert_eq!(strip_bearer_prefix("Bearer\tabc"), Some("abc"));
        assert_eq!(strip_bearer_prefix("  Bearer abc"), Some("abc"));
    }

    #[test]
    fn strip_bearer_prefix_rejects_other_schemes() {
        assert_eq!(strip_bearer_prefix("Basic abc"), None);
        assert_eq!(strip_bearer_prefix("Bearerabc"), None); // no separator
        assert_eq!(strip_bearer_prefix("Bearer "), None);   // empty token
        assert_eq!(strip_bearer_prefix(""), None);
    }

    // ── AuthValuePath helpers ────────────────────────────────────────────────

    #[test]
    fn value_path_falls_back_to_default() {
        let vp = AuthValuePath {
            default: "tenant_id".into(),
            log: None,
            metric_tag: None,
            trace: None,
        };
        assert_eq!(vp.for_log(), "tenant_id");
        assert_eq!(vp.for_metric(), "tenant_id");
        assert_eq!(vp.for_trace(), "tenant_id");
    }

    #[test]
    fn value_path_uses_type_specific_overrides() {
        let vp = AuthValuePath {
            default: "default_field".into(),
            log: Some("log_field".into()),
            metric_tag: Some("metric_key".into()),
            trace: Some("trace_field".into()),
        };
        assert_eq!(vp.for_log(), "log_field");
        assert_eq!(vp.for_metric(), "metric_key");
        assert_eq!(vp.for_trace(), "trace_field");
    }

    // ── AuthPublicKey serde ──────────────────────────────────────────────────

    #[test]
    fn public_key_inline_deserializes() {
        let toml = r#"type = "inline"
value = "my-pem-value""#;
        let key: AuthPublicKey = toml::from_str(toml).unwrap();
        assert!(matches!(key, AuthPublicKey::Inline { value } if value == "my-pem-value"));
    }

    #[test]
    fn public_key_file_deserializes() {
        let toml = r#"type = "file"
path = "/etc/certs/auth.pem""#;
        let key: AuthPublicKey = toml::from_str(toml).unwrap();
        assert!(
            matches!(key, AuthPublicKey::File { path } if path == "/etc/certs/auth.pem")
        );
    }

    #[test]
    fn public_key_missing_type_fails() {
        assert!(toml::from_str::<AuthPublicKey>(r#"value = "pem""#).is_err());
    }

    #[test]
    fn public_key_unknown_type_fails() {
        assert!(toml::from_str::<AuthPublicKey>(r#"type = "env""#).is_err());
    }
}
