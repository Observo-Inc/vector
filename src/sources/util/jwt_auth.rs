use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, LazyLock, Mutex as StdMutex, Weak};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet, KeyAlgorithm, PublicKeyUse};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use openssl::x509::X509;
use serde_json::Value;
use vector_lib::configurable::configurable_component;
use vector_lib::event::Event;
use vrl::path::{parse_target_path, OwnedTargetPath};

use crate::http::HttpClient;

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

/// Source of a PEM value — either inline or loaded from a file at startup.
///
/// Used by both [`Authority::PublicKey`] (bare RSA public key PEM) and
/// [`Authority::TlsCert`] (X.509 certificate PEM). The semantic distinction
/// between "this is a public key" and "this is a certificate" is carried by
/// the [`Authority`] variant; this type only models the I/O shape.
///
/// ## Examples
///
/// Inline (use Vector's `${VAR}` interpolation for env vars):
/// ```toml
/// public_key.type  = "inline"
/// public_key.value = "${RSA_PUBLIC_KEY}"
/// ```
///
/// File path (preferred for Kubernetes ConfigMap / secret volume mounts — the
/// file is read once at source startup):
/// ```toml
/// public_key.type = "file"
/// public_key.path = "/etc/certs/auth.pem"
/// ```
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(rename_all = "snake_case", tag = "type", deny_unknown_fields)]
pub enum AuthorityData {
    /// Inline PEM value.
    ///
    /// Supports Vector's `${ENV_VAR}` interpolation. The value is read once at startup.
    Inline {
        /// PEM-encoded value (RSA public key or X.509 certificate, depending
        /// on the enclosing [`Authority`] variant).
        value: String,
    },

    /// Path to a file containing the PEM.
    ///
    /// Preferred for Kubernetes ConfigMap or secret volume mounts.
    /// The file is read once at source startup.
    File {
        /// Path to the PEM file.
        path: String,
    },
}

/// JWKS endpoint source (Keycloak / Auth0 / Okta / Cognito / Google / any
/// OIDC-compliant IdP). The JWKS is fetched at startup, indexed by `kid`,
/// and refreshed both periodically and reactively when a token arrives with
/// a `kid` not in the cache.
///
/// Selected via the [`Authority::Jwks`] variant on [`AuthConfig`].
///
/// ## Example
///
/// ```toml
/// [sources.my_source.auth.jwks]
/// jwks_url = "https://kc.example/realms/master/protocol/openid-connect/certs"
/// refresh_interval_secs = 300
/// ```
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct JwksAuthority {
    /// URL of the JWKS endpoint. Must return a JSON document of the form
    /// `{"keys": [<JWK>...]}` as defined by RFC 7517.
    pub jwks_url: String,

    /// Background refresh interval, in seconds. Default: 300 (5 minutes).
    #[serde(default = "default_jwks_refresh_interval_secs")]
    pub refresh_interval_secs: u64,

    /// Per-fetch timeout, in seconds. Applies to both the initial fetch
    /// and subsequent refreshes. Default: 10.
    #[serde(default = "default_jwks_fetch_timeout_secs")]
    pub fetch_timeout_secs: u64,

    /// Minimum interval between reactive (on-unknown-kid) refreshes, in
    /// seconds. Acts as a cooldown to prevent refresh storms triggered by
    /// adversarial traffic. Default: 30.
    #[serde(default = "default_jwks_min_reactive_refresh_secs")]
    pub min_reactive_refresh_secs: u64,
}

const fn default_jwks_refresh_interval_secs() -> u64 {
    300
}

const fn default_jwks_fetch_timeout_secs() -> u64 {
    10
}

const fn default_jwks_min_reactive_refresh_secs() -> u64 {
    30
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

/// Source of the RSA public key used to verify auth token signatures.
///
/// Exactly one variant must be configured. Flattened into [`AuthConfig`], so the
/// variant key sits directly under `[auth]`:
///
/// ```toml
/// [auth]
/// public_key.type  = "inline"
/// public_key.value = "${RSA_PUBLIC_KEY}"
/// ```
///
/// or
///
/// ```toml
/// [auth]
/// tls_cert.type = "file"
/// tls_cert.path = "/etc/pki/tls/certs/jwt-signer.crt"
/// ```
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Authority {
    /// Bare RSA public key PEM (`BEGIN PUBLIC KEY` / `BEGIN RSA PUBLIC KEY`).
    PublicKey(AuthorityData),
    /// X.509 certificate PEM; the embedded public key is extracted at startup.
    ///
    /// Useful when the JWT signer's key is distributed as a TLS / trust-bundle
    /// certificate. Only the public key bytes are kept at runtime — certificate
    /// validity windows, issuer chains, and revocation status are **not** checked.
    TlsCert(AuthorityData),
    /// JWKS endpoint (Keycloak / Auth0 / Okta / Cognito / any OIDC IdP).
    /// Multi-key, refreshes both periodically and reactively on unknown `kid`.
    Jwks(JwksAuthority),
}

impl Authority {
    /// Resolve the configured source into a runtime [`KeyStore`].
    ///
    /// For static variants this is a synchronous PEM parse. For [`Self::Jwks`]
    /// this performs the initial HTTPS fetch and spawns the background
    /// refresh task — fail-fast if the endpoint is unreachable.
    async fn build_key_store(
        &self,
        algorithms: &[AuthAlgorithm],
    ) -> crate::Result<KeyStore> {
        match self {
            Authority::PublicKey(pk) => {
                let pem = pk.load("public_key")?;
                let key = DecodingKey::from_rsa_pem(pem.as_bytes()).map_err(|error| {
                    format!("Failed to parse RSA public key PEM: {error}")
                })?;
                Ok(KeyStore::Static(Arc::new(key)))
            }
            Authority::TlsCert(cert) => {
                let pem = Self::extract_public_key_pem_from_cert_pem(&cert.load("tls_cert")?)?;
                let key = DecodingKey::from_rsa_pem(pem.as_bytes()).map_err(|error| {
                    format!("Failed to parse RSA public key PEM: {error}")
                })?;
                Ok(KeyStore::Static(Arc::new(key)))
            }
            Authority::Jwks(cfg) => {
                let cache = JwksCache::new(cfg, algorithms).await?;
                Ok(KeyStore::Jwks(cache))
            }
        }
    }

    /// Parse an X.509 certificate PEM and emit a `BEGIN PUBLIC KEY` (SPKI) PEM of its
    /// embedded public key — the form `jsonwebtoken::DecodingKey::from_rsa_pem` accepts.
    fn extract_public_key_pem_from_cert_pem(cert_pem: &str) -> crate::Result<String> {
        let cert = X509::from_pem(cert_pem.as_bytes())
            .map_err(|error| format!("Failed to parse X.509 certificate PEM: {error}"))?;
        let pubkey = cert
            .public_key()
            .map_err(|error| format!("Failed to extract public key from certificate: {error}"))?;
        let pem_bytes = pubkey
            .public_key_to_pem()
            .map_err(|error| format!("Failed to encode extracted public key as PEM: {error}"))?;
        String::from_utf8(pem_bytes)
            .map_err(|error| format!("Extracted public key PEM was not valid UTF-8: {error}").into())
    }
}

/// Runtime verification key material. Two shapes:
///
/// - [`Self::Static`]: a single [`DecodingKey`] resolved at startup. The hot
///   path is a single pointer deref — no locks, no allocation.
/// - [`Self::Jwks`]: an [`ArcSwap`]-backed map keyed by `kid`. Reads are
///   lock-free atomic pointer loads; the background refresher swaps in a new
///   map on each successful fetch. Designed for the millions-of-requests-per-
///   second hot path.
enum KeyStore {
    Static(Arc<DecodingKey>),
    Jwks(Arc<JwksCache>),
}

/// Decoded JWKS, indexed by `kid` for O(1) per-request lookup.
type KeyMap = HashMap<String, DecodingKey>;

/// Shared cache backing the [`Authority::Jwks`] variant.
///
/// Hot-path reads go through [`Self::snapshot`] which returns a lock-free
/// [`arc_swap::Guard`] over the current [`KeyMap`]. Refreshes — both periodic
/// (background tokio task) and reactive (on unknown `kid`) — produce a new
/// [`KeyMap`] and call [`ArcSwap::store`] to publish it atomically.
struct JwksCache {
    keys: ArcSwap<KeyMap>,
    fetcher: JwksFetcher,
    /// Last-refresh timestamp guarding the reactive-refresh cooldown. A
    /// stdlib mutex (uncontended, sub-µs) is sufficient — this gate is hit
    /// only on the cold path of unknown-kid tokens.
    last_refresh: StdMutex<Instant>,
    min_reactive_refresh: Duration,
}

impl JwksCache {
    /// Construct, perform the initial fetch (fail-fast), and spawn the
    /// background refresh task. Returns `Arc<Self>` so the refresh task can
    /// hold a `Weak` and self-terminate when the [`Auth`] is dropped.
    async fn new(
        cfg: &JwksAuthority,
        algorithms: &[AuthAlgorithm],
    ) -> crate::Result<Arc<Self>> {
        let fetcher = JwksFetcher::new(cfg, algorithms)?;
        let initial = fetcher.fetch().await.map_err(|error| {
            format!("auth.jwks: initial fetch from '{}' failed: {error}", cfg.jwks_url)
        })?;
        if initial.is_empty() {
            return Err(format!(
                "auth.jwks: '{}' returned no usable signing keys \
                 (none matched use=sig and an allowed algorithm)",
                cfg.jwks_url
            )
            .into());
        }
        let cache = Arc::new(Self {
            keys: ArcSwap::new(Arc::new(initial)),
            fetcher,
            last_refresh: StdMutex::new(Instant::now()),
            min_reactive_refresh: Duration::from_secs(cfg.min_reactive_refresh_secs),
        });
        Self::spawn_refresher(&cache, Duration::from_secs(cfg.refresh_interval_secs));
        Ok(cache)
    }

    fn spawn_refresher(cache: &Arc<Self>, interval: Duration) {
        let weak: Weak<Self> = Arc::downgrade(cache);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            // Skip the immediate first firing — we already fetched in `new`.
            tick.tick().await;
            loop {
                tick.tick().await;
                let Some(strong) = weak.upgrade() else {
                    debug!(message = "JWKS refresher exiting: Auth dropped.");
                    return;
                };
                match strong.fetcher.fetch().await {
                    Ok(map) if map.is_empty() => {
                        warn!(message = "JWKS periodic refresh returned no usable keys; keeping previous keys.");
                    }
                    Ok(map) => {
                        strong.keys.store(Arc::new(map));
                        *strong.last_refresh.lock().expect("last_refresh poisoned") =
                            Instant::now();
                    }
                    Err(error) => {
                        warn!(message = "JWKS periodic refresh failed; keeping previous keys.", %error);
                    }
                }
            }
        });
    }

    /// Lock-free snapshot of the current key map. Caller holds the guard for
    /// the duration of `decode` so the borrow into the map remains valid.
    fn snapshot(&self) -> arc_swap::Guard<Arc<KeyMap>> {
        self.keys.load()
    }

    /// Trigger a one-shot reactive refresh, gated by the cooldown window.
    ///
    /// Concurrent callers: the cooldown timestamp is set *before* the network
    /// fetch, so a second caller that races past the gate sees the updated
    /// timestamp and returns without firing a duplicate request.
    async fn refresh_if_due(&self) {
        {
            let mut last = self.last_refresh.lock().expect("last_refresh poisoned");
            if last.elapsed() < self.min_reactive_refresh {
                return;
            }
            *last = Instant::now();
        }
        match self.fetcher.fetch().await {
            Ok(map) if map.is_empty() => {
                warn!(message = "JWKS reactive refresh returned no usable keys.");
            }
            Ok(map) => {
                self.keys.store(Arc::new(map));
            }
            Err(error) => {
                warn!(message = "JWKS reactive refresh failed.", %error);
            }
        }
    }
}

/// HTTPS fetcher for the JWKS endpoint.
///
/// Uses Vector's standard [`HttpClient`] so it shares TLS/proxy/user-agent
/// behavior with the rest of the binary. The [`ProxyConfig::from_env`] call
/// at construction time picks up the standard `HTTPS_PROXY` / `NO_PROXY`
/// environment variables automatically.
struct JwksFetcher {
    url: http::Uri,
    client: HttpClient,
    timeout: Duration,
    algorithms: Vec<Algorithm>,
}

impl JwksFetcher {
    fn new(cfg: &JwksAuthority, algorithms: &[AuthAlgorithm]) -> crate::Result<Self> {
        let url: http::Uri = cfg.jwks_url.parse().map_err(|error| {
            format!("auth.jwks.jwks_url '{}' is not a valid URL: {error}", cfg.jwks_url)
        })?;
        let proxy = vector_lib::config::proxy::ProxyConfig::from_env();
        let client = HttpClient::new(None, &proxy, &crate::app_info())
            .map_err(|error| format!("auth.jwks: failed to build HTTP client: {error}"))?;
        Ok(Self {
            url,
            client,
            timeout: Duration::from_secs(cfg.fetch_timeout_secs),
            algorithms: algorithms.iter().copied().map(Algorithm::from).collect(),
        })
    }

    async fn fetch(&self) -> crate::Result<KeyMap> {
        let request = http::Request::get(&self.url)
            .header(http::header::ACCEPT, "application/json")
            .body(hyper::Body::empty())
            .map_err(|error| format!("failed to build JWKS request: {error}"))?;

        let response = tokio::time::timeout(self.timeout, self.client.send(request))
            .await
            .map_err(|_| format!("timed out after {:?}", self.timeout))?
            .map_err(|error| format!("HTTP request failed: {error}"))?;

        if !response.status().is_success() {
            return Err(format!("JWKS endpoint returned HTTP {}", response.status()).into());
        }

        let bytes = hyper::body::to_bytes(response.into_body())
            .await
            .map_err(|error| format!("failed to read JWKS response body: {error}"))?;

        let jwk_set: JwkSet = serde_json::from_slice(&bytes)
            .map_err(|error| format!("JWKS response is not valid JSON: {error}"))?;

        Ok(self.build_key_map(jwk_set))
    }

    fn build_key_map(&self, jwk_set: JwkSet) -> KeyMap {
        let mut map = KeyMap::with_capacity(jwk_set.keys.len());
        for jwk in &jwk_set.keys {
            // Skip non-signing keys (Keycloak publishes both `enc` and `sig`).
            if let Some(use_) = &jwk.common.public_key_use {
                if !matches!(use_, PublicKeyUse::Signature) {
                    continue;
                }
            }
            // Skip non-RSA keys; the current Auth only supports RSA.
            if !matches!(jwk.algorithm, AlgorithmParameters::RSA(_)) {
                continue;
            }
            // Filter to configured algorithm allowlist if `alg` is advertised.
            if let Some(alg) = jwk.common.key_algorithm {
                if !key_algorithm_in_allowlist(alg, &self.algorithms) {
                    continue;
                }
            }
            let Some(kid) = jwk.common.key_id.clone() else {
                // `kid`-less JWKS entries are unusable: we can't look them up
                // per token without scanning every key. Skip with a hint.
                warn!(message = "JWKS entry skipped: missing `kid`.");
                continue;
            };
            match DecodingKey::from_jwk(jwk) {
                Ok(key) => {
                    map.insert(kid, key);
                }
                Err(error) => {
                    warn!(message = "JWKS entry skipped: failed to build decoding key.", %error);
                }
            }
        }
        map
    }
}

/// Map a JWK-side [`KeyAlgorithm`] to our [`Algorithm`] allowlist.
///
/// jsonwebtoken distinguishes between `Algorithm` (used at verification time)
/// and `KeyAlgorithm` (advertised on the JWK). They share names but live in
/// different types with no `From` impl in either direction.
fn key_algorithm_in_allowlist(jwk_alg: KeyAlgorithm, allowlist: &[Algorithm]) -> bool {
    let mapped = match jwk_alg {
        KeyAlgorithm::RS256 => Some(Algorithm::RS256),
        KeyAlgorithm::RS384 => Some(Algorithm::RS384),
        KeyAlgorithm::RS512 => Some(Algorithm::RS512),
        KeyAlgorithm::PS256 => Some(Algorithm::PS256),
        KeyAlgorithm::PS384 => Some(Algorithm::PS384),
        KeyAlgorithm::PS512 => Some(Algorithm::PS512),
        _ => None,
    };
    mapped.is_some_and(|a| allowlist.contains(&a))
}

/// Auth configuration for sources.
///
/// `authority` selects the RSA public key source (a bare public key PEM or an
/// X.509 certificate PEM) and is flattened — its `public_key` / `tls_cert`
/// variant key sits directly under `[auth]`. The resulting key is parsed once
/// at source startup, after which per-request validation is purely in-process
/// with no network calls. When the `authorization` header is absent,
/// [`Auth::authenticate`] returns `Ok(None)` and the request is accepted
/// without per-event filtering.
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// Source of the RSA public key used to verify auth token signatures.
    ///
    /// Required — deserialization fails if no variant key is present.
    #[serde(flatten, deserialize_with = "deserialize_authority_required")]
    pub authority: Authority,

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

/// Replace serde's flattened-enum error with an actionable message naming the
/// expected variant keys. Other errors (typos in inner fields, bad `type`
/// values) are passed through with an `auth.authority` prefix so the failing
/// config path is unambiguous.
fn deserialize_authority_required<'de, D>(d: D) -> Result<Authority, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    use serde::Deserialize;

    Authority::deserialize(d).map_err(|original| {
        let msg = original.to_string();
        if msg.contains("no variant of enum") {
            D::Error::custom(
                "auth: must set one of `public_key`, `tls_cert`, or `jwks` \
                 (e.g. `public_key.type = \"file\"`, `public_key.path = \"/path/to/key.pem\"`)",
            )
        } else {
            D::Error::custom(format!("auth.authority: {msg}"))
        }
    })
}

impl AuthConfig {
    /// Builds the runtime [`Auth`] by resolving the configured [`Authority`]
    /// (a static PEM, a TLS cert via SPKI extraction, or a JWKS endpoint with
    /// initial fetch + background refresh) and assembling the verifier.
    ///
    /// All I/O and PEM parsing happen here — once at startup. The resulting
    /// [`Auth`] is cheap to clone and holds no file handles. For the JWKS
    /// authority, build returns an error if the initial fetch fails so that
    /// misconfigurations surface at `vector validate` / source startup
    /// rather than at first-request time.
    pub async fn build(&self) -> crate::Result<Auth> {
        if self.algorithms.is_empty() {
            return Err("auth.algorithms must contain at least one algorithm".into());
        }

        let key_store = self.authority.build_key_store(&self.algorithms).await?;

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
            key_store,
            validation,
            membership_claim: self.membership_claim.clone(),
            value_path,
            require_token: self.require_token,
        })))
    }
}

impl AuthorityData {
    /// Resolve to the PEM string. `kind` is the configuration field name
    /// (`"public_key"` or `"tls_cert"`) used to make I/O failures point at
    /// the right config field.
    fn load(&self, kind: &str) -> crate::Result<String> {
        match self {
            Self::Inline { value } => Ok(value.clone()),
            Self::File { path } => std::fs::read_to_string(path).map_err(|error| {
                format!("Failed to read auth {kind} from '{path}': {error}").into()
            }),
        }
    }
}

// Private — holds the resolved key material and validation config behind Arc
// so Auth is cheap to clone across tokio tasks without copying RSA key bytes
// or duplicating the JWKS cache.
struct Inner {
    key_store: KeyStore,
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
    pub async fn authenticate(
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
        let token_data = match &inner.key_store {
            // Static key: single-pointer-deref hot path, no locks.
            KeyStore::Static(key) => {
                decode::<serde_json::Map<String, Value>>(token, key, &inner.validation).map_err(
                    |err| {
                        warn!(message = "Token validation failed.", error = %err);
                        AuthError::InvalidToken("invalid or expired token")
                    },
                )?
            }
            // JWKS: look up by token's `kid`. ArcSwap snapshot is lock-free.
            // On miss, trigger a cooldown-gated reactive refresh and retry once.
            KeyStore::Jwks(cache) => {
                let header = decode_header(token).map_err(|err| {
                    warn!(message = "JWT header parse failed.", error = %err);
                    AuthError::InvalidToken("invalid token header")
                })?;
                let kid = header.kid.as_deref().ok_or(AuthError::InvalidToken(
                    "token missing `kid` header",
                ))?;

                // Fast path: snapshot, lookup, verify under the same guard.
                {
                    let snapshot = cache.snapshot();
                    if let Some(key) = snapshot.get(kid) {
                        let result = decode::<serde_json::Map<String, Value>>(
                            token,
                            key,
                            &inner.validation,
                        );
                        match result {
                            Ok(data) => return Ok(Some(extract_membership(
                                data,
                                &inner.membership_claim,
                            )?)),
                            Err(err) => {
                                warn!(message = "Token validation failed.", error = %err);
                                return Err(AuthError::InvalidToken("invalid or expired token"));
                            }
                        }
                    }
                }

                // Slow path: unknown kid → reactive refresh (cooldown-gated)
                // → look up again. If still missing, the kid is genuinely
                // not served by this IdP.
                cache.refresh_if_due().await;
                let snapshot = cache.snapshot();
                let key = snapshot.get(kid).ok_or_else(|| {
                    warn!(message = "Token signed by unknown key.", kid = %kid);
                    AuthError::InvalidToken("unknown signing key")
                })?;
                decode::<serde_json::Map<String, Value>>(token, key, &inner.validation).map_err(
                    |err| {
                        warn!(message = "Token validation failed.", error = %err);
                        AuthError::InvalidToken("invalid or expired token")
                    },
                )?
            }
        };

        Ok(Some(extract_membership(token_data, &inner.membership_claim)?))
    }
}

/// Extract the membership-claim array from validated token data into an
/// [`AuthContext`]. Returns `InvalidToken` if the claim is missing or not
/// a JSON array.
fn extract_membership(
    token_data: jsonwebtoken::TokenData<serde_json::Map<String, Value>>,
    membership_claim: &str,
) -> Result<AuthContext, AuthError> {
    let allowed = token_data
        .claims
        .get(membership_claim)
        .and_then(Value::as_array)
        .ok_or(AuthError::InvalidToken("token missing membership claim"))?;

    let allowed_values: BTreeSet<String> = allowed
        .iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();

    Ok(AuthContext { allowed_values })
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
        bearer, build_auth, make_token, now_secs, TEST_CERT, TEST_PRIVATE_KEY, TEST_PUBLIC_KEY,
    };

    // Construct a baseline `AuthConfig` from the given authority, using the
    // permissive defaults the tests below want (no issuer/audience/value_path,
    // `require_token = false`). Individual tests override fields as needed.
    fn cfg_with(authority: Authority) -> AuthConfig {
        AuthConfig {
            authority,
            issuer: None,
            audience: None,
            membership_claim: "site_ids".to_string(),
            value_path: None,
            algorithms: default_algorithms(),
            require_token: false,
        }
    }

    fn inline_public_key() -> Authority {
        Authority::PublicKey(AuthorityData::Inline {
            value: TEST_PUBLIC_KEY.to_string(),
        })
    }

    fn inline_tls_cert() -> Authority {
        Authority::TlsCert(AuthorityData::Inline {
            value: TEST_CERT.to_string(),
        })
    }

    // ── AuthConfig::build ────────────────────────────────────────────────────

    #[tokio::test]
    async fn build_from_inline_pem_succeeds() {
        assert!(cfg_with(inline_public_key()).build().await.is_ok());
    }

    #[tokio::test]
    async fn build_from_file_pem_succeeds() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(TEST_PUBLIC_KEY.as_bytes()).unwrap();

        let cfg = cfg_with(Authority::PublicKey(AuthorityData::File {
            path: f.path().to_str().unwrap().into(),
        }));
        assert!(cfg.build().await.is_ok());
    }

    #[tokio::test]
    async fn build_with_invalid_pem_fails() {
        let cfg = cfg_with(Authority::PublicKey(AuthorityData::Inline {
            value: "this is not a PEM".to_string(),
        }));
        assert!(cfg.build().await.is_err());
    }

    #[tokio::test]
    async fn build_with_missing_pem_file_fails() {
        let cfg = cfg_with(Authority::PublicKey(AuthorityData::File {
            path: "/nonexistent/path/key.pem".to_string(),
        }));
        assert!(cfg.build().await.is_err());
    }

    #[tokio::test]
    async fn build_with_missing_tls_cert_file_fails() {
        let cfg = cfg_with(Authority::TlsCert(AuthorityData::File {
            path: "/nonexistent/path/auth.crt".to_string(),
        }));
        assert!(cfg.build().await.is_err());
    }

    #[tokio::test]
    async fn build_from_inline_tls_cert_succeeds() {
        let auth = cfg_with(inline_tls_cert())
            .build()
            .await
            .expect("AuthConfig::build should accept an X.509 certificate PEM via tls_cert");

        // The public key extracted from the cert must actually verify tokens
        // signed by the matching test private key — not just parse cleanly.
        let token = make_token(HashMap::new());
        let ctx = auth.authenticate(Some(&bearer(&token))).await.unwrap().unwrap();
        assert!(ctx.is_authorized("site-123"));
    }

    #[tokio::test]
    async fn build_from_tls_cert_file_succeeds() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(TEST_CERT.as_bytes()).unwrap();

        let cfg = cfg_with(Authority::TlsCert(AuthorityData::File {
            path: f.path().to_str().unwrap().into(),
        }));
        assert!(cfg.build().await.is_ok());
    }

    #[tokio::test]
    async fn build_with_malformed_tls_cert_pem_fails() {
        let cfg = cfg_with(Authority::TlsCert(AuthorityData::Inline {
            value: "-----BEGIN CERTIFICATE-----\nnot-base64\n-----END CERTIFICATE-----\n"
                .to_string(),
        }));
        assert!(cfg.build().await.is_err());
    }

    #[tokio::test]
    async fn build_with_public_key_pem_in_tls_cert_field_fails() {
        // tls_cert is strictly X.509 — feeding it a bare RSA public key
        // PEM must surface the cert parser's failure, not silently accept it.
        let cfg = cfg_with(Authority::TlsCert(AuthorityData::Inline {
            value: TEST_PUBLIC_KEY.to_string(),
        }));
        assert!(cfg.build().await.is_err());
    }

    // No symmetric `cert PEM in public_key field` negative test: jsonwebtoken's
    // `DecodingKey::from_rsa_pem` will *sometimes* accept a `BEGIN CERTIFICATE`
    // PEM (it extracts the first ASN.1 BitString, which is the SPKI bitstring
    // for simple RSA certs) and *sometimes* reject it (`InvalidKeyFormat`,
    // depending on the cert's extension layout). That's upstream behavior, not
    // ours — we don't promise either outcome, so we don't assert it.

    // No "both authority variants set" runtime check is needed: the
    // `Authority` enum makes that state unrepresentable in Rust, and the
    // externally-tagged serde form rejects TOML with two variant keys at
    // parse time. See `authority_with_multiple_variants_in_toml_fails`.

    // ── Auth::authenticate ───────────────────────────────────────────────────

    #[tokio::test]
    async fn no_auth_header_allows_legacy_client_when_require_token_false() {
        // The shared `build_auth` helper now matches production default
        // (require_token = true), so explicitly opt out to test legacy mode.
        let auth = build_auth_with_require_token(false).await;
        let result = auth.authenticate(None).await;
        assert!(matches!(result, Ok(None)));
    }

    #[tokio::test]
    async fn valid_token_returns_allowed_values() {
        let auth = build_auth(None, None).await;
        let token = make_token(HashMap::new());
        let ctx = auth.authenticate(Some(&bearer(&token))).await.unwrap().unwrap();
        assert!(ctx.is_authorized("site-123"));
        assert!(ctx.is_authorized("site-456"));
        assert!(!ctx.is_authorized("site-other"));
    }

    #[tokio::test]
    async fn non_bearer_scheme_rejected() {
        let auth = build_auth(None, None).await;
        let token = make_token(HashMap::new());
        let result = auth.authenticate(Some(&format!("Basic {token}"))).await;
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    #[tokio::test]
    async fn malformed_token_rejected() {
        let auth = build_auth(None, None).await;
        let result = auth.authenticate(Some("Bearer not.a.jwt")).await;
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    #[tokio::test]
    async fn expired_token_rejected() {
        let auth = build_auth(None, None).await;
        let mut extra = HashMap::new();
        extra.insert("exp", serde_json::json!(now_secs() - 3600));
        let token = make_token(extra);
        let result = auth.authenticate(Some(&bearer(&token))).await;
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    #[tokio::test]
    async fn wrong_issuer_rejected() {
        let auth = build_auth(Some("https://expected.example.com/"), None).await;
        let mut extra = HashMap::new();
        extra.insert("iss", serde_json::json!("https://other.example.com/"));
        let token = make_token(extra);
        let result = auth.authenticate(Some(&bearer(&token))).await;
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    #[tokio::test]
    async fn matching_issuer_passes() {
        let auth = build_auth(Some("https://expected.example.com/"), None).await;
        let mut extra = HashMap::new();
        extra.insert("iss", serde_json::json!("https://expected.example.com/"));
        let token = make_token(extra);
        let result = auth.authenticate(Some(&bearer(&token))).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn wrong_audience_rejected() {
        let auth = build_auth(None, Some(vec!["https://expected-api/"])).await;
        let mut extra = HashMap::new();
        extra.insert("aud", serde_json::json!(["https://other-api/"]));
        let token = make_token(extra);
        let result = auth.authenticate(Some(&bearer(&token))).await;
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    #[tokio::test]
    async fn matching_audience_passes() {
        let auth = build_auth(None, Some(vec!["https://expected-api/"])).await;
        let mut extra = HashMap::new();
        extra.insert("aud", serde_json::json!(["https://expected-api/"]));
        let token = make_token(extra);
        let result = auth.authenticate(Some(&bearer(&token))).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn missing_membership_claim_in_token_rejected() {
        let auth = build_auth(None, None).await;
        // Token has no site_ids claim at all.
        let mut claims = serde_json::Map::new();
        claims.insert("sub".into(), serde_json::json!("user"));
        claims.insert("exp".into(), serde_json::json!(now_secs() + 3600));
        let key = EncodingKey::from_rsa_pem(TEST_PRIVATE_KEY.as_bytes()).unwrap();
        let token = encode(&Header::new(Algorithm::RS256), &claims, &key).unwrap();
        let result = auth.authenticate(Some(&bearer(&token))).await;
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    #[tokio::test]
    async fn wrong_type_membership_claim_in_token_rejected() {
        // The claim is present but is a plain string instead of the required
        // array-of-strings. Must be rejected at `authenticate` rather than
        // silently treated as an empty allowlist.
        let auth = build_auth(None, None).await;
        let mut extra = HashMap::new();
        extra.insert("site_ids", serde_json::json!("site-123"));
        let token = make_token(extra);
        let result = auth.authenticate(Some(&bearer(&token))).await;
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    #[tokio::test]
    async fn custom_membership_claim_is_checked() {
        let mut cfg = cfg_with(inline_public_key());
        cfg.membership_claim = "allowed_tenants".to_string();
        let auth = cfg.build().await.unwrap();

        let mut extra = HashMap::new();
        extra.insert("allowed_tenants", serde_json::json!(["tenant-abc"]));
        let token = make_token(extra);

        let ctx = auth.authenticate(Some(&bearer(&token))).await.unwrap().unwrap();
        assert!(ctx.is_authorized("tenant-abc"));
        assert!(!ctx.is_authorized("site-123")); // site-123 is in site_ids, not allowed_tenants
    }

    // ── algorithm allowlist ──────────────────────────────────────────────────

    #[tokio::test]
    async fn empty_algorithms_list_fails_build() {
        let mut cfg = cfg_with(inline_public_key());
        cfg.algorithms = vec![];
        assert!(cfg.build().await.is_err());
    }

    #[tokio::test]
    async fn build_fails_on_invalid_value_path_expression() {
        // `CompiledValuePath::try_from` runs `parse_target_path` on each
        // configured string. A malformed path must surface as a build
        // failure with the documented `Failed to parse auth value_path`
        // prefix — not silently succeed.
        let mut cfg = cfg_with(inline_public_key());
        cfg.value_path = Some(AuthValuePath {
            default: ".[unterminated".to_string(),
            log: None,
            metric_tag: None,
            trace: None,
        });
        let err = cfg.build().await.unwrap_err().to_string();
        assert!(
            err.contains("Failed to parse auth value_path"),
            "expected value_path parse error, got: {err}",
        );
    }

    #[test]
    fn auth_event_error_labels_match_documented_metric_tags() {
        // These strings are emitted as the `outcome` tag on the per-event
        // auth metrics in `src/sources/vector/mod.rs`. Renaming them would
        // silently break dashboards / alerting that filter on this tag.
        assert_eq!(
            AuthEventError::AuthorizationMissing.label(),
            "authorization_missing"
        );
        assert_eq!(AuthEventError::Forbidden.label(), "forbidden");
    }

    #[tokio::test]
    async fn token_with_algorithm_not_in_allowlist_is_rejected() {
        // Allowlist only RS512; sign the token with RS256 → must be rejected.
        let mut cfg = cfg_with(inline_public_key());
        cfg.algorithms = vec![AuthAlgorithm::Rs512];
        let auth = cfg.build().await.unwrap();
        let token = make_token(HashMap::new()); // signed with RS256 by helper
        let result = auth.authenticate(Some(&bearer(&token))).await;
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    #[tokio::test]
    async fn token_with_algorithm_in_allowlist_is_accepted() {
        let mut cfg = cfg_with(inline_public_key());
        cfg.algorithms = vec![AuthAlgorithm::Rs256, AuthAlgorithm::Rs512];
        let auth = cfg.build().await.unwrap();
        let token = make_token(HashMap::new()); // signed with RS256
        assert!(auth.authenticate(Some(&bearer(&token))).await.is_ok());
    }

    // ── require_token enforcement ────────────────────────────────────────────

    async fn build_auth_with_require_token(require: bool) -> Auth {
        let mut cfg = cfg_with(inline_public_key());
        cfg.require_token = require;
        cfg.build().await.unwrap()
    }

    #[tokio::test]
    async fn require_token_false_allows_missing_authorization() {
        let auth = build_auth_with_require_token(false).await;
        assert!(matches!(auth.authenticate(None).await, Ok(None)));
    }

    #[tokio::test]
    async fn require_token_true_rejects_missing_authorization() {
        let auth = build_auth_with_require_token(true).await;
        let result = auth.authenticate(None).await;
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    #[tokio::test]
    async fn require_token_true_accepts_valid_token() {
        let auth = build_auth_with_require_token(true).await;
        let token = make_token(HashMap::new());
        assert!(auth.authenticate(Some(&bearer(&token))).await.is_ok());
    }

    #[tokio::test]
    async fn require_token_true_still_rejects_invalid_token() {
        let auth = build_auth_with_require_token(true).await;
        let result = auth.authenticate(Some("Bearer not.a.jwt")).await;
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

    // ── AuthorityData serde ──────────────────────────────────────────────────
    //
    // `AuthorityData` is the shared shape used by both `Authority::PublicKey`
    // and `Authority::TlsCert`, so a single set of tests covers both paths.

    #[test]
    fn authority_data_inline_deserializes() {
        let toml = r#"type = "inline"
value = "my-pem-value""#;
        let data: AuthorityData = toml::from_str(toml).unwrap();
        assert!(matches!(data, AuthorityData::Inline { value } if value == "my-pem-value"));
    }

    #[test]
    fn authority_data_file_deserializes() {
        let toml = r#"type = "file"
path = "/etc/certs/auth.pem""#;
        let data: AuthorityData = toml::from_str(toml).unwrap();
        assert!(matches!(data, AuthorityData::File { path } if path == "/etc/certs/auth.pem"));
    }

    #[test]
    fn authority_data_missing_type_fails() {
        assert!(toml::from_str::<AuthorityData>(r#"value = "pem""#).is_err());
    }

    #[test]
    fn authority_data_unknown_type_fails() {
        assert!(toml::from_str::<AuthorityData>(r#"type = "env""#).is_err());
    }

    // ── Authority serde ──────────────────────────────────────────────────────

    #[test]
    fn authority_public_key_deserializes() {
        let toml = r#"public_key = { type = "inline", value = "pem" }"#;
        let a: Authority = toml::from_str(toml).unwrap();
        assert!(matches!(
            a,
            Authority::PublicKey(AuthorityData::Inline { value }) if value == "pem"
        ));
    }

    #[test]
    fn authority_tls_cert_deserializes() {
        let toml = r#"tls_cert = { type = "file", path = "/etc/pki/tls/certs/auth.crt" }"#;
        let a: Authority = toml::from_str(toml).unwrap();
        assert!(matches!(
            a,
            Authority::TlsCert(AuthorityData::File { path }) if path == "/etc/pki/tls/certs/auth.crt"
        ));
    }

    #[test]
    fn authority_empty_table_fails() {
        // Externally-tagged enum: an empty `[authority]` (no variant key) is
        // not deserializable — this is how we surface "nothing is set".
        assert!(toml::from_str::<Authority>("").is_err());
    }

    #[test]
    fn authority_unknown_variant_fails() {
        let toml = r#"jwks_url = "https://idp.example.com/jwks""#;
        assert!(toml::from_str::<Authority>(toml).is_err());
    }

    #[test]
    fn authority_with_multiple_variants_in_toml_fails() {
        // Externally-tagged enums accept exactly one key. Specifying both
        // `public_key` and `tls_cert` under `[authority]` must be rejected.
        let toml = r#"
public_key = { type = "inline", value = "pem" }
tls_cert   = { type = "inline", value = "cert" }
"#;
        assert!(toml::from_str::<Authority>(toml).is_err());
    }

    // ── AuthConfig serde ─────────────────────────────────────────────────────

    #[test]
    fn auth_config_requires_authority() {
        // No `[authority]` block at all → missing required field.
        let toml = r#"membership_claim = "site_ids""#;
        assert!(toml::from_str::<AuthConfig>(toml).is_err());
    }

    #[test]
    fn auth_config_with_public_key_authority_deserializes() {
        // Flat form: variant key sits directly under [auth] thanks to
        // #[serde(flatten)] on AuthConfig.authority.
        let toml = r#"
public_key.type  = "inline"
public_key.value = "pem"
"#;
        let cfg: AuthConfig = toml::from_str(toml).unwrap();
        assert!(matches!(
            cfg.authority,
            Authority::PublicKey(AuthorityData::Inline { value }) if value == "pem"
        ));
    }

    #[test]
    fn auth_config_with_tls_cert_authority_deserializes() {
        let toml = r#"
tls_cert.type = "file"
tls_cert.path = "/etc/pki/tls/certs/auth.crt"
"#;
        let cfg: AuthConfig = toml::from_str(toml).unwrap();
        assert!(matches!(
            cfg.authority,
            Authority::TlsCert(AuthorityData::File { path }) if path == "/etc/pki/tls/certs/auth.crt"
        ));
    }

    #[test]
    fn auth_config_typo_in_sibling_field_is_rejected() {
        // `#[serde(deny_unknown_fields)]` on AuthConfig catches misspellings
        // of any sibling top-level key (here `mempership_claim` →
        // `membership_claim`) at parse time, so the configured value is
        // never silently lost.
        let toml = r#"
public_key.type  = "inline"
public_key.value = "pem"
mempership_claim = "tenants"
"#;
        let err = toml::from_str::<AuthConfig>(toml).unwrap_err().to_string();
        assert!(
            err.contains("unknown field `mempership_claim`"),
            "expected `unknown field` error for the typo, got: {err}",
        );
    }

    #[test]
    fn auth_config_typo_in_variant_name_is_rejected() {
        // The variant key itself is misspelled; sibling fields are valid.
        // Authority sees `pubic_key` as an unknown variant and rejects it.
        let toml = r#"
pubic_key.type   = "inline"
pubic_key.value  = "pem"
membership_claim = "tenants"
"#;
        assert!(toml::from_str::<AuthConfig>(toml).is_err());
    }

    // ── deserialize_authority_required error messages ───────────────────────
    //
    // These tests pin the contract of `deserialize_authority_required`:
    // 1. Missing/unrecognized variant key → friendly message naming the
    //    expected keys.
    // 2. Any other deserialization error → original detail preserved with
    //    an `auth.authority:` prefix so the failing field path is unambiguous.

    #[test]
    fn auth_config_missing_authority_variant_gives_friendly_error() {
        // No `public_key` or `tls_cert` at all — replaces serde's opaque
        // "no variant of enum Authority found in flattened data".
        let toml = r#"membership_claim = "site_ids""#;
        let err = toml::from_str::<AuthConfig>(toml).unwrap_err().to_string();
        assert!(
            err.contains("must set one of `public_key`, `tls_cert`, or `jwks`"),
            "expected friendly message, got: {err}",
        );
    }

    #[test]
    fn auth_config_typo_in_variant_name_gives_friendly_error() {
        // Typo'd variant key (`pubic_key`) is indistinguishable from
        // "no variant set" at the flatten layer, so the friendly fallback
        // fires here too.
        let toml = r#"
pubic_key.type  = "inline"
pubic_key.value = "pem"
"#;
        let err = toml::from_str::<AuthConfig>(toml).unwrap_err().to_string();
        assert!(
            err.contains("must set one of `public_key`, `tls_cert`, or `jwks`"),
            "expected friendly message, got: {err}",
        );
    }

    #[test]
    fn auth_config_bad_type_value_gets_authority_prefix() {
        // Variant key is correct; the inner `type` discriminator is
        // unknown. The original serde "unknown variant" message must
        // survive — only prefixed with the field path.
        let toml = r#"
public_key.type  = "env"
public_key.value = "pem"
"#;
        let err = toml::from_str::<AuthConfig>(toml).unwrap_err().to_string();
        assert!(
            err.contains("auth.authority:"),
            "expected `auth.authority:` prefix, got: {err}",
        );
        assert!(
            err.contains("env"),
            "expected the bad variant name in the message, got: {err}",
        );
    }

    #[test]
    fn auth_config_inner_field_typo_gets_authority_prefix() {
        // Variant resolves, but `deny_unknown_fields` on AuthorityData
        // rejects the misspelled `paht`. Want the `auth.authority:` prefix
        // in front of serde's "unknown field" detail.
        let toml = r#"
public_key.type = "file"
public_key.paht = "/etc/key.pem"
"#;
        let err = toml::from_str::<AuthConfig>(toml).unwrap_err().to_string();
        assert!(
            err.contains("auth.authority:"),
            "expected `auth.authority:` prefix, got: {err}",
        );
        assert!(
            err.contains("paht"),
            "expected the typo'd field name in the message, got: {err}",
        );
    }

    #[test]
    fn auth_config_with_other_fields_alongside_variant_deserializes() {
        // Confirms the flatten machinery doesn't get confused by sibling
        // top-level fields — `issuer`, `membership_claim` etc. coexist with
        // the flattened variant key.
        let toml = r#"
public_key.type   = "inline"
public_key.value  = "pem"
membership_claim  = "tenants"
issuer            = "https://issuer.example.com/"
require_token     = false
"#;
        let cfg: AuthConfig = toml::from_str(toml).unwrap();
        assert!(matches!(
            cfg.authority,
            Authority::PublicKey(AuthorityData::Inline { value }) if value == "pem"
        ));
        assert_eq!(cfg.membership_claim, "tenants");
        assert_eq!(cfg.issuer.as_deref(), Some("https://issuer.example.com/"));
        assert!(!cfg.require_token);
    }

    // ── JWKS / Keycloak authority ────────────────────────────────────────────

    const TEST_KID: &str = "test-kid";

    /// Build a single-entry JWKS JSON from the test public key.
    fn make_jwks_json(kid: &str, use_sig: bool) -> serde_json::Value {
        use base64::Engine;
        use openssl::rsa::Rsa;

        let rsa = Rsa::public_key_from_pem(TEST_PUBLIC_KEY.as_bytes()).unwrap();
        let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rsa.n().to_vec());
        let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rsa.e().to_vec());
        let use_field = if use_sig { "sig" } else { "enc" };
        serde_json::json!({
            "keys": [
                {
                    "kid": kid,
                    "kty": "RSA",
                    "use": use_field,
                    "alg": "RS256",
                    "n": n,
                    "e": e,
                }
            ]
        })
    }

    /// Mint a JWT signed by the test private key with an explicit `kid`.
    fn make_token_with_kid(kid: &str) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        let mut claims = serde_json::Map::new();
        claims.insert("sub".into(), serde_json::json!("test-subject"));
        claims.insert("exp".into(), serde_json::json!(now_secs() + 3600));
        claims.insert("site_ids".into(), serde_json::json!(["site-123"]));
        let key = EncodingKey::from_rsa_pem(TEST_PRIVATE_KEY.as_bytes()).unwrap();
        encode(&header, &claims, &key).unwrap()
    }

    fn jwks_cfg(jwks_url: String) -> AuthConfig {
        AuthConfig {
            authority: Authority::Jwks(JwksAuthority {
                jwks_url,
                refresh_interval_secs: 3600, // long; periodic refresh shouldn't fire during test
                fetch_timeout_secs: 5,
                min_reactive_refresh_secs: 0, // allow reactive refresh without cooldown wait
            }),
            issuer: None,
            audience: None,
            membership_claim: "site_ids".to_string(),
            value_path: None,
            algorithms: default_algorithms(),
            require_token: false,
        }
    }

    #[tokio::test]
    async fn jwks_build_succeeds_with_mock_endpoint() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(make_jwks_json(TEST_KID, true)))
            .mount(&server)
            .await;

        let cfg = jwks_cfg(format!("{}/jwks", server.uri()));
        assert!(cfg.build().await.is_ok());
    }

    #[tokio::test]
    async fn jwks_build_fails_when_endpoint_unreachable() {
        // Port 1 is reserved and refuses connections — guaranteed failure
        // without depending on a mock server lifecycle.
        let cfg = jwks_cfg("http://127.0.0.1:1/jwks".to_string());
        let err = cfg.build().await.unwrap_err().to_string();
        assert!(
            err.contains("initial fetch") && err.contains("failed"),
            "got: {err}",
        );
    }

    #[tokio::test]
    async fn jwks_build_fails_when_endpoint_returns_no_signing_keys() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"keys": []})))
            .mount(&server)
            .await;

        let cfg = jwks_cfg(format!("{}/jwks", server.uri()));
        let err = cfg.build().await.unwrap_err().to_string();
        assert!(err.contains("no usable signing keys"), "got: {err}");
    }

    #[tokio::test]
    async fn jwks_authenticate_valid_token() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(make_jwks_json(TEST_KID, true)))
            .mount(&server)
            .await;

        let auth = jwks_cfg(format!("{}/jwks", server.uri())).build().await.unwrap();
        let token = make_token_with_kid(TEST_KID);
        let ctx = auth.authenticate(Some(&bearer(&token))).await.unwrap().unwrap();
        assert!(ctx.is_authorized("site-123"));
    }

    #[tokio::test]
    async fn jwks_authenticate_unknown_kid_triggers_refresh() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        // First two fetches (initial build + the unknown-kid token will come
        // before any refresh fires) return a JWKS with the WRONG kid. The
        // third onwards (reactive refresh after unknown-kid) returns the
        // correct one.
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(make_jwks_json("stale-kid", true)))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(make_jwks_json(TEST_KID, true)))
            .mount(&server)
            .await;

        let auth = jwks_cfg(format!("{}/jwks", server.uri())).build().await.unwrap();
        let token = make_token_with_kid(TEST_KID);
        // First authenticate: initial cache has stale-kid only; unknown-kid
        // miss triggers reactive refresh which fetches the corrected JWKS.
        let ctx = auth.authenticate(Some(&bearer(&token))).await.unwrap().unwrap();
        assert!(ctx.is_authorized("site-123"));
    }

    #[tokio::test]
    async fn jwks_token_without_kid_is_rejected() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(make_jwks_json(TEST_KID, true)))
            .mount(&server)
            .await;

        let auth = jwks_cfg(format!("{}/jwks", server.uri())).build().await.unwrap();
        // Mint a kid-less token directly (helper that adds kid bypassed).
        let token = make_token(HashMap::new());
        let result = auth.authenticate(Some(&bearer(&token))).await;
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    #[tokio::test]
    async fn jwks_skips_use_enc_entries() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // Only a use=enc entry — must be filtered out, leaving an empty key
        // map which the build() rejects with "no usable signing keys".
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(make_jwks_json(TEST_KID, false)))
            .mount(&server)
            .await;

        let cfg = jwks_cfg(format!("{}/jwks", server.uri()));
        let err = cfg.build().await.unwrap_err().to_string();
        assert!(err.contains("no usable signing keys"), "got: {err}");
    }

    // ── concurrent / race-condition tests ────────────────────────────────────

    /// N concurrent requests with an unknown `kid` must trigger exactly ONE
    /// reactive HTTP fetch, not N. The cooldown gate (`min_reactive_refresh_secs`)
    /// must hold under real concurrency — the timestamp is stamped inside the
    /// mutex before the fetch begins so racing callers see it and bail out.
    ///
    /// Note: `last_refresh` is stamped at build time (initial fetch). We sleep
    /// past the cooldown before spawning requests so the gate is actually open
    /// when the concurrent calls arrive — otherwise they'd all be blocked by
    /// the build-time stamp and no reactive fetch would fire at all.
    #[tokio::test(flavor = "multi_thread")]
    async fn jwks_concurrent_unknown_kid_triggers_exactly_one_refresh() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        // First fetch (initial build): stale-kid only.
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(make_jwks_json("stale-kid", true)))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        // All subsequent fetches return the correct kid.
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(make_jwks_json(TEST_KID, true)))
            .mount(&server)
            .await;

        // 1-second cooldown — short enough to expire in the test, non-zero so
        // the gate logic is actually exercised by the concurrent callers.
        let mut cfg = jwks_cfg(format!("{}/jwks", server.uri()));
        if let Authority::Jwks(ref mut j) = cfg.authority {
            j.min_reactive_refresh_secs = 1;
        }
        let auth = cfg.build().await.unwrap();

        // Sleep past the cooldown window so it is open when the 20 requests race.
        tokio::time::sleep(Duration::from_millis(1100)).await;

        let token = make_token_with_kid(TEST_KID);

        // Spawn 20 concurrent authenticate calls, all with the unknown kid.
        let mut handles = Vec::new();
        for _ in 0..20 {
            let auth = auth.clone();
            let bearer = bearer(&token);
            handles.push(tokio::spawn(async move {
                // Result is intentionally ignored — we only care about HTTP call count.
                let _ = auth.authenticate(Some(&bearer)).await;
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        // Exactly 2 HTTP calls: 1 initial build + 1 reactive refresh.
        // The StdMutex gate ensures only the first caller past the cooldown
        // fires a fetch; the remaining 19 see the freshly-stamped timestamp
        // and return early without issuing their own requests.
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            2,
            "expected exactly 1 initial + 1 reactive fetch; cooldown gate failed to suppress duplicates"
        );
    }

    /// Concurrent readers must all see a consistent key map — either the old
    /// snapshot or the new one — never a partially-written state. Spawn many
    /// readers while a refresh is swapping in a new key map and assert that
    /// every reader either validates correctly or gets a clean "unknown key"
    /// error; no panics, no partial reads.
    #[tokio::test(flavor = "multi_thread")]
    async fn jwks_concurrent_readers_see_consistent_snapshot_during_swap() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        // Alternate between two valid key sets on successive fetches so that
        // the periodic refresher swaps the map while readers are running.
        let kid_a = "kid-a";
        let kid_b = "kid-b";

        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(make_jwks_json(kid_a, true)))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(make_jwks_json(kid_b, true)))
            .mount(&server)
            .await;

        // Very short periodic refresh so it fires during the test.
        let mut cfg = jwks_cfg(format!("{}/jwks", server.uri()));
        if let Authority::Jwks(ref mut j) = cfg.authority {
            j.refresh_interval_secs = 1;
            j.min_reactive_refresh_secs = 0;
        }
        let auth = cfg.build().await.unwrap();

        // Token for kid_a (in the initial cache).
        let token_a = make_token_with_kid(kid_a);
        // Token for kid_b (arrives after the swap).
        let token_b = make_token_with_kid(kid_b);

        // Hammer with 50 concurrent readers across both kids for ~1.5 seconds,
        // spanning at least one periodic swap. Every result must be either a
        // clean Ok or a clean InvalidToken — no panics, no corrupted state.
        let mut handles = Vec::new();
        for i in 0..50 {
            let auth = auth.clone();
            let token = if i % 2 == 0 { token_a.clone() } else { token_b.clone() };
            handles.push(tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(i * 30)).await;
                let bearer = bearer(&token);
                // Must be Ok or InvalidToken — no panic, no partial read.
                let _ = auth.authenticate(Some(&bearer)).await;
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
    }
}
