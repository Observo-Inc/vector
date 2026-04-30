use std::sync::Arc;

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde_json::Value;
use vector_lib::configurable::configurable_component;

/// Errors returned by [`JwtAuth::validate`].
#[derive(Debug)]
pub enum JwtAuthError {
    /// The `authorization` header was present but the token is invalid, malformed, expired,
    /// or failed signature verification. Callers should respond with HTTP 401 /
    /// gRPC `Unauthenticated`.
    InvalidToken(&'static str),

    /// The token was valid but the companion membership value header (`x-site-id`) was
    /// absent or contained non-ASCII bytes. Callers should respond with HTTP 401 /
    /// gRPC `Unauthenticated`.
    MissingMembershipValue,

    /// The membership value is not listed in the token's [`JwtAuthConfig::membership_claim`].
    /// Callers should respond with HTTP 403 / gRPC `PermissionDenied`.
    MembershipNotAuthorized,
}

/// Source of the RSA public key PEM used to verify JWT signatures.
///
/// Exactly one variant must be configured.
///
/// ## Examples
///
/// Inline PEM (use Vector's `${VAR}` interpolation for env vars):
/// ```toml
/// public_key.type = "inline"
/// public_key.value = "${AUTH0_RSA_PUBLIC_KEY}"
/// ```
///
/// File path (preferred for Kubernetes ConfigMap mounts — key is read once at startup):
/// ```toml
/// public_key.type = "file"
/// public_key.path = "/etc/certs/auth0.pem"
/// ```
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum JwtPublicKey {
    /// Inline PEM value.
    ///
    /// Supports Vector's `${ENV_VAR}` interpolation, e.g.
    /// `value = "${AUTH0_RSA_PUBLIC_KEY}"`. The value is read once at startup.
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

/// JWT authentication configuration for sources.
///
/// Can be embedded in any source — HTTP-based (Splunk HEC, http_server, …) or gRPC-based
/// (vector, opentelemetry, …). The validation logic is transport-agnostic: callers extract
/// the `authorization` and membership-value header strings themselves and pass them to
/// [`JwtAuth::validate`].
///
/// Tokens are Auth0-issued RS256 JWTs. The RSA public key is parsed **once** at source
/// startup; per-request validation is purely in-process with no network calls.
///
/// ## Backward-compatible fallback
///
/// When the `authorization` header is absent, [`JwtAuth::validate`] returns `Ok(None)`.
/// Agents that predate authentication continue to be accepted during a rolling upgrade.
///
/// ## Example
///
/// ```toml
/// [sources.my_source.auth]
/// public_key.type  = "inline"
/// public_key.value = "${AUTH0_RSA_PUBLIC_KEY}"
/// jwt_issuer       = "https://your-tenant.example.com/"
/// jwt_audience     = ["https://your-api-identifier"]
/// membership_claim = "https://your-domain.com/site_ids"
/// ```
#[configurable_component]
#[derive(Clone, Debug)]
pub struct JwtAuthConfig {
    /// Source of the RSA public key PEM used to verify JWT signatures.
    ///
    /// Set exactly one of `type = "inline"` (with `value`) or `type = "file"` (with `path`).
    pub public_key: JwtPublicKey,

    /// Expected `iss` (issuer) claim, e.g. `"https://your-tenant.example.com/"`.
    ///
    /// When set, tokens whose issuer does not match are rejected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwt_issuer: Option<String>,

    /// Expected `aud` (audience) claim values.
    ///
    /// When set, tokens that do not include at least one of these audiences are rejected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwt_audience: Option<Vec<String>>,

    /// Name of the JWT claim whose array value the incoming membership value is checked
    /// against.
    ///
    /// Auth0 custom claims must be namespaced, e.g.
    /// `"https://your-domain.com/site_ids"`. Defaults to `"site_ids"`.
    #[serde(default = "default_membership_claim")]
    pub membership_claim: String,
}

fn default_membership_claim() -> String {
    "site_ids".to_string()
}

impl JwtAuthConfig {
    /// Builds the runtime [`JwtAuth`] by loading and parsing the RSA public key.
    ///
    /// All I/O and PEM parsing happen here — once at startup.
    /// The resulting [`JwtAuth`] is cheap to clone and holds no file handles.
    pub fn build(&self) -> crate::Result<JwtAuth> {
        let pem = self.load_pem()?;

        let decoding_key = DecodingKey::from_rsa_pem(pem.as_bytes())
            .map_err(|e| format!("Failed to parse RSA public key PEM: {e}"))?;

        let mut validation = Validation::new(Algorithm::RS256);

        if let Some(issuer) = &self.jwt_issuer {
            validation.set_issuer(&[issuer]);
        }

        if let Some(audiences) = &self.jwt_audience {
            validation.set_audience(audiences);
        } else {
            validation.validate_aud = false;
        }

        Ok(JwtAuth(Arc::new(Inner {
            decoding_key,
            validation,
            membership_claim: self.membership_claim.clone(),
        })))
    }

    fn load_pem(&self) -> crate::Result<String> {
        match &self.public_key {
            JwtPublicKey::Inline { value } => Ok(value.clone()),
            JwtPublicKey::File { path } => std::fs::read_to_string(path)
                .map_err(|e| format!("Failed to read JWT public key from '{path}': {e}").into()),
        }
    }
}

// Private — holds the parsed key and validation config behind Arc so JwtAuth is
// cheap to clone across tokio tasks without copying the RSA key bytes.
struct Inner {
    decoding_key: DecodingKey,
    validation: Validation,
    membership_claim: String,
}

/// Runtime JWT authentication handle built from [`JwtAuthConfig`].
///
/// Cheap to clone — all state is held behind an [`Arc`].
#[derive(Clone)]
pub struct JwtAuth(Arc<Inner>);

impl std::fmt::Debug for JwtAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtAuth")
            .field("membership_claim", &self.0.membership_claim)
            .finish_non_exhaustive()
    }
}

impl JwtAuth {
    /// Validate JWT authentication from raw header string values.
    ///
    /// # Parameters
    ///
    /// * `authorization` — value of the `authorization` / `Authorization` header, if present.
    ///   Expected format: `"Bearer <jwt>"`.
    /// * `membership_value` — the value to look up inside the token's
    ///   [`JwtAuthConfig::membership_claim`] array (e.g. the `x-site-id` header value).
    ///
    /// # Returns
    ///
    /// * `Ok(None)` — `authorization` was absent; request is from a legacy sender and is
    ///   allowed through for backwards compatibility.
    /// * `Ok(Some(value))` — token is valid and `value` was found in the membership claim.
    ///   The returned `&str` borrows from the `membership_value` argument.
    /// * `Err(JwtAuthError::InvalidToken)` — token is malformed, expired, has a bad
    ///   signature, wrong issuer/audience, or the claim is missing.
    /// * `Err(JwtAuthError::MissingMembershipValue)` — token is valid but
    ///   `membership_value` was `None`.
    /// * `Err(JwtAuthError::MembershipNotAuthorized)` — value is not in the claim array.
    pub fn validate<'a>(
        &self,
        authorization: Option<&str>,
        membership_value: Option<&'a str>,
    ) -> Result<Option<&'a str>, JwtAuthError> {
        let Some(auth_value) = authorization else {
            debug!(message = "No authorization header; allowing request (legacy client fallback).");
            return Ok(None);
        };

        let token = auth_value
            .strip_prefix("Bearer ")
            .ok_or(JwtAuthError::InvalidToken("authorization must use Bearer scheme"))?;

        let inner = &self.0;

        let token_data =
            decode::<serde_json::Map<String, Value>>(token, &inner.decoding_key, &inner.validation)
                .map_err(|err| {
                    warn!(message = "JWT validation failed.", error = %err);
                    JwtAuthError::InvalidToken("invalid or expired token")
                })?;

        let value = membership_value.ok_or(JwtAuthError::MissingMembershipValue)?;

        let allowed = token_data
            .claims
            .get(&inner.membership_claim)
            .and_then(Value::as_array)
            .ok_or(JwtAuthError::InvalidToken("token missing membership claim"))?;

        if !allowed.iter().any(|v| v.as_str() == Some(value)) {
            warn!(
                message = "JWT membership check failed.",
                value = value,
                claim = %inner.membership_claim,
            );
            return Err(JwtAuthError::MembershipNotAuthorized);
        }

        Ok(Some(value))
    }
}

#[cfg(all(test, feature = "sources-utils-jwt-auth"))]
mod tests {
    use std::collections::HashMap;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

    use super::*;

    // RSA-2048 test key pair (not used outside of tests).
    const TEST_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDJ5D7lpMrGJpl7
zCcZ73XqbzBaagaPa9QDoGmypTbOoiysnnmcTHfy+wcP2aBlDTC8aB+7iPdZr0tA
ENdzIQ0/kZFBWCdwqAtQYDyfGuZx9y+3E9I8RFleDqDSwA6aUrSoesC9OBHztebX
0m4T9dAWzn8Vr3CYKVpp4XcYwfX6iWszCm43zv4fCJu/qYX67IvOP8h66OMBZ8s7
A4K15z1n8ScI3R6v6amc94iB7z2B9hdvuoTKk89dF5XGxE1ZVnIzSPr/8/oQQJgG
RaYqQAViy4kPmctW4uaI9ajQPIQe58LpNh1lDw+aLRHO/e0SCqbUNARTLSdSIwNV
3dltWgS9AgMBAAECggEAHPo4NuDYw+kdZYHvaM8QdyYfZBLMv0AkTaL0GNKS08S+
McaLQO5O1x7FrDY5yddDU/+D8nhdvE8nN1pTejBXxPSBS0Y6XvaXrSErAlErm1b1
z8q2BbVvuErUNXugfPD7AiWgTWhjVz4YFIkdCJtjEyrvXa7xM73XvtPAMtsAEcXv
MgeRaZVdIledQUozu72RfPuG0yYWG5j+1W1IjNDcuLvld+RrZZ6JqyedhHMwlsFU
bi1DDGaBvp7jkDr6hDp81dqUVposvq+yw3THoyDnQCNxrSCfDpRkYk7DWJKVD8XS
6GvFHuHfaktzm+KkUHBQAebGn6qM+3QBIOWXZkHBdwKBgQDwhVtLUNnz7LLOlAxH
/IF5WM96DoPilOG548yMt/81Zez9QzgJXhxefhCpl2ZQDUCWr9CFvn+98XFai8jt
voVQMV23AGi6nJJ+jGw9koQUt/uYAxZ4U8tG0KqxVGhmrab1MfTpLp2mQWkJN7y1
Hk5moPHwpQhxW73qlzwR8Ug8FwKBgQDW4nX8ZvFfmyJcrckquh0KMpILe5i+klmd
ENU7TmlQ8Sq1QX2j+w4gOWpUR6/bnij1XeEsI21z10Sv3yEgu2E8V7Cqf9mJX0in
+H5+WpEbTHqgfWhA8wXoZIizRfHDKOsOnhNmTFMBBrcp0zd4V1N1xH+APkw1q3jF
YxnmMAMmSwKBgBH5xYLxffiO/iYWRnyy0HJjQs5ae1zZx6z+63Cw56/z+CxNc8iv
cetV/KTQHeNpuiQI68qzHBT0EIa138R08r21ks10iF86CHDQyd4oLxrlTTZlNK61
hIG8YqVyK4NRAyNcInOy+jFMvi7kLYRTyYQ+DxbvHpxqQN1hhCnLIJztAoGAakX9
zCKtZXc3+1YHk5YQHqb8C6nI1RdUMpXMn1QcSee8E4CcPqk/RzieGaiKlLcX0qHn
ZwjubMgeNEzJ+YIyiMFloi0wzPvO1yPSi3MHKNUeIJllIhoO5ewyn1cMRlTKS6Rq
O8Grm2pS0+CeImot4KSZ2jb1QeXYCOcGPA2qwRkCgYEAnCI12DQuInN8nLEo4qtq
XEgyvUZ0fGaezcmeT4hhY94l0/HXS0D0qXs/f/rvfFFnvRYlEyiycA4pClkNRNkM
TM9RBaFTEKw9NQP895KUx6hHIAM/LB1Qyf7cDixtwf8ly7Gqhx4vU9tCiiDGSr9Z
T+QEb2Rxj5SJ8cGbNr+NAEI=
-----END PRIVATE KEY-----";

    const TEST_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyeQ+5aTKxiaZe8wnGe91
6m8wWmoGj2vUA6BpsqU2zqIsrJ55nEx38vsHD9mgZQ0wvGgfu4j3Wa9LQBDXcyEN
P5GRQVgncKgLUGA8nxrmcfcvtxPSPERZXg6g0sAOmlK0qHrAvTgR87Xm19JuE/XQ
Fs5/Fa9wmClaaeF3GMH1+olrMwpuN87+Hwibv6mF+uyLzj/IeujjAWfLOwOCtec9
Z/EnCN0er+mpnPeIge89gfYXb7qEypPPXReVxsRNWVZyM0j6//P6EECYBkWmKkAF
YsuJD5nLVuLmiPWo0DyEHufC6TYdZQ8Pmi0Rzv3tEgqm1DQEUy0nUiMDVd3ZbVoE
vQIDAQAB
-----END PUBLIC KEY-----";

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Signs a JWT with the test private key. `extra` is merged into the claims.
    fn make_token(extra: HashMap<&str, serde_json::Value>) -> String {
        let mut claims = serde_json::Map::new();
        claims.insert("sub".into(), serde_json::json!("test-user"));
        claims.insert("exp".into(), serde_json::json!(now_secs() + 3600));
        claims.insert("site_ids".into(), serde_json::json!(["site-123", "site-456"]));
        for (k, v) in extra {
            claims.insert(k.into(), v);
        }
        let key = EncodingKey::from_rsa_pem(TEST_PRIVATE_KEY.as_bytes()).unwrap();
        encode(&Header::new(Algorithm::RS256), &claims, &key).unwrap()
    }

    fn bearer(token: &str) -> String {
        format!("Bearer {token}")
    }

    /// Builds a `JwtAuth` from the test public key with optional issuer/audience.
    fn build_auth(issuer: Option<&str>, audience: Option<Vec<&str>>) -> JwtAuth {
        JwtAuthConfig {
            public_key: JwtPublicKey::Inline {
                value: TEST_PUBLIC_KEY.to_string(),
            },
            jwt_issuer: issuer.map(str::to_string),
            jwt_audience: audience.map(|v| v.iter().map(|s| s.to_string()).collect()),
            membership_claim: "site_ids".to_string(),
        }
        .build()
        .unwrap()
    }

    // ── JwtAuthConfig::build ─────────────────────────────────────────────────

    #[test]
    fn build_from_inline_pem_succeeds() {
        let cfg = JwtAuthConfig {
            public_key: JwtPublicKey::Inline {
                value: TEST_PUBLIC_KEY.to_string(),
            },
            jwt_issuer: None,
            jwt_audience: None,
            membership_claim: "site_ids".to_string(),
        };
        assert!(cfg.build().is_ok());
    }

    #[test]
    fn build_from_file_pem_succeeds() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(TEST_PUBLIC_KEY.as_bytes()).unwrap();

        let cfg = JwtAuthConfig {
            public_key: JwtPublicKey::File {
                path: f.path().to_str().unwrap().into(),
            },
            jwt_issuer: None,
            jwt_audience: None,
            membership_claim: "site_ids".to_string(),
        };
        assert!(cfg.build().is_ok());
    }

    #[test]
    fn build_with_invalid_pem_fails() {
        let cfg = JwtAuthConfig {
            public_key: JwtPublicKey::Inline {
                value: "this is not a PEM".to_string(),
            },
            jwt_issuer: None,
            jwt_audience: None,
            membership_claim: "site_ids".to_string(),
        };
        assert!(cfg.build().is_err());
    }

    #[test]
    fn build_with_missing_pem_file_fails() {
        let cfg = JwtAuthConfig {
            public_key: JwtPublicKey::File {
                path: "/nonexistent/path/key.pem".to_string(),
            },
            jwt_issuer: None,
            jwt_audience: None,
            membership_claim: "site_ids".to_string(),
        };
        assert!(cfg.build().is_err());
    }

    // ── JwtAuth::validate ────────────────────────────────────────────────────

    #[test]
    fn no_auth_header_allows_legacy_client() {
        let auth = build_auth(None, None);
        let result = auth.validate(None, Some("site-123"));
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn valid_token_with_authorized_site_id_passes() {
        let auth = build_auth(None, None);
        let token = make_token(HashMap::new());
        let result = auth.validate(Some(&bearer(&token)), Some("site-123"));
        assert_eq!(result.unwrap(), Some("site-123"));
    }

    #[test]
    fn non_bearer_scheme_rejected() {
        let auth = build_auth(None, None);
        let token = make_token(HashMap::new());
        let result = auth.validate(Some(&format!("Basic {token}")), Some("site-123"));
        assert!(matches!(result, Err(JwtAuthError::InvalidToken(_))));
    }

    #[test]
    fn malformed_token_rejected() {
        let auth = build_auth(None, None);
        let result = auth.validate(Some("Bearer not.a.jwt"), Some("site-123"));
        assert!(matches!(result, Err(JwtAuthError::InvalidToken(_))));
    }

    #[test]
    fn expired_token_rejected() {
        let auth = build_auth(None, None);
        let mut extra = HashMap::new();
        // exp in the past
        extra.insert("exp", serde_json::json!(now_secs() - 3600));
        let token = make_token(extra);
        let result = auth.validate(Some(&bearer(&token)), Some("site-123"));
        assert!(matches!(result, Err(JwtAuthError::InvalidToken(_))));
    }

    #[test]
    fn wrong_issuer_rejected() {
        let auth = build_auth(Some("https://expected.example.com/"), None);
        let mut extra = HashMap::new();
        extra.insert("iss", serde_json::json!("https://other.example.com/"));
        let token = make_token(extra);
        let result = auth.validate(Some(&bearer(&token)), Some("site-123"));
        assert!(matches!(result, Err(JwtAuthError::InvalidToken(_))));
    }

    #[test]
    fn matching_issuer_passes() {
        let auth = build_auth(Some("https://expected.example.com/"), None);
        let mut extra = HashMap::new();
        extra.insert("iss", serde_json::json!("https://expected.example.com/"));
        let token = make_token(extra);
        let result = auth.validate(Some(&bearer(&token)), Some("site-123"));
        assert!(result.is_ok());
    }

    #[test]
    fn wrong_audience_rejected() {
        let auth = build_auth(None, Some(vec!["https://expected-api/"]));
        let mut extra = HashMap::new();
        extra.insert("aud", serde_json::json!(["https://other-api/"]));
        let token = make_token(extra);
        let result = auth.validate(Some(&bearer(&token)), Some("site-123"));
        assert!(matches!(result, Err(JwtAuthError::InvalidToken(_))));
    }

    #[test]
    fn matching_audience_passes() {
        let auth = build_auth(None, Some(vec!["https://expected-api/"]));
        let mut extra = HashMap::new();
        extra.insert("aud", serde_json::json!(["https://expected-api/"]));
        let token = make_token(extra);
        let result = auth.validate(Some(&bearer(&token)), Some("site-123"));
        assert!(result.is_ok());
    }

    #[test]
    fn missing_site_id_header_returns_missing_membership_value() {
        let auth = build_auth(None, None);
        let token = make_token(HashMap::new());
        let result = auth.validate(Some(&bearer(&token)), None);
        assert!(matches!(result, Err(JwtAuthError::MissingMembershipValue)));
    }

    #[test]
    fn unauthorized_site_id_returns_membership_not_authorized() {
        let auth = build_auth(None, None);
        let token = make_token(HashMap::new());
        let result = auth.validate(Some(&bearer(&token)), Some("site-not-in-token"));
        assert!(matches!(
            result,
            Err(JwtAuthError::MembershipNotAuthorized)
        ));
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
        let result = auth.validate(Some(&bearer(&token)), Some("site-123"));
        assert!(matches!(result, Err(JwtAuthError::InvalidToken(_))));
    }

    #[test]
    fn custom_membership_claim_is_checked() {
        let cfg = JwtAuthConfig {
            public_key: JwtPublicKey::Inline {
                value: TEST_PUBLIC_KEY.to_string(),
            },
            jwt_issuer: None,
            jwt_audience: None,
            membership_claim: "allowed_tenants".to_string(),
        };
        let auth = cfg.build().unwrap();

        let mut extra = HashMap::new();
        extra.insert("allowed_tenants", serde_json::json!(["tenant-abc"]));
        let token = make_token(extra);

        // "site-123" is in site_ids but not in allowed_tenants — membership check uses the
        // configured claim, so this should be unauthorised rather than an invalid token.
        assert!(matches!(
            auth.validate(Some(&bearer(&token)), Some("site-123")),
            Err(JwtAuthError::MembershipNotAuthorized)
        ));
        assert!(auth
            .validate(Some(&bearer(&token)), Some("tenant-abc"))
            .is_ok());
    }

    // ── JwtPublicKey serde ───────────────────────────────────────────────────

    #[test]
    fn public_key_inline_deserializes() {
        let toml = r#"type = "inline"
value = "my-pem-value""#;
        let key: JwtPublicKey = toml::from_str(toml).unwrap();
        assert!(matches!(key, JwtPublicKey::Inline { value } if value == "my-pem-value"));
    }

    #[test]
    fn public_key_file_deserializes() {
        let toml = r#"type = "file"
path = "/etc/certs/auth0.pem""#;
        let key: JwtPublicKey = toml::from_str(toml).unwrap();
        assert!(
            matches!(key, JwtPublicKey::File { path } if path == "/etc/certs/auth0.pem")
        );
    }

    #[test]
    fn public_key_missing_type_fails() {
        assert!(toml::from_str::<JwtPublicKey>(r#"value = "pem""#).is_err());
    }

    #[test]
    fn public_key_unknown_type_fails() {
        assert!(toml::from_str::<JwtPublicKey>(r#"type = "env""#).is_err());
    }
}
