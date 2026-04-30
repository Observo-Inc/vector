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
/// jwt_issuer       = "https://your-tenant.auth0.com/"
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

    /// Expected `iss` (issuer) claim, e.g. `"https://your-tenant.auth0.com/"`.
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
