use vector_lib::configurable::configurable_component;

/// Source of a JWT bearer token sent with outgoing requests.
///
/// Exactly one variant must be configured.
///
/// ## Examples
///
/// Inline value (use Vector's `${VAR}` interpolation for env vars):
/// ```toml
/// jwt_token.type  = "inline"
/// jwt_token.value = "${MY_JWT_TOKEN}"
/// ```
///
/// File path (re-read on every request for Kubernetes secret rotation):
/// ```toml
/// jwt_token.type = "file"
/// jwt_token.path = "/var/run/secrets/vector/token"
/// ```
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum JwtTokenConfig {
    /// Inline token value.
    ///
    /// Supports Vector's `${ENV_VAR}` interpolation. The value is resolved once at
    /// config load time.
    Inline {
        /// JWT bearer token value.
        value: String,
    },

    /// Path to a file containing the JWT bearer token.
    ///
    /// The file is re-read on **every request** so that a rotated Kubernetes secret
    /// volume mount is picked up automatically without restarting the agent.
    File {
        /// Path to the token file.
        path: String,
    },
}

/// Pre-parsed auth state built once at sink construction time.
///
/// `site_id` and, for inline tokens, the `Authorization` header value are parsed
/// into `MetadataValue` up front so the hot request path pays no allocation or
/// parse cost for those fields.
#[cfg(feature = "sinks-utils-jwt-auth")]
#[derive(Debug)]
pub struct JwtAuthState {
    site_id: tonic::metadata::MetadataValue<tonic::metadata::Ascii>,
    token: JwtAuthToken,
}

#[cfg(feature = "sinks-utils-jwt-auth")]
#[derive(Debug)]
pub enum JwtAuthToken {
    /// Fully-formatted `"Bearer <value>"` ready to insert into gRPC metadata.
    Static(tonic::metadata::MetadataValue<tonic::metadata::Ascii>),
    /// Path to a file re-read on every request (K8s secret rotation).
    File(String),
}

#[cfg(feature = "sinks-utils-jwt-auth")]
impl JwtAuthState {
    /// Builds a `JwtAuthState` from a raw `site_id` string and a [`JwtTokenConfig`].
    ///
    /// Both the `site_id` and any inline token value are parsed into
    /// [`tonic::metadata::MetadataValue`] here — once at construction — so the hot
    /// request path has no parse or allocation work to do.
    ///
    /// Returns a `&'static str` error message on failure; the caller is responsible
    /// for converting it to the appropriate error type.
    pub fn from_config(
        site_id: &str,
        token: JwtTokenConfig,
    ) -> Result<Self, &'static str> {
        let site_id = site_id
            .parse()
            .map_err(|_| "site_id contains characters invalid for gRPC metadata")?;

        let token = match token {
            JwtTokenConfig::Inline { value } => {
                let header = format!("Bearer {value}")
                    .parse()
                    .map_err(|_| "JWT token (inline) contains characters invalid for gRPC metadata")?;
                JwtAuthToken::Static(header)
            }
            JwtTokenConfig::File { path } => JwtAuthToken::File(path),
        };

        Ok(Self { site_id, token })
    }

    /// Returns the pre-parsed `x-site-id` metadata value.
    pub fn site_id(&self) -> &tonic::metadata::MetadataValue<tonic::metadata::Ascii> {
        &self.site_id
    }

    /// Returns the current bearer token as a gRPC `MetadataValue`.
    ///
    /// For [`JwtAuthToken::Static`] this is a cheap clone of the pre-built value.
    /// For [`JwtAuthToken::File`] the token file is re-read on every call so that
    /// a rotated Kubernetes secret is picked up without restarting the agent.
    ///
    /// Returns an error message string on failure; the caller is responsible for
    /// converting it to the appropriate error type.
    pub fn bearer_token(
        &self,
    ) -> Result<tonic::metadata::MetadataValue<tonic::metadata::Ascii>, String> {
        match &self.token {
            JwtAuthToken::Static(value) => Ok(value.clone()),
            JwtAuthToken::File(path) => {
                let raw = std::fs::read_to_string(path)
                    .map_err(|err| format!("failed to read token file '{}': {err}", path))?;
                let token = raw.trim();
                format!("Bearer {token}")
                    .parse::<tonic::metadata::MetadataValue<_>>()
                    .map_err(|err| format!("token file contains invalid characters: {err}"))
            }
        }
    }
}

#[cfg(all(test, feature = "sinks-utils-jwt-auth"))]
mod tests {
    use std::io::Write;

    use super::*;

    // -- from_config --

    #[test]
    fn from_config_inline_builds_correctly() {
        let state = JwtAuthState::from_config(
            "site-abc",
            JwtTokenConfig::Inline {
                value: "my-jwt-token".into(),
            },
        )
        .expect("valid inline config should build");

        assert_eq!(state.site_id().to_str().unwrap(), "site-abc");
        assert_eq!(
            state.bearer_token().unwrap().to_str().unwrap(),
            "Bearer my-jwt-token"
        );
    }

    #[test]
    fn from_config_file_stores_path() {
        let state = JwtAuthState::from_config(
            "site-abc",
            JwtTokenConfig::File {
                path: "/some/path/token".into(),
            },
        )
        .expect("valid file config should build");

        // Construction succeeds without reading the file.
        assert_eq!(state.site_id().to_str().unwrap(), "site-abc");
        assert!(matches!(state.token, JwtAuthToken::File(_)));
    }

    #[test]
    fn from_config_invalid_site_id_returns_error() {
        let result = JwtAuthState::from_config(
            "site\0bad",
            JwtTokenConfig::Inline {
                value: "token".into(),
            },
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("site_id contains characters invalid"));
    }

    #[test]
    fn from_config_inline_invalid_token_returns_error() {
        let result = JwtAuthState::from_config(
            "site-abc",
            JwtTokenConfig::Inline {
                value: "bad\0token".into(),
            },
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("JWT token (inline) contains characters invalid"));
    }

    // -- bearer_token --

    #[test]
    fn bearer_token_inline_is_cheap_clone() {
        let state = JwtAuthState::from_config(
            "site-abc",
            JwtTokenConfig::Inline {
                value: "tok".into(),
            },
        )
        .unwrap();

        // Both calls return the same value without I/O.
        assert_eq!(
            state.bearer_token().unwrap().to_str().unwrap(),
            state.bearer_token().unwrap().to_str().unwrap()
        );
    }

    #[test]
    fn bearer_token_file_reads_content() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(f, "my-rotating-token").unwrap();

        let state = JwtAuthState::from_config(
            "site-abc",
            JwtTokenConfig::File {
                path: f.path().to_str().unwrap().into(),
            },
        )
        .unwrap();

        assert_eq!(
            state.bearer_token().unwrap().to_str().unwrap(),
            "Bearer my-rotating-token"
        );
    }

    #[test]
    fn bearer_token_file_trims_trailing_whitespace() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(f, "token-with-newline\n").unwrap();

        let state = JwtAuthState::from_config(
            "site-abc",
            JwtTokenConfig::File {
                path: f.path().to_str().unwrap().into(),
            },
        )
        .unwrap();

        assert_eq!(
            state.bearer_token().unwrap().to_str().unwrap(),
            "Bearer token-with-newline"
        );
    }

    #[test]
    fn bearer_token_file_rotation_reflected_on_next_call() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(f, "original-token").unwrap();

        let state = JwtAuthState::from_config(
            "site-abc",
            JwtTokenConfig::File {
                path: f.path().to_str().unwrap().into(),
            },
        )
        .unwrap();

        assert_eq!(
            state.bearer_token().unwrap().to_str().unwrap(),
            "Bearer original-token"
        );

        // Simulate Kubernetes secret rotation.
        f.reopen().unwrap();
        std::fs::write(f.path(), "rotated-token").unwrap();

        assert_eq!(
            state.bearer_token().unwrap().to_str().unwrap(),
            "Bearer rotated-token"
        );
    }

    #[test]
    fn bearer_token_file_not_found_returns_error_with_path() {
        let path = "/nonexistent/path/to/token";
        let state = JwtAuthState::from_config(
            "site-abc",
            JwtTokenConfig::File { path: path.into() },
        )
        .unwrap();

        let err = state.bearer_token().unwrap_err();
        assert!(err.contains(path), "error should contain path: {err}");
    }

    // -- serde round-trips --

    #[test]
    fn jwt_token_config_inline_deserializes() {
        let toml = r#"type = "inline"
value = "my-token""#;
        let cfg: JwtTokenConfig = toml::from_str(toml).unwrap();
        assert!(matches!(cfg, JwtTokenConfig::Inline { value } if value == "my-token"));
    }

    #[test]
    fn jwt_token_config_file_deserializes() {
        let toml = r#"type = "file"
path = "/var/run/secrets/token""#;
        let cfg: JwtTokenConfig = toml::from_str(toml).unwrap();
        assert!(
            matches!(cfg, JwtTokenConfig::File { path } if path == "/var/run/secrets/token")
        );
    }

    #[test]
    fn jwt_token_config_missing_type_fails() {
        let toml = r#"value = "token""#;
        assert!(toml::from_str::<JwtTokenConfig>(toml).is_err());
    }

    #[test]
    fn jwt_token_config_unknown_type_fails() {
        let toml = r#"type = "env""#;
        assert!(toml::from_str::<JwtTokenConfig>(toml).is_err());
    }
}
