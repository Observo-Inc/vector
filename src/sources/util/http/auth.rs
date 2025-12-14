use std::convert::TryFrom;

// Re-export StatelessAuth from vector-core
pub use vector_lib::http::StatelessAuth;

// Import ErrorMessage from the local error module
#[cfg(any(
    feature = "sources-utils-http-prelude",
    feature = "sources-utils-http-auth"
))]
use super::error::ErrorMessage;

// Alias for backward compatibility
pub type HttpSourceAuthConfig = StatelessAuth;

// Wrapper type for optional authentication
#[derive(Clone, Debug)]
pub struct HttpSourceAuth {
    inner: Option<StatelessAuth>,
}

impl HttpSourceAuth {
    pub fn new(auth: Option<StatelessAuth>) -> Self {
        Self { inner: auth }
    }

    #[allow(unused)] // triggered by check-component-features
    pub fn is_valid(&self, header: &Option<String>) -> Result<(), ErrorMessage> {
        match &self.inner {
            Some(auth) => {
                // Convert AuthError to ErrorMessage
                auth.is_valid(header).map_err(|auth_err| {
                    ErrorMessage::new(auth_err.status, auth_err.message)
                })
            }
            None => Ok(()), // No auth configured, allow all requests
        }
    }
}

impl TryFrom<Option<&StatelessAuth>> for HttpSourceAuth {
    type Error = String;

    fn try_from(auth: Option<&StatelessAuth>) -> Result<Self, Self::Error> {
        Ok(Self {
            inner: auth.cloned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vector_lib::sensitive_string::SensitiveString;
    use warp::http::StatusCode;

    #[test]
    fn test_http_source_auth_no_auth_configured() {
        let auth = HttpSourceAuth::new(None);

        // Should accept any request when no auth is configured
        assert!(auth.is_valid(&None).is_ok());
        assert!(auth.is_valid(&Some("Bearer token".to_string())).is_ok());
        assert!(auth.is_valid(&Some("Basic xyz".to_string())).is_ok());
    }

    #[test]
    fn test_http_source_auth_basic_valid() {
        let stateless_auth = StatelessAuth::Basic {
            user: "admin".to_string(),
            password: SensitiveString::from("secret".to_string()),
        };
        let auth = HttpSourceAuth::new(Some(stateless_auth));

        // Valid basic auth header
        let valid_header = Some("Basic YWRtaW46c2VjcmV0".to_string());
        assert!(auth.is_valid(&valid_header).is_ok());
    }

    #[test]
    fn test_http_source_auth_basic_invalid() {
        let stateless_auth = StatelessAuth::Basic {
            user: "admin".to_string(),
            password: SensitiveString::from("secret".to_string()),
        };
        let auth = HttpSourceAuth::new(Some(stateless_auth));

        // Invalid basic auth header
        let invalid_header = Some("Basic d3Jvbmc6Y3JlZHM=".to_string());
        let result = auth.is_valid(&invalid_header);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_http_source_auth_bearer_valid() {
        let stateless_auth = StatelessAuth::Bearer {
            token: SensitiveString::from("my-secret-token".to_string()),
        };
        let auth = HttpSourceAuth::new(Some(stateless_auth));

        // Valid bearer token
        let valid_header = Some("Bearer my-secret-token".to_string());
        assert!(auth.is_valid(&valid_header).is_ok());
    }

    #[test]
    fn test_http_source_auth_bearer_invalid() {
        let stateless_auth = StatelessAuth::Bearer {
            token: SensitiveString::from("my-secret-token".to_string()),
        };
        let auth = HttpSourceAuth::new(Some(stateless_auth));

        // Invalid bearer token
        let invalid_header = Some("Bearer wrong-token".to_string());
        let result = auth.is_valid(&invalid_header);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_http_source_auth_missing_header() {
        let stateless_auth = StatelessAuth::Basic {
            user: "admin".to_string(),
            password: SensitiveString::from("secret".to_string()),
        };
        let auth = HttpSourceAuth::new(Some(stateless_auth));

        // Missing header
        let result = auth.is_valid(&None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_http_source_auth_try_from_some() {
        let stateless_auth = StatelessAuth::Bearer {
            token: SensitiveString::from("token123".to_string()),
        };

        let result = HttpSourceAuth::try_from(Some(&stateless_auth));
        assert!(result.is_ok());

        let auth = result.unwrap();
        let valid_header = Some("Bearer token123".to_string());
        assert!(auth.is_valid(&valid_header).is_ok());
    }

    #[test]
    fn test_http_source_auth_try_from_none() {
        let result = HttpSourceAuth::try_from(None);
        assert!(result.is_ok());

        let auth = result.unwrap();
        // Should accept any request when no auth is configured
        assert!(auth.is_valid(&None).is_ok());
        assert!(auth.is_valid(&Some("any header".to_string())).is_ok());
    }
}
