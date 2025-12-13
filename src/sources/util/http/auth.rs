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
