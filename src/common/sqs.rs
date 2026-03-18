use crate::aws::ClientBuilder;
use crate::common::backoff::ExponentialBackoff;
use std::time::Duration;

pub(crate) struct SqsClientBuilder;

impl ClientBuilder for SqsClientBuilder {
    type Client = aws_sdk_sqs::client::Client;

    fn build(&self, config: &aws_types::SdkConfig) -> Self::Client {
        aws_sdk_sqs::client::Client::new(config)
    }
}

pub(crate) const fn fresh_backoff() -> ExponentialBackoff {
    // TODO: make configurable
    ExponentialBackoff::from_millis(2)
        .factor(250)
        .max_delay(Duration::from_secs(60))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fresh_backoff_configuration() {
        // Validates that fresh_backoff() returns the correct configuration for SQS sources
        let mut backoff = fresh_backoff();
        
        // Should start at 500ms (2ms base * 250 factor)
        assert_eq!(backoff.next(), Some(Duration::from_millis(500)));
        
        // Should double to 1000ms
        assert_eq!(backoff.next(), Some(Duration::from_millis(1000)));
        
        // Advance to max delay
        for _ in 0..10 {
            backoff.next();
        }
        
        // Should cap at 60 seconds
        assert_eq!(backoff.next(), Some(Duration::from_secs(60)));
    }
}
