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
