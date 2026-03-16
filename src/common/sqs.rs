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
    fn test_backoff_starts_at_500ms() {
        // Validates the initial delay prevents immediate retry hammering
        let mut backoff = fresh_backoff();
        let first_delay = backoff.next().expect("backoff should produce a delay");

        assert_eq!(first_delay, Duration::from_millis(500));
        assert!(first_delay >= Duration::from_millis(100), "delay should be reasonable for network errors");
    }

    #[test]
    fn test_backoff_doubles_each_retry() {
        // Validates exponential growth to prevent sustained API hammering
        let mut backoff = fresh_backoff();

        let delays: Vec<Duration> = (0..7).map(|_| backoff.next().unwrap()).collect();

        // Each delay should be roughly double the previous (within rounding)
        for i in 1..delays.len() {
            let ratio = delays[i].as_millis() as f64 / delays[i-1].as_millis() as f64;
            assert!(
                (1.9..=2.1).contains(&ratio),
                "delay[{}] ({:?}) should be ~2x delay[{}] ({:?}), got ratio {}",
                i, delays[i], i-1, delays[i-1], ratio
            );
        }
    }

    #[test]
    fn test_backoff_caps_at_60_seconds() {
        // Validates max delay prevents indefinite waiting
        let mut backoff = fresh_backoff();

        // Exhaust the exponential growth
        for _ in 0..20 {
            backoff.next();
        }

        // All subsequent delays should be exactly 60 seconds
        for i in 0..5 {
            let delay = backoff.next().expect("backoff should always produce delays");
            assert_eq!(
                delay,
                Duration::from_secs(60),
                "delay {} after cap should be 60s, got {:?}",
                i, delay
            );
        }
    }

    #[test]
    fn test_backoff_reset_returns_to_initial_state() {
        // Validates reset allows fast recovery after transient errors
        let mut backoff = fresh_backoff();

        // Advance to a high delay
        for _ in 0..5 {
            backoff.next();
        }
        let high_delay = backoff.next().unwrap();
        assert!(high_delay > Duration::from_secs(1), "should have advanced beyond initial delay");

        // Reset and verify we're back to 500ms
        backoff.reset();
        let reset_delay = backoff.next().unwrap();
        assert_eq!(reset_delay, Duration::from_millis(500), "reset should return to initial 500ms delay");
    }

    #[test]
    fn test_backoff_progression_prevents_tight_loops() {
        // Validates the backoff prevents tight retry loops that could DOS the service
        let mut backoff = fresh_backoff();

        let mut total_wait_time = Duration::ZERO;
        for _ in 0..10 {
            total_wait_time += backoff.next().unwrap();
        }

        // After 10 retries, should have waited at least 30 seconds total
        assert!(
            total_wait_time >= Duration::from_secs(30),
            "10 retries should accumulate significant wait time, got {:?}",
            total_wait_time
        );
    }

    #[test]
    fn test_multiple_backoff_instances_are_independent() {
        // Validates that different sources can have independent backoff states
        let mut backoff1 = fresh_backoff();
        let mut backoff2 = fresh_backoff();

        // Advance backoff1
        backoff1.next();
        backoff1.next();
        let delay1 = backoff1.next().unwrap();

        // backoff2 should still be at initial state
        let delay2 = backoff2.next().unwrap();

        assert_eq!(delay2, Duration::from_millis(500), "new backoff should start at 500ms");
        assert!(delay1 > delay2, "advanced backoff should have higher delay");
    }
}
