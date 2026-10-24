//! Bounded retry policy with injectable delays (so tests do not sleep long).

use std::time::Duration;

#[derive(Debug, Clone)]
pub(super) struct RetryPolicy {
    pub max_attempts: u32,
    pub backoff_base: Duration,
    pub retry_after_cap: Duration,
    pub total_cap: Duration,
    pub request_timeout: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            backoff_base: Duration::from_millis(500),
            retry_after_cap: Duration::from_secs(30),
            total_cap: Duration::from_secs(60),
            request_timeout: Duration::from_secs(30),
        }
    }
}

impl RetryPolicy {
    /// Delay before the retry that follows failed attempt number `attempt` (1-based).
    pub fn delay(&self, attempt: u32, retry_after: Option<Duration>) -> Duration {
        match retry_after {
            Some(d) => d.min(self.retry_after_cap),
            None => self
                .backoff_base
                .saturating_mul(1u32 << attempt.saturating_sub(1).min(8))
                .min(self.retry_after_cap),
        }
    }
}

/// Parse a `Retry-After` header given in delta-seconds (HTTP-date is ignored).
pub(super) fn parse_retry_after(v: &str) -> Option<Duration> {
    v.trim().parse::<u64>().ok().map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_is_capped() {
        let p = RetryPolicy::default();
        assert_eq!(
            p.delay(1, Some(Duration::from_secs(9999))),
            Duration::from_secs(30)
        );
        assert_eq!(
            p.delay(1, Some(Duration::from_secs(2))),
            Duration::from_secs(2)
        );
    }

    #[test]
    fn backoff_grows_and_is_capped() {
        let p = RetryPolicy::default();
        assert_eq!(p.delay(1, None), Duration::from_millis(500));
        assert_eq!(p.delay(2, None), Duration::from_millis(1000));
        assert_eq!(p.delay(20, None), Duration::from_secs(30));
    }

    #[test]
    fn parses_seconds_only() {
        assert_eq!(parse_retry_after(" 5 "), Some(Duration::from_secs(5)));
        assert_eq!(parse_retry_after("Wed, 21 Oct 2026 07:28:00 GMT"), None);
    }
}
