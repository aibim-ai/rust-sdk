use std::time::Duration;
use tracing::warn;

/// Retry policy with exponential backoff and jitter.
pub struct RetryPolicy {
    pub max_retries: u32,
    pub backoff_factor: f64,
    pub max_backoff_secs: f64,
    pub retryable_statuses: Vec<u16>,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            backoff_factor: 0.5,
            max_backoff_secs: 30.0,
            retryable_statuses: vec![429, 500, 502, 503, 504],
        }
    }
}

impl RetryPolicy {
    /// Execute an async operation with retry.
    pub async fn execute<F, Fut, T>(&self, f: F) -> Result<T, crate::types::AibimSdkError>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T, crate::types::AibimSdkError>>,
    {
        let mut last_err = None;
        for attempt in 0..=self.max_retries {
            match f().await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    let should_retry = match &e {
                        crate::types::AibimSdkError::Http(_) => true,
                        crate::types::AibimSdkError::Api { status, .. } => {
                            self.retryable_statuses.contains(status)
                        }
                        crate::types::AibimSdkError::RateLimit { retry_after } => {
                            if let Some(secs) = retry_after {
                                tokio::time::sleep(Duration::from_secs_f64(*secs)).await;
                                last_err = Some(e);
                                continue;
                            }
                            true
                        }
                        _ => false,
                    };

                    if !should_retry || attempt == self.max_retries {
                        return Err(e);
                    }

                    let backoff = (self.backoff_factor * 2.0_f64.powi(attempt as i32))
                        .min(self.max_backoff_secs);
                    let jitter = backoff * 0.1 * rand_jitter();
                    let delay = backoff + jitter;

                    warn!(attempt, delay_secs = delay, "Retrying after error");
                    tokio::time::sleep(Duration::from_secs_f64(delay)).await;
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| crate::types::AibimSdkError::Api {
            status: 0,
            body: "Max retries exceeded".into(),
        }))
    }
}

/// Generate a pseudo-random jitter value in [0.0, 1.0) using system time nanos.
fn rand_jitter() -> f64 {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    (nanos % 1000) as f64 / 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.max_retries, 3);
        assert!((policy.backoff_factor - 0.5).abs() < f64::EPSILON);
        assert!((policy.max_backoff_secs - 30.0).abs() < f64::EPSILON);
        assert!(policy.retryable_statuses.contains(&429));
        assert!(policy.retryable_statuses.contains(&503));
    }

    #[test]
    fn test_rand_jitter_range() {
        for _ in 0..100 {
            let j = rand_jitter();
            assert!(j >= 0.0, "jitter must be >= 0.0, got {j}");
            assert!(j < 1.0, "jitter must be < 1.0, got {j}");
        }
    }
}
