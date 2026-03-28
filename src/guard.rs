use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

/// Default AIBIM proxy URL.
pub const DEFAULT_PROXY_URL: &str = "http://localhost:8080";

/// SDK client configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdkConfig {
    pub base_url: String,
    pub api_key: String,
    pub timeout_secs: u64,
    pub retry_count: u32,
}

impl Default for SdkConfig {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_PROXY_URL.to_string(),
            api_key: String::new(),
            timeout_secs: 30,
            retry_count: 3,
        }
    }
}

/// Detection result from AIBIM analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    pub risk_score: f64,
    pub is_threat: bool,
    pub rules_matched: Vec<String>,
    pub model: String,
    pub latency_ms: f64,
}

/// Async context for direct AIBIM analysis.
///
/// # Example
///
/// ```no_run
/// use aibim_sdk::AibimGuard;
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let guard = AibimGuard::new("http://localhost:8080", "my-api-key");
/// let result = guard.analyze("Is this injection?", "gpt-4").await?;
/// if result.is_threat {
///     println!("Threat detected: {}", result.risk_score);
/// }
/// # Ok(())
/// # }
/// ```
pub struct AibimGuard {
    client: reqwest::Client,
    base_url: String,
    api_key: String,
}

impl AibimGuard {
    /// Create a guard connected to the AIBIM proxy.
    #[must_use]
    pub fn new(base_url: &str, api_key: &str) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_default();

        info!(base_url, "aibim_guard_created");
        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key: api_key.to_string(),
        }
    }

    /// Analyze text for prompt injection.
    pub async fn analyze(&self, text: &str, model: &str) -> Result<DetectionResult, String> {
        let url = format!("{}/v1/analyze", self.base_url);
        let payload = serde_json::json!({
            "prompt": text,
            "model": model,
        });

        let resp = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("HTTP error: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("API error {status}: {body}"));
        }

        resp.json::<DetectionResult>()
            .await
            .map_err(|e| format!("Parse error: {e}"))
    }

    /// Get all loaded detection rules.
    pub async fn get_rules(&self) -> Result<Vec<serde_json::Value>, String> {
        let url = format!("{}/v1/rules", self.base_url);
        let resp = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .send()
            .await
            .map_err(|e| format!("HTTP error: {e}"))?;

        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        resp.json::<Vec<serde_json::Value>>()
            .await
            .map_err(|e| format!("Parse error: {e}"))
    }

    /// Add a custom detection rule.
    pub async fn add_rule(
        &self,
        rule_id: &str,
        name: &str,
        pattern: &str,
        severity: f64,
        category: &str,
    ) -> Result<serde_json::Value, String> {
        let url = format!("{}/v1/rules", self.base_url);
        let payload = serde_json::json!({
            "rule_id": rule_id,
            "name": name,
            "pattern": pattern,
            "severity": severity,
            "category": category,
        });

        let resp = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("HTTP error: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("API error {status}: {body}"));
        }

        resp.json::<serde_json::Value>()
            .await
            .map_err(|e| format!("Parse error: {e}"))
    }

    /// Check AIBIM proxy health.
    pub async fn health(&self) -> Result<HashMap<String, serde_json::Value>, String> {
        let url = format!("{}/health", self.base_url);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("HTTP error: {e}"))?;

        resp.json::<HashMap<String, serde_json::Value>>()
            .await
            .map_err(|e| format!("Parse error: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = SdkConfig::default();
        assert_eq!(config.base_url, DEFAULT_PROXY_URL);
        assert_eq!(config.timeout_secs, 30);
        assert_eq!(config.retry_count, 3);
    }

    #[test]
    fn test_guard_creation() {
        let guard = AibimGuard::new("http://example.com:8080", "test-key");
        assert_eq!(guard.base_url, "http://example.com:8080");
        assert_eq!(guard.api_key, "test-key");
    }

    #[test]
    fn test_guard_url_trailing_slash() {
        let guard = AibimGuard::new("http://example.com:8080/", "key");
        assert_eq!(guard.base_url, "http://example.com:8080");
    }

    #[test]
    fn test_detection_result_serialization() {
        let result = DetectionResult {
            risk_score: 0.85,
            is_threat: true,
            rules_matched: vec!["INJECT_001".into()],
            model: "gpt-4".into(),
            latency_ms: 2.5,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"is_threat\":true"));
        assert!(json.contains("INJECT_001"));
    }
}
