use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::Value;

use crate::types::AibimSdkError;

/// Client for managing AIBIM detection rules.
pub struct RulesClient {
    client: reqwest::Client,
    base_url: String,
    api_key: Option<String>,
}

impl RulesClient {
    /// Create a new rules client.
    #[must_use]
    pub fn new(base_url: &str, api_key: Option<&str>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_default();

        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key: api_key.map(String::from),
        }
    }

    fn headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("Content-Type", HeaderValue::from_static("application/json"));
        if let Some(ref key) = self.api_key {
            if let Ok(v) = HeaderValue::from_str(key) {
                headers.insert("X-API-Key", v);
            }
        }
        headers
    }

    /// List all detection rules.
    pub async fn list(&self) -> Result<Vec<Value>, AibimSdkError> {
        let url = format!("{}/api/v1/rules", self.base_url);
        let resp = self
            .client
            .get(&url)
            .headers(self.headers())
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(AibimSdkError::Api { status, body });
        }

        resp.json::<Vec<Value>>()
            .await
            .map_err(|e| AibimSdkError::Parse(e.to_string()))
    }

    /// Create a new detection rule.
    pub async fn create(&self, rule: Value) -> Result<Value, AibimSdkError> {
        let url = format!("{}/api/v1/rules", self.base_url);
        let resp = self
            .client
            .post(&url)
            .headers(self.headers())
            .json(&rule)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(AibimSdkError::Api { status, body });
        }

        resp.json::<Value>()
            .await
            .map_err(|e| AibimSdkError::Parse(e.to_string()))
    }

    /// Delete a detection rule by ID (soft delete).
    pub async fn delete(&self, rule_id: &str) -> Result<(), AibimSdkError> {
        let url = format!("{}/api/v1/rules/{}", self.base_url, rule_id);
        let resp = self
            .client
            .delete(&url)
            .headers(self.headers())
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(AibimSdkError::Api { status, body });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rules_client_creation() {
        let client = RulesClient::new("https://api.aibim.ai", Some("key-123"));
        assert_eq!(client.base_url, "https://api.aibim.ai");
        assert_eq!(client.api_key.as_deref(), Some("key-123"));
    }

    #[test]
    fn test_rules_client_trailing_slash() {
        let client = RulesClient::new("https://api.aibim.ai/", None);
        assert_eq!(client.base_url, "https://api.aibim.ai");
    }

    #[test]
    fn test_rules_headers() {
        let client = RulesClient::new("https://api.aibim.ai", Some("test-key"));
        let headers = client.headers();
        assert_eq!(
            headers.get("X-API-Key").unwrap().to_str().unwrap(),
            "test-key"
        );
        assert_eq!(
            headers.get("Content-Type").unwrap().to_str().unwrap(),
            "application/json"
        );
    }
}
