use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::Value;

use crate::types::AibimSdkError;

/// Client for querying and managing AIBIM security alerts.
pub struct AlertsClient {
    client: reqwest::Client,
    base_url: String,
    api_key: Option<String>,
}

impl AlertsClient {
    /// Create a new alerts client.
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

    /// List alerts with optional filter parameters.
    ///
    /// Supported params: `limit`, `offset`, `severity`, `status`, `start_date`, `end_date`.
    pub async fn list(
        &self,
        params: Option<&[(&str, &str)]>,
    ) -> Result<Vec<Value>, AibimSdkError> {
        let url = format!("{}/api/v1/alerts", self.base_url);
        let mut req = self.client.get(&url).headers(self.headers());
        if let Some(p) = params {
            req = req.query(p);
        }
        let resp = req.send().await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(AibimSdkError::Api { status, body });
        }

        resp.json::<Vec<Value>>()
            .await
            .map_err(|e| AibimSdkError::Parse(e.to_string()))
    }

    /// List alert rules.
    pub async fn list_rules(&self) -> Result<Vec<Value>, AibimSdkError> {
        let url = format!("{}/api/v1/alert-rules", self.base_url);
        let resp = self.client.get(&url).headers(self.headers()).send().await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(AibimSdkError::Api { status, body });
        }

        resp.json::<Vec<Value>>()
            .await
            .map_err(|e| AibimSdkError::Parse(e.to_string()))
    }

    /// Create a new alert rule.
    pub async fn create_rule(&self, rule: Value) -> Result<Value, AibimSdkError> {
        let url = format!("{}/api/v1/alert-rules", self.base_url);
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

    /// Get alert statistics (counts by severity, status, etc.).
    pub async fn stats(&self) -> Result<Value, AibimSdkError> {
        let url = format!("{}/api/v1/alerts/stats", self.base_url);
        let resp = self.client.get(&url).headers(self.headers()).send().await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(AibimSdkError::Api { status, body });
        }

        resp.json::<Value>()
            .await
            .map_err(|e| AibimSdkError::Parse(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alerts_client_creation() {
        let client = AlertsClient::new("https://api.aibim.ai", Some("key-123"));
        assert_eq!(client.base_url, "https://api.aibim.ai");
        assert_eq!(client.api_key.as_deref(), Some("key-123"));
    }

    #[test]
    fn test_alerts_client_no_key() {
        let client = AlertsClient::new("https://api.aibim.ai", None);
        assert!(client.api_key.is_none());
    }

    #[test]
    fn test_alerts_headers() {
        let client = AlertsClient::new("https://api.aibim.ai", Some("a-key"));
        let headers = client.headers();
        assert_eq!(
            headers.get("X-API-Key").unwrap().to_str().unwrap(),
            "a-key"
        );
    }
}
