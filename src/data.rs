use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::Value;

use crate::types::AibimSdkError;

/// Client for querying AIBIM detection events, stats, and analytics.
pub struct DataClient {
    client: reqwest::Client,
    base_url: String,
    api_key: Option<String>,
}

impl DataClient {
    /// Create a new data client.
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

    /// Handle response returning a single JSON value.
    async fn handle_response(resp: reqwest::Response) -> Result<Value, AibimSdkError> {
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(AibimSdkError::Api { status, body });
        }
        resp.json::<Value>()
            .await
            .map_err(|e| AibimSdkError::Parse(e.to_string()))
    }

    /// Handle response returning a list.
    async fn handle_list_response(resp: reqwest::Response) -> Result<Vec<Value>, AibimSdkError> {
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(AibimSdkError::Api { status, body });
        }
        resp.json::<Vec<Value>>()
            .await
            .map_err(|e| AibimSdkError::Parse(e.to_string()))
    }

    /// Query detection events with optional filter parameters.
    ///
    /// Supported params: `limit`, `offset`, `severity`, `action`, `start_date`, `end_date`.
    pub async fn events(
        &self,
        params: Option<&[(&str, &str)]>,
    ) -> Result<Vec<Value>, AibimSdkError> {
        let url = format!("{}/api/v1/events", self.base_url);
        let mut req = self.client.get(&url).headers(self.headers());
        if let Some(p) = params {
            req = req.query(p);
        }
        let resp = req.send().await?;
        Self::handle_list_response(resp).await
    }

    /// Get real-time statistics (request counts, threat distribution, etc.).
    pub async fn realtime_stats(&self) -> Result<Value, AibimSdkError> {
        let url = format!("{}/api/v1/realtime-stats", self.base_url);
        let resp = self.client.get(&url).headers(self.headers()).send().await?;
        Self::handle_response(resp).await
    }

    /// Get benchmark results.
    pub async fn benchmarks(&self) -> Result<Vec<Value>, AibimSdkError> {
        let url = format!("{}/api/v1/benchmarks", self.base_url);
        let resp = self.client.get(&url).headers(self.headers()).send().await?;
        Self::handle_list_response(resp).await
    }

    /// Get compliance assessment results.
    pub async fn compliance(&self) -> Result<Vec<Value>, AibimSdkError> {
        let url = format!("{}/api/v1/compliance", self.base_url);
        let resp = self.client.get(&url).headers(self.headers()).send().await?;
        Self::handle_list_response(resp).await
    }

    /// Get trust scores for registered agents.
    pub async fn trust_agents(&self) -> Result<Vec<Value>, AibimSdkError> {
        let url = format!("{}/api/v1/trust/agents", self.base_url);
        let resp = self.client.get(&url).headers(self.headers()).send().await?;
        Self::handle_list_response(resp).await
    }

    /// Get threat intelligence feed.
    pub async fn threat_feed(&self) -> Result<Vec<Value>, AibimSdkError> {
        let url = format!("{}/api/v1/threat-intel/feed", self.base_url);
        let resp = self.client.get(&url).headers(self.headers()).send().await?;
        Self::handle_list_response(resp).await
    }

    /// Get DLP (Data Loss Prevention) events.
    pub async fn dlp_events(&self) -> Result<Vec<Value>, AibimSdkError> {
        let url = format!("{}/api/v1/dlp/events", self.base_url);
        let resp = self.client.get(&url).headers(self.headers()).send().await?;
        Self::handle_list_response(resp).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_client_creation() {
        let client = DataClient::new("https://api.aibim.ai", Some("key-123"));
        assert_eq!(client.base_url, "https://api.aibim.ai");
        assert_eq!(client.api_key.as_deref(), Some("key-123"));
    }

    #[test]
    fn test_data_client_no_key() {
        let client = DataClient::new("https://api.aibim.ai", None);
        assert!(client.api_key.is_none());
    }

    #[test]
    fn test_data_headers() {
        let client = DataClient::new("https://api.aibim.ai", Some("d-key"));
        let headers = client.headers();
        assert_eq!(
            headers.get("X-API-Key").unwrap().to_str().unwrap(),
            "d-key"
        );
    }
}
