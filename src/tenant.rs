use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::Value;

use crate::types::AibimSdkError;

/// Client for managing tenant configuration and resources.
pub struct TenantClient {
    client: reqwest::Client,
    base_url: String,
    api_key: Option<String>,
}

impl TenantClient {
    /// Create a new tenant client.
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

    /// Handle HTTP response.
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

    /// Handle HTTP response returning a list.
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

    /// Get current tenant info.
    pub async fn me(&self) -> Result<Value, AibimSdkError> {
        let url = format!("{}/api/v1/tenant/me", self.base_url);
        let resp = self.client.get(&url).headers(self.headers()).send().await?;
        Self::handle_response(resp).await
    }

    /// Get tenant configuration.
    pub async fn get_config(&self) -> Result<Value, AibimSdkError> {
        let url = format!("{}/api/v1/tenant/config", self.base_url);
        let resp = self.client.get(&url).headers(self.headers()).send().await?;
        Self::handle_response(resp).await
    }

    /// Update tenant configuration.
    pub async fn update_config(&self, config: Value) -> Result<Value, AibimSdkError> {
        let url = format!("{}/api/v1/tenant/config", self.base_url);
        let resp = self
            .client
            .put(&url)
            .headers(self.headers())
            .json(&config)
            .send()
            .await?;
        Self::handle_response(resp).await
    }

    /// Get current detection mode.
    pub async fn get_detection_mode(&self) -> Result<Value, AibimSdkError> {
        let url = format!("{}/api/v1/tenant/detection-mode", self.base_url);
        let resp = self.client.get(&url).headers(self.headers()).send().await?;
        Self::handle_response(resp).await
    }

    /// Set detection mode (e.g. "monitor", "enforce", "passive").
    pub async fn set_detection_mode(&self, mode: &str) -> Result<Value, AibimSdkError> {
        let url = format!("{}/api/v1/tenant/detection-mode", self.base_url);
        let payload = serde_json::json!({ "mode": mode });
        let resp = self
            .client
            .put(&url)
            .headers(self.headers())
            .json(&payload)
            .send()
            .await?;
        Self::handle_response(resp).await
    }

    /// List API keys for the tenant.
    pub async fn list_api_keys(&self) -> Result<Vec<Value>, AibimSdkError> {
        let url = format!("{}/api/v1/api-keys", self.base_url);
        let resp = self.client.get(&url).headers(self.headers()).send().await?;
        Self::handle_list_response(resp).await
    }

    /// Create a new API key.
    pub async fn create_api_key(&self, name: &str) -> Result<Value, AibimSdkError> {
        let url = format!("{}/api/v1/api-keys", self.base_url);
        let payload = serde_json::json!({ "name": name });
        let resp = self
            .client
            .post(&url)
            .headers(self.headers())
            .json(&payload)
            .send()
            .await?;
        Self::handle_response(resp).await
    }

    /// Delete (deactivate) an API key.
    pub async fn delete_api_key(&self, key_id: &str) -> Result<(), AibimSdkError> {
        let url = format!("{}/api/v1/api-keys/{}", self.base_url, key_id);
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

    /// Get usage statistics for the tenant.
    pub async fn get_usage(&self) -> Result<Value, AibimSdkError> {
        let url = format!("{}/api/v1/tenant/usage", self.base_url);
        let resp = self.client.get(&url).headers(self.headers()).send().await?;
        Self::handle_response(resp).await
    }

    /// List proxy endpoints configured for the tenant.
    pub async fn list_endpoints(&self) -> Result<Vec<Value>, AibimSdkError> {
        let url = format!("{}/api/v1/endpoints", self.base_url);
        let resp = self.client.get(&url).headers(self.headers()).send().await?;
        Self::handle_list_response(resp).await
    }

    /// Create a new proxy endpoint.
    pub async fn create_endpoint(&self, endpoint: Value) -> Result<Value, AibimSdkError> {
        let url = format!("{}/api/v1/endpoints", self.base_url);
        let resp = self
            .client
            .post(&url)
            .headers(self.headers())
            .json(&endpoint)
            .send()
            .await?;
        Self::handle_response(resp).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_client_creation() {
        let client = TenantClient::new("https://api.aibim.ai", Some("key-123"));
        assert_eq!(client.base_url, "https://api.aibim.ai");
        assert_eq!(client.api_key.as_deref(), Some("key-123"));
    }

    #[test]
    fn test_tenant_client_no_key() {
        let client = TenantClient::new("https://api.aibim.ai", None);
        assert!(client.api_key.is_none());
    }

    #[test]
    fn test_tenant_headers() {
        let client = TenantClient::new("https://api.aibim.ai", Some("t-key"));
        let headers = client.headers();
        assert_eq!(
            headers.get("X-API-Key").unwrap().to_str().unwrap(),
            "t-key"
        );
    }
}
