use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::Value;
use tracing::info;

use crate::retry::RetryPolicy;
use crate::types::{AibimResponseMeta, AibimSdkError};

/// AIBIM Proxy client -- routes LLM requests through the AIBIM security proxy.
///
/// Sends requests to the AIBIM proxy instead of directly to the LLM provider.
/// The proxy inspects, scores, and optionally blocks malicious content.
///
/// # Example
///
/// ```no_run
/// use aibim_sdk::AibimProxy;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let proxy = AibimProxy::new("https://proxy.aibim.ai", "aibim-key", "sk-openai");
/// let (response, meta) = proxy.chat_completion(serde_json::json!({
///     "model": "gpt-4",
///     "messages": [{"role": "user", "content": "Hello"}]
/// })).await?;
/// println!("Decision: {}, Score: {}", meta.decision, meta.score);
/// # Ok(())
/// # }
/// ```
pub struct AibimProxy {
    client: reqwest::Client,
    aibim_url: String,
    api_key: String,
    provider_api_key: String,
    retry: RetryPolicy,
}

impl AibimProxy {
    /// Create a new proxy client.
    ///
    /// - `aibim_url`: Base URL of the AIBIM proxy (e.g. `https://proxy.aibim.ai`)
    /// - `api_key`: AIBIM API key for authentication
    /// - `provider_api_key`: Upstream LLM provider API key (e.g. OpenAI `sk-...`)
    #[must_use]
    pub fn new(aibim_url: &str, api_key: &str, provider_api_key: &str) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .unwrap_or_default();

        info!(aibim_url, "aibim_proxy_created");
        Self {
            client,
            aibim_url: aibim_url.trim_end_matches('/').to_string(),
            api_key: api_key.to_string(),
            provider_api_key: provider_api_key.to_string(),
            retry: RetryPolicy::default(),
        }
    }

    /// Set custom retry policy.
    #[must_use]
    pub fn with_retry(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    /// Build common headers for all proxy requests.
    fn headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("Content-Type", HeaderValue::from_static("application/json"));
        if let Ok(v) = HeaderValue::from_str(&format!("Bearer {}", self.provider_api_key)) {
            headers.insert("Authorization", v);
        }
        if let Ok(v) = HeaderValue::from_str(&self.api_key) {
            headers.insert("X-AIBIM-API-Key", v);
        }
        headers
    }

    /// Send a chat completion request through AIBIM proxy.
    ///
    /// Returns the LLM response body and AIBIM metadata (decision, score, cache info).
    /// Returns `AibimSdkError::Blocked` if the proxy blocked the request (HTTP 403).
    /// Returns `AibimSdkError::RateLimit` if rate limited (HTTP 429).
    pub async fn chat_completion(
        &self,
        body: Value,
    ) -> Result<(Value, AibimResponseMeta), AibimSdkError> {
        let url = format!("{}/v1/chat/completions", self.aibim_url);
        self.send_llm_request(&url, body).await
    }

    /// Send a completions request (non-chat, e.g. /v1/completions).
    pub async fn completions(
        &self,
        body: Value,
    ) -> Result<(Value, AibimResponseMeta), AibimSdkError> {
        self.request(reqwest::Method::POST, "/v1/completions", Some(body))
            .await
    }

    /// Send an embeddings request through AIBIM proxy.
    pub async fn embeddings(
        &self,
        body: Value,
    ) -> Result<(Value, AibimResponseMeta), AibimSdkError> {
        self.request(reqwest::Method::POST, "/v1/embeddings", Some(body))
            .await
    }

    /// Send a generic request through AIBIM proxy.
    pub async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<(Value, AibimResponseMeta), AibimSdkError> {
        let url = format!("{}{}", self.aibim_url, path);
        let mut req = self.client.request(method, &url).headers(self.headers());
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await?;
        let meta = AibimResponseMeta::from_headers(resp.headers());

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body_text = resp.text().await.unwrap_or_default();
            return Err(AibimSdkError::Api {
                status,
                body: body_text,
            });
        }

        let response_body = resp
            .json::<Value>()
            .await
            .map_err(|e| AibimSdkError::Parse(e.to_string()))?;
        Ok((response_body, meta))
    }

    /// Internal helper: send an LLM request and handle AIBIM-specific status codes.
    async fn send_llm_request(
        &self,
        url: &str,
        body: Value,
    ) -> Result<(Value, AibimResponseMeta), AibimSdkError> {
        let resp = self
            .client
            .post(url)
            .headers(self.headers())
            .json(&body)
            .send()
            .await?;

        let meta = AibimResponseMeta::from_headers(resp.headers());

        if resp.status().as_u16() == 403 {
            let body_text = resp.text().await.unwrap_or_default();
            let parsed: Value = serde_json::from_str(&body_text).unwrap_or_default();
            return Err(AibimSdkError::Blocked {
                score: meta.score,
                decision: meta.decision,
                rules: parsed
                    .get("matched_rules")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default(),
                correlation_id: meta.correlation_id,
            });
        }

        if resp.status().as_u16() == 429 {
            let retry_after = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse().ok());
            return Err(AibimSdkError::RateLimit { retry_after });
        }

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body_text = resp.text().await.unwrap_or_default();
            return Err(AibimSdkError::Api {
                status,
                body: body_text,
            });
        }

        let response_body = resp
            .json::<Value>()
            .await
            .map_err(|e| AibimSdkError::Parse(e.to_string()))?;

        Ok((response_body, meta))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_creation() {
        let proxy = AibimProxy::new("https://proxy.aibim.ai", "key-123", "sk-openai");
        assert_eq!(proxy.aibim_url, "https://proxy.aibim.ai");
        assert_eq!(proxy.api_key, "key-123");
        assert_eq!(proxy.provider_api_key, "sk-openai");
    }

    #[test]
    fn test_proxy_trailing_slash() {
        let proxy = AibimProxy::new("https://proxy.aibim.ai/", "k", "sk");
        assert_eq!(proxy.aibim_url, "https://proxy.aibim.ai");
    }

    #[test]
    fn test_headers_contain_keys() {
        let proxy = AibimProxy::new("https://proxy.aibim.ai", "aibim-key", "sk-test");
        let headers = proxy.headers();
        assert_eq!(
            headers.get("Content-Type").unwrap().to_str().unwrap(),
            "application/json"
        );
        assert!(headers
            .get("Authorization")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("sk-test"));
        assert_eq!(
            headers.get("X-AIBIM-API-Key").unwrap().to_str().unwrap(),
            "aibim-key"
        );
    }

    #[test]
    fn test_with_retry() {
        let proxy = AibimProxy::new("https://proxy.aibim.ai", "k", "sk").with_retry(RetryPolicy {
            max_retries: 5,
            ..RetryPolicy::default()
        });
        assert_eq!(proxy.retry.max_retries, 5);
    }
}
