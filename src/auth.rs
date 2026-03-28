use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::Value;

use crate::types::AibimSdkError;

/// Auth client for AIBIM authentication endpoints.
///
/// Supports both JWT (SaaS) and API key (self-hosted) authentication flows.
pub struct AuthClient {
    client: reqwest::Client,
    base_url: String,
    api_key: Option<String>,
}

impl AuthClient {
    /// Create a new auth client.
    ///
    /// - `base_url`: AIBIM API base URL
    /// - `api_key`: Optional API key for self-hosted auth
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

    /// Build common headers.
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

    /// Build headers with a bearer token.
    fn bearer_headers(&self, token: &str) -> HeaderMap {
        let mut headers = self.headers();
        if let Ok(v) = HeaderValue::from_str(&format!("Bearer {token}")) {
            headers.insert("Authorization", v);
        }
        headers
    }

    /// Login with email and password. Returns JWT tokens.
    pub async fn login(&self, email: &str, password: &str) -> Result<Value, AibimSdkError> {
        let url = format!("{}/api/v1/auth/login", self.base_url);
        let payload = serde_json::json!({
            "email": email,
            "password": password,
        });

        let resp = self
            .client
            .post(&url)
            .headers(self.headers())
            .json(&payload)
            .send()
            .await?;

        Self::handle_response(resp).await
    }

    /// Register a new user.
    pub async fn register(
        &self,
        email: &str,
        password: &str,
        tenant_name: &str,
    ) -> Result<Value, AibimSdkError> {
        let url = format!("{}/api/v1/auth/register", self.base_url);
        let payload = serde_json::json!({
            "email": email,
            "password": password,
            "tenant_name": tenant_name,
        });

        let resp = self
            .client
            .post(&url)
            .headers(self.headers())
            .json(&payload)
            .send()
            .await?;

        Self::handle_response(resp).await
    }

    /// Refresh JWT token.
    pub async fn refresh(&self, refresh_token: &str) -> Result<Value, AibimSdkError> {
        let url = format!("{}/api/v1/auth/refresh", self.base_url);
        let payload = serde_json::json!({
            "refresh_token": refresh_token,
        });

        let resp = self
            .client
            .post(&url)
            .headers(self.headers())
            .json(&payload)
            .send()
            .await?;

        Self::handle_response(resp).await
    }

    /// Validate current API key or JWT.
    pub async fn validate(&self) -> Result<Value, AibimSdkError> {
        let url = format!("{}/api/v1/auth/validate", self.base_url);
        let resp = self
            .client
            .get(&url)
            .headers(self.headers())
            .send()
            .await?;

        Self::handle_response(resp).await
    }

    /// Get authenticated user info using a bearer token.
    pub async fn me(&self, token: &str) -> Result<Value, AibimSdkError> {
        let url = format!("{}/api/v1/auth/me", self.base_url);
        let resp = self
            .client
            .get(&url)
            .headers(self.bearer_headers(token))
            .send()
            .await?;

        Self::handle_response(resp).await
    }

    /// Handle HTTP response, converting non-success status to errors.
    async fn handle_response(resp: reqwest::Response) -> Result<Value, AibimSdkError> {
        if resp.status().as_u16() == 401 {
            let body = resp.text().await.unwrap_or_default();
            return Err(AibimSdkError::Auth(body));
        }

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
    fn test_auth_client_creation() {
        let client = AuthClient::new("https://api.aibim.ai", Some("my-key"));
        assert_eq!(client.base_url, "https://api.aibim.ai");
        assert_eq!(client.api_key.as_deref(), Some("my-key"));
    }

    #[test]
    fn test_auth_client_no_key() {
        let client = AuthClient::new("https://api.aibim.ai", None);
        assert!(client.api_key.is_none());
    }

    #[test]
    fn test_auth_client_trailing_slash() {
        let client = AuthClient::new("https://api.aibim.ai/", None);
        assert_eq!(client.base_url, "https://api.aibim.ai");
    }

    #[test]
    fn test_headers_with_api_key() {
        let client = AuthClient::new("https://api.aibim.ai", Some("test-key"));
        let headers = client.headers();
        assert_eq!(
            headers.get("X-API-Key").unwrap().to_str().unwrap(),
            "test-key"
        );
    }

    #[test]
    fn test_headers_without_api_key() {
        let client = AuthClient::new("https://api.aibim.ai", None);
        let headers = client.headers();
        assert!(headers.get("X-API-Key").is_none());
    }

    #[test]
    fn test_bearer_headers() {
        let client = AuthClient::new("https://api.aibim.ai", None);
        let headers = client.bearer_headers("my-jwt-token");
        assert!(headers
            .get("Authorization")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("my-jwt-token"));
    }
}
