use serde::{Deserialize, Serialize};

/// AIBIM proxy decision on a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AibimDecision {
    Allow,
    Warn,
    Block,
}

impl std::fmt::Display for AibimDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Warn => write!(f, "warn"),
            Self::Block => write!(f, "block"),
        }
    }
}

/// Parsed AIBIM response metadata from x-aibim-* headers.
#[derive(Debug, Clone)]
pub struct AibimResponseMeta {
    pub decision: AibimDecision,
    pub score: f64,
    pub cache: Option<String>,
    pub cache_tier: Option<String>,
    pub correlation_id: Option<String>,
}

impl AibimResponseMeta {
    /// Parse from reqwest response headers.
    pub fn from_headers(headers: &reqwest::header::HeaderMap) -> Self {
        let decision = headers
            .get("x-aibim-decision")
            .and_then(|v| v.to_str().ok())
            .map(|s| match s {
                "block" => AibimDecision::Block,
                "warn" => AibimDecision::Warn,
                _ => AibimDecision::Allow,
            })
            .unwrap_or(AibimDecision::Allow);

        let score = headers
            .get("x-aibim-score")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0.0);

        let cache = headers
            .get("x-aibim-cache")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let cache_tier = headers
            .get("x-aibim-cache-tier")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let correlation_id = headers
            .get("x-correlation-id")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        Self {
            decision,
            score,
            cache,
            cache_tier,
            correlation_id,
        }
    }
}

/// AIBIM SDK error types.
#[derive(Debug, thiserror::Error)]
pub enum AibimSdkError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("API error {status}: {body}")]
    Api { status: u16, body: String },

    #[error("Blocked: score={score}, rules={rules:?}")]
    Blocked {
        score: f64,
        decision: AibimDecision,
        rules: Vec<String>,
        correlation_id: Option<String>,
    },

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Rate limited, retry after {retry_after:?}s")]
    RateLimit { retry_after: Option<f64> },

    #[error("Parse error: {0}")]
    Parse(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decision_display() {
        assert_eq!(AibimDecision::Allow.to_string(), "allow");
        assert_eq!(AibimDecision::Warn.to_string(), "warn");
        assert_eq!(AibimDecision::Block.to_string(), "block");
    }

    #[test]
    fn test_decision_serialization() {
        let json = serde_json::to_string(&AibimDecision::Block).unwrap();
        assert_eq!(json, "\"block\"");

        let parsed: AibimDecision = serde_json::from_str("\"warn\"").unwrap();
        assert_eq!(parsed, AibimDecision::Warn);
    }

    #[test]
    fn test_decision_roundtrip() {
        for decision in [AibimDecision::Allow, AibimDecision::Warn, AibimDecision::Block] {
            let json = serde_json::to_string(&decision).unwrap();
            let back: AibimDecision = serde_json::from_str(&json).unwrap();
            assert_eq!(decision, back);
        }
    }

    #[test]
    fn test_response_meta_from_empty_headers() {
        let headers = reqwest::header::HeaderMap::new();
        let meta = AibimResponseMeta::from_headers(&headers);
        assert_eq!(meta.decision, AibimDecision::Allow);
        assert!((meta.score - 0.0).abs() < f64::EPSILON);
        assert!(meta.cache.is_none());
        assert!(meta.cache_tier.is_none());
        assert!(meta.correlation_id.is_none());
    }

    #[test]
    fn test_response_meta_from_populated_headers() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-aibim-decision", "block".parse().unwrap());
        headers.insert("x-aibim-score", "0.95".parse().unwrap());
        headers.insert("x-aibim-cache", "hit".parse().unwrap());
        headers.insert("x-aibim-cache-tier", "semantic".parse().unwrap());
        headers.insert("x-correlation-id", "abc-123".parse().unwrap());

        let meta = AibimResponseMeta::from_headers(&headers);
        assert_eq!(meta.decision, AibimDecision::Block);
        assert!((meta.score - 0.95).abs() < f64::EPSILON);
        assert_eq!(meta.cache.as_deref(), Some("hit"));
        assert_eq!(meta.cache_tier.as_deref(), Some("semantic"));
        assert_eq!(meta.correlation_id.as_deref(), Some("abc-123"));
    }

    #[test]
    fn test_sdk_error_display() {
        let err = AibimSdkError::Api {
            status: 500,
            body: "internal".into(),
        };
        assert_eq!(err.to_string(), "API error 500: internal");

        let err = AibimSdkError::Auth("bad token".into());
        assert_eq!(err.to_string(), "Authentication error: bad token");

        let err = AibimSdkError::RateLimit {
            retry_after: Some(5.0),
        };
        assert!(err.to_string().contains("5.0"));
    }
}
