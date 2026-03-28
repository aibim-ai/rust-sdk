//! AIBIM SDK — Route LLM traffic through the AIBIM AI security proxy.
//!
//! # Quick Start
//!
//! ```no_run
//! use aibim_sdk::AibimProxy;
//!
//! # async fn example() -> Result<(), aibim_sdk::AibimSdkError> {
//! let proxy = AibimProxy::new(
//!     "https://your-aibim.example.com",
//!     "aibim-your-api-key",
//!     "sk-your-openai-key",
//! );
//!
//! let (response, meta) = proxy.chat_completion(serde_json::json!({
//!     "model": "gpt-4o",
//!     "messages": [{"role": "user", "content": "Hello!"}]
//! })).await?;
//!
//! println!("Decision: {}, Score: {}", meta.decision, meta.score);
//! # Ok(())
//! # }
//! ```

mod types;
mod retry;
mod proxy;
mod guard;
mod auth;
mod rules;
mod tenant;
mod data;
mod alerts;

pub use types::{AibimDecision, AibimResponseMeta, AibimSdkError};
pub use proxy::AibimProxy;
pub use guard::{AibimGuard, DetectionResult, SdkConfig, DEFAULT_PROXY_URL};
pub use auth::AuthClient;
pub use rules::RulesClient;
pub use tenant::TenantClient;
pub use data::DataClient;
pub use alerts::AlertsClient;
pub use retry::RetryPolicy;
