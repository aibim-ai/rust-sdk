# AIBIM Rust SDK

Route LLM traffic through the AIBIM AI security proxy for prompt injection detection, behavioral monitoring, and governance.

## Installation

```sh
cargo add aibim-sdk
```

## Quick Start

```rust
use aibim_sdk::AibimProxy;

#[tokio::main]
async fn main() -> Result<(), aibim_sdk::AibimSdkError> {
    let proxy = AibimProxy::new(
        "https://your-aibim.example.com",
        "aibim-your-api-key",
        "sk-your-openai-key",
    );

    let (response, meta) = proxy.chat_completion(serde_json::json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Hello!"}]
    })).await?;

    println!("Decision: {}, Score: {}", meta.decision, meta.score);
    Ok(())
}
```

## Guard API

Use `AibimGuard` for direct prompt analysis:

```rust
use aibim_sdk::AibimGuard;

let guard = AibimGuard::new("http://localhost:8080", "my-api-key");
let result = guard.analyze("Check this prompt", "gpt-4").await.unwrap();
if result.is_threat {
    println!("Blocked: score={}", result.risk_score);
}
```

## Clients

| Client | Purpose |
|--------|---------|
| `AibimProxy` | Route LLM requests through the security proxy |
| `AibimGuard` | Direct prompt analysis |
| `AuthClient` | Authentication (JWT + API key) |
| `RulesClient` | Manage detection rules |
| `TenantClient` | Tenant configuration and API keys |
| `DataClient` | Query detection events and analytics |
| `AlertsClient` | Security alerts and alert rules |

## License

MIT
