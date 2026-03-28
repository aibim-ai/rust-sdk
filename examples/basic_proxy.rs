//! Example: Send a chat completion through the AIBIM security proxy.

use aibim_sdk::AibimProxy;

#[tokio::main]
async fn main() {
    let aibim_url = std::env::var("AIBIM_URL")
        .unwrap_or_else(|_| "https://proxy.aibim.ai".to_string());
    let aibim_key = std::env::var("AIBIM_API_KEY").unwrap_or_default();
    let provider_key = std::env::var("OPENAI_API_KEY").unwrap_or_default();

    let proxy = AibimProxy::new(&aibim_url, &aibim_key, &provider_key);

    let body = serde_json::json!({
        "model": "gpt-4o",
        "messages": [
            {"role": "user", "content": "What is prompt injection and how does AIBIM protect against it?"}
        ]
    });

    match proxy.chat_completion(body).await {
        Ok((response, meta)) => {
            println!("Decision: {}", meta.decision);
            println!("Score:    {}", meta.score);
            if let Some(cache) = &meta.cache {
                println!("Cache:    {}", cache);
            }
            if let Some(corr_id) = &meta.correlation_id {
                println!("Correlation ID: {}", corr_id);
            }
            println!("\nResponse: {}", serde_json::to_string_pretty(&response).unwrap());
        }
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }
}
