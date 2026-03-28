//! Example: Use AuthClient, TenantClient, and RulesClient for AIBIM management.

use aibim_sdk::{AuthClient, RulesClient, TenantClient};

#[tokio::main]
async fn main() {
    let base_url = std::env::var("AIBIM_URL")
        .unwrap_or_else(|_| "https://proxy.aibim.ai".to_string());
    let api_key = std::env::var("AIBIM_API_KEY").unwrap_or_default();

    // --- Authentication ---
    let auth = AuthClient::new(&base_url, Some(&api_key));

    println!("Validating API key...");
    match auth.validate().await {
        Ok(result) => println!("  Validated: {}\n", result),
        Err(e) => eprintln!("  Validation error: {e}\n"),
    }

    // --- Tenant Management ---
    let tenant = TenantClient::new(&base_url, Some(&api_key));

    println!("Getting tenant info...");
    match tenant.me().await {
        Ok(info) => println!("  Tenant: {}\n", info),
        Err(e) => eprintln!("  Error: {e}\n"),
    }

    println!("Getting tenant config...");
    match tenant.get_config().await {
        Ok(config) => println!("  Config: {}\n", config),
        Err(e) => eprintln!("  Error: {e}\n"),
    }

    println!("Getting detection mode...");
    match tenant.get_detection_mode().await {
        Ok(mode) => println!("  Mode: {}\n", mode),
        Err(e) => eprintln!("  Error: {e}\n"),
    }

    println!("Listing API keys...");
    match tenant.list_api_keys().await {
        Ok(keys) => {
            println!("  Found {} API keys", keys.len());
            for key in &keys {
                println!("    - {}", key);
            }
        }
        Err(e) => eprintln!("  Error: {e}"),
    }

    println!("\nGetting usage stats...");
    match tenant.get_usage().await {
        Ok(usage) => println!("  Usage: {}\n", usage),
        Err(e) => eprintln!("  Error: {e}\n"),
    }

    // --- Detection Rules ---
    let rules = RulesClient::new(&base_url, Some(&api_key));

    println!("Listing detection rules...");
    match rules.list().await {
        Ok(rule_list) => {
            println!("  Found {} rules", rule_list.len());
            for r in rule_list.iter().take(5) {
                println!("    - {}", r);
            }
        }
        Err(e) => eprintln!("  Error: {e}"),
    }

    // Create a custom rule.
    println!("\nCreating custom rule...");
    let new_rule = serde_json::json!({
        "name": "block-system-prompt-leak",
        "pattern": "(?i)(system prompt|reveal.*instructions)",
        "severity": 0.9,
        "action": "block",
        "category": "prompt_injection"
    });
    match rules.create(new_rule).await {
        Ok(created) => println!("  Created: {}", created),
        Err(e) => eprintln!("  Error (may already exist): {e}"),
    }
}
