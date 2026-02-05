//! ZAP Rust Client Example
//!
//! This example demonstrates connecting to a ZAP gateway and using
//! the MCP operations: tools, resources, and prompts.
//!
//! Run with: cargo run --example chat_client

use zap::{Client, Result};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("ZAP Chat Client Example");
    println!("=======================\n");

    // Connect to the ZAP gateway
    let client = Client::connect("zap://localhost:9999").await?;
    println!("Connected to ZAP gateway\n");

    // Initialize the connection
    let server_info = client.init().await?;
    println!("Server: {} v{}", server_info.name, server_info.version);
    println!("Protocol: {}\n", server_info.protocol_version);

    // List available tools
    println!("Available Tools:");
    println!("----------------");
    let tools = client.list_tools().await?;
    for tool in &tools {
        println!("  {} - {}", tool.name, tool.description);
    }
    println!();

    // Call a tool
    println!("Calling 'search' tool...");
    let result = client.call_tool("search", json!({
        "query": "rust programming",
        "limit": 5
    })).await?;

    if result.is_error {
        println!("Tool error: {}", result.error.unwrap_or_default());
    } else {
        println!("Search results:");
        for content in &result.content {
            println!("  - {}", content.text);
        }
    }
    println!();

    // List resources
    println!("Available Resources:");
    println!("--------------------");
    let resources = client.list_resources().await?;
    for resource in &resources {
        println!("  {} - {}", resource.uri, resource.name);
    }
    println!();

    // Read a resource
    println!("Reading config resource...");
    let content = client.read_resource("file:///etc/zap/config.json").await?;
    println!("Config: {}\n", content.text);

    // List prompts
    println!("Available Prompts:");
    println!("------------------");
    let prompts = client.list_prompts().await?;
    for prompt in &prompts {
        println!("  {} - {}", prompt.name, prompt.description.as_deref().unwrap_or(""));
    }
    println!();

    // Get a prompt
    println!("Getting 'code-review' prompt...");
    let messages = client.get_prompt("code-review", json!({
        "language": "rust",
        "file": "src/main.rs"
    })).await?;

    println!("Prompt messages:");
    for msg in &messages {
        println!("  [{}] {}", msg.role, &msg.content[..50.min(msg.content.len())]);
    }

    println!("\nDone!");
    Ok(())
}

/// Example: Using post-quantum cryptography
#[allow(dead_code)]
fn pq_crypto_example() -> Result<()> {
    use zap::crypto::{MLKem, MLDsa};

    // ML-KEM key encapsulation
    let (pk, sk) = MLKem::generate_keypair()?;
    let (ciphertext, shared_secret) = MLKem::encapsulate(&pk)?;
    let decrypted = MLKem::decapsulate(&ciphertext, &sk)?;
    assert_eq!(shared_secret, decrypted);

    // ML-DSA digital signatures
    let (pk, sk) = MLDsa::generate_keypair()?;
    let message = b"Hello, ZAP!";
    let signature = MLDsa::sign(message, &sk)?;
    assert!(MLDsa::verify(message, &signature, &pk)?);

    println!("Post-quantum crypto working!");
    Ok(())
}

/// Example: Using decentralized identity
#[allow(dead_code)]
fn identity_example() -> Result<()> {
    use zap::identity::NodeIdentity;

    // Generate a new identity
    let identity = NodeIdentity::generate()?;
    println!("Generated DID: {}", identity.did());

    // Sign a message
    let message = b"Hello from ZAP!";
    let signature = identity.sign(message)?;

    // Verify the signature
    assert!(identity.verify(message, &signature)?);

    println!("Identity and signatures working!");
    Ok(())
}

/// Example: Agent consensus
#[allow(dead_code)]
async fn consensus_example() -> Result<()> {
    use zap::consensus::AgentConsensus;

    // Create consensus with 67% threshold
    let mut consensus = AgentConsensus::new(0.67);

    // Simulate agent responses
    let agents = vec![
        ("did:key:agent1", "The answer is 42"),
        ("did:key:agent2", "The answer is 42"),
        ("did:key:agent3", "The answer is 41"),
    ];

    for (did, response) in agents {
        consensus.submit_response(did, response).await?;
    }

    // Check for consensus
    let result = consensus.finalize().await?;
    if result.reached {
        println!("Consensus reached: {}", result.response);
    } else {
        println!("No consensus reached");
    }

    Ok(())
}
