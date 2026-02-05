//! ZAP - Zero-Copy App Proto
//!
//! High-performance Cap'n Proto RPC for AI agent communication.
//!
//! # Example
//!
//! ```rust,ignore
//! use zap::{Client, Server};
//! use serde_json::json;
//!
//! #[tokio::main]
//! async fn main() -> zap::Result<()> {
//!     // Connect to ZAP gateway
//!     let client = Client::connect("zap://localhost:9999").await?;
//!
//!     // List available tools
//!     let tools = client.list_tools().await?;
//!
//!     // Call a tool
//!     let result = client.call_tool("search", json!({"query": "hello"})).await?;
//!
//!     Ok(())
//! }
//! ```

// Generated Cap'n Proto bindings - must be at crate root for correct module path
#[allow(dead_code, clippy::all)]
pub mod zap_capnp {
    include!(concat!(env!("OUT_DIR"), "/zap_capnp.rs"));
}

pub mod client;
pub mod server;
pub mod gateway;
pub mod transport;
pub mod error;
pub mod config;
pub mod crypto;
pub mod consensus;
pub mod identity;
pub mod agent_consensus;
pub mod schema;

pub use client::Client;
pub use server::Server;
pub use gateway::Gateway;
pub use error::{Error, Result};
pub use config::Config;
pub use consensus::{RingtailConsensus, AgentConsensus, RingtailSignature, Round1Output, Round2Output};
pub use identity::{Did, DidMethod, DidDocument, VerificationMethod, Service, NodeIdentity, StakeRegistry};
pub use agent_consensus::{AgentConsensusVoting, Query, Response, ConsensusResult, QueryId, ResponseId};
pub use schema::{ZapSchema, SchemaFormat, transpile, transpile_str, compile_to_rust, capnp_to_zap, migrate_capnp_to_zap};

/// ZAP protocol version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default port for ZAP connections
pub const DEFAULT_PORT: u16 = 9999;
