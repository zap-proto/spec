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

pub mod agent_consensus;
pub mod cap;
pub mod client;
pub mod config;
pub mod consensus;
pub mod crypto;
pub mod error;
pub mod gateway;
pub mod identity;
pub mod schema;
pub mod server;
pub mod transport;
pub mod zwing;

pub use agent_consensus::{
    AgentConsensusVoting, ConsensusResult, Query, QueryId, Response, ResponseId,
};
// ZAP capability runtime (delegation tokens). `cap::Result` is intentionally
// NOT re-exported to avoid colliding with `error::Result`; reach it as
// `zap::cap::Result` where needed.
pub use cap::{
    issue as cap_issue, revoke as cap_revoke, verify_revocation as cap_verify_revocation,
    Capability, CapError, CapKind, Caveat, CaveatKind, Ed25519Signer, Issuance, MlDsa65Signer,
    Revocation, Scheme, Signer, Verifier,
};
pub use client::Client;
pub use config::Config;
pub use consensus::{
    AgentConsensus, RingtailConsensus, RingtailSignature, Round1Output, Round2Output,
};
pub use error::{Error, Result};
pub use gateway::Gateway;
pub use identity::{
    Did, DidDocument, DidMethod, NodeIdentity, Service, StakeRegistry, VerificationMethod,
};
pub use schema::{
    capnp_to_zap, compile_to_rust, migrate_capnp_to_zap, transpile, transpile_str, SchemaFormat,
    ZapSchema,
};
pub use server::Server;

/// ZAP protocol version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default port for ZAP connections
pub const DEFAULT_PORT: u16 = 9999;
