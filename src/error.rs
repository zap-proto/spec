//! Error types for ZAP

use thiserror::Error;

/// ZAP error type
#[derive(Error, Debug)]
pub enum Error {
    #[error("connection failed: {0}")]
    Connection(String),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("tool not found: {0}")]
    ToolNotFound(String),

    #[error("tool call failed: {0}")]
    ToolCallFailed(String),

    #[error("resource not found: {0}")]
    ResourceNotFound(String),

    #[error("server error: {0}")]
    Server(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("identity error: {0}")]
    Identity(String),

    #[error("consensus error: {0}")]
    Consensus(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("capnp error: {0}")]
    Capnp(#[from] capnp::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("url error: {0}")]
    Url(#[from] url::ParseError),
}

/// Result type for ZAP operations
pub type Result<T> = std::result::Result<T, Error>;
