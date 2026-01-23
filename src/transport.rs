//! Transport implementations for ZAP

use crate::Result;
use std::pin::Pin;
use std::future::Future;
use url::Url;

/// Transport trait for ZAP connections
pub trait Transport: Send + Sync {
    /// Send a message
    fn send(&mut self, data: &[u8]) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;

    /// Receive a message
    fn recv(&mut self) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + '_>>;

    /// Close the transport
    fn close(&mut self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;
}

/// Stub transport for placeholder implementations
pub struct StubTransport;

impl Transport for StubTransport {
    fn send(&mut self, _data: &[u8]) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async { Err(crate::Error::Transport("not implemented".into())) })
    }

    fn recv(&mut self) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + '_>> {
        Box::pin(async { Err(crate::Error::Transport("not implemented".into())) })
    }

    fn close(&mut self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async { Ok(()) })
    }
}

/// Create a transport from a URL
pub async fn connect(url: &str) -> Result<Box<dyn Transport>> {
    let parsed = Url::parse(url)?;

    match parsed.scheme() {
        "zap" | "zap+tcp" => {
            // TCP transport - placeholder
            Ok(Box::new(StubTransport))
        }
        "zap+unix" | "unix" => {
            // Unix socket transport - placeholder
            Ok(Box::new(StubTransport))
        }
        "stdio" => {
            // Stdio transport for subprocess MCP servers - placeholder
            Ok(Box::new(StubTransport))
        }
        "http" | "https" => {
            // HTTP transport (SSE) - placeholder
            Ok(Box::new(StubTransport))
        }
        "ws" | "wss" => {
            // WebSocket transport - placeholder
            Ok(Box::new(StubTransport))
        }
        _ => Err(crate::Error::Transport(format!(
            "unsupported scheme: {}",
            parsed.scheme()
        ))),
    }
}
