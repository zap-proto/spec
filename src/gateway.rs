//! ZAP gateway for MCP bridging

use crate::{Config, Result, config::ServerConfig};
use std::collections::HashMap;

/// ZAP gateway that bridges MCP servers
pub struct Gateway {
    config: Config,
    servers: HashMap<String, ConnectedServer>,
}

/// Connected server state
struct ConnectedServer {
    id: String,
    config: ServerConfig,
    status: ServerStatus,
}

/// Server connection status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerStatus {
    Connecting,
    Connected,
    Disconnected,
    Error,
}

impl Gateway {
    /// Create a new gateway
    pub fn new(config: Config) -> Self {
        Self {
            config,
            servers: HashMap::new(),
        }
    }

    /// Add an MCP server
    pub async fn add_server(&mut self, name: &str, url: &str, config: ServerConfig) -> Result<String> {
        let id = uuid();
        let server = ConnectedServer {
            id: id.clone(),
            config,
            status: ServerStatus::Connecting,
        };
        self.servers.insert(id.clone(), server);
        // TODO: Connect to MCP server
        Ok(id)
    }

    /// Remove a server
    pub fn remove_server(&mut self, id: &str) -> Result<()> {
        self.servers.remove(id);
        Ok(())
    }

    /// List connected servers
    pub fn list_servers(&self) -> Vec<ServerInfo> {
        self.servers
            .values()
            .map(|s| ServerInfo {
                id: s.id.clone(),
                name: s.config.name.clone(),
                url: s.config.url.clone(),
                status: s.status,
            })
            .collect()
    }

    /// Run the gateway
    pub async fn run(&mut self) -> Result<()> {
        let addr = format!("{}:{}", self.config.listen, self.config.port);
        tracing::info!("ZAP gateway listening on {}", addr);

        // Connect to configured servers
        let servers: Vec<_> = self.config.servers.clone();
        for server_config in servers {
            let name = server_config.name.clone();
            let url = server_config.url.clone();
            let _ = self.add_server(&name, &url, server_config).await;
        }

        // TODO: Start Cap'n Proto RPC server
        tokio::signal::ctrl_c().await?;

        Ok(())
    }
}

/// Server info
#[derive(Debug, Clone)]
pub struct ServerInfo {
    pub id: String,
    pub name: String,
    pub url: String,
    pub status: ServerStatus,
}

fn uuid() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:x}", now)
}
