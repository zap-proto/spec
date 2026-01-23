//! ZAP server implementation

use crate::{Config, Result};

/// ZAP server
pub struct Server {
    config: Config,
}

impl Server {
    /// Create a new server with the given config
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// Run the server
    pub async fn run(&self) -> Result<()> {
        let addr = format!("{}:{}", self.config.listen, self.config.port);
        tracing::info!("ZAP server listening on {}", addr);

        // TODO: Start Cap'n Proto RPC server
        tokio::signal::ctrl_c().await?;

        Ok(())
    }
}
