//! ZAP daemon (gateway)

use clap::Parser;
use zap::{Config, Gateway, Result};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "zapd")]
#[command(about = "ZAP daemon - Gateway for MCP and ZAP servers")]
#[command(version)]
struct Cli {
    /// Config file path
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Listen address
    #[arg(short, long, default_value = "0.0.0.0")]
    listen: String,

    /// Port
    #[arg(short, long, default_value = "9999")]
    port: u16,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(&cli.log_level)
        .init();

    let config = if let Some(path) = &cli.config {
        Config::load(path)?
    } else {
        Config {
            listen: cli.listen,
            port: cli.port,
            log_level: cli.log_level,
            ..Default::default()
        }
    };

    tracing::info!(
        "Starting ZAP gateway v{} on {}:{}",
        zap::VERSION,
        config.listen,
        config.port
    );

    let mut gateway = Gateway::new(config);
    gateway.run().await?;

    Ok(())
}
