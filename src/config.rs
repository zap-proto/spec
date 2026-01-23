//! Configuration for ZAP

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// ZAP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Listen address for the gateway
    #[serde(default = "default_listen")]
    pub listen: String,

    /// Port number
    #[serde(default = "default_port")]
    pub port: u16,

    /// Connected servers
    #[serde(default)]
    pub servers: Vec<ServerConfig>,

    /// Logging level
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server name
    pub name: String,

    /// Server URL (stdio://, http://, ws://, zap://, unix://)
    pub url: String,

    /// Transport type
    #[serde(default)]
    pub transport: Transport,

    /// Connection timeout in milliseconds
    #[serde(default = "default_timeout")]
    pub timeout: u32,

    /// Authentication
    #[serde(default)]
    pub auth: Option<Auth>,
}

/// Transport type
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    #[default]
    Stdio,
    Http,
    WebSocket,
    Zap,
    Unix,
}

/// Authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Auth {
    Bearer { token: String },
    Basic { username: String, password: String },
}

fn default_listen() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    9999
}

fn default_timeout() -> u32 {
    30000
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            port: default_port(),
            servers: Vec::new(),
            log_level: default_log_level(),
        }
    }
}

impl Config {
    /// Load config from file
    pub fn load(path: &PathBuf) -> crate::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)
            .map_err(|e| crate::Error::Config(e.to_string()))?;
        Ok(config)
    }

    /// Save config to file
    pub fn save(&self, path: &PathBuf) -> crate::Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| crate::Error::Config(e.to_string()))?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Get default config path
    pub fn default_path() -> PathBuf {
        directories::ProjectDirs::from("ai", "hanzo", "zap")
            .map(|dirs| dirs.config_dir().join("config.toml"))
            .unwrap_or_else(|| PathBuf::from("zap.toml"))
    }
}
