//! ZAP CLI tool

use clap::{Parser, Subcommand};
use zap::{Client, Config, Result};

#[derive(Parser)]
#[command(name = "zap")]
#[command(about = "ZAP - Zero-copy Agent Protocol CLI")]
#[command(version)]
struct Cli {
    /// Config file path
    #[arg(short, long, global = true)]
    config: Option<std::path::PathBuf>,

    /// Gateway URL
    #[arg(short = 'u', long, global = true, default_value = "zap://localhost:9999")]
    url: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List available tools
    Tools,

    /// Call a tool
    Call {
        /// Tool name
        name: String,
        /// JSON arguments
        #[arg(default_value = "{}")]
        args: String,
    },

    /// List available resources
    Resources,

    /// Read a resource
    Read {
        /// Resource URI
        uri: String,
    },

    /// List available prompts
    Prompts,

    /// Get a prompt
    Prompt {
        /// Prompt name
        name: String,
        /// JSON arguments
        #[arg(default_value = "{}")]
        args: String,
    },

    /// Show gateway status
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    let client = Client::connect(&cli.url).await?;

    match cli.command {
        Commands::Tools => {
            let tools = client.list_tools().await?;
            for tool in tools {
                println!("{}: {}", tool.name, tool.description);
            }
        }
        Commands::Call { name, args } => {
            let args: serde_json::Value = serde_json::from_str(&args)?;
            let result = client.call_tool(&name, args).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Commands::Resources => {
            let resources = client.list_resources().await?;
            for resource in resources {
                println!("{}: {}", resource.uri, resource.name);
            }
        }
        Commands::Read { uri } => {
            let content = client.read_resource(&uri).await?;
            match content.content {
                zap::client::Content::Text(text) => println!("{}", text),
                zap::client::Content::Blob(blob) => {
                    use std::io::Write;
                    std::io::stdout().write_all(&blob)?;
                }
            }
        }
        Commands::Prompts => {
            println!("Prompts listing not yet implemented");
        }
        Commands::Prompt { name, args } => {
            println!("Prompt {} with args {}", name, args);
        }
        Commands::Status => {
            println!("Connected to {}", cli.url);
        }
    }

    Ok(())
}
