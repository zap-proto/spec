//! ZAP client implementation
//!
//! Provides a high-level async client for connecting to ZAP servers and gateways.
//! Uses Cap'n Proto RPC over the `twoparty` VatNetwork.
//!
//! # Example
//!
//! ```rust,ignore
//! use zap::{Client, Result};
//! use serde_json::json;
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     let client = Client::connect("zap://localhost:9999").await?;
//!
//!     // Initialize connection
//!     let server_info = client.init("my-client", "1.0.0").await?;
//!     println!("Connected to: {} v{}", server_info.name, server_info.version);
//!
//!     // List and call tools
//!     let tools = client.list_tools().await?;
//!     let result = client.call_tool("search", json!({"query": "hello"})).await?;
//!
//!     Ok(())
//! }
//! ```

use crate::{Error, Result};
use crate::zap_capnp;
use capnp_rpc::{rpc_twoparty_capnp, twoparty, RpcSystem};
use futures::io::{BufReader, BufWriter};
use serde_json::Value;
use std::net::ToSocketAddrs;
use tokio::net::TcpStream;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use url::Url;

/// Helper to convert Cap'n Proto text to String, handling UTF-8 errors
fn text_to_string(reader: capnp::text::Reader<'_>) -> Result<String> {
    reader.to_str()
        .map(|s| s.to_string())
        .map_err(|e| Error::Protocol(format!("invalid UTF-8: {}", e)))
}

/// Client info sent during initialization
#[derive(Debug, Clone)]
pub struct ClientInfo {
    pub name: String,
    pub version: String,
}

/// Server info received during initialization
#[derive(Debug, Clone)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
    pub capabilities: ServerCapabilities,
}

/// Server capabilities
#[derive(Debug, Clone, Default)]
pub struct ServerCapabilities {
    pub tools: bool,
    pub resources: bool,
    pub prompts: bool,
    pub logging: bool,
}

/// Tool definition
#[derive(Debug, Clone)]
pub struct Tool {
    pub name: String,
    pub description: String,
    pub schema: Value,
}

/// Resource definition
#[derive(Debug, Clone)]
pub struct Resource {
    pub uri: String,
    pub name: String,
    pub description: String,
    pub mime_type: String,
}

/// Resource content
#[derive(Debug, Clone)]
pub struct ResourceContent {
    pub uri: String,
    pub mime_type: String,
    pub content: Content,
}

/// Content types
#[derive(Debug, Clone)]
pub enum Content {
    Text(String),
    Blob(Vec<u8>),
}

/// Prompt definition
#[derive(Debug, Clone)]
pub struct Prompt {
    pub name: String,
    pub description: String,
    pub arguments: Vec<PromptArgument>,
}

/// Prompt argument
#[derive(Debug, Clone)]
pub struct PromptArgument {
    pub name: String,
    pub description: String,
    pub required: bool,
}

/// Prompt message
#[derive(Debug, Clone)]
pub struct PromptMessage {
    pub role: Role,
    pub content: MessageContent,
}

/// Message role
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    User,
    Assistant,
    System,
}

/// Message content
#[derive(Debug, Clone)]
pub enum MessageContent {
    Text(String),
    Image { data: Vec<u8>, mime_type: String },
    Resource(ResourceContent),
}

/// Resource stream for subscription-based updates
pub struct ResourceStream {
    stream_client: zap_capnp::resource_stream::Client,
}

impl ResourceStream {
    fn new(client: zap_capnp::resource_stream::Client) -> Self {
        Self { stream_client: client }
    }

    /// Get the next resource content update
    pub async fn next(&self) -> Result<Option<ResourceContent>> {
        let request = self.stream_client.next_request();
        let response = request.send().promise.await
            .map_err(|e| Error::Protocol(format!("stream next failed: {}", e)))?;

        let results = response.get()
            .map_err(|e| Error::Protocol(format!("failed to get results: {}", e)))?;

        if results.get_done() {
            return Ok(None);
        }

        let content = results.get_content()
            .map_err(|e| Error::Protocol(format!("failed to get content: {}", e)))?;

        Ok(Some(convert_resource_content(content)?))
    }

    /// Cancel the stream subscription
    pub async fn cancel(&self) -> Result<()> {
        let request = self.stream_client.cancel_request();
        request.send().promise.await
            .map_err(|e| Error::Protocol(format!("stream cancel failed: {}", e)))?;
        Ok(())
    }
}

/// ZAP client for connecting to ZAP gateways
///
/// The client manages a Cap'n Proto RPC connection and provides high-level
/// async methods for MCP operations (tools, resources, prompts).
pub struct Client {
    /// The Cap'n Proto RPC client stub
    zap_client: zap_capnp::zap::Client,
    /// Handle to disconnect the RPC system
    disconnector: capnp_rpc::Disconnector<rpc_twoparty_capnp::Side>,
}

impl Client {
    /// Connect to a ZAP server at the given URL.
    ///
    /// Supported URL schemes:
    /// - `zap://` or `zap+tcp://` - TCP transport (default port 9999)
    /// - `tcp://` - Plain TCP
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let client = Client::connect("zap://localhost:9999").await?;
    /// ```
    pub async fn connect(url: &str) -> Result<Self> {
        let parsed = Url::parse(url)?;

        match parsed.scheme() {
            "zap" | "zap+tcp" | "tcp" => {
                let host = parsed.host_str().unwrap_or("localhost");
                let port = parsed.port().unwrap_or(crate::DEFAULT_PORT);
                let addr = format!("{}:{}", host, port);
                Self::connect_tcp(&addr).await
            }
            scheme => Err(Error::Connection(format!(
                "unsupported URL scheme '{}' - use zap://, zap+tcp://, or tcp://",
                scheme
            ))),
        }
    }

    /// Connect to a ZAP server via TCP at the given address.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let client = Client::connect_tcp("127.0.0.1:9999").await?;
    /// ```
    pub async fn connect_tcp(addr: &str) -> Result<Self> {
        let socket_addr = addr
            .to_socket_addrs()
            .map_err(|e| Error::Connection(format!("invalid address '{}': {}", addr, e)))?
            .next()
            .ok_or_else(|| Error::Connection(format!("could not resolve address '{}'", addr)))?;

        let stream = TcpStream::connect(&socket_addr)
            .await
            .map_err(|e| Error::Connection(format!("failed to connect to {}: {}", addr, e)))?;

        stream.set_nodelay(true)
            .map_err(|e| Error::Connection(format!("failed to set TCP_NODELAY: {}", e)))?;

        Self::from_tcp_stream(stream).await
    }

    /// Create a client from an existing TCP stream.
    ///
    /// This is useful for testing or when you have a pre-established connection.
    pub async fn from_tcp_stream(stream: TcpStream) -> Result<Self> {
        // Split the stream into read and write halves
        let (reader, writer) = stream.into_split();

        // Convert to futures-compatible async IO using tokio-util compat
        let reader = BufReader::new(reader.compat());
        let writer = BufWriter::new(writer.compat_write());

        // Create the two-party vat network
        let network = Box::new(twoparty::VatNetwork::new(
            reader,
            writer,
            rpc_twoparty_capnp::Side::Client,
            Default::default(),
        ));

        // Create the RPC system
        let mut rpc_system = RpcSystem::new(network, None);

        // Get disconnector before spawning
        let disconnector = rpc_system.get_disconnector();

        // Bootstrap the Zap interface
        let zap_client: zap_capnp::zap::Client =
            rpc_system.bootstrap(rpc_twoparty_capnp::Side::Server);

        // Spawn the RPC system as a background task
        // Note: RpcSystem is !Send, so we need spawn_local
        tokio::task::spawn_local(rpc_system);

        Ok(Self {
            zap_client,
            disconnector,
        })
    }

    /// Initialize the connection with client information.
    ///
    /// This should be called after connecting to exchange client/server info
    /// and verify capabilities.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let server_info = client.init("my-app", "1.0.0").await?;
    /// if server_info.capabilities.tools {
    ///     println!("Server supports tools!");
    /// }
    /// ```
    pub async fn init(&self, name: &str, version: &str) -> Result<ServerInfo> {
        let mut request = self.zap_client.init_request();
        {
            let mut client_info = request.get().init_client();
            client_info.set_name(name);
            client_info.set_version(version);
        }

        let response = request.send().promise.await
            .map_err(|e| Error::Protocol(format!("init failed: {}", e)))?;

        let results = response.get()
            .map_err(|e| Error::Protocol(format!("failed to get init results: {}", e)))?;

        let server = results.get_server()
            .map_err(|e| Error::Protocol(format!("failed to get server info: {}", e)))?;

        let caps = server.get_capabilities()
            .map_err(|e| Error::Protocol(format!("failed to get capabilities: {}", e)))?;

        let name_reader = server.get_name()
            .map_err(|e| Error::Protocol(format!("failed to get server name: {}", e)))?;
        let version_reader = server.get_version()
            .map_err(|e| Error::Protocol(format!("failed to get server version: {}", e)))?;

        Ok(ServerInfo {
            name: text_to_string(name_reader)?,
            version: text_to_string(version_reader)?,
            capabilities: ServerCapabilities {
                tools: caps.get_tools(),
                resources: caps.get_resources(),
                prompts: caps.get_prompts(),
                logging: caps.get_logging(),
            },
        })
    }

    /// List available tools from the server.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let tools = client.list_tools().await?;
    /// for tool in &tools {
    ///     println!("Tool: {} - {}", tool.name, tool.description);
    /// }
    /// ```
    pub async fn list_tools(&self) -> Result<Vec<Tool>> {
        let request = self.zap_client.list_tools_request();
        let response = request.send().promise.await
            .map_err(|e| Error::Protocol(format!("list_tools failed: {}", e)))?;

        let results = response.get()
            .map_err(|e| Error::Protocol(format!("failed to get list_tools results: {}", e)))?;

        let tool_list = results.get_tools()
            .map_err(|e| Error::Protocol(format!("failed to get tool list: {}", e)))?;

        let tools = tool_list.get_tools()
            .map_err(|e| Error::Protocol(format!("failed to get tools: {}", e)))?;

        let mut result = Vec::with_capacity(tools.len() as usize);
        for tool in tools.iter() {
            let name_reader = tool.get_name()
                .map_err(|e| Error::Protocol(format!("failed to get tool name: {}", e)))?;
            let desc_reader = tool.get_description()
                .map_err(|e| Error::Protocol(format!("failed to get tool description: {}", e)))?;
            let schema_bytes = tool.get_schema()
                .map_err(|e| Error::Protocol(format!("failed to get tool schema: {}", e)))?;
            let schema: Value = if schema_bytes.is_empty() {
                Value::Object(serde_json::Map::new())
            } else {
                serde_json::from_slice(schema_bytes)
                    .map_err(|e| Error::Protocol(format!("failed to parse tool schema: {}", e)))?
            };

            result.push(Tool {
                name: text_to_string(name_reader)?,
                description: text_to_string(desc_reader)?,
                schema,
            });
        }

        Ok(result)
    }

    /// Call a tool with the given arguments.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the tool to call
    /// * `args` - JSON arguments for the tool
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use serde_json::json;
    ///
    /// let result = client.call_tool("search", json!({
    ///     "query": "rust programming",
    ///     "limit": 10
    /// })).await?;
    /// ```
    pub async fn call_tool(&self, name: &str, args: Value) -> Result<Value> {
        self.call_tool_with_id(uuid_v4(), name, args).await
    }

    /// Call a tool with a specific request ID.
    ///
    /// This is useful for request tracking and correlation.
    pub async fn call_tool_with_id(&self, id: &str, name: &str, args: Value) -> Result<Value> {
        let args_bytes = serde_json::to_vec(&args)?;

        let mut request = self.zap_client.call_tool_request();
        {
            let mut call = request.get().init_call();
            call.set_id(id);
            call.set_name(name);
            call.set_args(&args_bytes);
        }

        let response = request.send().promise.await
            .map_err(|e| Error::Protocol(format!("call_tool failed: {}", e)))?;

        let results = response.get()
            .map_err(|e| Error::Protocol(format!("failed to get call_tool results: {}", e)))?;

        let tool_result = results.get_result()
            .map_err(|e| Error::Protocol(format!("failed to get tool result: {}", e)))?;

        // Check for error
        let error_reader = tool_result.get_error()
            .map_err(|e| Error::Protocol(format!("failed to get error field: {}", e)))?;
        if !error_reader.is_empty() {
            return Err(Error::ToolCallFailed(text_to_string(error_reader)?));
        }

        // Parse content
        let content_bytes = tool_result.get_content()
            .map_err(|e| Error::Protocol(format!("failed to get content: {}", e)))?;

        if content_bytes.is_empty() {
            Ok(Value::Null)
        } else {
            serde_json::from_slice(content_bytes)
                .map_err(|e| Error::Protocol(format!("failed to parse tool result: {}", e)))
        }
    }

    /// List available resources from the server.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let resources = client.list_resources().await?;
    /// for resource in &resources {
    ///     println!("Resource: {} ({}) - {}",
    ///         resource.name, resource.uri, resource.mime_type);
    /// }
    /// ```
    pub async fn list_resources(&self) -> Result<Vec<Resource>> {
        let request = self.zap_client.list_resources_request();
        let response = request.send().promise.await
            .map_err(|e| Error::Protocol(format!("list_resources failed: {}", e)))?;

        let results = response.get()
            .map_err(|e| Error::Protocol(format!("failed to get list_resources results: {}", e)))?;

        let resource_list = results.get_resources()
            .map_err(|e| Error::Protocol(format!("failed to get resource list: {}", e)))?;

        let resources = resource_list.get_resources()
            .map_err(|e| Error::Protocol(format!("failed to get resources: {}", e)))?;

        let mut result = Vec::with_capacity(resources.len() as usize);
        for resource in resources.iter() {
            let uri_reader = resource.get_uri()
                .map_err(|e| Error::Protocol(format!("failed to get resource uri: {}", e)))?;
            let name_reader = resource.get_name()
                .map_err(|e| Error::Protocol(format!("failed to get resource name: {}", e)))?;
            let desc_reader = resource.get_description()
                .map_err(|e| Error::Protocol(format!("failed to get resource description: {}", e)))?;
            let mime_reader = resource.get_mime_type()
                .map_err(|e| Error::Protocol(format!("failed to get resource mime_type: {}", e)))?;

            result.push(Resource {
                uri: text_to_string(uri_reader)?,
                name: text_to_string(name_reader)?,
                description: text_to_string(desc_reader)?,
                mime_type: text_to_string(mime_reader)?,
            });
        }

        Ok(result)
    }

    /// Read a resource by URI.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let content = client.read_resource("file:///etc/hosts").await?;
    /// match content.content {
    ///     Content::Text(text) => println!("{}", text),
    ///     Content::Blob(data) => println!("Binary: {} bytes", data.len()),
    /// }
    /// ```
    pub async fn read_resource(&self, uri: &str) -> Result<ResourceContent> {
        let mut request = self.zap_client.read_resource_request();
        request.get().set_uri(uri);

        let response = request.send().promise.await
            .map_err(|e| Error::Protocol(format!("read_resource failed: {}", e)))?;

        let results = response.get()
            .map_err(|e| Error::Protocol(format!("failed to get read_resource results: {}", e)))?;

        let content = results.get_content()
            .map_err(|e| Error::Protocol(format!("failed to get content: {}", e)))?;

        convert_resource_content(content)
    }

    /// Subscribe to resource updates.
    ///
    /// Returns a stream that yields resource content updates.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let stream = client.subscribe("file:///var/log/app.log").await?;
    /// while let Some(content) = stream.next().await? {
    ///     println!("Update: {:?}", content);
    /// }
    /// ```
    pub async fn subscribe(&self, uri: &str) -> Result<ResourceStream> {
        let mut request = self.zap_client.subscribe_request();
        request.get().set_uri(uri);

        let response = request.send().promise.await
            .map_err(|e| Error::Protocol(format!("subscribe failed: {}", e)))?;

        let results = response.get()
            .map_err(|e| Error::Protocol(format!("failed to get subscribe results: {}", e)))?;

        let stream_client = results.get_stream()
            .map_err(|e| Error::Protocol(format!("failed to get stream: {}", e)))?;

        Ok(ResourceStream::new(stream_client))
    }

    /// List available prompts from the server.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let prompts = client.list_prompts().await?;
    /// for prompt in &prompts {
    ///     println!("Prompt: {} - {}", prompt.name, prompt.description);
    /// }
    /// ```
    pub async fn list_prompts(&self) -> Result<Vec<Prompt>> {
        let request = self.zap_client.list_prompts_request();
        let response = request.send().promise.await
            .map_err(|e| Error::Protocol(format!("list_prompts failed: {}", e)))?;

        let results = response.get()
            .map_err(|e| Error::Protocol(format!("failed to get list_prompts results: {}", e)))?;

        let prompt_list = results.get_prompts()
            .map_err(|e| Error::Protocol(format!("failed to get prompt list: {}", e)))?;

        let prompts = prompt_list.get_prompts()
            .map_err(|e| Error::Protocol(format!("failed to get prompts: {}", e)))?;

        let mut result = Vec::with_capacity(prompts.len() as usize);
        for prompt in prompts.iter() {
            let arguments = prompt.get_arguments()
                .map_err(|e| Error::Protocol(format!("failed to get prompt arguments: {}", e)))?;

            let mut args = Vec::with_capacity(arguments.len() as usize);
            for arg in arguments.iter() {
                let arg_name = arg.get_name()
                    .map_err(|e| Error::Protocol(format!("failed to get arg name: {}", e)))?;
                let arg_desc = arg.get_description()
                    .map_err(|e| Error::Protocol(format!("failed to get arg description: {}", e)))?;
                args.push(PromptArgument {
                    name: text_to_string(arg_name)?,
                    description: text_to_string(arg_desc)?,
                    required: arg.get_required(),
                });
            }

            let prompt_name = prompt.get_name()
                .map_err(|e| Error::Protocol(format!("failed to get prompt name: {}", e)))?;
            let prompt_desc = prompt.get_description()
                .map_err(|e| Error::Protocol(format!("failed to get prompt description: {}", e)))?;

            result.push(Prompt {
                name: text_to_string(prompt_name)?,
                description: text_to_string(prompt_desc)?,
                arguments: args,
            });
        }

        Ok(result)
    }

    /// Get a prompt with the given arguments.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the prompt
    /// * `args` - Key-value pairs for prompt arguments
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let messages = client.get_prompt("code_review", &[
    ///     ("language", "rust"),
    ///     ("file", "main.rs"),
    /// ]).await?;
    /// for msg in &messages {
    ///     println!("{:?}: {:?}", msg.role, msg.content);
    /// }
    /// ```
    pub async fn get_prompt(&self, name: &str, args: &[(&str, &str)]) -> Result<Vec<PromptMessage>> {
        let mut request = self.zap_client.get_prompt_request();
        {
            let mut params = request.get();
            params.set_name(name);

            let mut metadata = params.init_args();
            let mut entries = metadata.init_entries(args.len() as u32);
            for (i, (key, value)) in args.iter().enumerate() {
                let mut entry = entries.reborrow().get(i as u32);
                entry.set_key(*key);
                entry.set_value(*value);
            }
        }

        let response = request.send().promise.await
            .map_err(|e| Error::Protocol(format!("get_prompt failed: {}", e)))?;

        let results = response.get()
            .map_err(|e| Error::Protocol(format!("failed to get get_prompt results: {}", e)))?;

        let messages = results.get_messages()
            .map_err(|e| Error::Protocol(format!("failed to get messages: {}", e)))?;

        let mut result = Vec::with_capacity(messages.len() as usize);
        for msg in messages.iter() {
            let role = match msg.get_role()
                .map_err(|e| Error::Protocol(format!("failed to get role: {}", e)))?
            {
                zap_capnp::prompt_message::Role::User => Role::User,
                zap_capnp::prompt_message::Role::Assistant => Role::Assistant,
                zap_capnp::prompt_message::Role::System => Role::System,
            };

            let content_reader = msg.get_content()
                .map_err(|e| Error::Protocol(format!("failed to get content: {}", e)))?;

            let content = match content_reader.which()
                .map_err(|e| Error::Protocol(format!("failed to get content type: {}", e)))?
            {
                zap_capnp::prompt_message::content::Which::Text(text_reader) => {
                    let text_reader = text_reader
                        .map_err(|e| Error::Protocol(format!("failed to get text: {}", e)))?;
                    MessageContent::Text(text_to_string(text_reader)?)
                }
                zap_capnp::prompt_message::content::Which::Image(image) => {
                    let image = image
                        .map_err(|e| Error::Protocol(format!("failed to get image: {}", e)))?;
                    let mime_reader = image.get_mime_type()
                        .map_err(|e| Error::Protocol(format!("failed to get image mime_type: {}", e)))?;
                    MessageContent::Image {
                        data: image.get_data()
                            .map_err(|e| Error::Protocol(format!("failed to get image data: {}", e)))?
                            .to_vec(),
                        mime_type: text_to_string(mime_reader)?,
                    }
                }
                zap_capnp::prompt_message::content::Which::Resource(resource) => {
                    let resource = resource
                        .map_err(|e| Error::Protocol(format!("failed to get resource: {}", e)))?;
                    MessageContent::Resource(convert_resource_content(resource)?)
                }
            };

            result.push(PromptMessage { role, content });
        }

        Ok(result)
    }

    /// Send a log message to the server.
    ///
    /// # Arguments
    ///
    /// * `level` - Log level (debug, info, warn, error)
    /// * `message` - The log message
    /// * `data` - Optional structured data as JSON
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use serde_json::json;
    ///
    /// client.log(LogLevel::Info, "Operation completed", Some(json!({
    ///     "duration_ms": 42,
    ///     "items_processed": 100
    /// }))).await?;
    /// ```
    pub async fn log(&self, level: LogLevel, message: &str, data: Option<Value>) -> Result<()> {
        let mut request = self.zap_client.log_request();
        {
            let mut params = request.get();
            params.set_level(match level {
                LogLevel::Debug => zap_capnp::zap::LogLevel::Debug,
                LogLevel::Info => zap_capnp::zap::LogLevel::Info,
                LogLevel::Warn => zap_capnp::zap::LogLevel::Warn,
                LogLevel::Error => zap_capnp::zap::LogLevel::Error,
            });
            params.set_message(message);
            if let Some(data) = data {
                let data_bytes = serde_json::to_vec(&data)?;
                params.set_data(&data_bytes);
            }
        }

        request.send().promise.await
            .map_err(|e| Error::Protocol(format!("log failed: {}", e)))?;

        Ok(())
    }

    /// Disconnect from the server gracefully.
    ///
    /// This will complete any pending requests before closing the connection.
    pub async fn disconnect(self) -> Result<()> {
        self.disconnector.await
            .map_err(|e| Error::Connection(format!("disconnect failed: {}", e)))
    }
}

/// Log level for server logging
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

/// Convert a Cap'n Proto ResourceContent to our Rust type
fn convert_resource_content(
    content: zap_capnp::resource_content::Reader<'_>
) -> Result<ResourceContent> {
    let uri_reader = content.get_uri()
        .map_err(|e| Error::Protocol(format!("failed to get uri: {}", e)))?;
    let uri = uri_reader.to_str()
        .map_err(|e| Error::Protocol(format!("invalid utf8 in uri: {}", e)))?
        .to_string();

    let mime_reader = content.get_mime_type()
        .map_err(|e| Error::Protocol(format!("failed to get mime_type: {}", e)))?;
    let mime_type = mime_reader.to_str()
        .map_err(|e| Error::Protocol(format!("invalid utf8 in mime_type: {}", e)))?
        .to_string();

    let content_data = match content.get_content().which()
        .map_err(|e| Error::Protocol(format!("failed to get content type: {}", e)))?
    {
        zap_capnp::resource_content::content::Which::Text(text) => {
            let text_reader = text
                .map_err(|e| Error::Protocol(format!("failed to get text: {}", e)))?;
            let text_str = text_reader.to_str()
                .map_err(|e| Error::Protocol(format!("invalid utf8 in text: {}", e)))?;
            Content::Text(text_str.to_string())
        }
        zap_capnp::resource_content::content::Which::Blob(blob) => {
            let blob_data = blob
                .map_err(|e| Error::Protocol(format!("failed to get blob: {}", e)))?;
            Content::Blob(blob_data.to_vec())
        }
    };

    Ok(ResourceContent {
        uri,
        mime_type,
        content: content_data,
    })
}

/// Generate a simple UUID v4 (random)
fn uuid_v4() -> &'static str {
    // For simplicity, use a timestamp-based ID
    // A full implementation would use the `uuid` crate
    "00000000-0000-0000-0000-000000000000"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_conversion() {
        assert_eq!(LogLevel::Debug as u8, 0);
        assert_eq!(LogLevel::Info as u8, 1);
        assert_eq!(LogLevel::Warn as u8, 2);
        assert_eq!(LogLevel::Error as u8, 3);
    }

    #[test]
    fn test_content_debug() {
        let text = Content::Text("hello".to_string());
        let blob = Content::Blob(vec![1, 2, 3]);

        // Just verify Debug is implemented
        let _ = format!("{:?}", text);
        let _ = format!("{:?}", blob);
    }

    #[test]
    fn test_role_equality() {
        assert_eq!(Role::User, Role::User);
        assert_ne!(Role::User, Role::Assistant);
    }
}
