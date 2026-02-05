//! ZAP server implementation
//!
//! Cap'n Proto RPC server for AI agent communication.
//!
//! # Example
//!
//! ```rust,ignore
//! use zap::{Server, Config};
//! use zap::server::{ToolHandler, ResourceHandler, PromptHandler, ToolDef};
//! use std::collections::HashMap;
//! use std::sync::Arc;
//!
//! struct MyToolHandler;
//!
//! impl ToolHandler for MyToolHandler {
//!     fn list(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<ToolDef>> + Send + '_>> {
//!         Box::pin(async {
//!             vec![ToolDef {
//!                 name: "echo".into(),
//!                 description: "Echo input".into(),
//!                 schema: b"{}".to_vec(),
//!                 annotations: HashMap::new(),
//!             }]
//!         })
//!     }
//!
//!     fn call(
//!         &self,
//!         _name: &str,
//!         args: &[u8],
//!         _metadata: HashMap<String, String>,
//!     ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + Send + '_>> {
//!         let args = args.to_vec();
//!         Box::pin(async move { Ok(args) })
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() -> zap::Result<()> {
//!     let mut server = Server::new(Config::default());
//!     server.set_tool_handler(Arc::new(MyToolHandler));
//!     server.run().await
//! }
//! ```

use crate::zap_capnp::{
    prompt_message, resource_stream, zap,
};
use crate::{Config, Error, Result};
use capnp::capability::Promise;
use capnp_rpc::{rpc_twoparty_capnp, twoparty, RpcSystem};
use futures::AsyncReadExt;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::task::LocalSet;

/// Tool definition
#[derive(Debug, Clone)]
pub struct ToolDef {
    pub name: String,
    pub description: String,
    pub schema: Vec<u8>,
    pub annotations: HashMap<String, String>,
}

/// Resource definition
#[derive(Debug, Clone)]
pub struct ResourceDef {
    pub uri: String,
    pub name: String,
    pub description: String,
    pub mime_type: String,
    pub annotations: HashMap<String, String>,
}

/// Resource content
#[derive(Debug, Clone)]
pub enum ResourceContentData {
    Text(String),
    Blob(Vec<u8>),
}

/// Resource content with metadata
#[derive(Debug, Clone)]
pub struct ResourceContentDef {
    pub uri: String,
    pub mime_type: String,
    pub content: ResourceContentData,
}

/// Prompt definition
#[derive(Debug, Clone)]
pub struct PromptDef {
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
    pub role: PromptRole,
    pub content: PromptContent,
}

/// Prompt role
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptRole {
    User,
    Assistant,
    System,
}

/// Prompt content
#[derive(Debug, Clone)]
pub enum PromptContent {
    Text(String),
    Image { data: Vec<u8>, mime_type: String },
    Resource(ResourceContentDef),
}

/// Tool handler trait
///
/// Implement this trait to handle tool operations.
pub trait ToolHandler: Send + Sync + 'static {
    /// List available tools
    fn list(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<ToolDef>> + Send + '_>>;

    /// Call a tool
    fn call(
        &self,
        name: &str,
        args: &[u8],
        metadata: HashMap<String, String>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::result::Result<Vec<u8>, String>> + Send + '_>>;
}

/// Resource handler trait
///
/// Implement this trait to handle resource operations.
pub trait ResourceHandler: Send + Sync + 'static {
    /// List available resources
    fn list(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<ResourceDef>> + Send + '_>>;

    /// Read a resource
    fn read(
        &self,
        uri: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::result::Result<ResourceContentDef, String>> + Send + '_>>;

    /// Subscribe to resource updates (returns a stream receiver)
    fn subscribe(
        &self,
        uri: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::result::Result<tokio::sync::mpsc::Receiver<ResourceContentDef>, String>> + Send + '_>>;
}

/// Prompt handler trait
///
/// Implement this trait to handle prompt operations.
pub trait PromptHandler: Send + Sync + 'static {
    /// List available prompts
    fn list(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<PromptDef>> + Send + '_>>;

    /// Get a prompt with arguments
    fn get(
        &self,
        name: &str,
        args: HashMap<String, String>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::result::Result<Vec<PromptMessage>, String>> + Send + '_>>;
}

/// Log handler trait
pub trait LogHandler: Send + Sync + 'static {
    fn log(&self, level: LogLevel, message: &str, data: &[u8]);
}

/// Log level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

/// Default no-op tool handler
pub struct NoopToolHandler;

impl ToolHandler for NoopToolHandler {
    fn list(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<ToolDef>> + Send + '_>> {
        Box::pin(async { Vec::new() })
    }

    fn call(
        &self,
        _name: &str,
        _args: &[u8],
        _metadata: HashMap<String, String>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::result::Result<Vec<u8>, String>> + Send + '_>> {
        Box::pin(async { Err("no tool handler registered".to_string()) })
    }
}

/// Default no-op resource handler
pub struct NoopResourceHandler;

impl ResourceHandler for NoopResourceHandler {
    fn list(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<ResourceDef>> + Send + '_>> {
        Box::pin(async { Vec::new() })
    }

    fn read(
        &self,
        _uri: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::result::Result<ResourceContentDef, String>> + Send + '_>> {
        Box::pin(async { Err("no resource handler registered".to_string()) })
    }

    fn subscribe(
        &self,
        _uri: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::result::Result<tokio::sync::mpsc::Receiver<ResourceContentDef>, String>> + Send + '_>> {
        Box::pin(async { Err("no resource handler registered".to_string()) })
    }
}

/// Default no-op prompt handler
pub struct NoopPromptHandler;

impl PromptHandler for NoopPromptHandler {
    fn list(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<PromptDef>> + Send + '_>> {
        Box::pin(async { Vec::new() })
    }

    fn get(
        &self,
        _name: &str,
        _args: HashMap<String, String>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::result::Result<Vec<PromptMessage>, String>> + Send + '_>> {
        Box::pin(async { Err("no prompt handler registered".to_string()) })
    }
}

/// Default log handler (uses tracing)
pub struct TracingLogHandler;

impl LogHandler for TracingLogHandler {
    fn log(&self, level: LogLevel, message: &str, _data: &[u8]) {
        match level {
            LogLevel::Debug => tracing::debug!("{}", message),
            LogLevel::Info => tracing::info!("{}", message),
            LogLevel::Warn => tracing::warn!("{}", message),
            LogLevel::Error => tracing::error!("{}", message),
        }
    }
}

/// Server info
#[derive(Debug, Clone)]
pub struct ServerInfoDef {
    pub name: String,
    pub version: String,
    pub tools: bool,
    pub resources: bool,
    pub prompts: bool,
    pub logging: bool,
}

impl Default for ServerInfoDef {
    fn default() -> Self {
        Self {
            name: "zap".to_string(),
            version: crate::VERSION.to_string(),
            tools: true,
            resources: true,
            prompts: true,
            logging: true,
        }
    }
}

/// ZAP Server
///
/// A Cap'n Proto RPC server that implements the Zap interface.
pub struct Server {
    config: Config,
    tool_handler: Arc<dyn ToolHandler>,
    resource_handler: Arc<dyn ResourceHandler>,
    prompt_handler: Arc<dyn PromptHandler>,
    log_handler: Arc<dyn LogHandler>,
    server_info: ServerInfoDef,
}

impl Server {
    /// Create a new server with the given config
    pub fn new(config: Config) -> Self {
        Self {
            config,
            tool_handler: Arc::new(NoopToolHandler),
            resource_handler: Arc::new(NoopResourceHandler),
            prompt_handler: Arc::new(NoopPromptHandler),
            log_handler: Arc::new(TracingLogHandler),
            server_info: ServerInfoDef::default(),
        }
    }

    /// Set the tool handler
    pub fn set_tool_handler(&mut self, handler: Arc<dyn ToolHandler>) {
        self.tool_handler = handler;
    }

    /// Set the resource handler
    pub fn set_resource_handler(&mut self, handler: Arc<dyn ResourceHandler>) {
        self.resource_handler = handler;
    }

    /// Set the prompt handler
    pub fn set_prompt_handler(&mut self, handler: Arc<dyn PromptHandler>) {
        self.prompt_handler = handler;
    }

    /// Set the log handler
    pub fn set_log_handler(&mut self, handler: Arc<dyn LogHandler>) {
        self.log_handler = handler;
    }

    /// Set server info
    pub fn set_server_info(&mut self, info: ServerInfoDef) {
        self.server_info = info;
    }

    /// Run the server
    ///
    /// This runs the Cap'n Proto RPC server on a LocalSet since the RPC system
    /// uses Rc internally and is not Send.
    pub async fn run(&self) -> Result<()> {
        let addr = format!("{}:{}", self.config.listen, self.config.port);
        tracing::info!("ZAP server listening on {}", addr);

        let listener = TcpListener::bind(&addr).await?;

        // Create shared state for all connections
        let state = Arc::new(ServerState {
            tool_handler: self.tool_handler.clone(),
            resource_handler: self.resource_handler.clone(),
            prompt_handler: self.prompt_handler.clone(),
            log_handler: self.log_handler.clone(),
            server_info: self.server_info.clone(),
            client_count: AtomicU64::new(0),
        });

        // Use LocalSet for non-Send RPC futures
        let local = LocalSet::new();

        local.run_until(async move {
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, addr)) => {
                                let client_id = state.client_count.fetch_add(1, Ordering::SeqCst);
                                tracing::debug!("client {} connected from {}", client_id, addr);

                                let state = state.clone();
                                // Use spawn_local for non-Send futures
                                tokio::task::spawn_local(async move {
                                    if let Err(e) = handle_connection(stream, state, client_id).await {
                                        tracing::error!("client {} error: {}", client_id, e);
                                    }
                                    tracing::debug!("client {} disconnected", client_id);
                                });
                            }
                            Err(e) => {
                                tracing::error!("accept error: {}", e);
                            }
                        }
                    }
                    _ = tokio::signal::ctrl_c() => {
                        tracing::info!("shutting down");
                        break;
                    }
                }
            }
            Ok::<(), Error>(())
        }).await?;

        Ok(())
    }

    /// Run on an existing TCP listener (useful for tests)
    pub async fn run_on_listener(&self, listener: TcpListener) -> Result<()> {
        let state = Arc::new(ServerState {
            tool_handler: self.tool_handler.clone(),
            resource_handler: self.resource_handler.clone(),
            prompt_handler: self.prompt_handler.clone(),
            log_handler: self.log_handler.clone(),
            server_info: self.server_info.clone(),
            client_count: AtomicU64::new(0),
        });

        let local = LocalSet::new();

        local.run_until(async move {
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, addr)) => {
                                let client_id = state.client_count.fetch_add(1, Ordering::SeqCst);
                                tracing::debug!("client {} connected from {}", client_id, addr);

                                let state = state.clone();
                                tokio::task::spawn_local(async move {
                                    if let Err(e) = handle_connection(stream, state, client_id).await {
                                        tracing::error!("client {} error: {}", client_id, e);
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::error!("accept error: {}", e);
                                break;
                            }
                        }
                    }
                    _ = tokio::signal::ctrl_c() => {
                        break;
                    }
                }
            }
            Ok::<(), Error>(())
        }).await?;

        Ok(())
    }
}

/// Shared server state
struct ServerState {
    tool_handler: Arc<dyn ToolHandler>,
    resource_handler: Arc<dyn ResourceHandler>,
    prompt_handler: Arc<dyn PromptHandler>,
    log_handler: Arc<dyn LogHandler>,
    server_info: ServerInfoDef,
    client_count: AtomicU64,
}

/// Handle a single client connection
async fn handle_connection(
    stream: tokio::net::TcpStream,
    state: Arc<ServerState>,
    _client_id: u64,
) -> Result<()> {
    stream.set_nodelay(true)?;

    // Convert tokio TcpStream to futures-compatible stream
    let stream = tokio_util::compat::TokioAsyncReadCompatExt::compat(stream);
    let (reader, writer) = stream.split();

    // Create the Cap'n Proto RPC network
    let network = twoparty::VatNetwork::new(
        reader,
        writer,
        rpc_twoparty_capnp::Side::Server,
        Default::default(),
    );

    // Create the Zap implementation
    let zap_impl = ZapImpl::new(state);
    let zap_client: zap::Client = capnp_rpc::new_client(zap_impl);

    // Run the RPC system
    let rpc_system = RpcSystem::new(Box::new(network), Some(zap_client.client));

    rpc_system.await.map_err(Error::Capnp)
}

/// Implementation of the Zap interface
struct ZapImpl {
    state: Arc<ServerState>,
}

impl ZapImpl {
    fn new(state: Arc<ServerState>) -> Self {
        Self { state }
    }
}

impl zap::Server for ZapImpl {
    /// Initialize connection
    fn init(
        &mut self,
        params: zap::InitParams,
        mut results: zap::InitResults,
    ) -> Promise<(), capnp::Error> {
        let state = self.state.clone();

        Promise::from_future(async move {
            // Read client info
            let client = params.get()?.get_client()?;
            let client_name = client.get_name()?.to_str()?;
            let client_version = client.get_version()?.to_str()?;

            tracing::info!("client connected: {} v{}", client_name, client_version);

            // Build server info response
            let mut server = results.get().init_server();
            server.set_name(&state.server_info.name);
            server.set_version(&state.server_info.version);

            let mut caps = server.init_capabilities();
            caps.set_tools(state.server_info.tools);
            caps.set_resources(state.server_info.resources);
            caps.set_prompts(state.server_info.prompts);
            caps.set_logging(state.server_info.logging);

            Ok(())
        })
    }

    /// List available tools
    fn list_tools(
        &mut self,
        _params: zap::ListToolsParams,
        mut results: zap::ListToolsResults,
    ) -> Promise<(), capnp::Error> {
        let handler = self.state.tool_handler.clone();

        Promise::from_future(async move {
            let tools = handler.list().await;

            let tool_list = results.get().init_tools();
            let mut builder = tool_list.init_tools(tools.len() as u32);

            for (i, t) in tools.iter().enumerate() {
                let mut tool = builder.reborrow().get(i as u32);
                tool.set_name(&t.name);
                tool.set_description(&t.description);
                tool.set_schema(&t.schema);

                // Set annotations
                if !t.annotations.is_empty() {
                    let annotations = tool.init_annotations();
                    let mut entries = annotations.init_entries(t.annotations.len() as u32);
                    for (j, (k, v)) in t.annotations.iter().enumerate() {
                        let mut entry = entries.reborrow().get(j as u32);
                        entry.set_key(k);
                        entry.set_value(v);
                    }
                }
            }

            Ok(())
        })
    }

    /// Call a tool
    fn call_tool(
        &mut self,
        params: zap::CallToolParams,
        mut results: zap::CallToolResults,
    ) -> Promise<(), capnp::Error> {
        let handler = self.state.tool_handler.clone();

        Promise::from_future(async move {
            let call = params.get()?.get_call()?;
            let id = call.get_id()?.to_str()?;
            let name = call.get_name()?.to_str()?;
            let args = call.get_args()?;

            // Extract metadata
            let mut metadata = HashMap::new();
            if call.has_metadata() {
                let md = call.get_metadata()?;
                if md.has_entries() {
                    for entry in md.get_entries()? {
                        let key = entry.get_key()?.to_str()?;
                        let value = entry.get_value()?.to_str()?;
                        metadata.insert(key.to_string(), value.to_string());
                    }
                }
            }

            // Call the handler
            let result = handler.call(name, args, metadata).await;

            // Build response
            let mut tool_result = results.get().init_result();
            tool_result.set_id(id);

            match result {
                Ok(content) => {
                    tool_result.set_content(&content);
                }
                Err(e) => {
                    tool_result.set_error(&e);
                }
            }

            Ok(())
        })
    }

    /// List available resources
    fn list_resources(
        &mut self,
        _params: zap::ListResourcesParams,
        mut results: zap::ListResourcesResults,
    ) -> Promise<(), capnp::Error> {
        let handler = self.state.resource_handler.clone();

        Promise::from_future(async move {
            let resources = handler.list().await;

            let resource_list = results.get().init_resources();
            let mut builder = resource_list.init_resources(resources.len() as u32);

            for (i, r) in resources.iter().enumerate() {
                let mut resource = builder.reborrow().get(i as u32);
                resource.set_uri(&r.uri);
                resource.set_name(&r.name);
                resource.set_description(&r.description);
                resource.set_mime_type(&r.mime_type);

                if !r.annotations.is_empty() {
                    let annotations = resource.init_annotations();
                    let mut entries = annotations.init_entries(r.annotations.len() as u32);
                    for (j, (k, v)) in r.annotations.iter().enumerate() {
                        let mut entry = entries.reborrow().get(j as u32);
                        entry.set_key(k);
                        entry.set_value(v);
                    }
                }
            }

            Ok(())
        })
    }

    /// Read a resource
    fn read_resource(
        &mut self,
        params: zap::ReadResourceParams,
        mut results: zap::ReadResourceResults,
    ) -> Promise<(), capnp::Error> {
        let handler = self.state.resource_handler.clone();

        Promise::from_future(async move {
            let uri = params.get()?.get_uri()?.to_str()?;

            let result = handler.read(uri).await;

            let mut content = results.get().init_content();

            match result {
                Ok(data) => {
                    content.set_uri(&data.uri);
                    content.set_mime_type(&data.mime_type);

                    match data.content {
                        ResourceContentData::Text(text) => {
                            content.init_content().set_text(&text);
                        }
                        ResourceContentData::Blob(blob) => {
                            content.init_content().set_blob(&blob);
                        }
                    }
                }
                Err(e) => {
                    // Set error as text content
                    content.set_uri(uri);
                    content.set_mime_type("text/plain");
                    content.init_content().set_text(&format!("error: {}", e));
                }
            }

            Ok(())
        })
    }

    /// Subscribe to resource updates
    fn subscribe(
        &mut self,
        params: zap::SubscribeParams,
        mut results: zap::SubscribeResults,
    ) -> Promise<(), capnp::Error> {
        let handler = self.state.resource_handler.clone();

        Promise::from_future(async move {
            let uri = params.get()?.get_uri()?.to_str()?.to_string();

            let result = handler.subscribe(&uri).await;

            match result {
                Ok(receiver) => {
                    let stream_impl = ResourceStreamImpl::new(uri, receiver);
                    let stream_client: resource_stream::Client =
                        capnp_rpc::new_client(stream_impl);
                    results.get().set_stream(stream_client);
                }
                Err(_e) => {
                    // Return an empty stream that immediately completes
                    let (_, receiver) = tokio::sync::mpsc::channel(1);
                    let stream_impl = ResourceStreamImpl::new(uri, receiver);
                    let stream_client: resource_stream::Client =
                        capnp_rpc::new_client(stream_impl);
                    results.get().set_stream(stream_client);
                }
            }

            Ok(())
        })
    }

    /// List available prompts
    fn list_prompts(
        &mut self,
        _params: zap::ListPromptsParams,
        mut results: zap::ListPromptsResults,
    ) -> Promise<(), capnp::Error> {
        let handler = self.state.prompt_handler.clone();

        Promise::from_future(async move {
            let prompts = handler.list().await;

            let prompt_list = results.get().init_prompts();
            let mut builder = prompt_list.init_prompts(prompts.len() as u32);

            for (i, p) in prompts.iter().enumerate() {
                let mut prompt = builder.reborrow().get(i as u32);
                prompt.set_name(&p.name);
                prompt.set_description(&p.description);

                let mut args = prompt.init_arguments(p.arguments.len() as u32);
                for (j, arg) in p.arguments.iter().enumerate() {
                    let mut a = args.reborrow().get(j as u32);
                    a.set_name(&arg.name);
                    a.set_description(&arg.description);
                    a.set_required(arg.required);
                }
            }

            Ok(())
        })
    }

    /// Get a prompt
    fn get_prompt(
        &mut self,
        params: zap::GetPromptParams,
        mut results: zap::GetPromptResults,
    ) -> Promise<(), capnp::Error> {
        let handler = self.state.prompt_handler.clone();

        Promise::from_future(async move {
            let params_reader = params.get()?;
            let name = params_reader.get_name()?.to_str()?;

            // Extract args
            let mut args = HashMap::new();
            if params_reader.has_args() {
                let md = params_reader.get_args()?;
                if md.has_entries() {
                    for entry in md.get_entries()? {
                        let key = entry.get_key()?.to_str()?;
                        let value = entry.get_value()?.to_str()?;
                        args.insert(key.to_string(), value.to_string());
                    }
                }
            }

            let result = handler.get(name, args).await;

            match result {
                Ok(messages) => {
                    let mut builder = results.get().init_messages(messages.len() as u32);

                    for (i, msg) in messages.iter().enumerate() {
                        let mut m = builder.reborrow().get(i as u32);

                        // Set role
                        match msg.role {
                            PromptRole::User => m.set_role(prompt_message::Role::User),
                            PromptRole::Assistant => m.set_role(prompt_message::Role::Assistant),
                            PromptRole::System => m.set_role(prompt_message::Role::System),
                        }

                        // Set content
                        let mut content = m.init_content();
                        match &msg.content {
                            PromptContent::Text(text) => {
                                content.set_text(text);
                            }
                            PromptContent::Image { data, mime_type } => {
                                let mut img = content.init_image();
                                img.set_data(data);
                                img.set_mime_type(mime_type);
                            }
                            PromptContent::Resource(r) => {
                                let mut res = content.init_resource();
                                res.set_uri(&r.uri);
                                res.set_mime_type(&r.mime_type);
                                match &r.content {
                                    ResourceContentData::Text(t) => {
                                        res.init_content().set_text(t);
                                    }
                                    ResourceContentData::Blob(b) => {
                                        res.init_content().set_blob(b);
                                    }
                                }
                            }
                        }
                    }
                }
                Err(_e) => {
                    // Return empty list on error
                    results.get().init_messages(0);
                }
            }

            Ok(())
        })
    }

    /// Log a message
    fn log(
        &mut self,
        params: zap::LogParams,
        _results: zap::LogResults,
    ) -> Promise<(), capnp::Error> {
        let handler = self.state.log_handler.clone();

        Promise::from_future(async move {
            let params_reader = params.get()?;
            let level = match params_reader.get_level()? {
                zap::LogLevel::Debug => LogLevel::Debug,
                zap::LogLevel::Info => LogLevel::Info,
                zap::LogLevel::Warn => LogLevel::Warn,
                zap::LogLevel::Error => LogLevel::Error,
            };
            let message = params_reader.get_message()?.to_str()?;
            let data = params_reader.get_data()?;

            handler.log(level, message, data);

            Ok(())
        })
    }
}

/// Implementation of ResourceStream interface
struct ResourceStreamImpl {
    uri: String,
    receiver: std::cell::RefCell<tokio::sync::mpsc::Receiver<ResourceContentDef>>,
    done: std::cell::Cell<bool>,
}

impl ResourceStreamImpl {
    fn new(uri: String, receiver: tokio::sync::mpsc::Receiver<ResourceContentDef>) -> Self {
        Self {
            uri,
            receiver: std::cell::RefCell::new(receiver),
            done: std::cell::Cell::new(false),
        }
    }
}

impl resource_stream::Server for ResourceStreamImpl {
    fn next(
        &mut self,
        _params: resource_stream::NextParams,
        mut results: resource_stream::NextResults,
    ) -> Promise<(), capnp::Error> {
        if self.done.get() {
            return Promise::from_future(async move {
                results.get().set_done(true);
                Ok(())
            });
        }

        // Since we're running on LocalSet, we don't need Send
        let receiver = &self.receiver;
        let done_flag = &self.done;

        // Use a simple approach: try to receive now
        let mut guard = receiver.borrow_mut();
        match guard.try_recv() {
            Ok(data) => {
                drop(guard);
                Promise::from_future(async move {
                    let mut content = results.get().init_content();
                    content.set_uri(&data.uri);
                    content.set_mime_type(&data.mime_type);

                    match data.content {
                        ResourceContentData::Text(text) => {
                            content.init_content().set_text(&text);
                        }
                        ResourceContentData::Blob(blob) => {
                            content.init_content().set_blob(&blob);
                        }
                    }

                    results.get().set_done(false);
                    Ok(())
                })
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                // Channel is empty but not closed - return not done
                drop(guard);
                Promise::from_future(async move {
                    results.get().set_done(false);
                    Ok(())
                })
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                done_flag.set(true);
                drop(guard);
                Promise::from_future(async move {
                    results.get().set_done(true);
                    Ok(())
                })
            }
        }
    }

    fn cancel(
        &mut self,
        _params: resource_stream::CancelParams,
        _results: resource_stream::CancelResults,
    ) -> Promise<(), capnp::Error> {
        self.done.set(true);
        Promise::ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_new() {
        let config = Config::default();
        let server = Server::new(config);
        assert_eq!(server.server_info.name, "zap");
    }

    #[test]
    fn test_tool_def() {
        let tool = ToolDef {
            name: "test".into(),
            description: "A test tool".into(),
            schema: b"{}".to_vec(),
            annotations: HashMap::new(),
        };
        assert_eq!(tool.name, "test");
    }

    #[test]
    fn test_resource_content_data() {
        let text = ResourceContentData::Text("hello".into());
        assert!(matches!(text, ResourceContentData::Text(_)));

        let blob = ResourceContentData::Blob(vec![1, 2, 3]);
        assert!(matches!(blob, ResourceContentData::Blob(_)));
    }

    #[test]
    fn test_log_levels() {
        assert_ne!(LogLevel::Debug, LogLevel::Error);
        assert_eq!(LogLevel::Info, LogLevel::Info);
    }

    #[test]
    fn test_server_info_default() {
        let info = ServerInfoDef::default();
        assert_eq!(info.name, "zap");
        assert!(info.tools);
        assert!(info.resources);
        assert!(info.prompts);
        assert!(info.logging);
    }
}
