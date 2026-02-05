//! ZAP MCP Gateway - Full Implementation
//!
//! A gateway that bridges multiple MCP servers, providing:
//! - Multi-transport support (stdio, HTTP/SSE, WebSocket)
//! - Tool/resource/prompt aggregation across servers
//! - Request routing to correct backend servers
//! - Health checking and automatic reconnection
//! - Server lifecycle management
//!
//! This module implements MCP (Model Context Protocol) gateway functionality
//! allowing ZAP to act as a unified interface to multiple MCP servers.

use crate::{Config, Result, Error, config::{ServerConfig, Transport, Auth}};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use tokio::time::{interval, timeout};

// ============================================================================
// MCP Protocol Types
// ============================================================================

/// JSON-RPC 2.0 request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Value,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// JSON-RPC 2.0 response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// JSON-RPC 2.0 notification (no id)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcNotification {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// JSON-RPC 2.0 error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// MCP Tool definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpTool {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

/// MCP Resource definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpResource {
    pub uri: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// MCP Prompt definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpPrompt {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub arguments: Vec<McpPromptArgument>,
}

/// MCP Prompt argument
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpPromptArgument {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub required: bool,
}

/// MCP Server capabilities
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct McpCapabilities {
    #[serde(default)]
    pub tools: Option<ToolsCapability>,
    #[serde(default)]
    pub resources: Option<ResourcesCapability>,
    #[serde(default)]
    pub prompts: Option<PromptsCapability>,
    #[serde(default)]
    pub logging: Option<Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolsCapability {
    #[serde(rename = "listChanged", default)]
    pub list_changed: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourcesCapability {
    #[serde(rename = "listChanged", default)]
    pub list_changed: bool,
    #[serde(default)]
    pub subscribe: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PromptsCapability {
    #[serde(rename = "listChanged", default)]
    pub list_changed: bool,
}

/// MCP Server info from initialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerInfo {
    pub name: String,
    #[serde(default)]
    pub version: String,
}

// ============================================================================
// Server Connection Status
// ============================================================================

/// Server connection status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerStatus {
    Connecting,
    Connected,
    Disconnected,
    Error,
    Reconnecting,
}

impl std::fmt::Display for ServerStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerStatus::Connecting => write!(f, "connecting"),
            ServerStatus::Connected => write!(f, "connected"),
            ServerStatus::Disconnected => write!(f, "disconnected"),
            ServerStatus::Error => write!(f, "error"),
            ServerStatus::Reconnecting => write!(f, "reconnecting"),
        }
    }
}

// ============================================================================
// Stdio Transport
// ============================================================================

/// Stdio transport for subprocess MCP servers
pub struct StdioTransport {
    stdin: Arc<Mutex<tokio::process::ChildStdin>>,
    pending: Arc<RwLock<HashMap<String, oneshot::Sender<JsonRpcResponse>>>>,
    connected: Arc<std::sync::atomic::AtomicBool>,
    _child: Arc<Mutex<Child>>,
}

impl StdioTransport {
    /// Spawn a subprocess and connect via stdio
    pub async fn spawn(command: &str, args: &[String], env: Option<&HashMap<String, String>>) -> Result<Self> {
        let mut cmd = Command::new(command);
        cmd.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if let Some(env_vars) = env {
            for (k, v) in env_vars {
                cmd.env(k, v);
            }
        }

        let mut child = cmd.spawn()
            .map_err(|e| Error::Transport(format!("failed to spawn {}: {}", command, e)))?;

        let stdin = child.stdin.take()
            .ok_or_else(|| Error::Transport("failed to get stdin".into()))?;
        let stdout = child.stdout.take()
            .ok_or_else(|| Error::Transport("failed to get stdout".into()))?;

        let pending: Arc<RwLock<HashMap<String, oneshot::Sender<JsonRpcResponse>>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let connected = Arc::new(std::sync::atomic::AtomicBool::new(true));

        // Spawn reader task
        let pending_clone = pending.clone();
        let connected_clone = connected.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                if line.is_empty() {
                    continue;
                }

                match serde_json::from_str::<JsonRpcResponse>(&line) {
                    Ok(response) => {
                        let id_str = match &response.id {
                            Value::Number(n) => n.to_string(),
                            Value::String(s) => s.clone(),
                            _ => continue,
                        };

                        let mut pending = pending_clone.write().await;
                        if let Some(tx) = pending.remove(&id_str) {
                            let _ = tx.send(response);
                        }
                    }
                    Err(e) => {
                        tracing::debug!("Failed to parse response: {} - line: {}", e, line);
                    }
                }
            }
            connected_clone.store(false, std::sync::atomic::Ordering::SeqCst);
        });

        Ok(Self {
            stdin: Arc::new(Mutex::new(stdin)),
            pending,
            connected,
            _child: Arc::new(Mutex::new(child)),
        })
    }

    pub async fn request(&self, req: JsonRpcRequest) -> Result<JsonRpcResponse> {
        let id_str = match &req.id {
            Value::Number(n) => n.to_string(),
            Value::String(s) => s.clone(),
            _ => return Err(Error::Protocol("invalid request id".into())),
        };

        let (tx, rx) = oneshot::channel();

        {
            let mut pending = self.pending.write().await;
            pending.insert(id_str.clone(), tx);
        }

        let line = serde_json::to_string(&req)? + "\n";
        {
            let mut stdin = self.stdin.lock().await;
            stdin.write_all(line.as_bytes()).await
                .map_err(|e| Error::Transport(format!("write failed: {}", e)))?;
            stdin.flush().await
                .map_err(|e| Error::Transport(format!("flush failed: {}", e)))?;
        }

        match timeout(Duration::from_secs(30), rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => Err(Error::Transport("response channel closed".into())),
            Err(_) => {
                let mut pending = self.pending.write().await;
                pending.remove(&id_str);
                Err(Error::Transport("request timeout".into()))
            }
        }
    }

    pub async fn notify(&self, notif: JsonRpcNotification) -> Result<()> {
        let line = serde_json::to_string(&notif)? + "\n";
        let mut stdin = self.stdin.lock().await;
        stdin.write_all(line.as_bytes()).await
            .map_err(|e| Error::Transport(format!("write failed: {}", e)))?;
        stdin.flush().await
            .map_err(|e| Error::Transport(format!("flush failed: {}", e)))?;
        Ok(())
    }

    pub async fn close(&self) -> Result<()> {
        let mut child = self._child.lock().await;
        let _ = child.kill().await;
        self.connected.store(false, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(std::sync::atomic::Ordering::SeqCst)
    }
}

// ============================================================================
// HTTP Transport (using hyper directly)
// ============================================================================

/// HTTP transport with optional SSE support
pub struct HttpTransport {
    endpoint: String,
    session_id: Arc<RwLock<Option<String>>>,
    auth: Option<Auth>,
    connected: Arc<std::sync::atomic::AtomicBool>,
}

impl HttpTransport {
    pub fn new(endpoint: &str, auth: Option<Auth>) -> Result<Self> {
        Ok(Self {
            endpoint: endpoint.to_string(),
            session_id: Arc::new(RwLock::new(None)),
            auth,
            connected: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        })
    }

    pub async fn request(&self, req: JsonRpcRequest) -> Result<JsonRpcResponse> {
        use http_body_util::{BodyExt, Full};
        use hyper::body::Bytes;
        use hyper::Request;
        use hyper_util::client::legacy::Client;
        use hyper_util::rt::TokioExecutor;

        let body_json = serde_json::to_string(&req)?;

        let uri: hyper::Uri = self.endpoint.parse()
            .map_err(|e| Error::Transport(format!("invalid URI: {}", e)))?;

        let mut request_builder = Request::builder()
            .method("POST")
            .uri(&uri)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream");

        if let Some(ref auth) = self.auth {
            match auth {
                Auth::Bearer { token } => {
                    request_builder = request_builder.header("Authorization", format!("Bearer {}", token));
                }
                Auth::Basic { username, password } => {
                    let credentials = format!("{}:{}", username, password);
                    let encoded = hex::encode(credentials.as_bytes());
                    request_builder = request_builder.header("Authorization", format!("Basic {}", encoded));
                }
            }
        }

        if let Some(ref sid) = *self.session_id.read().await {
            request_builder = request_builder.header("Mcp-Session-Id", sid.as_str());
        }

        let request = request_builder
            .body(Full::new(Bytes::from(body_json)))
            .map_err(|e| Error::Transport(format!("failed to build request: {}", e)))?;

        let https = hyper_util::client::legacy::connect::HttpConnector::new();
        let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(https);

        let response = client.request(request).await
            .map_err(|e| Error::Transport(format!("HTTP request failed: {}", e)))?;

        if let Some(sid) = response.headers().get("Mcp-Session-Id") {
            if let Ok(sid_str) = sid.to_str() {
                *self.session_id.write().await = Some(sid_str.to_string());
            }
        }

        let status = response.status();
        if !status.is_success() {
            self.connected.store(false, std::sync::atomic::Ordering::SeqCst);
            return Err(Error::Transport(format!("HTTP error: {}", status)));
        }

        let body_bytes = response.into_body().collect().await
            .map_err(|e| Error::Transport(format!("failed to read response: {}", e)))?
            .to_bytes();

        let body = String::from_utf8_lossy(&body_bytes);

        let json_str = if body.starts_with("data:") {
            body.lines()
                .filter(|l| l.starts_with("data:"))
                .last()
                .map(|l| l.trim_start_matches("data:").trim())
                .unwrap_or(&body)
        } else {
            &body
        };

        serde_json::from_str(json_str)
            .map_err(|e| Error::Protocol(format!("invalid JSON response: {}", e)))
    }

    pub async fn notify(&self, notif: JsonRpcNotification) -> Result<()> {
        use http_body_util::Full;
        use hyper::body::Bytes;
        use hyper::Request;
        use hyper_util::client::legacy::Client;
        use hyper_util::rt::TokioExecutor;

        let body_json = serde_json::to_string(&notif)?;
        let uri: hyper::Uri = self.endpoint.parse()
            .map_err(|e| Error::Transport(format!("invalid URI: {}", e)))?;

        let mut request_builder = Request::builder()
            .method("POST")
            .uri(&uri)
            .header("Content-Type", "application/json");

        if let Some(ref auth) = self.auth {
            match auth {
                Auth::Bearer { token } => {
                    request_builder = request_builder.header("Authorization", format!("Bearer {}", token));
                }
                Auth::Basic { username, password } => {
                    let credentials = format!("{}:{}", username, password);
                    let encoded = hex::encode(credentials.as_bytes());
                    request_builder = request_builder.header("Authorization", format!("Basic {}", encoded));
                }
            }
        }

        if let Some(ref sid) = *self.session_id.read().await {
            request_builder = request_builder.header("Mcp-Session-Id", sid.as_str());
        }

        let request = request_builder
            .body(Full::new(Bytes::from(body_json)))
            .map_err(|e| Error::Transport(format!("failed to build request: {}", e)))?;

        let https = hyper_util::client::legacy::connect::HttpConnector::new();
        let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(https);

        let response = client.request(request).await
            .map_err(|e| Error::Transport(format!("HTTP request failed: {}", e)))?;

        let status = response.status();
        if status != hyper::StatusCode::ACCEPTED && !status.is_success() {
            return Err(Error::Transport(format!("unexpected status: {}", status)));
        }

        Ok(())
    }

    pub async fn close(&self) -> Result<()> {
        self.connected.store(false, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(std::sync::atomic::Ordering::SeqCst)
    }
}

// ============================================================================
// WebSocket Transport
// ============================================================================

/// WebSocket transport
pub struct WebSocketTransport {
    write: Arc<Mutex<futures::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
        tokio_tungstenite::tungstenite::Message
    >>>,
    pending: Arc<RwLock<HashMap<String, oneshot::Sender<JsonRpcResponse>>>>,
    connected: Arc<std::sync::atomic::AtomicBool>,
}

impl WebSocketTransport {
    pub async fn connect(url: &str) -> Result<Self> {
        use futures::StreamExt;
        use tokio_tungstenite::connect_async;

        let (ws_stream, _) = connect_async(url).await
            .map_err(|e| Error::Transport(format!("WebSocket connect failed: {}", e)))?;

        let (write, mut read) = ws_stream.split();
        let pending: Arc<RwLock<HashMap<String, oneshot::Sender<JsonRpcResponse>>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let connected = Arc::new(std::sync::atomic::AtomicBool::new(true));

        let pending_clone = pending.clone();
        let connected_clone = connected.clone();
        tokio::spawn(async move {
            while let Some(msg) = read.next().await {
                match msg {
                    Ok(tokio_tungstenite::tungstenite::Message::Text(text)) => {
                        if let Ok(response) = serde_json::from_str::<JsonRpcResponse>(&text) {
                            let id_str = match &response.id {
                                Value::Number(n) => n.to_string(),
                                Value::String(s) => s.clone(),
                                _ => continue,
                            };

                            let mut pending = pending_clone.write().await;
                            if let Some(tx) = pending.remove(&id_str) {
                                let _ = tx.send(response);
                            }
                        }
                    }
                    Ok(tokio_tungstenite::tungstenite::Message::Close(_)) => break,
                    Err(_) => break,
                    _ => {}
                }
            }
            connected_clone.store(false, std::sync::atomic::Ordering::SeqCst);
        });

        Ok(Self { write: Arc::new(Mutex::new(write)), pending, connected })
    }

    pub async fn request(&self, req: JsonRpcRequest) -> Result<JsonRpcResponse> {
        use futures::SinkExt;
        use tokio_tungstenite::tungstenite::Message;

        let id_str = match &req.id {
            Value::Number(n) => n.to_string(),
            Value::String(s) => s.clone(),
            _ => return Err(Error::Protocol("invalid request id".into())),
        };

        let (tx, rx) = oneshot::channel();
        { self.pending.write().await.insert(id_str.clone(), tx); }

        let json = serde_json::to_string(&req)?;
        { self.write.lock().await.send(Message::Text(json.into())).await
            .map_err(|e| Error::Transport(format!("WebSocket send failed: {}", e)))?; }

        match timeout(Duration::from_secs(30), rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => Err(Error::Transport("response channel closed".into())),
            Err(_) => { self.pending.write().await.remove(&id_str); Err(Error::Transport("request timeout".into())) }
        }
    }

    pub async fn notify(&self, notif: JsonRpcNotification) -> Result<()> {
        use futures::SinkExt;
        use tokio_tungstenite::tungstenite::Message;

        let json = serde_json::to_string(&notif)?;
        self.write.lock().await.send(Message::Text(json.into())).await
            .map_err(|e| Error::Transport(format!("WebSocket send failed: {}", e)))
    }

    pub async fn close(&self) -> Result<()> {
        use futures::SinkExt;
        use tokio_tungstenite::tungstenite::Message;
        let _ = self.write.lock().await.send(Message::Close(None)).await;
        self.connected.store(false, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(std::sync::atomic::Ordering::SeqCst)
    }
}

// ============================================================================
// MCP Client
// ============================================================================

enum McpClientTransport {
    Stdio(StdioTransport),
    Http(HttpTransport),
    WebSocket(WebSocketTransport),
}

/// MCP client for a single server connection
pub struct McpClient {
    transport: McpClientTransport,
    server_info: RwLock<Option<McpServerInfo>>,
    capabilities: RwLock<McpCapabilities>,
    tools: RwLock<Vec<McpTool>>,
    resources: RwLock<Vec<McpResource>>,
    prompts: RwLock<Vec<McpPrompt>>,
    request_id: std::sync::atomic::AtomicU64,
}

impl McpClient {
    fn next_id(&self) -> Value {
        Value::Number(self.request_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst).into())
    }

    async fn send_request(&self, method: &str, params: Option<Value>) -> Result<JsonRpcResponse> {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: self.next_id(),
            method: method.to_string(),
            params,
        };
        match &self.transport {
            McpClientTransport::Stdio(t) => t.request(req).await,
            McpClientTransport::Http(t) => t.request(req).await,
            McpClientTransport::WebSocket(t) => t.request(req).await,
        }
    }

    async fn send_notification(&self, method: &str, params: Option<Value>) -> Result<()> {
        let notif = JsonRpcNotification {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
        };
        match &self.transport {
            McpClientTransport::Stdio(t) => t.notify(notif).await,
            McpClientTransport::Http(t) => t.notify(notif).await,
            McpClientTransport::WebSocket(t) => t.notify(notif).await,
        }
    }

    pub async fn connect_stdio(command: &str, args: &[String], env: Option<&HashMap<String, String>>) -> Result<Self> {
        let transport = StdioTransport::spawn(command, args, env).await?;
        let client = Self {
            transport: McpClientTransport::Stdio(transport),
            server_info: RwLock::new(None),
            capabilities: RwLock::new(McpCapabilities::default()),
            tools: RwLock::new(Vec::new()),
            resources: RwLock::new(Vec::new()),
            prompts: RwLock::new(Vec::new()),
            request_id: std::sync::atomic::AtomicU64::new(1),
        };
        client.initialize().await?;
        Ok(client)
    }

    pub async fn connect_http(endpoint: &str, auth: Option<Auth>) -> Result<Self> {
        let transport = HttpTransport::new(endpoint, auth)?;
        let client = Self {
            transport: McpClientTransport::Http(transport),
            server_info: RwLock::new(None),
            capabilities: RwLock::new(McpCapabilities::default()),
            tools: RwLock::new(Vec::new()),
            resources: RwLock::new(Vec::new()),
            prompts: RwLock::new(Vec::new()),
            request_id: std::sync::atomic::AtomicU64::new(1),
        };
        client.initialize().await?;
        Ok(client)
    }

    pub async fn connect_websocket(url: &str) -> Result<Self> {
        let transport = WebSocketTransport::connect(url).await?;
        let client = Self {
            transport: McpClientTransport::WebSocket(transport),
            server_info: RwLock::new(None),
            capabilities: RwLock::new(McpCapabilities::default()),
            tools: RwLock::new(Vec::new()),
            resources: RwLock::new(Vec::new()),
            prompts: RwLock::new(Vec::new()),
            request_id: std::sync::atomic::AtomicU64::new(1),
        };
        client.initialize().await?;
        Ok(client)
    }

    async fn initialize(&self) -> Result<()> {
        let params = json!({
            "protocolVersion": "2024-11-05",
            "capabilities": { "roots": { "listChanged": true }, "sampling": {} },
            "clientInfo": { "name": "zap-gateway", "version": env!("CARGO_PKG_VERSION") }
        });

        let response = self.send_request("initialize", Some(params)).await?;
        if let Some(error) = response.error {
            return Err(Error::Protocol(format!("initialize failed: {}", error.message)));
        }

        if let Some(result) = response.result {
            if let Some(server_info) = result.get("serverInfo") {
                *self.server_info.write().await = serde_json::from_value(server_info.clone()).ok();
            }
            if let Some(caps) = result.get("capabilities") {
                *self.capabilities.write().await = serde_json::from_value(caps.clone()).unwrap_or_default();
            }
        }

        self.send_notification("notifications/initialized", None).await?;
        self.refresh_all().await?;
        Ok(())
    }

    pub async fn refresh_all(&self) -> Result<()> {
        let caps = self.capabilities.read().await.clone();
        if caps.tools.is_some() { let _ = self.refresh_tools().await; }
        if caps.resources.is_some() { let _ = self.refresh_resources().await; }
        if caps.prompts.is_some() { let _ = self.refresh_prompts().await; }
        Ok(())
    }

    pub async fn refresh_tools(&self) -> Result<()> {
        let response = self.send_request("tools/list", None).await?;
        if let Some(result) = response.result {
            if let Some(tools_val) = result.get("tools") {
                *self.tools.write().await = serde_json::from_value(tools_val.clone()).unwrap_or_default();
            }
        }
        Ok(())
    }

    pub async fn refresh_resources(&self) -> Result<()> {
        let response = self.send_request("resources/list", None).await?;
        if let Some(result) = response.result {
            if let Some(resources_val) = result.get("resources") {
                *self.resources.write().await = serde_json::from_value(resources_val.clone()).unwrap_or_default();
            }
        }
        Ok(())
    }

    pub async fn refresh_prompts(&self) -> Result<()> {
        let response = self.send_request("prompts/list", None).await?;
        if let Some(result) = response.result {
            if let Some(prompts_val) = result.get("prompts") {
                *self.prompts.write().await = serde_json::from_value(prompts_val.clone()).unwrap_or_default();
            }
        }
        Ok(())
    }

    pub async fn call_tool(&self, name: &str, arguments: Value) -> Result<Value> {
        let params = json!({ "name": name, "arguments": arguments });
        let response = self.send_request("tools/call", Some(params)).await?;
        if let Some(error) = response.error {
            return Err(Error::ToolCallFailed(format!("{}: {}", name, error.message)));
        }
        response.result.ok_or_else(|| Error::Protocol("empty tool result".into()))
    }

    pub async fn read_resource(&self, uri: &str) -> Result<Value> {
        let params = json!({ "uri": uri });
        let response = self.send_request("resources/read", Some(params)).await?;
        if let Some(error) = response.error {
            return Err(Error::ResourceNotFound(format!("{}: {}", uri, error.message)));
        }
        response.result.ok_or_else(|| Error::Protocol("empty resource result".into()))
    }

    pub async fn get_prompt(&self, name: &str, arguments: Option<Value>) -> Result<Value> {
        let params = json!({ "name": name, "arguments": arguments.unwrap_or(json!({})) });
        let response = self.send_request("prompts/get", Some(params)).await?;
        if let Some(error) = response.error {
            return Err(Error::Protocol(format!("prompt {} failed: {}", name, error.message)));
        }
        response.result.ok_or_else(|| Error::Protocol("empty prompt result".into()))
    }

    pub async fn tools(&self) -> Vec<McpTool> { self.tools.read().await.clone() }
    pub async fn resources(&self) -> Vec<McpResource> { self.resources.read().await.clone() }
    pub async fn prompts(&self) -> Vec<McpPrompt> { self.prompts.read().await.clone() }
    pub async fn server_info(&self) -> Option<McpServerInfo> { self.server_info.read().await.clone() }

    pub fn is_connected(&self) -> bool {
        match &self.transport {
            McpClientTransport::Stdio(t) => t.is_connected(),
            McpClientTransport::Http(t) => t.is_connected(),
            McpClientTransport::WebSocket(t) => t.is_connected(),
        }
    }

    pub async fn close(&self) -> Result<()> {
        match &self.transport {
            McpClientTransport::Stdio(t) => t.close().await,
            McpClientTransport::Http(t) => t.close().await,
            McpClientTransport::WebSocket(t) => t.close().await,
        }
    }
}

// ============================================================================
// Connected Server State
// ============================================================================

struct ConnectedServer {
    id: String,
    name: String,
    config: ServerConfig,
    client: Option<Arc<McpClient>>,
    status: ServerStatus,
    last_error: Option<String>,
    #[allow(dead_code)]
    last_health_check: Option<Instant>,
    reconnect_attempts: u32,
}

impl ConnectedServer {
    fn new(id: String, name: String, config: ServerConfig) -> Self {
        Self { id, name, config, client: None, status: ServerStatus::Disconnected,
               last_error: None, last_health_check: None, reconnect_attempts: 0 }
    }
}

// ============================================================================
// Gateway Implementation
// ============================================================================

/// ZAP MCP Gateway - aggregates multiple MCP servers
pub struct Gateway {
    config: Config,
    servers: Arc<RwLock<HashMap<String, ConnectedServer>>>,
    tool_routing: Arc<RwLock<HashMap<String, String>>>,
    resource_routing: Arc<RwLock<HashMap<String, String>>>,
    prompt_routing: Arc<RwLock<HashMap<String, String>>>,
    shutdown_tx: Option<mpsc::Sender<()>>,
}

/// Server info returned by list_servers
#[derive(Debug, Clone)]
pub struct ServerInfo {
    pub id: String,
    pub name: String,
    pub url: String,
    pub status: ServerStatus,
    pub tools_count: usize,
    pub resources_count: usize,
    pub prompts_count: usize,
    pub last_error: Option<String>,
}

impl Gateway {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            servers: Arc::new(RwLock::new(HashMap::new())),
            tool_routing: Arc::new(RwLock::new(HashMap::new())),
            resource_routing: Arc::new(RwLock::new(HashMap::new())),
            prompt_routing: Arc::new(RwLock::new(HashMap::new())),
            shutdown_tx: None,
        }
    }

    fn generate_id() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        format!("{:x}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos())
    }

    pub async fn add_server(&self, name: &str, config: ServerConfig) -> Result<String> {
        let id = Self::generate_id();
        let server = ConnectedServer::new(id.clone(), name.to_string(), config);
        self.servers.write().await.insert(id.clone(), server);

        let servers = self.servers.clone();
        let tool_routing = self.tool_routing.clone();
        let resource_routing = self.resource_routing.clone();
        let prompt_routing = self.prompt_routing.clone();
        let server_id = id.clone();

        tokio::spawn(async move {
            if let Err(e) = Self::connect_server(&servers, &tool_routing, &resource_routing, &prompt_routing, &server_id).await {
                tracing::error!("Failed to connect to server {}: {}", server_id, e);
            }
        });

        Ok(id)
    }

    async fn connect_server(
        servers: &Arc<RwLock<HashMap<String, ConnectedServer>>>,
        tool_routing: &Arc<RwLock<HashMap<String, String>>>,
        resource_routing: &Arc<RwLock<HashMap<String, String>>>,
        prompt_routing: &Arc<RwLock<HashMap<String, String>>>,
        server_id: &str,
    ) -> Result<()> {
        let config = {
            let mut servers = servers.write().await;
            let server = servers.get_mut(server_id).ok_or_else(|| Error::Server(format!("server {} not found", server_id)))?;
            server.status = ServerStatus::Connecting;
            server.config.clone()
        };

        let client_result = match config.transport {
            Transport::Stdio => {
                let url = url::Url::parse(&config.url).map_err(|e| Error::Config(format!("invalid URL: {}", e)))?;
                let command = url.path();
                let args: Vec<String> = url.query_pairs().filter(|(k, _)| k == "arg").map(|(_, v)| v.to_string()).collect();
                McpClient::connect_stdio(command, &args, None).await
            }
            Transport::Http => McpClient::connect_http(&config.url, config.auth.clone()).await,
            Transport::WebSocket => McpClient::connect_websocket(&config.url).await,
            Transport::Zap => return Err(Error::Transport("ZAP transport not yet implemented".into())),
            Transport::Unix => return Err(Error::Transport("Unix transport not yet implemented".into())),
        };

        match client_result {
            Ok(client) => {
                let client = Arc::new(client);

                { let tools = client.tools().await; let mut routing = tool_routing.write().await;
                  for tool in &tools { routing.insert(tool.name.clone(), server_id.to_string()); } }

                { let resources = client.resources().await; let mut routing = resource_routing.write().await;
                  for resource in &resources {
                      if let Some(scheme) = resource.uri.split(':').next() { routing.insert(format!("{}:", scheme), server_id.to_string()); }
                      routing.insert(resource.uri.clone(), server_id.to_string());
                  } }

                { let prompts = client.prompts().await; let mut routing = prompt_routing.write().await;
                  for prompt in &prompts { routing.insert(prompt.name.clone(), server_id.to_string()); } }

                { let mut servers = servers.write().await;
                  if let Some(server) = servers.get_mut(server_id) {
                      server.client = Some(client);
                      server.status = ServerStatus::Connected;
                      server.last_error = None;
                      server.reconnect_attempts = 0;
                      server.last_health_check = Some(Instant::now());
                  } }

                tracing::info!("Connected to MCP server: {}", server_id);
                Ok(())
            }
            Err(e) => {
                let mut servers = servers.write().await;
                if let Some(server) = servers.get_mut(server_id) {
                    server.status = ServerStatus::Error;
                    server.last_error = Some(e.to_string());
                    server.reconnect_attempts += 1;
                }
                Err(e)
            }
        }
    }

    pub async fn remove_server(&self, id: &str) -> Result<()> {
        let server = self.servers.write().await.remove(id);
        if let Some(server) = server {
            self.tool_routing.write().await.retain(|_, v| v != id);
            self.resource_routing.write().await.retain(|_, v| v != id);
            self.prompt_routing.write().await.retain(|_, v| v != id);
            if let Some(client) = &server.client { let _ = client.close().await; }
        }
        Ok(())
    }

    pub async fn list_servers(&self) -> Vec<ServerInfo> {
        let servers = self.servers.read().await;
        let mut result = Vec::new();
        for server in servers.values() {
            let (tools_count, resources_count, prompts_count) = if let Some(client) = &server.client {
                (client.tools().await.len(), client.resources().await.len(), client.prompts().await.len())
            } else { (0, 0, 0) };
            result.push(ServerInfo {
                id: server.id.clone(), name: server.name.clone(), url: server.config.url.clone(),
                status: server.status, tools_count, resources_count, prompts_count, last_error: server.last_error.clone(),
            });
        }
        result
    }

    pub async fn server_status(&self, id: &str) -> Option<ServerStatus> {
        self.servers.read().await.get(id).map(|s| s.status)
    }

    pub async fn list_tools(&self) -> Vec<McpTool> {
        let servers = self.servers.read().await;
        let mut tools = Vec::new();
        for server in servers.values() {
            if let Some(client) = &server.client {
                if server.status == ServerStatus::Connected { tools.extend(client.tools().await); }
            }
        }
        tools
    }

    pub async fn list_resources(&self) -> Vec<McpResource> {
        let servers = self.servers.read().await;
        let mut resources = Vec::new();
        for server in servers.values() {
            if let Some(client) = &server.client {
                if server.status == ServerStatus::Connected { resources.extend(client.resources().await); }
            }
        }
        resources
    }

    pub async fn list_prompts(&self) -> Vec<McpPrompt> {
        let servers = self.servers.read().await;
        let mut prompts = Vec::new();
        for server in servers.values() {
            if let Some(client) = &server.client {
                if server.status == ServerStatus::Connected { prompts.extend(client.prompts().await); }
            }
        }
        prompts
    }

    pub async fn call_tool(&self, name: &str, arguments: Value) -> Result<Value> {
        let server_id = self.tool_routing.read().await.get(name).cloned()
            .ok_or_else(|| Error::ToolNotFound(name.to_string()))?;
        let client = self.servers.read().await.get(&server_id).and_then(|s| s.client.clone())
            .ok_or_else(|| Error::Server(format!("server {} not connected", server_id)))?;
        client.call_tool(name, arguments).await
    }

    pub async fn read_resource(&self, uri: &str) -> Result<Value> {
        let server_id = {
            let routing = self.resource_routing.read().await;
            routing.get(uri).cloned().or_else(|| routing.iter().find(|(prefix, _)| uri.starts_with(prefix.as_str())).map(|(_, id)| id.clone()))
        }.ok_or_else(|| Error::ResourceNotFound(uri.to_string()))?;
        let client = self.servers.read().await.get(&server_id).and_then(|s| s.client.clone())
            .ok_or_else(|| Error::Server(format!("server {} not connected", server_id)))?;
        client.read_resource(uri).await
    }

    pub async fn get_prompt(&self, name: &str, arguments: Option<Value>) -> Result<Value> {
        let server_id = self.prompt_routing.read().await.get(name).cloned()
            .ok_or_else(|| Error::Protocol(format!("prompt {} not found", name)))?;
        let client = self.servers.read().await.get(&server_id).and_then(|s| s.client.clone())
            .ok_or_else(|| Error::Server(format!("server {} not connected", server_id)))?;
        client.get_prompt(name, arguments).await
    }

    pub async fn run(&mut self) -> Result<()> {
        let addr = format!("{}:{}", self.config.listen, self.config.port);
        tracing::info!("ZAP gateway starting on {}", addr);

        for server_config in self.config.servers.clone() {
            let name = server_config.name.clone();
            match self.add_server(&name, server_config).await {
                Ok(id) => tracing::info!("Added server {} with id {}", name, id),
                Err(e) => tracing::error!("Failed to add server {}: {}", name, e),
            }
        }

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);

        let servers = self.servers.clone();
        let tool_routing = self.tool_routing.clone();
        let resource_routing = self.resource_routing.clone();
        let prompt_routing = self.prompt_routing.clone();

        let health_task = tokio::spawn(async move {
            let mut check_interval = interval(Duration::from_secs(30));
            loop {
                check_interval.tick().await;
                let server_ids: Vec<String> = servers.read().await.keys().cloned().collect();
                for server_id in server_ids {
                    let (needs_reconnect, client) = {
                        let servers = servers.read().await;
                        if let Some(server) = servers.get(&server_id) {
                            let needs_reconnect = match server.status {
                                ServerStatus::Error | ServerStatus::Disconnected => true,
                                ServerStatus::Connected => server.client.as_ref().map(|c| !c.is_connected()).unwrap_or(true),
                                _ => false,
                            };
                            (needs_reconnect, server.client.clone())
                        } else { (false, None) }
                    };

                    if needs_reconnect {
                        tracing::info!("Health check: reconnecting {}", server_id);
                        { servers.write().await.get_mut(&server_id).map(|s| s.status = ServerStatus::Reconnecting); }
                        let _ = Self::connect_server(&servers, &tool_routing, &resource_routing, &prompt_routing, &server_id).await;
                    } else if let Some(client) = client {
                        let _ = client.refresh_all().await;
                    }
                }
            }
        });

        tokio::select! {
            _ = shutdown_rx.recv() => { tracing::info!("Shutdown signal received"); }
            _ = tokio::signal::ctrl_c() => { tracing::info!("Ctrl+C received"); }
        }

        health_task.abort();
        for id in self.servers.read().await.keys().cloned().collect::<Vec<_>>() { let _ = self.remove_server(&id).await; }
        tracing::info!("Gateway shutdown complete");
        Ok(())
    }

    pub async fn shutdown(&self) -> Result<()> {
        if let Some(tx) = &self.shutdown_tx { let _ = tx.send(()).await; }
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_rpc_request_serialize() {
        let req = JsonRpcRequest { jsonrpc: "2.0".to_string(), id: json!(1), method: "tools/list".to_string(), params: None };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"jsonrpc\":\"2.0\""));
        assert!(json.contains("\"method\":\"tools/list\""));
    }

    #[test]
    fn test_json_rpc_response_deserialize() {
        let json = r#"{"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}"#;
        let resp: JsonRpcResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.jsonrpc, "2.0");
        assert!(resp.result.is_some());
    }

    #[test]
    fn test_mcp_tool_deserialize() {
        let json = r#"{"name": "calculator", "description": "Perform calculations", "inputSchema": {"type": "object"}}"#;
        let tool: McpTool = serde_json::from_str(json).unwrap();
        assert_eq!(tool.name, "calculator");
    }

    #[tokio::test]
    async fn test_gateway_create() {
        let config = Config::default();
        let gateway = Gateway::new(config);
        assert!(gateway.list_servers().await.is_empty());
    }

    #[tokio::test]
    async fn test_gateway_add_remove_server() {
        let config = Config::default();
        let gateway = Gateway::new(config);
        let server_config = ServerConfig { name: "test".to_string(), url: "http://localhost:8080".to_string(),
                                           transport: Transport::Http, timeout: 30000, auth: None };
        let id = gateway.add_server("test", server_config).await.unwrap();
        assert!(!id.is_empty());
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(gateway.list_servers().await.len(), 1);
        gateway.remove_server(&id).await.unwrap();
        assert!(gateway.list_servers().await.is_empty());
    }

    #[test]
    fn test_server_status_display() {
        assert_eq!(ServerStatus::Connecting.to_string(), "connecting");
        assert_eq!(ServerStatus::Connected.to_string(), "connected");
    }
}
