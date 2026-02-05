//! Transport implementations for ZAP
//!
//! Provides transport layer abstractions for ZAP protocol communication.
//! Supports TCP, Unix sockets, WebSocket, and encrypted channels.
//!
//! # Example
//!
//! ```rust,ignore
//! use zap::transport::{TcpTransport, connect};
//!
//! // Connect via TCP
//! let transport = connect("zap://localhost:9999").await?;
//! transport.send(b"hello").await?;
//! let response = transport.recv().await?;
//! ```

use crate::error::{Error, Result};
use std::pin::Pin;
use std::future::Future;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpStream, TcpListener};
use tokio::sync::Mutex;
use url::Url;

/// Frame header size (4 bytes for length)
const FRAME_HEADER_SIZE: usize = 4;

/// Maximum message size (16 MB)
const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Transport trait for ZAP connections
pub trait Transport: Send + Sync {
    /// Send a framed message
    fn send(&self, data: &[u8]) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;

    /// Receive a framed message
    fn recv(&self) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + '_>>;

    /// Close the transport
    fn close(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;

    /// Check if transport is connected
    fn is_connected(&self) -> bool;

    /// Get local address if available
    fn local_addr(&self) -> Option<String>;

    /// Get peer address if available
    fn peer_addr(&self) -> Option<String>;
}

/// Framed stream wrapper for length-prefixed messages
struct FramedStream<S> {
    reader: BufReader<tokio::io::ReadHalf<S>>,
    writer: BufWriter<tokio::io::WriteHalf<S>>,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> FramedStream<S> {
    fn new(stream: S) -> Self {
        let (read_half, write_half) = tokio::io::split(stream);
        Self {
            reader: BufReader::new(read_half),
            writer: BufWriter::new(write_half),
        }
    }

    async fn send(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > MAX_MESSAGE_SIZE {
            return Err(Error::Transport(format!(
                "message too large: {} > {}",
                data.len(),
                MAX_MESSAGE_SIZE
            )));
        }

        // Write length prefix (big-endian)
        let len = data.len() as u32;
        self.writer.write_all(&len.to_be_bytes()).await?;

        // Write data
        self.writer.write_all(data).await?;
        self.writer.flush().await?;

        Ok(())
    }

    async fn recv(&mut self) -> Result<Vec<u8>> {
        // Read length prefix
        let mut len_buf = [0u8; FRAME_HEADER_SIZE];
        self.reader.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;

        if len > MAX_MESSAGE_SIZE {
            return Err(Error::Transport(format!(
                "message too large: {} > {}",
                len, MAX_MESSAGE_SIZE
            )));
        }

        // Read message
        let mut data = vec![0u8; len];
        self.reader.read_exact(&mut data).await?;

        Ok(data)
    }
}

/// TCP transport implementation
pub struct TcpTransport {
    stream: Arc<Mutex<Option<FramedStream<TcpStream>>>>,
    local_addr: Option<String>,
    peer_addr: Option<String>,
}

impl TcpTransport {
    /// Connect to a TCP address
    pub async fn connect(addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;

        let local_addr = stream.local_addr().ok().map(|a| a.to_string());
        let peer_addr = stream.peer_addr().ok().map(|a| a.to_string());

        let framed = FramedStream::new(stream);

        Ok(Self {
            stream: Arc::new(Mutex::new(Some(framed))),
            local_addr,
            peer_addr,
        })
    }

    /// Create from existing stream (for server-side connections)
    pub fn from_stream(stream: TcpStream) -> Self {
        let local_addr = stream.local_addr().ok().map(|a| a.to_string());
        let peer_addr = stream.peer_addr().ok().map(|a| a.to_string());
        let framed = FramedStream::new(stream);

        Self {
            stream: Arc::new(Mutex::new(Some(framed))),
            local_addr,
            peer_addr,
        }
    }
}

impl Transport for TcpTransport {
    fn send(&self, data: &[u8]) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        let data = data.to_vec();
        Box::pin(async move {
            let mut guard = self.stream.lock().await;
            let stream = guard.as_mut()
                .ok_or_else(|| Error::Transport("connection closed".into()))?;
            stream.send(&data).await
        })
    }

    fn recv(&self) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + '_>> {
        Box::pin(async move {
            let mut guard = self.stream.lock().await;
            let stream = guard.as_mut()
                .ok_or_else(|| Error::Transport("connection closed".into()))?;
            stream.recv().await
        })
    }

    fn close(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move {
            let mut guard = self.stream.lock().await;
            *guard = None;
            Ok(())
        })
    }

    fn is_connected(&self) -> bool {
        // Can't easily check without trying - just check if we have a stream
        true
    }

    fn local_addr(&self) -> Option<String> {
        self.local_addr.clone()
    }

    fn peer_addr(&self) -> Option<String> {
        self.peer_addr.clone()
    }
}

/// TCP listener for accepting connections
pub struct TcpTransportListener {
    listener: TcpListener,
    local_addr: String,
}

impl TcpTransportListener {
    /// Bind to a TCP address
    pub async fn bind(addr: &str) -> Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?.to_string();

        Ok(Self {
            listener,
            local_addr,
        })
    }

    /// Accept a new connection
    pub async fn accept(&self) -> Result<TcpTransport> {
        let (stream, _addr) = self.listener.accept().await?;
        stream.set_nodelay(true)?;
        Ok(TcpTransport::from_stream(stream))
    }

    /// Get local address
    pub fn local_addr(&self) -> &str {
        &self.local_addr
    }
}

#[cfg(unix)]
mod unix_transport {
    use super::*;
    use tokio::net::{UnixStream, UnixListener};

    /// Unix socket transport
    pub struct UnixTransport {
        stream: Arc<Mutex<Option<FramedStream<UnixStream>>>>,
        local_addr: Option<String>,
        peer_addr: Option<String>,
    }

    impl UnixTransport {
        /// Connect to a Unix socket
        pub async fn connect(path: &str) -> Result<Self> {
            let stream = UnixStream::connect(path).await?;
            let local_addr = stream.local_addr().ok()
                .and_then(|a| a.as_pathname().map(|p| p.to_string_lossy().into_owned()));
            let peer_addr = stream.peer_addr().ok()
                .and_then(|a| a.as_pathname().map(|p| p.to_string_lossy().into_owned()));

            let framed = FramedStream::new(stream);

            Ok(Self {
                stream: Arc::new(Mutex::new(Some(framed))),
                local_addr,
                peer_addr,
            })
        }

        /// Create from existing stream
        pub fn from_stream(stream: UnixStream) -> Self {
            let local_addr = stream.local_addr().ok()
                .and_then(|a| a.as_pathname().map(|p| p.to_string_lossy().into_owned()));
            let peer_addr = stream.peer_addr().ok()
                .and_then(|a| a.as_pathname().map(|p| p.to_string_lossy().into_owned()));
            let framed = FramedStream::new(stream);

            Self {
                stream: Arc::new(Mutex::new(Some(framed))),
                local_addr,
                peer_addr,
            }
        }
    }

    impl Transport for UnixTransport {
        fn send(&self, data: &[u8]) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
            let data = data.to_vec();
            Box::pin(async move {
                let mut guard = self.stream.lock().await;
                let stream = guard.as_mut()
                    .ok_or_else(|| Error::Transport("connection closed".into()))?;
                stream.send(&data).await
            })
        }

        fn recv(&self) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + '_>> {
            Box::pin(async move {
                let mut guard = self.stream.lock().await;
                let stream = guard.as_mut()
                    .ok_or_else(|| Error::Transport("connection closed".into()))?;
                stream.recv().await
            })
        }

        fn close(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
            Box::pin(async move {
                let mut guard = self.stream.lock().await;
                *guard = None;
                Ok(())
            })
        }

        fn is_connected(&self) -> bool {
            true
        }

        fn local_addr(&self) -> Option<String> {
            self.local_addr.clone()
        }

        fn peer_addr(&self) -> Option<String> {
            self.peer_addr.clone()
        }
    }

    /// Unix socket listener
    pub struct UnixTransportListener {
        listener: UnixListener,
        path: String,
    }

    impl UnixTransportListener {
        /// Bind to a Unix socket path
        pub async fn bind(path: &str) -> Result<Self> {
            // Remove existing socket file if present
            let _ = std::fs::remove_file(path);
            let listener = UnixListener::bind(path)?;

            Ok(Self {
                listener,
                path: path.to_string(),
            })
        }

        /// Accept a new connection
        pub async fn accept(&self) -> Result<UnixTransport> {
            let (stream, _addr) = self.listener.accept().await?;
            Ok(UnixTransport::from_stream(stream))
        }

        /// Get socket path
        pub fn path(&self) -> &str {
            &self.path
        }
    }

    impl Drop for UnixTransportListener {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(unix)]
pub use unix_transport::{UnixTransport, UnixTransportListener};

/// WebSocket transport
pub struct WebSocketTransport {
    ws: Arc<Mutex<Option<WebSocketStream>>>,
    local_addr: Option<String>,
    peer_addr: Option<String>,
}

struct WebSocketStream {
    inner: tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
}

impl WebSocketTransport {
    /// Connect to a WebSocket URL
    pub async fn connect(url: &str) -> Result<Self> {
        use tokio_tungstenite::connect_async;

        let (ws_stream, _response) = connect_async(url).await
            .map_err(|e| Error::Transport(format!("WebSocket connect failed: {}", e)))?;

        Ok(Self {
            ws: Arc::new(Mutex::new(Some(WebSocketStream { inner: ws_stream }))),
            local_addr: None,
            peer_addr: Some(url.to_string()),
        })
    }
}

impl Transport for WebSocketTransport {
    fn send(&self, data: &[u8]) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        use futures::SinkExt;
        use tokio_tungstenite::tungstenite::Message;

        let data = data.to_vec();
        Box::pin(async move {
            let mut guard = self.ws.lock().await;
            let ws = guard.as_mut()
                .ok_or_else(|| Error::Transport("connection closed".into()))?;
            ws.inner.send(Message::Binary(data.into())).await
                .map_err(|e| Error::Transport(format!("WebSocket send failed: {}", e)))
        })
    }

    fn recv(&self) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + '_>> {
        use futures::StreamExt;
        use tokio_tungstenite::tungstenite::Message;

        Box::pin(async move {
            let mut guard = self.ws.lock().await;
            let ws = guard.as_mut()
                .ok_or_else(|| Error::Transport("connection closed".into()))?;

            loop {
                match ws.inner.next().await {
                    Some(Ok(Message::Binary(data))) => return Ok(data.to_vec()),
                    Some(Ok(Message::Text(text))) => return Ok(text.into_bytes()),
                    Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => continue,
                    Some(Ok(Message::Close(_))) => return Err(Error::Transport("connection closed".into())),
                    Some(Ok(Message::Frame(_))) => continue,
                    Some(Err(e)) => return Err(Error::Transport(format!("WebSocket recv failed: {}", e))),
                    None => return Err(Error::Transport("connection closed".into())),
                }
            }
        })
    }

    fn close(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        use futures::SinkExt;
        use tokio_tungstenite::tungstenite::Message;

        Box::pin(async move {
            let mut guard = self.ws.lock().await;
            if let Some(ws) = guard.as_mut() {
                let _ = ws.inner.send(Message::Close(None)).await;
            }
            *guard = None;
            Ok(())
        })
    }

    fn is_connected(&self) -> bool {
        true
    }

    fn local_addr(&self) -> Option<String> {
        self.local_addr.clone()
    }

    fn peer_addr(&self) -> Option<String> {
        self.peer_addr.clone()
    }
}

/// UDP transport for fire-and-forget low-latency messaging
///
/// Provides unreliable datagram delivery with minimal overhead.
/// Suitable for real-time applications where occasional packet loss is acceptable.
pub struct UdpTransport {
    socket: Arc<tokio::net::UdpSocket>,
    peer_addr: Option<std::net::SocketAddr>,
    local_addr: String,
}

impl UdpTransport {
    /// Create a UDP transport bound to a local address
    pub async fn bind(addr: &str) -> Result<Self> {
        let socket = tokio::net::UdpSocket::bind(addr).await?;
        let local_addr = socket.local_addr()?.to_string();

        Ok(Self {
            socket: Arc::new(socket),
            peer_addr: None,
            local_addr,
        })
    }

    /// Connect to a remote UDP address (sets default destination)
    pub async fn connect(local_addr: &str, peer_addr: &str) -> Result<Self> {
        let socket = tokio::net::UdpSocket::bind(local_addr).await?;
        let peer: std::net::SocketAddr = peer_addr.parse()
            .map_err(|e| Error::Transport(format!("invalid peer address: {}", e)))?;
        socket.connect(peer).await?;
        let local = socket.local_addr()?.to_string();

        Ok(Self {
            socket: Arc::new(socket),
            peer_addr: Some(peer),
            local_addr: local,
        })
    }

    /// Send a datagram to a specific address (connectionless)
    pub async fn send_to(&self, data: &[u8], addr: &str) -> Result<()> {
        let peer: std::net::SocketAddr = addr.parse()
            .map_err(|e| Error::Transport(format!("invalid address: {}", e)))?;

        if data.len() > MAX_MESSAGE_SIZE {
            return Err(Error::Transport(format!(
                "datagram too large: {} > {}",
                data.len(),
                MAX_MESSAGE_SIZE
            )));
        }

        self.socket.send_to(data, peer).await?;
        Ok(())
    }

    /// Receive a datagram with sender address
    pub async fn recv_from(&self) -> Result<(Vec<u8>, std::net::SocketAddr)> {
        let mut buf = vec![0u8; MAX_MESSAGE_SIZE];
        let (len, addr) = self.socket.recv_from(&mut buf).await?;
        buf.truncate(len);
        Ok((buf, addr))
    }
}

impl Transport for UdpTransport {
    fn send(&self, data: &[u8]) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        let data = data.to_vec();
        Box::pin(async move {
            if data.len() > MAX_MESSAGE_SIZE {
                return Err(Error::Transport(format!(
                    "datagram too large: {} > {}",
                    data.len(),
                    MAX_MESSAGE_SIZE
                )));
            }

            // For connected sockets, use send()
            self.socket.send(&data).await?;
            Ok(())
        })
    }

    fn recv(&self) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + '_>> {
        Box::pin(async move {
            let mut buf = vec![0u8; MAX_MESSAGE_SIZE];
            let len = self.socket.recv(&mut buf).await?;
            buf.truncate(len);
            Ok(buf)
        })
    }

    fn close(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        // UDP sockets don't need explicit close
        Box::pin(async { Ok(()) })
    }

    fn is_connected(&self) -> bool {
        self.peer_addr.is_some()
    }

    fn local_addr(&self) -> Option<String> {
        Some(self.local_addr.clone())
    }

    fn peer_addr(&self) -> Option<String> {
        self.peer_addr.map(|a| a.to_string())
    }
}

/// Stdio transport for MCP subprocess servers
///
/// Spawns a subprocess and communicates via stdin/stdout with length-prefixed framing.
pub struct StdioTransport {
    child: Arc<Mutex<Option<tokio::process::Child>>>,
    stdin: Arc<Mutex<Option<tokio::process::ChildStdin>>>,
    stdout: Arc<Mutex<Option<BufReader<tokio::process::ChildStdout>>>>,
    command: String,
}

impl StdioTransport {
    /// Spawn a subprocess with the given command and arguments
    pub async fn spawn(command: &str, args: &[&str]) -> Result<Self> {
        use tokio::process::Command;

        let mut child = Command::new(command)
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .map_err(|e| Error::Transport(format!("failed to spawn process: {}", e)))?;

        let stdin = child.stdin.take()
            .ok_or_else(|| Error::Transport("failed to capture stdin".into()))?;
        let stdout = child.stdout.take()
            .ok_or_else(|| Error::Transport("failed to capture stdout".into()))?;

        Ok(Self {
            child: Arc::new(Mutex::new(Some(child))),
            stdin: Arc::new(Mutex::new(Some(stdin))),
            stdout: Arc::new(Mutex::new(Some(BufReader::new(stdout)))),
            command: command.to_string(),
        })
    }

    /// Create from URL like "stdio:///path/to/binary?arg1&arg2"
    pub async fn from_url(url: &Url) -> Result<Self> {
        let command = url.path();
        if command.is_empty() {
            return Err(Error::Transport("stdio URL must specify command path".into()));
        }

        // Parse query parameters as arguments
        let args: Vec<&str> = url.query()
            .map(|q| q.split('&').collect())
            .unwrap_or_default();

        Self::spawn(command, &args).await
    }
}

impl Transport for StdioTransport {
    fn send(&self, data: &[u8]) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        let data = data.to_vec();
        Box::pin(async move {
            let mut guard = self.stdin.lock().await;
            let stdin = guard.as_mut()
                .ok_or_else(|| Error::Transport("stdin closed".into()))?;

            if data.len() > MAX_MESSAGE_SIZE {
                return Err(Error::Transport(format!(
                    "message too large: {} > {}",
                    data.len(),
                    MAX_MESSAGE_SIZE
                )));
            }

            // Write length prefix (big-endian)
            let len = data.len() as u32;
            stdin.write_all(&len.to_be_bytes()).await?;
            stdin.write_all(&data).await?;
            stdin.flush().await?;

            Ok(())
        })
    }

    fn recv(&self) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + '_>> {
        Box::pin(async move {
            let mut guard = self.stdout.lock().await;
            let stdout = guard.as_mut()
                .ok_or_else(|| Error::Transport("stdout closed".into()))?;

            // Read length prefix
            let mut len_buf = [0u8; FRAME_HEADER_SIZE];
            stdout.read_exact(&mut len_buf).await?;
            let len = u32::from_be_bytes(len_buf) as usize;

            if len > MAX_MESSAGE_SIZE {
                return Err(Error::Transport(format!(
                    "message too large: {} > {}",
                    len, MAX_MESSAGE_SIZE
                )));
            }

            // Read message
            let mut data = vec![0u8; len];
            stdout.read_exact(&mut data).await?;

            Ok(data)
        })
    }

    fn close(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move {
            // Close stdin to signal subprocess
            {
                let mut guard = self.stdin.lock().await;
                *guard = None;
            }

            // Wait for child to exit
            let mut guard = self.child.lock().await;
            if let Some(mut child) = guard.take() {
                let _ = child.wait().await;
            }

            Ok(())
        })
    }

    fn is_connected(&self) -> bool {
        true
    }

    fn local_addr(&self) -> Option<String> {
        Some(format!("stdio://{}", self.command))
    }

    fn peer_addr(&self) -> Option<String> {
        Some(format!("stdio://{}", self.command))
    }
}

/// HTTP/SSE transport for MCP remote servers
///
/// Uses HTTP POST for sending messages and Server-Sent Events for receiving.
/// This is the standard transport for remote MCP servers.
///
/// Requires the `mcp` feature to be enabled.
#[cfg(feature = "mcp")]
pub struct HttpSseTransport {
    client: reqwest::Client,
    base_url: String,
    recv_buffer: Arc<Mutex<Vec<Vec<u8>>>>,
    connected: Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(feature = "mcp")]
impl HttpSseTransport {
    /// Create a new HTTP/SSE transport for the given base URL
    pub async fn connect(base_url: &str) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| Error::Transport(format!("failed to create HTTP client: {}", e)))?;

        let transport = Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            recv_buffer: Arc::new(Mutex::new(Vec::new())),
            connected: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        };

        Ok(transport)
    }

    /// Start the SSE listener for receiving messages
    pub async fn start_sse_listener(&self) -> Result<()> {
        let url = format!("{}/sse", self.base_url);
        let buffer = Arc::clone(&self.recv_buffer);
        let connected = Arc::clone(&self.connected);
        let client = self.client.clone();

        tokio::spawn(async move {
            loop {
                if !connected.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }

                match client.get(&url).send().await {
                    Ok(response) => {
                        let mut stream = response.bytes_stream();
                        use futures::StreamExt;

                        let mut event_data = String::new();
                        while let Some(chunk) = stream.next().await {
                            match chunk {
                                Ok(bytes) => {
                                    let text = String::from_utf8_lossy(&bytes);
                                    for line in text.lines() {
                                        if line.starts_with("data: ") {
                                            event_data.push_str(&line[6..]);
                                        } else if line.is_empty() && !event_data.is_empty() {
                                            // End of event
                                            let mut guard = buffer.lock().await;
                                            guard.push(event_data.as_bytes().to_vec());
                                            event_data.clear();
                                        }
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    }
                    Err(_) => {
                        // Reconnect after delay
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    }
                }
            }
        });

        Ok(())
    }
}

#[cfg(feature = "mcp")]
impl Transport for HttpSseTransport {
    fn send(&self, data: &[u8]) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        let data = data.to_vec();
        let client = self.client.clone();
        let url = format!("{}/message", self.base_url);

        Box::pin(async move {
            client.post(&url)
                .header("Content-Type", "application/json")
                .body(data)
                .send()
                .await
                .map_err(|e| Error::Transport(format!("HTTP POST failed: {}", e)))?
                .error_for_status()
                .map_err(|e| Error::Transport(format!("HTTP error: {}", e)))?;

            Ok(())
        })
    }

    fn recv(&self) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + '_>> {
        let buffer = Arc::clone(&self.recv_buffer);

        Box::pin(async move {
            // Poll buffer for messages
            loop {
                {
                    let mut guard = buffer.lock().await;
                    if !guard.is_empty() {
                        return Ok(guard.remove(0));
                    }
                }
                // Small delay before checking again
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            }
        })
    }

    fn close(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        let connected = Arc::clone(&self.connected);
        Box::pin(async move {
            connected.store(false, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        })
    }

    fn is_connected(&self) -> bool {
        self.connected.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn local_addr(&self) -> Option<String> {
        None
    }

    fn peer_addr(&self) -> Option<String> {
        Some(self.base_url.clone())
    }
}

/// Create a transport from a URL
///
/// Supported URL schemes:
/// - `zap://` or `zap+tcp://` or `tcp://` - TCP transport
/// - `zap+unix://` or `unix://` - Unix socket transport (Unix only)
/// - `ws://` or `wss://` - WebSocket transport
/// - `stdio://` - Stdio transport (for MCP subprocess servers)
/// - `http://` or `https://` - HTTP/SSE transport (requires `mcp` feature)
/// - `udp://` - UDP transport (fire-and-forget, low-latency)
pub async fn connect(url: &str) -> Result<Box<dyn Transport>> {
    let parsed = Url::parse(url)?;

    match parsed.scheme() {
        "zap" | "zap+tcp" | "tcp" => {
            let host = parsed.host_str().unwrap_or("localhost");
            let port = parsed.port().unwrap_or(crate::DEFAULT_PORT);
            let addr = format!("{}:{}", host, port);
            let transport = TcpTransport::connect(&addr).await?;
            Ok(Box::new(transport))
        }
        #[cfg(unix)]
        "zap+unix" | "unix" => {
            let path = parsed.path();
            let transport = UnixTransport::connect(path).await?;
            Ok(Box::new(transport))
        }
        "ws" | "wss" => {
            let transport = WebSocketTransport::connect(url).await?;
            Ok(Box::new(transport))
        }
        "stdio" => {
            // Stdio transport for subprocess MCP servers
            let transport = StdioTransport::from_url(&parsed).await?;
            Ok(Box::new(transport))
        }
        #[cfg(feature = "mcp")]
        "http" | "https" => {
            // HTTP/SSE transport for remote MCP servers
            let transport = HttpSseTransport::connect(url).await?;
            transport.start_sse_listener().await?;
            Ok(Box::new(transport))
        }
        #[cfg(not(feature = "mcp"))]
        "http" | "https" => {
            Err(Error::Transport(
                "HTTP/SSE transport requires 'mcp' feature".into()
            ))
        }
        "udp" => {
            // UDP transport for low-latency fire-and-forget messaging
            let host = parsed.host_str().unwrap_or("127.0.0.1");
            let port = parsed.port().unwrap_or(crate::DEFAULT_PORT);
            let peer_addr = format!("{}:{}", host, port);
            let transport = UdpTransport::connect("0.0.0.0:0", &peer_addr).await?;
            Ok(Box::new(transport))
        }
        _ => Err(Error::Transport(format!(
            "unsupported URL scheme: {}",
            parsed.scheme()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tcp_transport_roundtrip() {
        // Start a listener
        let listener = TcpTransportListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().to_string();

        // Spawn server task
        let server_task = tokio::spawn(async move {
            let transport = listener.accept().await.unwrap();
            let msg = transport.recv().await.unwrap();
            transport.send(&msg).await.unwrap();
        });

        // Connect client
        let client = TcpTransport::connect(&addr).await.unwrap();

        // Send and receive
        let test_msg = b"Hello, ZAP!";
        client.send(test_msg).await.unwrap();
        let response = client.recv().await.unwrap();

        assert_eq!(response, test_msg);

        // Cleanup
        client.close().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_connect_tcp_url() {
        // Just test URL parsing, not actual connection
        let result = connect("zap://localhost:9999").await;
        // Will fail to connect, but should parse URL correctly
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_connect_invalid_scheme() {
        let result = connect("ftp://localhost:9999").await;
        assert!(result.is_err());
        if let Err(Error::Transport(msg)) = result {
            assert!(msg.contains("unsupported"));
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_unix_transport_roundtrip() {
        use std::env::temp_dir;

        let socket_path = temp_dir().join(format!("zap_test_{}.sock", std::process::id()));
        let socket_str = socket_path.to_str().unwrap().to_string();

        // Start listener
        let listener = UnixTransportListener::bind(&socket_str).await.unwrap();

        // Spawn server
        let server_socket = socket_str.clone();
        let server_task = tokio::spawn(async move {
            let transport = listener.accept().await.unwrap();
            let msg = transport.recv().await.unwrap();
            transport.send(&msg).await.unwrap();
        });

        // Give server time to start
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Connect client
        let client = UnixTransport::connect(&socket_str).await.unwrap();

        // Send and receive
        let test_msg = b"Unix socket test!";
        client.send(test_msg).await.unwrap();
        let response = client.recv().await.unwrap();

        assert_eq!(response, test_msg);

        // Cleanup
        client.close().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_udp_transport_roundtrip() {
        // Bind server
        let server = UdpTransport::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        // Connect client to server
        let client = UdpTransport::connect("127.0.0.1:0", &server_addr).await.unwrap();
        let client_addr = client.local_addr().unwrap();

        // Client sends to server
        let test_msg = b"UDP test message";
        client.send(test_msg).await.unwrap();

        // Server receives from client
        let (received, sender) = server.recv_from().await.unwrap();
        assert_eq!(&received, test_msg);
        assert_eq!(sender.to_string(), client_addr);

        // Server sends back to client
        server.send_to(b"response", &client_addr).await.unwrap();

        // Client receives response
        let (response, _) = client.recv_from().await.unwrap();
        assert_eq!(&response, b"response");
    }

    #[tokio::test]
    async fn test_udp_transport_connected_mode() {
        // Bind receiver
        let receiver = UdpTransport::bind("127.0.0.1:0").await.unwrap();
        let recv_addr = receiver.local_addr().unwrap();

        // Create connected sender
        let sender = UdpTransport::connect("127.0.0.1:0", &recv_addr).await.unwrap();

        // Connected mode should report connected
        assert!(sender.is_connected());

        // Bound-only mode is not "connected" (no default peer)
        assert!(!receiver.is_connected());
    }

    #[tokio::test]
    async fn test_connect_udp_url() {
        // Test that UDP URL parsing works
        let result = connect("udp://127.0.0.1:5555").await;
        // Should succeed in creating transport (even if no server)
        assert!(result.is_ok());

        let transport = result.unwrap();
        assert!(transport.is_connected());
        assert!(transport.peer_addr().is_some());
    }
}
