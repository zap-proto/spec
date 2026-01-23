# ZAP - Zero-copy Agent Protocol

High-performance Cap'n Proto RPC for AI agent communication.

ZAP provides a unified protocol for connecting to and aggregating MCP (Model Context Protocol) servers, enabling efficient tool calling, resource access, and prompt management for AI agents.

## Features

- **Zero-copy Serialization**: Cap'n Proto for minimal overhead
- **Multi-transport**: Unix sockets, TCP, WebSocket, HTTP
- **MCP Gateway**: Aggregate multiple MCP servers behind a single endpoint
- **Cross-language**: Rust, Python, TypeScript implementations
- **High Performance**: Designed for AI workloads with low latency

## Packages

| Package | Language | Install |
|---------|----------|---------|
| `hanzo-zap` | Rust | `cargo add hanzo-zap` |
| `hanzo-zap` | Python | `pip install hanzo-zap` |
| `@hanzo/zap` | TypeScript | `npm install @hanzo/zap` |

## Quick Start

### Rust

```rust
use zap::{Client, Gateway, Config};

// Connect to a ZAP gateway
let client = Client::connect("zap://localhost:9999").await?;

// List available tools
let tools = client.list_tools().await?;

// Call a tool
let result = client.call_tool("search", json!({"query": "hello"})).await?;
```

### Python

```python
from hanzo_zap import Client, Gateway

# Connect to a ZAP gateway
client = await Client.connect("zap://localhost:9999")

# List available tools
tools = await client.list_tools()

# Call a tool
result = await client.call_tool("search", {"query": "hello"})
```

### TypeScript

```typescript
import { Client, Gateway } from '@hanzo/zap';

// Connect to a ZAP gateway
const client = await Client.connect('zap://localhost:9999');

// List available tools
const tools = await client.listTools();

// Call a tool
const result = await client.callTool('search', { query: 'hello' });
```

## CLI Tools

### zap - Command Line Client

```bash
# List tools from a gateway
zap tools list

# Call a tool
zap call search --query "hello world"

# List resources
zap resources list

# Read a resource
zap read file:///path/to/file
```

### zapd - Gateway Daemon

```bash
# Start gateway with config file
zapd --config /etc/zap/config.toml

# Start with inline servers
zapd --server "stdio://npx @modelcontextprotocol/server-filesystem"
```

## Configuration

Create a `zap.toml` configuration file:

```toml
[gateway]
listen = "0.0.0.0"
port = 9999
log_level = "info"

[[servers]]
name = "filesystem"
transport = "stdio"
command = "npx"
args = ["@modelcontextprotocol/server-filesystem", "/path/to/files"]

[[servers]]
name = "database"
transport = "http"
url = "http://localhost:8080/mcp"

[[servers]]
name = "search"
transport = "websocket"
url = "ws://localhost:9000/ws"
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        AI Client                            │
│                    (Claude, GPT, etc.)                      │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           │ ZAP Protocol (Cap'n Proto RPC)
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                      ZAP Gateway                            │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                  Server Registry                      │  │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  │  │
│  │  │Server A │  │Server B │  │Server C │  │Server D │  │  │
│  │  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘  │  │
│  └───────┼────────────┼────────────┼────────────┼───────┘  │
│          │            │            │            │          │
└──────────┼────────────┼────────────┼────────────┼──────────┘
           │            │            │            │
           ▼            ▼            ▼            ▼
      ┌────────┐   ┌────────┐   ┌────────┐   ┌────────┐
      │ stdio  │   │  HTTP  │   │  WS    │   │ Unix   │
      │ MCP    │   │  MCP   │   │  MCP   │   │ Socket │
      │ Server │   │ Server │   │ Server │   │ Server │
      └────────┘   └────────┘   └────────┘   └────────┘
```

## Protocol

ZAP uses Cap'n Proto for efficient serialization and RPC:

```capnp
interface Zap {
  # Server discovery
  initialize @0 (info :ServerInfo) -> (info :ServerInfo);

  # Tools
  listTools @1 () -> (tools :List(Tool));
  callTool @2 (name :Text, arguments :Text) -> (result :ToolResult);

  # Resources
  listResources @3 () -> (resources :List(Resource));
  readResource @4 (uri :Text) -> (content :ResourceContent);

  # Prompts
  listPrompts @5 () -> (prompts :List(Prompt));
  getPrompt @6 (name :Text, arguments :Text) -> (messages :List(PromptMessage));
}
```

## Development

### Rust

```bash
cd /path/to/hanzo-zap
cargo build
cargo test
```

### Python

```bash
cd /path/to/hanzo-zap/python
uv sync
uv run pytest
```

### TypeScript

```bash
cd /path/to/hanzo-zap/typescript
npm install
npm run build
npm test
```

## Documentation

Full documentation available at: https://hanzoai.github.io/zap

## License

MIT OR Apache-2.0

## Links

- [GitHub](https://github.com/hanzoai/zap)
- [Documentation](https://hanzoai.github.io/zap)
- [Hanzo AI](https://hanzo.ai)
