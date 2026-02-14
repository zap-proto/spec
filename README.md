# ZAP - Zero-Copy App Proto

High-performance Cap'n Proto RPC for AI agent communication.

ZAP provides a unified protocol for connecting to and aggregating MCP (Model Context Protocol) servers, enabling efficient tool calling, resource access, and prompt management for AI agents.

**"Infinity Times Faster"** - When decode time is zero, the speedup is mathematically infinite.

## Features

- **Zero-copy Serialization**: Cap'n Proto wire format = memory format
- **Promise Pipelining**: N dependent calls in 1 round trip
- **Capability Security**: Possession = permission, no ambient authority
- **Multi-transport**: Unix sockets, TCP, TLS, QUIC, WebSocket, shared memory
- **MCP Gateway**: Aggregate multiple MCP servers behind a single endpoint
- **Agent Consensus**: Built-in metastable voting for multi-agent coordination
- **Post-Quantum Ready**: ML-KEM-768, ML-DSA-65, Ringtail signatures
- **Cross-language**: 17 language bindings

## Official Packages

| Package | Language | Install |
|---------|----------|---------|
| `zap-protocol` | Rust | `cargo add zap-protocol` |
| `zap-protocol` | Python | `pip install zap-protocol` |
| `@zap-protocol/zap` | TypeScript | `npm install @zap-protocol/zap` |
| `zap-protocol/zap-go` | Go | `go get github.com/zap-protocol/zap-go` |

## Language Bindings

All language bindings are maintained in the [zap-protocol](https://github.com/zap-protocol) GitHub organization:

| Language | Repository | Status |
|----------|------------|--------|
| **Rust** | [zap-protocol/zap](https://github.com/zap-protocol/zap) | Production |
| **Go** | [zap-protocol/zap-go](https://github.com/zap-protocol/zap-go) | Production |
| **Python** | [zap-protocol/zap-py](https://github.com/zap-protocol/zap-py) | Production |
| **JavaScript/TypeScript** | [zap-protocol/zap-js](https://github.com/zap-protocol/zap-js) | Production |
| **C++** | [zap-protocol/zap-cpp](https://github.com/zap-protocol/zap-cpp) | Stable |
| **C** | [zap-protocol/zap-c](https://github.com/zap-protocol/zap-c) | Stable |
| **C#** | [zap-protocol/zap-cs](https://github.com/zap-protocol/zap-cs) | Development |
| **Java** | [zap-protocol/zap-java](https://github.com/zap-protocol/zap-java) | Development |
| **Haskell** | [zap-protocol/zap-haskell](https://github.com/zap-protocol/zap-haskell) | Development |
| **OCaml** | [zap-protocol/zap-ocaml](https://github.com/zap-protocol/zap-ocaml) | Development |
| **Erlang** | [zap-protocol/zap-erlang](https://github.com/zap-protocol/zap-erlang) | Development |
| **D** | [zap-protocol/zap-d](https://github.com/zap-protocol/zap-d) | Development |
| **Lua** | [zap-protocol/zap-lua](https://github.com/zap-protocol/zap-lua) | Development |
| **Nim** | [zap-protocol/zap-nim](https://github.com/zap-protocol/zap-nim) | Development |
| **Ruby** | [zap-protocol/zap-ruby](https://github.com/zap-protocol/zap-ruby) | Development |
| **Scala** | [zap-protocol/zap-scala](https://github.com/zap-protocol/zap-scala) | Development |

## Quick Start

### Rust

```rust
use zap_protocol::{Client, Gateway};

// Connect to a ZAP gateway
let client = Client::connect("zap://localhost:9999").await?;

// List available tools
let tools = client.list_tools().await?;

// Call a tool
let result = client.call_tool("search", json!({"query": "hello"})).await?;
```

### Go

```go
import "github.com/zap-protocol/zap-go"

// Connect to a ZAP gateway
client, err := zap.Connect("zap://localhost:9999")

// List available tools
tools, err := client.ListTools(ctx)

// Call a tool
result, err := client.CallTool(ctx, "search", map[string]any{"query": "hello"})
```

### Python

```python
from zap import ZAP

# FastMCP-style decorator API
zap = ZAP("my-agent")

@zap.tool
def search(query: str) -> str:
    """Search for information."""
    return f"Results for: {query}"

# Or connect as client
from zap import Client
client = await Client.connect("zap://localhost:9999")
tools = await client.list_tools()
```

### TypeScript

```typescript
import { Client, Gateway } from '@zap-protocol/zap';

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

## Tools

| Tool | Repository | Description |
|------|------------|-------------|
| **VS Code** | [zap-protocol/zap-vscode](https://github.com/zap-protocol/zap-vscode) | VS Code extension |
| **Vim** | [zap-protocol/zap-vim](https://github.com/zap-protocol/zap-vim) | Vim plugin |
| **IntelliJ** | [zap-protocol/zap-intellij](https://github.com/zap-protocol/zap-intellij) | JetBrains plugin |
| **LSP** | [zap-protocol/zap-lsp](https://github.com/zap-protocol/zap-lsp) | Language server |
| **Wireshark** | [zap-protocol/zap-wireshark](https://github.com/zap-protocol/zap-wireshark) | Protocol dissector |

## Documentation

Full documentation available at: https://zap.hanzo.ai

- [Quick Start](https://zap.hanzo.ai/docs/quickstart)
- [Architecture](https://zap.hanzo.ai/docs/architecture)
- [Protocol Deep Dive](https://zap.hanzo.ai/docs/protocol)
- [Transport Layer](https://zap.hanzo.ai/docs/transports)
- [Why ZAP over MCP?](https://zap.hanzo.ai/docs/concepts/why-zap)

## License

MIT OR Apache-2.0

## Links

- [GitHub Organization](https://github.com/zap-protocol)
- [Documentation](https://zap.hanzo.ai)
- [Hanzo AI](https://hanzo.ai)
- [HIP-007 Whitepaper](https://zap.hanzo.ai/docs/whitepaper)
