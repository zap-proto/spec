# ZAP - Zero-Copy App Proto

<p align="center">
  <strong>High-performance zero-copy RPC for AI agent communication</strong>
</p>

<p align="center">
  <a href="https://crates.io/crates/zap-proto"><img src="https://img.shields.io/crates/v/zap-schema.svg" alt="crates.io"></a>
  <a href="https://www.npmjs.com/package/@zap-proto/zapc"><img src="https://img.shields.io/npm/v/@zap-proto/zapc.svg" alt="npm"></a>
  <a href="https://pypi.org/project/zap-proto/"><img src="https://img.shields.io/pypi/v/zap-schema.svg" alt="PyPI"></a>
  <a href="https://github.com/hanzo-ai/zap/actions"><img src="https://github.com/hanzo-ai/zap/workflows/CI/badge.svg" alt="CI"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg" alt="License"></a>
</p>

---

ZAP is a high-performance zero-copy RPC protocol designed for AI agent communication, built by [Hanzo AI](https://hanzo.ai). It provides:

- **Clean Schema Language** - Whitespace-significant syntax that's easy to read and write
- **Zero-copy Serialization** - Minimal overhead binary format
- **Multi-transport** - TCP, Unix sockets, WebSocket, UDP, HTTP/SSE, Stdio
- **MCP Gateway** - Aggregate multiple MCP servers behind a single endpoint
- **Post-Quantum Crypto** - ML-KEM and ML-DSA for future-proof security
- **Agent Consensus** - Trustless voting for distributed AI systems
- **Cross-language** - Rust, Python, TypeScript, Go, C/C++

## Installation

### Schema Compiler (zapc)

```bash
# npm (recommended)
npm install -g @zap-proto/zapc

# Cargo
cargo install zap-schema --bin zapc

# Or use npx without installing
npx @zap-proto/zapc --help
```

### Runtime Libraries

| Language | Package | Install |
|----------|---------|---------|
| Rust | `zap-proto` | `cargo add zap-proto` |
| Python | `zap-proto` | `pip install zap-proto` |
| TypeScript | `@zap-proto/zap` | `npm install @zap-proto/zap` |
| Go | `github.com/hanzo-ai/zap` | `go get github.com/hanzo-ai/zap` |

## ZAP Schema Language

ZAP uses a clean, whitespace-significant syntax:

```zap
# person.zap - Clean and minimal schema definition

struct Person
  name Text
  email Text
  age UInt32
  phones List(PhoneNumber)

  struct PhoneNumber
    number Text
    type Type

    enum Type
      mobile
      home
      work

interface PersonService
  create (person Person) -> (id Text)
  get (id Text) -> (person Person)
  list () -> (people List(Person))
  search (query Text) -> (results List(Person))
  delete (id Text) -> (success Bool)
```

### Compile Schema

```bash
# Compile to ZAP binary format
zapc compile person.zap --out person.zapb

# Generate Rust code
zapc generate person.zap --lang rust --out ./gen/

# Generate for multiple languages
zapc generate person.zap --lang go --out ./gen/go/
zapc generate person.zap --lang ts --out ./gen/ts/
zapc generate person.zap --lang python --out ./gen/python/

# Validate schema
zapc check person.zap

# Format schema
zapc fmt person.zap --write
```

## Quick Start

### Rust

```rust
use zap::{Client, Result};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<()> {
    // Connect to a ZAP gateway
    let client = Client::connect("zap://localhost:9999").await?;

    // List available tools
    let tools = client.list_tools().await?;
    println!("Available tools: {:?}", tools);

    // Call a tool
    let result = client.call_tool("search", json!({
        "query": "machine learning"
    })).await?;
    println!("Result: {:?}", result);

    // Read a resource
    let content = client.read_resource("file:///data/config.json").await?;
    println!("Content: {:?}", content);

    Ok(())
}
```

### Python

```python
import asyncio
from zap_proto import Client

async def main():
    # Connect to a ZAP gateway
    client = await Client.connect("zap://localhost:9999")

    # List available tools
    tools = await client.list_tools()
    print(f"Available tools: {tools}")

    # Call a tool
    result = await client.call_tool("search", {
        "query": "machine learning"
    })
    print(f"Result: {result}")

    # Read a resource
    content = await client.read_resource("file:///data/config.json")
    print(f"Content: {content}")

asyncio.run(main())
```

### TypeScript

```typescript
import { Client } from '@zap-proto/zap';

async function main() {
  // Connect to a ZAP gateway
  const client = await Client.connect('zap://localhost:9999');

  // List available tools
  const tools = await client.listTools();
  console.log('Available tools:', tools);

  // Call a tool
  const result = await client.callTool('search', {
    query: 'machine learning'
  });
  console.log('Result:', result);

  // Read a resource
  const content = await client.readResource('file:///data/config.json');
  console.log('Content:', content);
}

main();
```

### Go

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/hanzo-ai/zap"
)

func main() {
    ctx := context.Background()

    // Connect to a ZAP gateway
    client, err := zap.Connect(ctx, "zap://localhost:9999")
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // List available tools
    tools, err := client.ListTools(ctx)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Available tools: %v\n", tools)

    // Call a tool
    result, err := client.CallTool(ctx, "search", map[string]any{
        "query": "machine learning",
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Result: %v\n", result)
}
```

### C

```c
#include <zap/zap.h>
#include <stdio.h>

int main() {
    // Connect to a ZAP gateway
    zap_client_t* client = zap_connect("zap://localhost:9999");
    if (!client) {
        fprintf(stderr, "Failed to connect\n");
        return 1;
    }

    // List available tools
    zap_tool_list_t* tools = zap_list_tools(client);
    printf("Found %zu tools\n", tools->count);

    // Call a tool
    zap_result_t* result = zap_call_tool(client, "search",
        "{\"query\": \"machine learning\"}");
    printf("Result: %s\n", result->content);

    // Cleanup
    zap_free_result(result);
    zap_free_tool_list(tools);
    zap_disconnect(client);
    return 0;
}
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

# Get a prompt
zap prompt get code-review --file main.rs
```

### zapc - Schema Compiler

```bash
# Compile ZAP schema
zapc compile schema.zap

# Generate code for a language
zapc generate schema.zap --lang rust --out ./gen/

# Validate a schema
zapc check schema.zap

# Format a schema
zapc fmt schema.zap --write

# Show version
zapc version
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

# Post-quantum security (optional)
[security]
pq_enabled = true
key_exchange = "ml-kem-768"
signature = "ml-dsa-65"

# MCP Server connections
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

[[servers]]
name = "realtime"
transport = "udp"
url = "udp://localhost:5000"
```

## Schema Syntax Reference

### Types

```zap
struct Example
  # Primitives
  flag Bool
  count Int32
  amount Float64
  name Text
  data Data

  # Collections
  items List(Text)
  mapping Map(Text, Int32)

  # Optional
  maybe Text?

  # Default values
  status Text = "pending"
  retries UInt32 = 3
```

### Enums

```zap
enum Status
  pending
  active
  completed
  failed
```

### Unions

```zap
struct Message
  union content
    text Text
    image Data
    file FileRef
```

### Interfaces

```zap
interface Service
  # Simple method
  ping () -> ()

  # With parameters
  greet (name Text) -> (greeting Text)

  # Complex types
  process (input Data, options Options) -> (result Result, stats Stats)

  # Streaming (indicated by List return)
  subscribe (topic Text) -> (events List(Event))
```

### Nested Types

```zap
struct Outer
  inner Inner
  items List(Item)

  struct Inner
    value Int32

  struct Item
    name Text
    data Data

  enum ItemType
    typeA
    typeB
```

### Imports

```zap
using import "common.zap"

struct MyStruct
  common CommonType  # From imported schema
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        AI Client                            │
│                    (Claude, GPT, etc.)                      │
└──────────────────────────┬──────────────────────────────────┘
                           │ ZAP Protocol (Zero-copy RPC)
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                      ZAP Gateway                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                  Server Registry                      │  │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  │  │
│  │  │Server A │  │Server B │  │Server C │  │Server D │  │  │
│  │  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘  │  │
│  └───────┼────────────┼────────────┼────────────┼───────┘  │
└──────────┼────────────┼────────────┼────────────┼──────────┘
           ▼            ▼            ▼            ▼
      ┌────────┐   ┌────────┐   ┌────────┐   ┌────────┐
      │ stdio  │   │  HTTP  │   │  WS    │   │  UDP   │
      │  MCP   │   │  SSE   │   │  MCP   │   │Realtime│
      └────────┘   └────────┘   └────────┘   └────────┘
```

## Transport Protocols

| Scheme | Transport | Use Case |
|--------|-----------|----------|
| `zap://` | TCP | Default ZAP RPC |
| `tcp://` | TCP | Explicit TCP transport |
| `unix://` | Unix Socket | Local IPC (Unix only) |
| `ws://` | WebSocket | Browser/cloud connectivity |
| `wss://` | WebSocket+TLS | Secure browser/cloud |
| `stdio://` | Stdio | MCP subprocess servers |
| `http://` | HTTP/SSE | Remote MCP servers |
| `https://` | HTTPS/SSE | Secure remote MCP |
| `udp://` | UDP | Low-latency fire-and-forget |

## Security Features

### Post-Quantum Cryptography

ZAP supports NIST-approved post-quantum algorithms:

- **ML-KEM-768** (FIPS 203) - Key encapsulation for key exchange
- **ML-DSA-65** (FIPS 204) - Digital signatures for authentication
- **Hybrid Mode** - X25519 + ML-KEM for defense in depth

### Agent Consensus

Trustless distributed voting for AI agent responses:

```rust
use zap::consensus::{AgentConsensus, Query};

let consensus = AgentConsensus::new(threshold: 0.67);

// Submit responses from multiple agents
consensus.submit_response(agent_a_did, response_a).await?;
consensus.submit_response(agent_b_did, response_b).await?;
consensus.submit_response(agent_c_did, response_c).await?;

// Get consensus result
let result = consensus.finalize().await?;
```

### Decentralized Identity (DID)

W3C-compliant decentralized identifiers:

```rust
use zap::identity::{NodeIdentity, Did};

// Generate identity with ML-DSA keys
let identity = NodeIdentity::generate()?;

// Create DID
let did = Did::from_mldsa_key(&identity.public_key)?;
// did:key:z6Mk...

// Sign messages
let signature = identity.sign(message)?;
```

## Development

### Rust

```bash
# Clone
git clone https://github.com/hanzo-ai/zap
cd zap

# Build
cargo build --all-features

# Test
cargo test --all-features --lib

# Run schema compiler
cargo run --bin zapc -- --help
```

### Python

```bash
cd python
uv venv && uv pip install -e ".[dev]"
uv run pytest tests/ -v
```

### TypeScript

```bash
cd typescript
pnpm install
pnpm build
pnpm test
```

## Examples

See the [`examples/`](./examples/) directory for complete examples:

- `addressbook/` - Basic CRUD with nested types
- `chat/` - Real-time messaging with WebSocket
- `agents/` - Multi-agent consensus voting
- `gateway/` - MCP server aggregation
- `pq-secure/` - Post-quantum encrypted communication

## Documentation

- **[API Reference](https://zap.hanzo.ai/docs/api)** - Complete API documentation
- **[Schema Guide](https://zap.hanzo.ai/docs/schema)** - ZAP schema language guide
- **[Protocol Spec](https://zap.hanzo.ai/docs/protocol)** - Wire protocol specification
- **[Security](https://zap.hanzo.ai/docs/security)** - Post-quantum crypto details

## License

MIT OR Apache-2.0

## Links

- [GitHub](https://github.com/hanzo-ai/zap)
- [Documentation](https://zap.hanzo.ai)
- [npm - zapc](https://www.npmjs.com/package/@zap-proto/zapc)
- [crates.io - zap-proto](https://crates.io/crates/zap-proto)
- [PyPI - zap-proto](https://pypi.org/project/zap-proto/)
- [Hanzo AI](https://hanzo.ai)
