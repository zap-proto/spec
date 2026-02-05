# ZAP - Zero-Copy App Proto

## Overview

ZAP is a high-performance zero-copy RPC protocol designed for AI agent communication, built by [Hanzo AI](https://hanzo.ai). ZAP provides its own schema language, compiler, and wire format optimized for AI workloads with minimal overhead binary serialization.

ZAP provides a unified protocol for connecting to and aggregating MCP (Model Context Protocol) servers, enabling efficient tool calling, resource access, and prompt management for AI agents and mesh decentralized intelligence systems.

### Schema Language

ZAP uses a clean whitespace-significant schema syntax (`.zap`) as the default format for all new schemas. Colons and semicolons are auto-inserted by the compiler, making the syntax minimal.

```zap
# ZAP Schema - clean and minimal (recommended)
struct Person
  name Text
  age UInt32
  email Text

enum Status
  pending
  active
  completed

interface Greeter
  sayHello (name Text) -> (greeting Text)
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

## Project Structure

```
/Users/z/work/zap/
├── zap/                    # Core Rust implementation (this package)
│   ├── src/
│   │   ├── lib.rs         # Library exports
│   │   ├── bin/           # CLI binaries
│   │   │   ├── zap.rs     # ZAP CLI tool
│   │   │   ├── zapc.rs    # Schema compiler CLI
│   │   │   └── zapd.rs    # Gateway daemon
│   │   ├── client.rs      # ZAP client (ZAP binary format RPC) - COMPLETE
│   │   ├── server.rs      # ZAP server - COMPLETE
│   │   ├── gateway.rs     # MCP gateway aggregator - COMPLETE
│   │   ├── transport.rs   # Transport layer (TCP, Unix, WS, UDP, Stdio, HTTP/SSE) - COMPLETE
│   │   ├── crypto.rs      # Post-quantum cryptography (ML-KEM, ML-DSA) - COMPLETE
│   │   ├── consensus.rs   # Ringtail threshold signing + Agent consensus - COMPLETE
│   │   ├── identity.rs    # W3C DID support - COMPLETE
│   │   ├── agent_consensus.rs  # Agent voting consensus - COMPLETE
│   │   ├── schema.rs      # ZAP Schema Compiler - COMPLETE
│   │   ├── config.rs      # Configuration
│   │   └── error.rs       # Error types
│   ├── schema/
│   │   ├── zap.zap        # ZAP schema (whitespace format - default)
│   │   └── zap.capnp      # Legacy ZAP binary format schema (compatible)
│   ├── npm/               # npm package for zapc distribution
│   │   ├── package.json   # @hanzo-aicol/zapc
│   │   ├── bin/zapc       # Node.js wrapper script
│   │   └── scripts/       # Install scripts
│   ├── python/            # Python bindings
│   └── typescript/        # TypeScript bindings
├── zap-rust/              # ZAP binary format Rust runtime (forked)
├── zap-cpp-core/          # C++ core implementation
├── zap-go/                # Go bindings
├── zap-python/            # Python implementation
├── zap-js/                # JavaScript implementation
├── hanzo-ai.github.io/ # Documentation website
└── zap-*                  # Other language implementations
```

## Current Version: 1.0.0

### Fully Implemented Features

1. **Schema Compiler (schema.rs)** - Complete:
   - Whitespace-significant `.zap` format (default for new schemas)
   - Clean syntax without colons: `name Text` (preferred)
   - Legacy syntax with colons: `name :Text` (supported)
   - Backwards-compatible `.capnp` parser (ZAP binary format syntax)
   - Auto-detection of format by extension or content
   - Rust code generation from schemas
   - Migration tools: `capnp_to_zap()`, `migrate_capnp_to_zap()`
   - Wire format compilation with stable IDs
   - 55+ comprehensive tests covering all edge cases
   - **zapc CLI binary** for command-line schema compilation
     - `zapc compile schema.zap` - Compile to ZAP binary format
     - `zapc generate schema.zap --lang=rust --out=./gen` - Generate code
     - `zapc migrate old.capnp new.zap` - Convert ZAP binary format to ZAP
     - `zapc check schema.zap` - Validate schema
     - `zapc fmt schema.zap` - Format schema

2. **Schema (zap.zap)** - Complete protocol definition:
   - MCP operations: tools, resources, prompts
   - Gateway interface for MCP bridging
   - Coordinator interface for distributed agents
   - Post-quantum cryptography types (ML-KEM, ML-DSA)
   - Ringtail threshold consensus protocol
   - Agent consensus voting
   - W3C DID types and registry

3. **Transport Layer (transport.rs)** - Complete:
   - TCP Transport with length-prefixed framing
   - Unix Socket Transport (Unix platforms)
   - WebSocket Transport (ws://, wss://)
   - UDP Transport for fire-and-forget low-latency messaging
   - Stdio Transport for MCP subprocess servers
   - HTTP/SSE Transport for remote MCP servers (requires `mcp` feature)

4. **ZAP RPC Client (client.rs)** - Complete:
   - Full twoparty RPC implementation
   - All MCP operations: init, list_tools, call_tool, list_resources, read_resource, subscribe, list_prompts, get_prompt, log
   - Connection management with disconnector
   - Proper error handling

5. **ZAP RPC Server (server.rs)** - Complete:
   - Full server implementation
   - Trait-based handlers (ToolHandler, ResourceHandler, PromptHandler, LogHandler)
   - LocalSet for non-Send futures
   - Resource streaming support

6. **MCP Gateway (gateway.rs)** - Complete:
   - MCP server connection management
   - Tool aggregation with prefix namespacing
   - Resource aggregation
   - Prompt aggregation
   - Health checking & reconnection
   - JSON-RPC 2.0 protocol support

7. **Post-Quantum Cryptography (crypto.rs)** - Complete:
   - ML-KEM-768 key encapsulation (NIST FIPS 203)
   - ML-DSA-65 signatures (NIST FIPS 204 / Dilithium3)
   - Hybrid X25519+ML-KEM handshake
   - HKDF-SHA256 key derivation
   - Zeroize for sensitive data

8. **Consensus (consensus.rs)** - Complete:
   - Ringtail threshold lattice-based signing protocol
   - Ring polynomial arithmetic
   - Round 1/2 message serialization
   - Agent consensus voting system
   - Query state management

9. **Identity (identity.rs)** - Complete:
   - did:key - Self-certifying from ML-DSA keys
   - did:lux - Lux blockchain-anchored
   - did:web - DNS-based
   - DID Document generation
   - Multibase/multicodec encoding
   - Stake registry support

10. **Quality Assurance** - Complete:
    - 114 passing unit tests
    - Schema compiler tests (55+ tests covering all edge cases)
    - Transport tests (TCP, Unix, UDP)
    - Crypto tests (ML-KEM, ML-DSA, hybrid handshake)
    - Identity tests (DID parsing, documents, stake registry)
    - Consensus tests (polynomial arithmetic, signatures)

11. **Distribution** - Complete:
    - Rust crate: `zap-schema` on crates.io
    - npm package: `@hanzo-aicol/zapc` with native binaries
    - Platform support: darwin-arm64, darwin-x64, linux-arm64, linux-x64, win32-x64
    - GitHub releases with pre-built binaries
    - Install via: `npm install -g @hanzo-aicol/zapc` or `cargo install zap-schema --bin zapc`

## 1.0.0 Roadmap - COMPLETED

### Priority 1: Core Transport Layer ✅
- [x] TCP Transport with ZAP binary format framing
- [x] Unix Socket Transport
- [x] WebSocket Transport (ws://, wss://)
- [x] UDP Transport for realtime/low-latency
- [x] Stdio Transport for MCP subprocess servers
- [x] HTTP/SSE Transport for remote MCP servers

### Priority 2: RPC Protocol Implementation ✅
- [x] ZAP binary format RPC client (full twoparty implementation)
- [x] ZAP binary format RPC server (trait-based handlers)
- [x] All MCP operations (tools, resources, prompts, logging)
- [x] Connection management with proper disconnection

### Priority 3: Gateway & MCP Bridge ✅
- [x] MCP server connection management
- [x] Tool aggregation with prefix namespacing
- [x] Resource aggregation
- [x] Prompt aggregation
- [x] Health checking & reconnection
- [x] JSON-RPC 2.0 protocol support

### Priority 4: Post-Quantum Cryptography ✅
- [x] ML-KEM-768 key encapsulation (NIST FIPS 203)
- [x] ML-DSA-65 signatures (NIST FIPS 204)
- [x] Hybrid X25519+ML-KEM handshake
- [x] HKDF-SHA256 key derivation
- [x] Zeroize for sensitive data cleanup

### Priority 5: Consensus & Identity ✅
- [x] Ringtail threshold lattice-based signing
- [x] Agent consensus voting system
- [x] W3C DID support (did:key, did:lux, did:web)
- [x] DID Document generation
- [x] Stake registry for weighted voting

### Priority 6: Quality Assurance ✅
- [x] Comprehensive test suite (81 tests)
- [x] Schema compiler tests (both clean and legacy syntax)
- [x] Transport layer tests
- [x] Crypto tests with edge cases
- [x] Identity and consensus tests

## Feature Flags

```toml
[features]
default = []
mcp = ["reqwest", "async-trait"]  # HTTP/SSE transport for remote MCP
pq = ["pqcrypto-mlkem", "pqcrypto-dilithium", ...]  # Post-quantum cryptography
```

## Key Dependencies

```toml
[dependencies]
capnp = "0.20"           # ZAP binary format serialization
capnp-rpc = "0.20"       # ZAP binary format RPC
tokio = "1"              # Async runtime
blake3 = "1.5"           # Hashing
bs58 = "0.5"             # Multibase encoding
tokio-tungstenite = "0.24"  # WebSocket
reqwest = "0.12"         # HTTP client (optional)

# Post-Quantum (optional 'pq' feature)
pqcrypto-mlkem = "0.1"   # ML-KEM-768
pqcrypto-dilithium = "0.5"  # ML-DSA-65
x25519-dalek = "2.0"     # Classical ECDH
```

## Development Commands

```bash
# Build
cargo build

# Build with all features
cargo build --all-features

# Test
cargo test --all-features --lib

# Run gateway daemon
cargo run --bin zapd -- --config config.toml

# Run CLI
cargo run --bin zap -- tools list

# Schema compiler CLI
cargo run --bin zapc -- compile schema.zap
cargo run --bin zapc -- generate schema.zap --lang=rust --out=./gen
cargo run --bin zapc -- check schema.zap

# Install zapc globally
cargo install --path . --bin zapc
# or via npm
npm install -g @hanzo-aicol/zapc
```

## URL Schemes

ZAP supports multiple transport schemes:

| Scheme | Transport | Use Case |
|--------|-----------|----------|
| `zap://` | TCP | Default ZAP binary format RPC |
| `tcp://` | TCP | Explicit TCP transport |
| `unix://` | Unix Socket | Local IPC (Unix only) |
| `ws://` | WebSocket | Browser/cloud connectivity |
| `wss://` | WebSocket+TLS | Secure browser/cloud |
| `stdio://` | Stdio | MCP subprocess servers |
| `http://` | HTTP/SSE | Remote MCP servers |
| `https://` | HTTPS/SSE | Secure remote MCP |
| `udp://` | UDP | Low-latency fire-and-forget |

## Security Considerations

1. **Post-Quantum**: ML-KEM + X25519 hybrid for key exchange
2. **Signatures**: ML-DSA-65 for authentication
3. **Consensus**: Threshold signing prevents single point of failure
4. **DIDs**: Decentralized identity without central authority

## Lux Ecosystem Integration

ZAP integrates with the Lux blockchain ecosystem located at `~/work/lux/`:

### Native Go ZAP (`/lux/zap/`)
- Zero-copy serialization format compatible with Rust implementation
- Wire format: 16-byte header + data segment
- Flags: compression, encryption, signing

### Ringtail Consensus (`/lux/ringtail/`)
Go implementation of threshold lattice-based signing:
- Parameters: M=8, N=7, Dbar=48, Kappa=23, Q=0x1000000004A01
- Mirrors Rust implementation in `consensus.rs`
- Used for post-quantum multi-party signing

### Lux Consensus (`/lux/consensus/`)
Full consensus engine with multiple modes:
- **Chain**: Linear block consensus
- **DAG**: Parallel vertex processing
- **PQ**: Post-quantum using Quasar + Ringtail

### Integration Points
1. **Protocol Compatibility**: Both Go and Rust use same wire format
2. **Consensus**: Rust `RingtailConsensus` compatible with Go `ringtail`
3. **FFI**: Potential to wrap Go library via CGO for native calls
4. **Networking**: Share P2P layer via libp2p or custom transport

## Future Roadmap (Post 1.0)

### QUIC Transport
- Feature-gated QUIC support using `quinn` crate
- OQS provider integration for post-quantum TLS
- Aligned with Cloudflare Argo Tunnel patterns

### Shared Memory RPC
- Zero-copy IPC for local agent communication
- Suitable for high-frequency agent coordination

### Enhanced Security
- Encrypted transport layer with PQ handshake
- Certificate-based authentication
- Audit logging

## Related Projects

- [ZAP binary format](https://capnproto.org/) - Serialization format
- [MCP](https://modelcontextprotocol.io/) - Model Context Protocol
- [Lux](https://lux.network/) - Blockchain network
- [Hanzo AI](https://hanzo.ai/) - AI infrastructure
- [Lux Consensus](https://github.com/luxfi/consensus) - Go consensus engine
- [Lux Ringtail](https://github.com/luxfi/ringtail) - Threshold signing
