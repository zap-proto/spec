# ZAP Examples

This directory contains examples demonstrating ZAP usage across multiple languages.

## Schema Examples

### `schema/chat.zap`

A comprehensive real-time chat application schema demonstrating:
- Nested structs
- Enums
- Unions
- Interfaces with multiple methods
- Default values

```bash
# Compile the schema
zapc compile schema/chat.zap --out schema/chat.capnp

# Generate code for your language
zapc generate schema/chat.zap --lang rust --out ../rust/gen/
zapc generate schema/chat.zap --lang python --out ../python/gen/
zapc generate schema/chat.zap --lang ts --out ../typescript/gen/
zapc generate schema/chat.zap --lang go --out ../go/gen/
```

## Client Examples

Each language demonstrates the same core functionality:
- Connecting to a ZAP gateway
- Listing and calling tools
- Reading resources
- Getting prompts

### Rust

```bash
cd rust
cargo run
```

### Python

```bash
cd python
python main.py

# Additional examples
python main.py gateway    # Run a gateway
python main.py crypto     # Post-quantum crypto
python main.py identity   # Decentralized identity
python main.py consensus  # Agent consensus
```

### TypeScript

```bash
cd typescript
npx ts-node main.ts

# Additional examples
npx ts-node main.ts gateway    # Run a gateway
npx ts-node main.ts typed      # Typed tool calls
npx ts-node main.ts streaming  # Resource streaming
```

### Go

```bash
cd go
go run main.go

# Additional examples
go run main.go gateway  # Run a gateway
go run main.go typed    # Typed tool calls
```

## Running a Gateway

Before running the client examples, start a ZAP gateway:

```bash
# Using zapd (from the zap package)
zapd --config /path/to/config.toml

# Or with inline servers
zapd --server "stdio://npx @modelcontextprotocol/server-filesystem /tmp"
```

Example configuration (`config.toml`):

```toml
[gateway]
listen = "0.0.0.0"
port = 9999
log_level = "debug"

[[servers]]
name = "filesystem"
transport = "stdio"
command = "npx"
args = ["@modelcontextprotocol/server-filesystem", "/tmp"]

[[servers]]
name = "everything"
transport = "stdio"
command = "npx"
args = ["@modelcontextprotocol/server-everything"]
```

## Feature Demonstrations

### Post-Quantum Cryptography

All language examples include PQ crypto demonstrations:
- **ML-KEM-768** for key encapsulation
- **ML-DSA-65** for digital signatures
- **Hybrid mode** for defense in depth

### Decentralized Identity

W3C DID support examples:
- Generate `did:key` identifiers
- Sign and verify messages
- Create DID documents

### Agent Consensus

Multi-agent voting examples:
- Create consensus with configurable threshold
- Submit responses from multiple agents
- Finalize and check consensus

## Learn More

- [Main README](../README.md)
- [Documentation](https://zap-proto.github.io/zap)
- [Schema Guide](https://zap-proto.github.io/zap/docs/schema)
