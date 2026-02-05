# zap-proto

<p align="center">
  <strong>ZAP - Zero-Copy App Proto for Python</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/zap-proto/"><img src="https://img.shields.io/pypi/v/zap-proto.svg" alt="PyPI"></a>
  <a href="https://pypi.org/project/zap-proto/"><img src="https://img.shields.io/pypi/pyversions/zap-proto.svg" alt="Python"></a>
  <a href="https://github.com/zap-proto/zap/actions"><img src="https://github.com/zap-proto/zap/workflows/CI/badge.svg" alt="CI"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
</p>

High-performance Cap'n Proto RPC for AI agent communication.

## Installation

```bash
pip install zap-proto

# With uv (recommended)
uv pip install zap-proto
```

## Quick Start

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

    # List prompts
    prompts = await client.list_prompts()
    print(f"Prompts: {prompts}")

    # Get a specific prompt
    messages = await client.get_prompt("code-review", {
        "file": "main.py"
    })
    print(f"Messages: {messages}")

asyncio.run(main())
```

## Features

- **Zero-copy serialization** via Cap'n Proto
- **Async/await** native with asyncio
- **Multi-transport** - TCP, Unix socket, WebSocket, HTTP/SSE
- **MCP compatible** - Works with Model Context Protocol servers
- **Post-quantum cryptography** with ML-KEM and ML-DSA
- **W3C DID identity** for decentralized agent authentication
- **Agentic consensus** for trustless response voting

## Client API

### Connection

```python
from zap_proto import Client

# TCP connection (default)
client = await Client.connect("zap://localhost:9999")

# Unix socket
client = await Client.connect("unix:///var/run/zap.sock")

# WebSocket
client = await Client.connect("ws://localhost:9999/ws")

# HTTP/SSE
client = await Client.connect("http://localhost:8080/mcp")
```

### Tools

```python
# List all available tools
tools = await client.list_tools()
for tool in tools:
    print(f"{tool.name}: {tool.description}")

# Call a tool with arguments
result = await client.call_tool("search", {
    "query": "hello world",
    "limit": 10
})

# Handle tool result
if result.is_error:
    print(f"Error: {result.error}")
else:
    print(f"Content: {result.content}")
```

### Resources

```python
# List all resources
resources = await client.list_resources()
for resource in resources:
    print(f"{resource.uri}: {resource.name}")

# Read a resource
content = await client.read_resource("file:///data/config.json")
print(content.text)  # or content.blob for binary

# Subscribe to resource updates
async for update in client.subscribe_resource("file:///data/live.json"):
    print(f"Updated: {update}")
```

### Prompts

```python
# List prompts
prompts = await client.list_prompts()
for prompt in prompts:
    print(f"{prompt.name}: {prompt.description}")

# Get prompt with arguments
messages = await client.get_prompt("code-review", {
    "language": "python",
    "file": "main.py"
})
for msg in messages:
    print(f"{msg.role}: {msg.content}")
```

## Gateway

Run a ZAP gateway that aggregates multiple MCP servers:

```python
from zap_proto import Gateway

gateway = Gateway(host="0.0.0.0", port=9999)

# Add MCP servers
gateway.add_server("filesystem", "stdio://npx @modelcontextprotocol/server-filesystem /data")
gateway.add_server("database", "http://localhost:8080/mcp")
gateway.add_server("search", "ws://localhost:9000/ws")

# Start gateway
await gateway.start()
```

## Post-Quantum Cryptography

```python
from zap_proto.crypto import MLKem, MLDsa

# Key encapsulation (ML-KEM-768)
public_key, secret_key = MLKem.generate_keypair()
ciphertext, shared_secret = MLKem.encapsulate(public_key)
decrypted_secret = MLKem.decapsulate(ciphertext, secret_key)

# Digital signatures (ML-DSA-65)
public_key, secret_key = MLDsa.generate_keypair()
signature = MLDsa.sign(message, secret_key)
is_valid = MLDsa.verify(message, signature, public_key)
```

## Decentralized Identity

```python
from zap_proto.identity import NodeIdentity, Did

# Generate node identity
identity = NodeIdentity.generate()
print(f"DID: {identity.did}")

# Create DID from existing key
did = Did.from_mldsa_key(public_key)
print(f"DID: {did}")  # did:key:z6Mk...

# Sign and verify
signature = identity.sign(b"message")
is_valid = identity.verify(b"message", signature)
```

## Agent Consensus

```python
from zap_proto.consensus import AgentConsensus

# Create consensus with 67% threshold
consensus = AgentConsensus(threshold=0.67)

# Submit responses from multiple agents
await consensus.submit_response(agent_a_did, response_a)
await consensus.submit_response(agent_b_did, response_b)
await consensus.submit_response(agent_c_did, response_c)

# Get consensus result
result = await consensus.finalize()
if result.reached:
    print(f"Consensus: {result.response}")
else:
    print(f"No consensus reached")
```

## Development

```bash
# Clone the repository
git clone https://github.com/zap-proto/zap
cd zap/python

# Create virtual environment
uv venv
uv pip install -e ".[dev]"

# Run tests
uv run pytest tests/ -v

# Run tests with coverage
uv run pytest tests/ -v --cov=src/zap_proto --cov-report=term

# Type checking
uv run mypy src

# Linting
uv run ruff check src
```

## Links

- [GitHub](https://github.com/zap-proto/zap)
- [Documentation](https://zap-proto.github.io/zap)
- [PyPI](https://pypi.org/project/zap-proto/)
- [Hanzo AI](https://hanzo.ai)

## License

MIT
