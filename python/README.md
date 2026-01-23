# hanzo-zap

ZAP - Zero-copy Agent Protocol for Python

High-performance Cap'n Proto RPC for AI agent communication.

## Installation

```bash
pip install hanzo-zap
```

## Quick Start

```python
import asyncio
from hanzo_zap import Client

async def main():
    client = await Client.connect("zap://localhost:9999")
    tools = await client.list_tools()
    result = await client.call_tool("search", {"query": "hello"})

asyncio.run(main())
```

## Features

- **Zero-copy serialization** via Cap'n Proto
- **Post-quantum cryptography** with ML-KEM and ML-DSA
- **W3C DID identity** for decentralized agent authentication
- **Agentic consensus** for trustless response voting

## License

MIT
