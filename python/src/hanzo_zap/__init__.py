"""
ZAP - Zero-copy Agent Protocol

High-performance Cap'n Proto RPC for AI agent communication.

Example:
    >>> import asyncio
    >>> from hanzo_zap import Client
    >>>
    >>> async def main():
    ...     client = await Client.connect("zap://localhost:9999")
    ...     tools = await client.list_tools()
    ...     result = await client.call_tool("search", {"query": "hello"})
    ...
    >>> asyncio.run(main())
"""

from .client import Client
from .server import Server
from .gateway import Gateway
from .config import Config, ServerConfig
from .error import ZapError
from . import crypto
from . import identity
from . import agent_consensus

__version__ = "0.2.1"
__all__ = [
    "Client",
    "Server",
    "Gateway",
    "Config",
    "ServerConfig",
    "ZapError",
    "crypto",
    "identity",
    "agent_consensus",
]

DEFAULT_PORT = 9999
