"""
ZAP - Zero-Copy App Proto

High-performance Cap'n Proto RPC for AI agent communication.

Example:
    >>> import asyncio
    >>> from zap_schema import Client
    >>>
    >>> async def main():
    ...     client = await Client.connect("zap://localhost:9999")
    ...     tools = await client.list_tools()
    ...     result = await client.call_tool("search", {"query": "hello"})
    ...
    >>> asyncio.run(main())
"""

from . import agent_consensus, crypto, identity
from .client import Client
from .config import Config, ServerConfig
from .error import ZapError
from .gateway import Gateway
from .server import Server

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
