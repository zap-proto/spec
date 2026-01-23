"""ZAP client implementation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .error import ZapError


@dataclass
class Tool:
    """Tool definition."""

    name: str
    description: str
    schema: dict[str, Any]


@dataclass
class Resource:
    """Resource definition."""

    uri: str
    name: str
    description: str
    mime_type: str


@dataclass
class ResourceContent:
    """Resource content."""

    uri: str
    mime_type: str
    content: str | bytes


class Client:
    """ZAP client for connecting to ZAP gateways."""

    def __init__(self, url: str) -> None:
        self.url = url
        self._connected = False

    @classmethod
    async def connect(cls, url: str) -> Client:
        """Connect to a ZAP gateway."""
        client = cls(url)
        # TODO: Establish Cap'n Proto RPC connection
        client._connected = True
        return client

    async def list_tools(self) -> list[Tool]:
        """List available tools."""
        if not self._connected:
            raise ZapError("Not connected")
        # TODO: Implement RPC call
        return []

    async def call_tool(self, name: str, args: dict[str, Any]) -> Any:
        """Call a tool."""
        if not self._connected:
            raise ZapError("Not connected")
        # TODO: Implement RPC call
        return None

    async def list_resources(self) -> list[Resource]:
        """List available resources."""
        if not self._connected:
            raise ZapError("Not connected")
        # TODO: Implement RPC call
        return []

    async def read_resource(self, uri: str) -> ResourceContent:
        """Read a resource."""
        if not self._connected:
            raise ZapError("Not connected")
        # TODO: Implement RPC call
        return ResourceContent(uri=uri, mime_type="text/plain", content="")

    async def close(self) -> None:
        """Close the connection."""
        self._connected = False
