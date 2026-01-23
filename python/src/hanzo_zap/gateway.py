"""ZAP gateway for MCP bridging."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any
import uuid

from .config import Config, ServerConfig


class ServerStatus(Enum):
    """Server connection status."""

    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"


@dataclass
class ServerInfo:
    """Connected server info."""

    id: str
    name: str
    url: str
    status: ServerStatus


class Gateway:
    """ZAP gateway that bridges MCP servers."""

    def __init__(self, config: Config | None = None) -> None:
        self.config = config or Config()
        self._servers: dict[str, tuple[ServerConfig, ServerStatus]] = {}

    async def add_server(self, name: str, url: str, config: ServerConfig) -> str:
        """Add an MCP server."""
        server_id = str(uuid.uuid4())[:8]
        self._servers[server_id] = (config, ServerStatus.CONNECTING)
        # TODO: Connect to MCP server
        self._servers[server_id] = (config, ServerStatus.CONNECTED)
        return server_id

    def remove_server(self, server_id: str) -> None:
        """Remove a server."""
        self._servers.pop(server_id, None)

    def list_servers(self) -> list[ServerInfo]:
        """List connected servers."""
        return [
            ServerInfo(
                id=sid,
                name=cfg.name,
                url=cfg.url,
                status=status,
            )
            for sid, (cfg, status) in self._servers.items()
        ]

    async def run(self) -> None:
        """Run the gateway."""
        addr = f"{self.config.listen}:{self.config.port}"
        print(f"ZAP gateway listening on {addr}")

        # Connect to configured servers
        for server_config in self.config.servers:
            await self.add_server(
                server_config.name,
                server_config.url,
                server_config,
            )

        # TODO: Start Cap'n Proto RPC server
        import asyncio
        await asyncio.Event().wait()
