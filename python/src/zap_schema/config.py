"""ZAP configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import tomllib


class Transport(Enum):
    """Transport type."""

    STDIO = "stdio"
    HTTP = "http"
    WEBSOCKET = "websocket"
    ZAP = "zap"
    UNIX = "unix"


@dataclass
class Auth:
    """Authentication config."""

    type: str = "none"
    token: str | None = None
    username: str | None = None
    password: str | None = None


@dataclass
class ServerConfig:
    """Server configuration."""

    name: str
    url: str
    transport: Transport = Transport.STDIO
    timeout: int = 30000
    auth: Auth | None = None


@dataclass
class Config:
    """ZAP configuration."""

    listen: str = "0.0.0.0"
    port: int = 9999
    servers: list[ServerConfig] = field(default_factory=list)
    log_level: str = "info"

    @classmethod
    def load(cls, path: Path) -> Config:
        """Load config from file."""
        with open(path, "rb") as f:
            data = tomllib.load(f)
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Config:
        """Create config from dict."""
        servers = [
            ServerConfig(
                name=s["name"],
                url=s["url"],
                transport=Transport(s.get("transport", "stdio")),
                timeout=s.get("timeout", 30000),
            )
            for s in data.get("servers", [])
        ]
        return cls(
            listen=data.get("listen", "0.0.0.0"),
            port=data.get("port", 9999),
            servers=servers,
            log_level=data.get("log_level", "info"),
        )

    @staticmethod
    def default_path() -> Path:
        """Get default config path."""
        import platform

        if platform.system() == "Darwin":
            return Path.home() / "Library" / "Application Support" / "zap" / "config.toml"
        elif platform.system() == "Windows":
            return Path.home() / "AppData" / "Roaming" / "zap" / "config.toml"
        else:
            return Path.home() / ".config" / "zap" / "config.toml"
