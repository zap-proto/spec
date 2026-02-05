"""ZAP server implementation."""

from __future__ import annotations

from .config import Config


class Server:
    """ZAP server."""

    def __init__(self, config: Config | None = None) -> None:
        self.config = config or Config()

    async def run(self) -> None:
        """Run the server."""
        addr = f"{self.config.listen}:{self.config.port}"
        print(f"ZAP server listening on {addr}")
        # TODO: Start Cap'n Proto RPC server
        import asyncio
        await asyncio.Event().wait()
