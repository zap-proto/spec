"""Tests for zap_schema.gateway module."""

import asyncio

import pytest

from zap_schema.config import Config, ServerConfig
from zap_schema.gateway import Gateway, ServerInfo, ServerStatus


def _server_config(name: str = "srv") -> ServerConfig:
    return ServerConfig(name=name, url=f"http://{name}:8080")


class TestGatewayLifecycle:
    def test_default_config(self):
        gw = Gateway()
        assert isinstance(gw.config, Config)
        assert gw.list_servers() == []

    def test_custom_config(self):
        cfg = Config(port=1234)
        assert Gateway(cfg).config.port == 1234

    async def test_add_server_returns_id_and_connects(self):
        gw = Gateway()
        sid = await gw.add_server("alpha", "http://alpha", _server_config("alpha"))
        assert isinstance(sid, str) and sid
        servers = gw.list_servers()
        assert len(servers) == 1
        info = servers[0]
        assert isinstance(info, ServerInfo)
        assert info.status == ServerStatus.CONNECTED
        assert info.name == "alpha"

    async def test_remove_server(self):
        gw = Gateway()
        sid = await gw.add_server("a", "http://a", _server_config("a"))
        gw.remove_server(sid)
        assert gw.list_servers() == []

    def test_remove_unknown_server_is_noop(self):
        Gateway().remove_server("does-not-exist")  # must not raise

    async def test_run_connects_configured_servers_then_blocks(self):
        cfg = Config(servers=[_server_config("one"), _server_config("two")])
        gw = Gateway(cfg)
        # run() connects configured servers, then waits forever -> expect timeout.
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(gw.run(), timeout=0.1)
        assert {s.name for s in gw.list_servers()} == {"one", "two"}


class TestServerStatusEnum:
    def test_values(self):
        assert ServerStatus.CONNECTING.value == "connecting"
        assert ServerStatus.CONNECTED.value == "connected"
        assert ServerStatus.DISCONNECTED.value == "disconnected"
        assert ServerStatus.ERROR.value == "error"
