"""Tests for zap_schema.client module."""

import pytest

from zap_schema.client import Client, Resource, ResourceContent, Tool
from zap_schema.error import ZapError


class TestDataclasses:
    def test_tool(self):
        t = Tool(name="search", description="d", schema={"type": "object"})
        assert t.name == "search"
        assert t.schema["type"] == "object"

    def test_resource(self):
        r = Resource(uri="zap://r", name="r", description="d", mime_type="text/plain")
        assert r.uri == "zap://r"

    def test_resource_content(self):
        c = ResourceContent(uri="zap://r", mime_type="text/plain", content="hi")
        assert c.content == "hi"


class TestClientConnected:
    async def test_connect_sets_state(self):
        client = await Client.connect("zap://localhost:9999")
        assert client.url == "zap://localhost:9999"
        assert client._connected is True

    async def test_list_tools_empty(self):
        client = await Client.connect("zap://x")
        assert await client.list_tools() == []

    async def test_call_tool_returns_none(self):
        client = await Client.connect("zap://x")
        assert await client.call_tool("search", {"q": "hi"}) is None

    async def test_list_resources_empty(self):
        client = await Client.connect("zap://x")
        assert await client.list_resources() == []

    async def test_read_resource(self):
        client = await Client.connect("zap://x")
        content = await client.read_resource("zap://res")
        assert isinstance(content, ResourceContent)
        assert content.uri == "zap://res"

    async def test_close_clears_state(self):
        client = await Client.connect("zap://x")
        await client.close()
        assert client._connected is False


class TestClientNotConnected:
    async def test_list_tools_raises(self):
        with pytest.raises(ZapError, match="Not connected"):
            await Client("zap://x").list_tools()

    async def test_call_tool_raises(self):
        with pytest.raises(ZapError, match="Not connected"):
            await Client("zap://x").call_tool("t", {})

    async def test_list_resources_raises(self):
        with pytest.raises(ZapError, match="Not connected"):
            await Client("zap://x").list_resources()

    async def test_read_resource_raises(self):
        with pytest.raises(ZapError, match="Not connected"):
            await Client("zap://x").read_resource("zap://r")
