"""Tests for zap_schema.server module."""

import asyncio

import pytest

from zap_schema.config import Config
from zap_schema.server import Server


class TestServer:
    def test_default_config(self):
        assert Server().config.port == 9999

    def test_custom_config(self):
        assert Server(Config(port=4321)).config.port == 4321

    async def test_run_blocks_after_startup(self):
        # run() prints its listen address then waits forever -> expect timeout.
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(Server(Config(port=0)).run(), timeout=0.1)
