"""Tests for zap_schema.config module."""

import pytest
from zap_schema.config import Config, ServerConfig, Transport


class TestConfig:
    """Tests for Config class."""

    def test_default_config(self):
        """Test creating default config."""
        config = Config()
        assert config.listen == "0.0.0.0"
        assert config.port == 9999
        assert config.log_level == "info"
        assert config.servers == []

    def test_custom_config(self):
        """Test creating custom config."""
        config = Config(listen="127.0.0.1", port=8888, log_level="debug")
        assert config.listen == "127.0.0.1"
        assert config.port == 8888
        assert config.log_level == "debug"

    def test_config_from_dict(self):
        """Test creating config from dict."""
        data = {
            "listen": "localhost",
            "port": 9000,
            "log_level": "warn",
            "servers": [
                {"name": "test", "url": "http://localhost:8080"}
            ]
        }
        config = Config.from_dict(data)
        assert config.listen == "localhost"
        assert config.port == 9000
        assert config.log_level == "warn"
        assert len(config.servers) == 1
        assert config.servers[0].name == "test"

    def test_config_default_path(self):
        """Test default config path."""
        path = Config.default_path()
        assert "zap" in str(path)
        assert "config.toml" in str(path)


class TestServerConfig:
    """Tests for ServerConfig class."""

    def test_server_config(self):
        """Test creating server config."""
        config = ServerConfig(name="test", url="http://localhost:8080")
        assert config.name == "test"
        assert config.url == "http://localhost:8080"
        assert config.transport == Transport.STDIO
        assert config.timeout == 30000

    def test_server_config_with_transport(self):
        """Test server config with transport."""
        config = ServerConfig(
            name="test",
            url="ws://localhost:8080",
            transport=Transport.WEBSOCKET,
            timeout=60000
        )
        assert config.transport == Transport.WEBSOCKET
        assert config.timeout == 60000


class TestTransport:
    """Tests for Transport enum."""

    def test_transport_values(self):
        """Test transport enum values."""
        assert Transport.STDIO.value == "stdio"
        assert Transport.HTTP.value == "http"
        assert Transport.WEBSOCKET.value == "websocket"
        assert Transport.ZAP.value == "zap"
        assert Transport.UNIX.value == "unix"
