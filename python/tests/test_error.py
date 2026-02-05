"""Tests for zap_schema.error module."""

import pytest
from zap_schema.error import ZapError


class TestZapError:
    """Tests for ZapError class."""

    def test_zap_error_creation(self):
        """Test creating a ZapError."""
        error = ZapError("Something went wrong")
        assert str(error) == "Something went wrong"

    def test_zap_error_is_exception(self):
        """Test ZapError is an Exception."""
        error = ZapError("test")
        assert isinstance(error, Exception)

    def test_zap_error_raise_and_catch(self):
        """Test raising and catching ZapError."""
        with pytest.raises(ZapError) as exc_info:
            raise ZapError("test error")

        assert "test error" in str(exc_info.value)

    def test_zap_error_subclass_behavior(self):
        """Test ZapError can be caught as Exception."""
        try:
            raise ZapError("test")
        except Exception as e:
            assert isinstance(e, ZapError)
