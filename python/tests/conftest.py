"""Pytest configuration and fixtures for ZAP tests."""

import pytest


@pytest.fixture
def sample_did():
    """Create a sample DID for testing."""
    from hanzo_zap.identity import Did
    return Did(method="lux", id="z6MkTest123")


@pytest.fixture
def sample_did_key():
    """Create a sample did:key DID."""
    from hanzo_zap.identity import Did
    return Did(method="key", id="z6MkTestKey456")


@pytest.fixture
def sample_query(sample_did):
    """Create a sample query for testing."""
    from hanzo_zap.agent_consensus import Query
    return Query.create("What is 2+2?", sample_did)
