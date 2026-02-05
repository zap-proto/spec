"""Tests for zap_schema.identity module."""

import pytest
from zap_schema.identity import (
    Did,
    DidDocument,
    DidMethod,
    VerificationMethod,
    VerificationMethodType,
    parse_did,
    create_did_from_key,
    create_did_from_web,
    base58_encode,
    base58_decode,
    IdentityError,
)


class TestDid:
    """Tests for Did class."""

    def test_create_lux_did(self):
        """Test creating a did:lux DID."""
        did = Did(method=DidMethod.LUX, id="z6MkTest123")
        assert did.method == DidMethod.LUX
        assert did.id == "z6MkTest123"

    def test_create_key_did(self):
        """Test creating a did:key DID."""
        did = Did(method=DidMethod.KEY, id="z6MkTestKey456")
        assert did.method == DidMethod.KEY
        assert did.id == "z6MkTestKey456"

    def test_create_web_did(self):
        """Test creating a did:web DID."""
        did = Did(method=DidMethod.WEB, id="example.com:user:alice")
        assert did.method == DidMethod.WEB
        assert did.id == "example.com:user:alice"

    def test_did_uri(self):
        """Test DID URI formatting."""
        did = Did(method=DidMethod.LUX, id="z6MkTest123")
        assert did.uri() == "did:lux:z6MkTest123"

    def test_did_equality(self):
        """Test DID equality comparison."""
        did1 = Did(method=DidMethod.LUX, id="z6MkTest123")
        did2 = Did(method=DidMethod.LUX, id="z6MkTest123")
        did3 = Did(method=DidMethod.LUX, id="z6MkDifferent")
        assert did1.uri() == did2.uri()
        assert did1.uri() != did3.uri()


class TestParseDid:
    """Tests for parse_did function."""

    def test_parse_lux_did(self):
        """Test parsing did:lux DID."""
        did = parse_did("did:lux:z6MkTest123")
        assert did.method == DidMethod.LUX
        assert did.id == "z6MkTest123"

    def test_parse_key_did(self):
        """Test parsing did:key DID."""
        did = parse_did("did:key:z6MkTestKey456")
        assert did.method == DidMethod.KEY
        assert did.id == "z6MkTestKey456"

    def test_parse_web_did(self):
        """Test parsing did:web DID."""
        did = parse_did("did:web:example.com:user:alice")
        assert did.method == DidMethod.WEB
        assert did.id == "example.com:user:alice"

    def test_parse_invalid(self):
        """Test parsing invalid DID."""
        with pytest.raises((ValueError, IdentityError)):
            parse_did("invalid")

    def test_parse_missing_method(self):
        """Test parsing DID without method."""
        with pytest.raises((ValueError, IdentityError)):
            parse_did("did:")


class TestDidDocument:
    """Tests for DidDocument class."""

    def test_create_did_document(self):
        """Test creating a DID document."""
        did = Did(method=DidMethod.LUX, id="z6MkTest123")
        doc = did.document()
        assert doc.id == "did:lux:z6MkTest123"

    def test_did_document_to_json(self):
        """Test converting DID document to JSON."""
        did = Did(method=DidMethod.LUX, id="z6MkTest123")
        doc = did.document()
        json_str = doc.to_json()
        assert '"id": "did:lux:z6MkTest123"' in json_str or '"id":"did:lux:z6MkTest123"' in json_str


class TestBase58:
    """Tests for base58 encoding/decoding."""

    def test_base58_encode(self):
        """Test base58 encoding."""
        data = b"hello"
        encoded = base58_encode(data)
        assert len(encoded) > 0

    def test_base58_decode(self):
        """Test base58 decoding."""
        data = b"hello"
        encoded = base58_encode(data)
        decoded = base58_decode(encoded)
        assert decoded == data

    def test_base58_roundtrip(self):
        """Test base58 encode/decode roundtrip."""
        test_cases = [
            b"a",
            b"hello world",
            bytes(range(1, 256)),  # Skip leading zeros for this test
        ]
        for data in test_cases:
            encoded = base58_encode(data)
            decoded = base58_decode(encoded)
            assert decoded == data


class TestCreateDidFromKey:
    """Tests for create_did_from_key function."""

    def test_create_did_from_key(self):
        """Test creating did:key from bytes."""
        # 1952-byte fake ML-DSA public key (exact size required)
        public_key = bytes([i % 256 for i in range(1952)])
        did = create_did_from_key(public_key)

        assert did.method == DidMethod.KEY
        assert did.id.startswith("z")


class TestCreateDidFromWeb:
    """Tests for create_did_from_web function."""

    def test_create_did_from_web(self):
        """Test creating did:web from domain."""
        did = create_did_from_web("example.com")
        assert did.method == DidMethod.WEB
        assert did.id == "example.com"

    def test_create_did_from_web_with_path(self):
        """Test creating did:web with path."""
        did = create_did_from_web("example.com", "users/alice")
        assert did.method == DidMethod.WEB
        assert "example.com" in did.id
