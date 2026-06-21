"""Tests for zap_schema.identity module."""

import pytest

from zap_schema import crypto
from zap_schema.identity import (
    Did,
    DidDocument,
    DidMethod,
    IdentityError,
    InMemoryStakeRegistry,
    NodeIdentity,
    Service,
    ServiceEndpoint,
    ServiceType,
    VerificationMethod,
    VerificationMethodType,
    base58_decode,
    base58_encode,
    create_did_from_key,
    create_did_from_web,
    generate_identity,
    parse_did,
)

pq = pytest.mark.skipif(not crypto.PQ_AVAILABLE, reason="pqcrypto not installed")


def _real_public_key() -> bytes:
    """A valid ML-DSA-65 public key (real if pqcrypto present, else sized stub)."""
    if crypto.PQ_AVAILABLE:
        return crypto.PQSignature.generate().public_key
    return bytes(i % 256 for i in range(1952))


class TestDid:
    """Tests for Did class."""

    def test_create_lux_did(self):
        """Test creating a did:zap DID."""
        did = Did(method=DidMethod.ZAP, id="z6MkTest123")
        assert did.method == DidMethod.ZAP
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
        did = Did(method=DidMethod.ZAP, id="z6MkTest123")
        assert did.uri() == "did:zap:z6MkTest123"

    def test_did_equality(self):
        """Test DID equality comparison."""
        did1 = Did(method=DidMethod.ZAP, id="z6MkTest123")
        did2 = Did(method=DidMethod.ZAP, id="z6MkTest123")
        did3 = Did(method=DidMethod.ZAP, id="z6MkDifferent")
        assert did1.uri() == did2.uri()
        assert did1.uri() != did3.uri()


class TestParseDid:
    """Tests for parse_did function."""

    def test_parse_lux_did(self):
        """Test parsing did:zap DID."""
        did = parse_did("did:zap:z6MkTest123")
        assert did.method == DidMethod.ZAP
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
        did = Did(method=DidMethod.ZAP, id="z6MkTest123")
        doc = did.document()
        assert doc.id == "did:zap:z6MkTest123"

    def test_did_document_to_json(self):
        """Test converting DID document to JSON."""
        did = Did(method=DidMethod.ZAP, id="z6MkTest123")
        doc = did.document()
        json_str = doc.to_json()
        assert '"id": "did:zap:z6MkTest123"' in json_str or '"id":"did:zap:z6MkTest123"' in json_str


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
        # '/' in path becomes ':' per did:web spec
        assert did.id == "example.com:users:alice"

    def test_create_did_from_web_empty_domain(self):
        with pytest.raises(IdentityError, match="domain cannot be empty"):
            create_did_from_web("")

    def test_create_did_from_web_invalid_domain(self):
        with pytest.raises(IdentityError, match="invalid domain"):
            create_did_from_web("bad/domain.com")

    def test_create_did_from_key_bad_size(self):
        with pytest.raises(IdentityError, match="invalid ML-DSA public key size"):
            create_did_from_key(b"too-short")


class TestParseDidExtra:
    """Additional parse_did edge cases."""

    def test_parse_unknown_method(self):
        with pytest.raises(IdentityError, match="unknown DID method"):
            parse_did("did:sov:abc123")

    def test_parse_no_method_separator(self):
        with pytest.raises(IdentityError, match="invalid DID format"):
            parse_did("did:onlymethod")

    def test_str_dunder(self):
        assert str(Did(method=DidMethod.KEY, id="z6MkAbc")) == "did:key:z6MkAbc"

    def test_did_hashable(self):
        a = Did(method=DidMethod.ZAP, id="z6MkAbc")
        b = Did(method=DidMethod.ZAP, id="z6MkAbc")
        assert {a, b} == {a}


class TestKeyMaterial:
    """extract_key_material and key-anchored DID documents."""

    def test_roundtrip_key_material(self):
        pk = _real_public_key()
        did = create_did_from_key(pk)
        assert did.extract_key_material() == pk

    def test_extract_empty_identifier(self):
        with pytest.raises(IdentityError, match="empty DID identifier"):
            Did(method=DidMethod.KEY, id="").extract_key_material()

    def test_extract_wrong_multibase(self):
        with pytest.raises(IdentityError, match="unsupported multibase"):
            Did(method=DidMethod.KEY, id="Q123").extract_key_material()

    def test_key_document_has_verification_method(self):
        did = create_did_from_key(_real_public_key())
        doc = did.document()
        vm = doc.primary_verification_method()
        assert vm is not None
        assert vm.id.endswith("#keys-1")
        assert vm.public_key_multibase == did.id
        assert vm.blockchain_account_id is None

    def test_lux_document_has_blockchain_account_id(self):
        did = create_did_from_key(_real_public_key(), method=DidMethod.ZAP)
        doc = did.document()
        vm = doc.primary_verification_method()
        assert vm is not None
        assert vm.blockchain_account_id is not None
        assert vm.blockchain_account_id.startswith("zap:")

    def test_web_document_has_no_key_material(self):
        doc = create_did_from_web("example.com").document()
        vm = doc.primary_verification_method()
        assert vm is not None
        assert vm.public_key_multibase is None


class TestDidDocumentSerialization:
    """DID document to_dict / from_dict / JSON roundtrip."""

    def test_to_dict_contains_core_fields(self):
        doc = create_did_from_key(_real_public_key()).document()
        d = doc.to_dict()
        assert d["id"] == doc.id
        assert "@context" in d
        assert "verificationMethod" in d
        assert "service" in d
        assert d["authentication"]

    def test_json_roundtrip(self):
        original = create_did_from_key(_real_public_key()).document()
        restored = DidDocument.from_json(original.to_json())
        assert restored.id == original.id
        assert restored.primary_verification_method().id == (
            original.primary_verification_method().id
        )
        assert len(restored.service) == len(original.service)

    def test_get_verification_method_and_service(self):
        doc = create_did_from_key(_real_public_key()).document()
        vm_id = doc.primary_verification_method().id
        assert doc.get_verification_method(vm_id) is not None
        assert doc.get_verification_method("missing") is None
        svc_id = doc.service[0].id
        assert doc.get_service(svc_id) is not None
        assert doc.get_service("missing") is None

    def test_from_dict_with_string_service_endpoint(self):
        data = {
            "id": "did:web:example.com",
            "@context": ["https://www.w3.org/ns/did/v1"],
            "service": [
                {
                    "id": "did:web:example.com#agent",
                    "type": "ZapAgent",
                    "serviceEndpoint": "zap://example.com",
                }
            ],
        }
        doc = DidDocument.from_dict(data)
        assert doc.service[0].service_endpoint.uri == "zap://example.com"


class TestServiceAndVerificationMethodDicts:
    """to_dict branches for nested document objects."""

    def test_service_endpoint_plain_uri(self):
        assert ServiceEndpoint(uri="zap://node").to_dict() == "zap://node"

    def test_service_endpoint_rich(self):
        ep = ServiceEndpoint(uri="zap://node", accept=["a"], routing_keys=["k"])
        d = ep.to_dict()
        assert d == {"uri": "zap://node", "accept": ["a"], "routingKeys": ["k"]}

    def test_verification_method_to_dict_full(self):
        vm = VerificationMethod(
            id="did:key:z#1",
            type=VerificationMethodType.JSON_WEB_KEY_2020,
            controller="did:key:z",
            public_key_multibase="z6Mk",
            public_key_jwk={"kty": "OKP"},
            blockchain_account_id="zap:deadbeef",
        )
        d = vm.to_dict()
        assert d["publicKeyMultibase"] == "z6Mk"
        assert d["publicKeyJwk"] == {"kty": "OKP"}
        assert d["blockchainAccountId"] == "zap:deadbeef"

    def test_service_to_dict(self):
        svc = Service(
            id="did:web:x#agent",
            type=ServiceType.ZAP_AGENT,
            service_endpoint=ServiceEndpoint(uri="zap://x"),
        )
        d = svc.to_dict()
        assert d["type"] == "ZapAgent"
        assert d["serviceEndpoint"] == "zap://x"


class TestBase58LeadingZeros:
    """base58 leading-zero handling."""

    def test_leading_zero_bytes_roundtrip(self):
        data = b"\x00\x00\x01\x02"
        encoded = base58_encode(data)
        assert encoded.startswith("11")  # two leading zero bytes -> two '1's
        assert base58_decode(encoded) == data

    def test_all_zero_bytes(self):
        assert base58_decode(base58_encode(b"\x00\x00\x00")) == b"\x00\x00\x00"


class TestStakeRegistry:
    """InMemoryStakeRegistry behavior."""

    def test_set_get_and_weight(self):
        reg = InMemoryStakeRegistry()
        a = Did(method=DidMethod.ZAP, id="z6MkA")
        b = Did(method=DidMethod.ZAP, id="z6MkB")
        assert reg.get_stake(a) == 0
        assert reg.stake_weight(a) == 0.0  # empty registry
        reg.set_stake(a, 75)
        reg.set_stake(b, 25)
        assert reg.total_stake() == 100
        assert reg.stake_weight(a) == 0.75
        assert reg.has_sufficient_stake(a, 50) is True
        assert reg.has_sufficient_stake(b, 50) is False


@pq
class TestNodeIdentity:
    """NodeIdentity signing, verification, and builders."""

    def test_generate_can_sign(self):
        identity = generate_identity()
        assert identity.can_sign() is True
        assert identity.did.method == DidMethod.ZAP
        assert len(identity.public_key) == 1952

    def test_generate_key_method(self):
        identity = generate_identity(method=DidMethod.KEY)
        assert identity.did.method == DidMethod.KEY

    def test_sign_and_self_verify(self):
        identity = generate_identity()
        sig = identity.sign(b"payload")
        assert isinstance(sig, bytes)
        assert identity.verify(b"payload", sig) is True

    def test_verify_rejects_tampered(self):
        identity = generate_identity()
        sig = identity.sign(b"payload")
        bad = bytes([(sig[0] + 1) % 256]) + sig[1:]
        assert identity.verify(b"payload", bad) is False

    def test_verify_with_public_key_only(self):
        identity = generate_identity()
        sig = identity.sign(b"payload")
        verifier = NodeIdentity(did=identity.did, public_key=identity.public_key)
        assert verifier.can_sign() is False
        assert verifier.verify(b"payload", sig) is True

    def test_sign_without_signer_raises(self):
        identity = NodeIdentity(did=generate_identity().did, public_key=_real_public_key())
        with pytest.raises(IdentityError, match="no private key"):
            identity.sign(b"x")

    def test_with_stake_and_registry(self):
        identity = generate_identity()
        identity.with_stake(500).with_registry("registry://main")
        assert identity.stake == 500
        assert identity.stake_registry == "registry://main"

    def test_document_from_node_identity(self):
        identity = generate_identity()
        doc = identity.document()
        assert doc.id == identity.did.uri()
