"""Tests for zap_schema.crypto module.

These exercise the real ML-KEM-768 / ML-DSA-65 / hybrid handshake API. When the
optional post-quantum backends (cryptography, pqcrypto) are absent the module
degrades gracefully and these tests are skipped.
"""

import pytest

from zap_schema import crypto
from zap_schema.crypto import (
    HYBRID_SHARED_SECRET_SIZE,
    MLDSA_PUBLIC_KEY_SIZE,
    MLDSA_SIGNATURE_SIZE,
    MLKEM_CIPHERTEXT_SIZE,
    MLKEM_PUBLIC_KEY_SIZE,
    CryptoError,
    HandshakeRole,
    HybridHandshake,
    HybridInitiatorData,
    HybridResponderData,
    PQKeyExchange,
    PQSignature,
)

pq = pytest.mark.skipif(not crypto.PQ_AVAILABLE, reason="pqcrypto not installed")
hybrid = pytest.mark.skipif(
    not (crypto.PQ_AVAILABLE and crypto.X25519_AVAILABLE),
    reason="cryptography + pqcrypto required",
)


class TestConstants:
    """Module-level size constants follow FIPS 203/204."""

    def test_sizes(self):
        assert MLKEM_PUBLIC_KEY_SIZE == 1184
        assert MLKEM_CIPHERTEXT_SIZE == 1088
        assert MLDSA_PUBLIC_KEY_SIZE == 1952
        assert MLDSA_SIGNATURE_SIZE == 3309
        assert HYBRID_SHARED_SECRET_SIZE == 32


@pq
class TestPQKeyExchange:
    """ML-KEM-768 key encapsulation."""

    def test_generate_public_key_size(self):
        kx = PQKeyExchange.generate()
        assert len(kx.public_key) == MLKEM_PUBLIC_KEY_SIZE
        assert isinstance(kx.public_key, bytes)

    def test_generate_unique(self):
        assert PQKeyExchange.generate().public_key != PQKeyExchange.generate().public_key

    def test_encapsulate_decapsulate_roundtrip(self):
        alice = PQKeyExchange.generate()
        bob = PQKeyExchange.generate()
        ciphertext, shared_alice = alice.encapsulate(bob.public_key)
        shared_bob = bob.decapsulate(ciphertext)
        assert shared_alice == shared_bob
        assert len(ciphertext) == MLKEM_CIPHERTEXT_SIZE
        assert isinstance(shared_bob, bytes)

    def test_from_public_key(self):
        original = PQKeyExchange.generate()
        restored = PQKeyExchange.from_public_key(original.public_key)
        assert restored.public_key == original.public_key

    def test_from_public_key_bad_size(self):
        with pytest.raises(CryptoError, match="Invalid ML-KEM public key size"):
            PQKeyExchange.from_public_key(b"too-short")

    def test_encapsulate_bad_recipient_size(self):
        with pytest.raises(CryptoError, match="Invalid recipient public key size"):
            PQKeyExchange.generate().encapsulate(b"nope")

    def test_decapsulate_bad_ciphertext_size(self):
        with pytest.raises(CryptoError, match="Invalid ML-KEM ciphertext size"):
            PQKeyExchange.generate().decapsulate(b"nope")

    def test_decapsulate_without_secret_key(self):
        kx = PQKeyExchange.from_public_key(PQKeyExchange.generate().public_key)
        with pytest.raises(CryptoError, match="No secret key"):
            kx.decapsulate(bytes(MLKEM_CIPHERTEXT_SIZE))


@pq
class TestPQSignature:
    """ML-DSA-65 digital signatures."""

    def test_generate_public_key_size(self):
        sig = PQSignature.generate()
        assert len(sig.public_key) == MLDSA_PUBLIC_KEY_SIZE

    def test_sign_and_verify(self):
        signer = PQSignature.generate()
        signature = signer.sign(b"the quick brown fox")
        assert len(signature) == MLDSA_SIGNATURE_SIZE
        assert isinstance(signature, bytes)
        assert signer.verify(b"the quick brown fox", signature) is True

    def test_verify_tampered_signature_returns_false(self):
        signer = PQSignature.generate()
        signature = signer.sign(b"message")
        tampered = bytes([(signature[0] + 1) % 256]) + signature[1:]
        assert signer.verify(b"message", tampered) is False

    def test_verify_wrong_message_returns_false(self):
        signer = PQSignature.generate()
        signature = signer.sign(b"original")
        assert signer.verify(b"different", signature) is False

    def test_verify_with_public_key_only(self):
        signer = PQSignature.generate()
        signature = signer.sign(b"hi")
        verifier = PQSignature.from_public_key(signer.public_key)
        assert verifier.verify(b"hi", signature) is True

    def test_from_public_key_bad_size(self):
        with pytest.raises(CryptoError, match="Invalid ML-DSA public key size"):
            PQSignature.from_public_key(b"short")

    def test_sign_without_secret_key(self):
        verifier = PQSignature.from_public_key(PQSignature.generate().public_key)
        with pytest.raises(CryptoError, match="No secret key"):
            verifier.sign(b"x")

    def test_verify_bad_signature_size(self):
        with pytest.raises(CryptoError, match="Invalid ML-DSA signature size"):
            PQSignature.generate().verify(b"x", b"short-sig")


@hybrid
class TestHybridHandshake:
    """X25519 + ML-KEM-768 hybrid handshake."""

    def test_full_handshake_derives_secrets(self):
        initiator = HybridHandshake.initiate()
        assert initiator._role is HandshakeRole.INITIATOR

        public_data = initiator.public_data
        assert isinstance(public_data, HybridInitiatorData)
        assert len(public_data.x25519_public_key) == 32
        assert len(public_data.mlkem_public_key) == MLKEM_PUBLIC_KEY_SIZE

        responder, response = HybridHandshake.respond(public_data)
        assert responder._role is HandshakeRole.RESPONDER
        assert isinstance(response, HybridResponderData)

        secret = initiator.finalize(response)
        assert len(secret) == HYBRID_SHARED_SECRET_SIZE
        assert isinstance(secret, bytes)

        responder_secret = responder.complete(public_data)
        assert len(responder_secret) == HYBRID_SHARED_SECRET_SIZE

    def test_derive_hybrid_secret_deterministic(self):
        a = HybridHandshake._derive_hybrid_secret(b"x" * 32, b"y" * 32)
        b = HybridHandshake._derive_hybrid_secret(b"x" * 32, b"y" * 32)
        assert a == b
        assert len(a) == HYBRID_SHARED_SECRET_SIZE
        assert isinstance(a, bytes)

    def test_derive_hybrid_secret_input_sensitive(self):
        a = HybridHandshake._derive_hybrid_secret(b"x" * 32, b"y" * 32)
        b = HybridHandshake._derive_hybrid_secret(b"x" * 32, b"z" * 32)
        assert a != b

    def test_finalize_only_by_initiator(self):
        _, response = HybridHandshake.respond(HybridHandshake.initiate().public_data)
        responder, _ = HybridHandshake.respond(HybridHandshake.initiate().public_data)
        with pytest.raises(CryptoError, match="finalize"):
            responder.finalize(response)

    def test_complete_only_by_responder(self):
        initiator = HybridHandshake.initiate()
        with pytest.raises(CryptoError, match="complete"):
            initiator.complete(initiator.public_data)

    def test_respond_rejects_bad_x25519_size(self):
        bad = HybridInitiatorData(
            x25519_public_key=b"short",
            mlkem_public_key=bytes(MLKEM_PUBLIC_KEY_SIZE),
        )
        with pytest.raises(CryptoError, match="Invalid X25519 public key size"):
            HybridHandshake.respond(bad)

    def test_respond_rejects_bad_mlkem_size(self):
        bad = HybridInitiatorData(
            x25519_public_key=bytes(32),
            mlkem_public_key=b"short",
        )
        with pytest.raises(CryptoError, match="Invalid ML-KEM public key size"):
            HybridHandshake.respond(bad)
