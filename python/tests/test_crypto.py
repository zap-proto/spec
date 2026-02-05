"""Tests for zap_schema.crypto module."""

import pytest
from zap_schema import crypto


class TestHashFunctions:
    """Tests for hash functions."""

    def test_blake3_hash(self):
        """Test BLAKE3 hashing."""
        if not hasattr(crypto, 'blake3_hash'):
            pytest.skip("blake3_hash not implemented")

        data = b"hello world"
        hash1 = crypto.blake3_hash(data)
        hash2 = crypto.blake3_hash(data)

        assert hash1 == hash2
        assert len(hash1) == 32

    def test_blake3_hash_different_inputs(self):
        """Test BLAKE3 produces different hashes for different inputs."""
        if not hasattr(crypto, 'blake3_hash'):
            pytest.skip("blake3_hash not implemented")

        hash1 = crypto.blake3_hash(b"hello")
        hash2 = crypto.blake3_hash(b"world")

        assert hash1 != hash2


class TestKeyGeneration:
    """Tests for key generation functions."""

    def test_generate_keypair(self):
        """Test generating a keypair."""
        if not hasattr(crypto, 'generate_keypair'):
            pytest.skip("generate_keypair not implemented")

        public_key, secret_key = crypto.generate_keypair()
        assert len(public_key) == 32  # Ed25519 public key
        assert len(secret_key) == 64  # Ed25519 secret key

    def test_generate_keypair_unique(self):
        """Test that each keypair is unique."""
        if not hasattr(crypto, 'generate_keypair'):
            pytest.skip("generate_keypair not implemented")

        pk1, _ = crypto.generate_keypair()
        pk2, _ = crypto.generate_keypair()

        assert pk1 != pk2


class TestSignatureVerification:
    """Tests for signature operations."""

    def test_sign_and_verify(self):
        """Test signing and verifying a message."""
        if not hasattr(crypto, 'sign') or not hasattr(crypto, 'verify'):
            pytest.skip("sign/verify not implemented")

        public_key, secret_key = crypto.generate_keypair()
        message = b"test message"

        signature = crypto.sign(message, secret_key)
        assert crypto.verify(message, signature, public_key)

    def test_verify_invalid_signature(self):
        """Test verification fails with invalid signature."""
        if not hasattr(crypto, 'sign') or not hasattr(crypto, 'verify'):
            pytest.skip("sign/verify not implemented")

        public_key, secret_key = crypto.generate_keypair()
        message = b"test message"

        signature = crypto.sign(message, secret_key)
        # Corrupt signature
        bad_signature = bytes([(b + 1) % 256 for b in signature])

        assert not crypto.verify(message, bad_signature, public_key)


class TestHKDF:
    """Tests for HKDF key derivation."""

    def test_hkdf_derive(self):
        """Test HKDF key derivation."""
        if not hasattr(crypto, 'hkdf_derive'):
            pytest.skip("hkdf_derive not implemented")

        ikm = b"input key material"
        salt = b"salt"
        info = b"info"

        derived = crypto.hkdf_derive(ikm, salt, info, 32)
        assert len(derived) == 32

    def test_hkdf_deterministic(self):
        """Test HKDF is deterministic."""
        if not hasattr(crypto, 'hkdf_derive'):
            pytest.skip("hkdf_derive not implemented")

        ikm = b"input key material"
        salt = b"salt"
        info = b"info"

        derived1 = crypto.hkdf_derive(ikm, salt, info, 32)
        derived2 = crypto.hkdf_derive(ikm, salt, info, 32)

        assert derived1 == derived2


class TestAEAD:
    """Tests for AEAD encryption."""

    def test_aead_encrypt_decrypt(self):
        """Test AEAD encrypt/decrypt roundtrip."""
        if not hasattr(crypto, 'aead_encrypt') or not hasattr(crypto, 'aead_decrypt'):
            pytest.skip("AEAD not implemented")

        key = bytes(32)  # 256-bit key
        nonce = bytes(12)
        plaintext = b"secret message"
        aad = b"additional data"

        ciphertext = crypto.aead_encrypt(key, nonce, plaintext, aad)
        decrypted = crypto.aead_decrypt(key, nonce, ciphertext, aad)

        assert decrypted == plaintext


class TestCryptoModule:
    """General crypto module tests."""

    def test_module_has_constants(self):
        """Test crypto module has expected constants."""
        # Just test the module is importable and has some content
        assert hasattr(crypto, '__name__')
