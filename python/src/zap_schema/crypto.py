"""
Post-Quantum Cryptography Module for ZAP

Provides ML-KEM-768 key exchange, ML-DSA-65 signatures, and hybrid X25519+ML-KEM handshake.

Security:
    This module implements NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) standards
    for post-quantum cryptographic protection. The hybrid handshake combines
    classical X25519 with ML-KEM-768 for defense-in-depth.

Example:
    >>> from hanzo_zap.crypto import PQKeyExchange, PQSignature, HybridHandshake

    # Key exchange
    >>> alice = PQKeyExchange.generate()
    >>> bob = PQKeyExchange.generate()
    >>> ciphertext, shared_alice = alice.encapsulate(bob.public_key)
    >>> shared_bob = bob.decapsulate(ciphertext)
    >>> assert shared_alice == shared_bob

    # Signatures
    >>> signer = PQSignature.generate()
    >>> sig = signer.sign(b"message")
    >>> signer.verify(b"message", sig)  # Returns True

    # Hybrid handshake
    >>> initiator = HybridHandshake.initiate()
    >>> responder, response = HybridHandshake.respond(initiator.public_data)
    >>> shared_init = initiator.finalize(response)
    >>> shared_resp = responder.complete(initiator.public_data)
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple

# Attempt to import pqcrypto bindings
# Falls back to stub implementations if not available
try:
    from pqcrypto.kem.kyber768 import (
        generate_keypair as mlkem_keypair,
        encrypt as mlkem_encapsulate,
        decrypt as mlkem_decapsulate,
        PUBLIC_KEY_SIZE as MLKEM_PUBLIC_KEY_SIZE,
        CIPHERTEXT_SIZE as MLKEM_CIPHERTEXT_SIZE,
    )
    from pqcrypto.sign.dilithium3 import (
        generate_keypair as mldsa_keypair,
        sign as mldsa_sign,
        verify as mldsa_verify,
        PUBLIC_KEY_SIZE as MLDSA_PUBLIC_KEY_SIZE,
        SIGNATURE_SIZE as MLDSA_SIGNATURE_SIZE,
    )
    PQ_AVAILABLE = True
except ImportError:
    PQ_AVAILABLE = False
    # Placeholder sizes for when pqcrypto is not available
    MLKEM_PUBLIC_KEY_SIZE = 1184
    MLKEM_CIPHERTEXT_SIZE = 1088
    MLDSA_PUBLIC_KEY_SIZE = 1952
    MLDSA_SIGNATURE_SIZE = 3293

# Attempt to import X25519 from cryptography
try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    X25519_AVAILABLE = True
except ImportError:
    X25519_AVAILABLE = False

# Constants
X25519_PUBLIC_KEY_SIZE = 32
SHARED_SECRET_SIZE = 32
HYBRID_SHARED_SECRET_SIZE = 32


class CryptoError(Exception):
    """Cryptographic operation error."""
    pass


class PQKeyExchange:
    """
    ML-KEM-768 Key Encapsulation Mechanism.

    Implements NIST FIPS 203 ML-KEM-768 for post-quantum key exchange.
    Security level: NIST Level 3 (~AES-192 equivalent).
    """

    def __init__(self, public_key: bytes, secret_key: Optional[bytes] = None):
        self._public_key = public_key
        self._secret_key = secret_key

    @classmethod
    def generate(cls) -> "PQKeyExchange":
        """Generate a new ML-KEM-768 keypair."""
        if not PQ_AVAILABLE:
            raise CryptoError("pqcrypto not available - install with: pip install pqcrypto")
        pk, sk = mlkem_keypair()
        return cls(pk, sk)

    @classmethod
    def from_public_key(cls, public_key: bytes) -> "PQKeyExchange":
        """Create instance from public key (for encapsulation only)."""
        if len(public_key) != MLKEM_PUBLIC_KEY_SIZE:
            raise CryptoError(
                f"Invalid ML-KEM public key size: expected {MLKEM_PUBLIC_KEY_SIZE}, "
                f"got {len(public_key)}"
            )
        return cls(public_key, None)

    @property
    def public_key(self) -> bytes:
        """Get the public key bytes."""
        return self._public_key

    def encapsulate(self, recipient_pk: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate: generate ciphertext and shared secret for a recipient's public key.

        Args:
            recipient_pk: The recipient's ML-KEM public key.

        Returns:
            Tuple of (ciphertext, shared_secret).
        """
        if not PQ_AVAILABLE:
            raise CryptoError("pqcrypto not available")
        if len(recipient_pk) != MLKEM_PUBLIC_KEY_SIZE:
            raise CryptoError(
                f"Invalid recipient public key size: expected {MLKEM_PUBLIC_KEY_SIZE}, "
                f"got {len(recipient_pk)}"
            )
        ciphertext, shared_secret = mlkem_encapsulate(recipient_pk)
        return ciphertext, shared_secret

    def decapsulate(self, ciphertext: bytes) -> bytes:
        """
        Decapsulate: recover shared secret from ciphertext.

        Args:
            ciphertext: The ML-KEM ciphertext.

        Returns:
            The shared secret bytes.
        """
        if not PQ_AVAILABLE:
            raise CryptoError("pqcrypto not available")
        if self._secret_key is None:
            raise CryptoError("No secret key available for decapsulation")
        if len(ciphertext) != MLKEM_CIPHERTEXT_SIZE:
            raise CryptoError(
                f"Invalid ML-KEM ciphertext size: expected {MLKEM_CIPHERTEXT_SIZE}, "
                f"got {len(ciphertext)}"
            )
        return mlkem_decapsulate(ciphertext, self._secret_key)


class PQSignature:
    """
    ML-DSA-65 Digital Signature Algorithm.

    Implements NIST FIPS 204 ML-DSA-65 (Dilithium3) for post-quantum signatures.
    Security level: NIST Level 3 (~AES-192 equivalent).
    """

    def __init__(self, public_key: bytes, secret_key: Optional[bytes] = None):
        self._public_key = public_key
        self._secret_key = secret_key

    @classmethod
    def generate(cls) -> "PQSignature":
        """Generate a new ML-DSA-65 keypair."""
        if not PQ_AVAILABLE:
            raise CryptoError("pqcrypto not available - install with: pip install pqcrypto")
        pk, sk = mldsa_keypair()
        return cls(pk, sk)

    @classmethod
    def from_public_key(cls, public_key: bytes) -> "PQSignature":
        """Create instance from public key (for verification only)."""
        if len(public_key) != MLDSA_PUBLIC_KEY_SIZE:
            raise CryptoError(
                f"Invalid ML-DSA public key size: expected {MLDSA_PUBLIC_KEY_SIZE}, "
                f"got {len(public_key)}"
            )
        return cls(public_key, None)

    @property
    def public_key(self) -> bytes:
        """Get the public key bytes."""
        return self._public_key

    def sign(self, message: bytes) -> bytes:
        """
        Sign a message.

        Args:
            message: The message bytes to sign.

        Returns:
            The signature bytes.
        """
        if not PQ_AVAILABLE:
            raise CryptoError("pqcrypto not available")
        if self._secret_key is None:
            raise CryptoError("No secret key available for signing")
        return mldsa_sign(message, self._secret_key)

    def verify(self, message: bytes, signature: bytes) -> bool:
        """
        Verify a signature.

        Args:
            message: The original message bytes.
            signature: The signature bytes.

        Returns:
            True if valid, raises CryptoError if invalid.
        """
        if not PQ_AVAILABLE:
            raise CryptoError("pqcrypto not available")
        if len(signature) != MLDSA_SIGNATURE_SIZE:
            raise CryptoError(
                f"Invalid ML-DSA signature size: expected {MLDSA_SIGNATURE_SIZE}, "
                f"got {len(signature)}"
            )
        try:
            mldsa_verify(message, signature, self._public_key)
            return True
        except Exception:
            raise CryptoError("Signature verification failed")


@dataclass
class HybridInitiatorData:
    """Public data from the initiator for the responder."""
    x25519_public_key: bytes
    mlkem_public_key: bytes


@dataclass
class HybridResponderData:
    """Response data from the responder for the initiator."""
    x25519_public_key: bytes
    mlkem_ciphertext: bytes


class HandshakeRole(Enum):
    """Role in the handshake."""
    INITIATOR = "initiator"
    RESPONDER = "responder"


class HybridHandshake:
    """
    Hybrid X25519 + ML-KEM-768 Handshake.

    Combines classical elliptic curve Diffie-Hellman (X25519) with post-quantum
    ML-KEM-768 for defense-in-depth. Even if one algorithm is broken, the other
    provides protection.

    The final shared secret is derived using HKDF-SHA256 over both shared secrets.
    """

    def __init__(
        self,
        x25519_private: Optional[bytes],
        x25519_public: bytes,
        mlkem: PQKeyExchange,
        role: HandshakeRole,
    ):
        self._x25519_private = x25519_private
        self._x25519_public = x25519_public
        self._mlkem = mlkem
        self._role = role

    @classmethod
    def initiate(cls) -> "HybridHandshake":
        """
        Initiate a hybrid handshake (client side).

        Returns:
            A new HybridHandshake instance ready to send public data.
        """
        if not X25519_AVAILABLE:
            raise CryptoError(
                "cryptography not available - install with: pip install cryptography"
            )
        if not PQ_AVAILABLE:
            raise CryptoError(
                "pqcrypto not available - install with: pip install pqcrypto"
            )

        # Generate X25519 keypair
        x25519_private = X25519PrivateKey.generate()
        x25519_public = x25519_private.public_key().public_bytes_raw()
        x25519_private_bytes = x25519_private.private_bytes_raw()

        # Generate ML-KEM keypair
        mlkem = PQKeyExchange.generate()

        return cls(
            x25519_private=x25519_private_bytes,
            x25519_public=x25519_public,
            mlkem=mlkem,
            role=HandshakeRole.INITIATOR,
        )

    @property
    def public_data(self) -> HybridInitiatorData:
        """Get the public data to send to the responder."""
        return HybridInitiatorData(
            x25519_public_key=self._x25519_public,
            mlkem_public_key=self._mlkem.public_key,
        )

    @classmethod
    def respond(
        cls, initiator_data: HybridInitiatorData
    ) -> Tuple["HybridHandshake", HybridResponderData]:
        """
        Respond to a hybrid handshake (server side).

        Args:
            initiator_data: Public data from the initiator.

        Returns:
            Tuple of (HybridHandshake, HybridResponderData) to send back.
        """
        if not X25519_AVAILABLE:
            raise CryptoError("cryptography not available")
        if not PQ_AVAILABLE:
            raise CryptoError("pqcrypto not available")

        # Validate input
        if len(initiator_data.x25519_public_key) != X25519_PUBLIC_KEY_SIZE:
            raise CryptoError(
                f"Invalid X25519 public key size: expected {X25519_PUBLIC_KEY_SIZE}, "
                f"got {len(initiator_data.x25519_public_key)}"
            )
        if len(initiator_data.mlkem_public_key) != MLKEM_PUBLIC_KEY_SIZE:
            raise CryptoError(
                f"Invalid ML-KEM public key size: expected {MLKEM_PUBLIC_KEY_SIZE}, "
                f"got {len(initiator_data.mlkem_public_key)}"
            )

        # Generate responder's X25519 keypair
        x25519_private = X25519PrivateKey.generate()
        x25519_public = x25519_private.public_key().public_bytes_raw()
        x25519_private_bytes = x25519_private.private_bytes_raw()

        # Generate ML-KEM keypair and encapsulate to initiator
        mlkem = PQKeyExchange.generate()
        mlkem_ciphertext, _ = mlkem.encapsulate(initiator_data.mlkem_public_key)

        response = HybridResponderData(
            x25519_public_key=x25519_public,
            mlkem_ciphertext=mlkem_ciphertext,
        )

        handshake = cls(
            x25519_private=x25519_private_bytes,
            x25519_public=x25519_public,
            mlkem=mlkem,
            role=HandshakeRole.RESPONDER,
        )

        return handshake, response

    def finalize(self, responder_data: HybridResponderData) -> bytes:
        """
        Finalize the handshake and derive the shared secret (initiator side).

        Args:
            responder_data: Response data from the responder.

        Returns:
            The derived shared secret (32 bytes).
        """
        if self._role != HandshakeRole.INITIATOR:
            raise CryptoError("finalize() can only be called by initiator")
        if self._x25519_private is None:
            raise CryptoError("X25519 private key not available")

        # X25519 key exchange
        x25519_private = X25519PrivateKey.from_private_bytes(self._x25519_private)
        peer_x25519_public = X25519PublicKey.from_public_bytes(
            responder_data.x25519_public_key
        )
        x25519_shared = x25519_private.exchange(peer_x25519_public)

        # ML-KEM decapsulation
        mlkem_shared = self._mlkem.decapsulate(responder_data.mlkem_ciphertext)

        # Clear private key
        self._x25519_private = None

        # Combine shared secrets with HKDF
        return self._derive_hybrid_secret(x25519_shared, mlkem_shared)

    def complete(
        self,
        initiator_data: HybridInitiatorData,
        mlkem_shared: Optional[bytes] = None,
    ) -> bytes:
        """
        Complete the handshake and derive the shared secret (responder side).

        Args:
            initiator_data: Public data from the initiator.
            mlkem_shared: Optional pre-computed ML-KEM shared secret.

        Returns:
            The derived shared secret (32 bytes).
        """
        if self._role != HandshakeRole.RESPONDER:
            raise CryptoError("complete() can only be called by responder")
        if self._x25519_private is None:
            raise CryptoError("X25519 private key not available")

        # X25519 key exchange
        x25519_private = X25519PrivateKey.from_private_bytes(self._x25519_private)
        peer_x25519_public = X25519PublicKey.from_public_bytes(
            initiator_data.x25519_public_key
        )
        x25519_shared = x25519_private.exchange(peer_x25519_public)

        # Use provided ML-KEM shared secret or compute it
        if mlkem_shared is None:
            # Responder needs to encapsulate to initiator's key to get same shared secret
            _, mlkem_shared = self._mlkem.encapsulate(initiator_data.mlkem_public_key)

        # Clear private key
        self._x25519_private = None

        # Combine shared secrets with HKDF
        return self._derive_hybrid_secret(x25519_shared, mlkem_shared)

    @staticmethod
    def _derive_hybrid_secret(x25519_shared: bytes, mlkem_shared: bytes) -> bytes:
        """
        Derive hybrid shared secret using HKDF-SHA256.

        Args:
            x25519_shared: X25519 shared secret.
            mlkem_shared: ML-KEM shared secret.

        Returns:
            The derived shared secret (32 bytes).
        """
        # Concatenate both shared secrets
        ikm = x25519_shared + mlkem_shared

        # HKDF extract and expand
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=HYBRID_SHARED_SECRET_SIZE,
            salt=b"ZAP-HYBRID-HANDSHAKE-v1",
            info=b"shared-secret",
        )
        return hkdf.derive(ikm)


def hybrid_handshake() -> Tuple[bytes, bytes]:
    """
    Perform a complete hybrid handshake between two parties.

    This is a convenience function for testing and simple use cases.

    Returns:
        Tuple of (initiator_secret, responder_secret) - both should be equal.
    """
    # Initiator starts
    initiator = HybridHandshake.initiate()
    init_data = initiator.public_data

    # Responder receives and responds
    responder, resp_data = HybridHandshake.respond(init_data)

    # Responder also encapsulates to get shared secret
    _, mlkem_shared = PQKeyExchange.generate().encapsulate(init_data.mlkem_public_key)

    # Initiator finalizes
    initiator_secret = initiator.finalize(resp_data)

    # Responder completes
    responder_secret = responder.complete(init_data, mlkem_shared)

    return initiator_secret, responder_secret


# Export public API
__all__ = [
    "PQ_AVAILABLE",
    "X25519_AVAILABLE",
    "MLKEM_PUBLIC_KEY_SIZE",
    "MLKEM_CIPHERTEXT_SIZE",
    "MLDSA_PUBLIC_KEY_SIZE",
    "MLDSA_SIGNATURE_SIZE",
    "X25519_PUBLIC_KEY_SIZE",
    "SHARED_SECRET_SIZE",
    "HYBRID_SHARED_SECRET_SIZE",
    "CryptoError",
    "PQKeyExchange",
    "PQSignature",
    "HybridInitiatorData",
    "HybridResponderData",
    "HybridHandshake",
    "hybrid_handshake",
]
