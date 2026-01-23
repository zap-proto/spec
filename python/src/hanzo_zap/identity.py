"""
W3C Decentralized Identifier (DID) Implementation

Implements W3C DID Core 1.0 specification with support for:
- did:lux - Lux blockchain-anchored DIDs
- did:key - Self-certifying DIDs from cryptographic keys
- did:web - DNS-based DIDs

Example:
    >>> from hanzo_zap.identity import Did, DidMethod, NodeIdentity

    # Parse existing DID
    >>> did = parse_did("did:lux:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
    >>> did.method
    <DidMethod.LUX: 'lux'>

    # Create from ML-DSA public key
    >>> did = create_did_from_key(public_key_bytes)

    # Generate DID Document
    >>> doc = did.document()

    # Generate node identity
    >>> identity = generate_identity()
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Protocol, Tuple, Union

# Base58 alphabet (Bitcoin style)
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# Multibase prefix for base58btc
MULTIBASE_BASE58BTC = "z"

# Multicodec prefix for ML-DSA-65 public key (provisional)
MULTICODEC_MLDSA65 = bytes([0x13, 0x09])

# Expected ML-DSA-65 public key size
MLDSA_PUBLIC_KEY_SIZE = 1952


class IdentityError(Exception):
    """Identity-related error."""
    pass


def base58_encode(data: bytes) -> str:
    """Encode bytes to base58 (Bitcoin alphabet)."""
    num = int.from_bytes(data, "big")
    result = []
    while num > 0:
        num, remainder = divmod(num, 58)
        result.append(BASE58_ALPHABET[remainder])

    # Handle leading zeros
    for byte in data:
        if byte == 0:
            result.append(BASE58_ALPHABET[0])
        else:
            break

    return "".join(reversed(result))


def base58_decode(s: str) -> bytes:
    """Decode base58 string to bytes."""
    num = 0
    for char in s:
        num = num * 58 + BASE58_ALPHABET.index(char)

    # Calculate byte length
    result = []
    while num > 0:
        num, remainder = divmod(num, 256)
        result.append(remainder)

    # Handle leading ones (zeros in decoded)
    for char in s:
        if char == BASE58_ALPHABET[0]:
            result.append(0)
        else:
            break

    return bytes(reversed(result))


class DidMethod(Enum):
    """DID method identifier."""
    LUX = "lux"
    KEY = "key"
    WEB = "web"


class VerificationMethodType(Enum):
    """Verification method type."""
    JSON_WEB_KEY_2020 = "JsonWebKey2020"
    MULTIKEY = "Multikey"
    ML_DSA_65_VERIFICATION_KEY_2024 = "MlDsa65VerificationKey2024"


class ServiceType(Enum):
    """Service type."""
    ZAP_AGENT = "ZapAgent"
    DID_COMM_MESSAGING = "DIDCommMessaging"
    LINKED_DOMAINS = "LinkedDomains"
    CREDENTIAL_REGISTRY = "CredentialRegistry"


@dataclass
class ServiceEndpoint:
    """Service endpoint configuration."""
    uri: str
    accept: Optional[List[str]] = None
    routing_keys: Optional[List[str]] = None

    def to_dict(self) -> Union[str, Dict[str, Any]]:
        """Convert to JSON-serializable format."""
        if self.accept is None and self.routing_keys is None:
            return self.uri
        result: Dict[str, Any] = {"uri": self.uri}
        if self.accept:
            result["accept"] = self.accept
        if self.routing_keys:
            result["routingKeys"] = self.routing_keys
        return result


@dataclass
class VerificationMethod:
    """Verification method (public key) in DID Document."""
    id: str
    type: VerificationMethodType
    controller: str
    public_key_multibase: Optional[str] = None
    public_key_jwk: Optional[Dict[str, Any]] = None
    blockchain_account_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable format."""
        result = {
            "id": self.id,
            "type": self.type.value,
            "controller": self.controller,
        }
        if self.public_key_multibase:
            result["publicKeyMultibase"] = self.public_key_multibase
        if self.public_key_jwk:
            result["publicKeyJwk"] = self.public_key_jwk
        if self.blockchain_account_id:
            result["blockchainAccountId"] = self.blockchain_account_id
        return result


@dataclass
class Service:
    """Service endpoint in DID Document."""
    id: str
    type: ServiceType
    service_endpoint: ServiceEndpoint

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable format."""
        return {
            "id": self.id,
            "type": self.type.value,
            "serviceEndpoint": self.service_endpoint.to_dict(),
        }


@dataclass
class DidDocument:
    """W3C DID Document."""
    id: str
    context: List[str] = field(default_factory=lambda: [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/jws-2020/v1",
    ])
    controller: Optional[str] = None
    verification_method: List[VerificationMethod] = field(default_factory=list)
    authentication: List[str] = field(default_factory=list)
    assertion_method: List[str] = field(default_factory=list)
    key_agreement: List[str] = field(default_factory=list)
    capability_invocation: List[str] = field(default_factory=list)
    capability_delegation: List[str] = field(default_factory=list)
    service: List[Service] = field(default_factory=list)

    def primary_verification_method(self) -> Optional[VerificationMethod]:
        """Get the primary verification method."""
        return self.verification_method[0] if self.verification_method else None

    def get_verification_method(self, id: str) -> Optional[VerificationMethod]:
        """Get a verification method by ID."""
        for vm in self.verification_method:
            if vm.id == id:
                return vm
        return None

    def get_service(self, id: str) -> Optional[Service]:
        """Get a service by ID."""
        for svc in self.service:
            if svc.id == id:
                return svc
        return None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable format."""
        result: Dict[str, Any] = {
            "@context": self.context,
            "id": self.id,
        }
        if self.controller:
            result["controller"] = self.controller
        if self.verification_method:
            result["verificationMethod"] = [vm.to_dict() for vm in self.verification_method]
        if self.authentication:
            result["authentication"] = self.authentication
        if self.assertion_method:
            result["assertionMethod"] = self.assertion_method
        if self.key_agreement:
            result["keyAgreement"] = self.key_agreement
        if self.capability_invocation:
            result["capabilityInvocation"] = self.capability_invocation
        if self.capability_delegation:
            result["capabilityDelegation"] = self.capability_delegation
        if self.service:
            result["service"] = [svc.to_dict() for svc in self.service]
        return result

    def to_json(self, indent: int = 2) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, json_str: str) -> "DidDocument":
        """Deserialize from JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DidDocument":
        """Create from dictionary."""
        verification_methods = []
        for vm_data in data.get("verificationMethod", []):
            verification_methods.append(VerificationMethod(
                id=vm_data["id"],
                type=VerificationMethodType(vm_data["type"]),
                controller=vm_data["controller"],
                public_key_multibase=vm_data.get("publicKeyMultibase"),
                public_key_jwk=vm_data.get("publicKeyJwk"),
                blockchain_account_id=vm_data.get("blockchainAccountId"),
            ))

        services = []
        for svc_data in data.get("service", []):
            endpoint_data = svc_data["serviceEndpoint"]
            if isinstance(endpoint_data, str):
                endpoint = ServiceEndpoint(uri=endpoint_data)
            else:
                endpoint = ServiceEndpoint(
                    uri=endpoint_data["uri"],
                    accept=endpoint_data.get("accept"),
                    routing_keys=endpoint_data.get("routingKeys"),
                )
            services.append(Service(
                id=svc_data["id"],
                type=ServiceType(svc_data["type"]),
                service_endpoint=endpoint,
            ))

        return cls(
            id=data["id"],
            context=data.get("@context", []),
            controller=data.get("controller"),
            verification_method=verification_methods,
            authentication=data.get("authentication", []),
            assertion_method=data.get("assertionMethod", []),
            key_agreement=data.get("keyAgreement", []),
            capability_invocation=data.get("capabilityInvocation", []),
            capability_delegation=data.get("capabilityDelegation", []),
            service=services,
        )


@dataclass
class Did:
    """W3C Decentralized Identifier (DID)."""
    method: DidMethod
    id: str

    def uri(self) -> str:
        """Get the full DID URI string."""
        return f"did:{self.method.value}:{self.id}"

    def __str__(self) -> str:
        return self.uri()

    def __hash__(self) -> int:
        return hash((self.method, self.id))

    def extract_key_material(self) -> bytes:
        """Extract raw key material from did:key or did:lux identifier."""
        if not self.id:
            raise IdentityError("empty DID identifier")

        if not self.id.startswith(MULTIBASE_BASE58BTC):
            raise IdentityError(
                f"unsupported multibase encoding: expected '{MULTIBASE_BASE58BTC}', "
                f"got '{self.id[0]}'"
            )

        # Decode base58btc (skip multibase prefix)
        try:
            decoded = base58_decode(self.id[1:])
        except Exception as e:
            raise IdentityError(f"invalid base58btc encoding: {e}")

        if len(decoded) < 2:
            raise IdentityError("DID identifier too short")

        # Skip multicodec prefix if it matches ML-DSA-65
        if decoded[:2] == MULTICODEC_MLDSA65:
            return decoded[2:]

        return decoded

    def document(self) -> DidDocument:
        """Generate a W3C DID Document for this DID."""
        did_uri = self.uri()

        # Create verification method based on DID type
        if self.method in (DidMethod.KEY, DidMethod.LUX):
            key_material = self.extract_key_material()
            blockchain_account_id = None
            if self.method == DidMethod.LUX:
                blockchain_account_id = f"lux:{key_material[:20].hex()}"

            verification_method = VerificationMethod(
                id=f"{did_uri}#keys-1",
                type=VerificationMethodType.JSON_WEB_KEY_2020,
                controller=did_uri,
                public_key_multibase=self.id,
                blockchain_account_id=blockchain_account_id,
            )
        else:
            verification_method = VerificationMethod(
                id=f"{did_uri}#keys-1",
                type=VerificationMethodType.JSON_WEB_KEY_2020,
                controller=did_uri,
            )

        # Create default service endpoint for ZAP protocol
        service = Service(
            id=f"{did_uri}#zap-agent",
            type=ServiceType.ZAP_AGENT,
            service_endpoint=ServiceEndpoint(uri=f"zap://{self.id}"),
        )

        return DidDocument(
            id=did_uri,
            verification_method=[verification_method],
            authentication=[f"{did_uri}#keys-1"],
            assertion_method=[f"{did_uri}#keys-1"],
            capability_invocation=[f"{did_uri}#keys-1"],
            service=[service],
        )


def parse_did(s: str) -> Did:
    """
    Parse a DID from a string in the format "did:method:id".

    Args:
        s: DID string to parse

    Returns:
        Parsed Did object

    Raises:
        IdentityError: If the DID string is invalid

    Example:
        >>> did = parse_did("did:lux:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
        >>> did.method
        <DidMethod.LUX: 'lux'>
    """
    if not s.startswith("did:"):
        raise IdentityError(f"invalid DID: must start with 'did:', got '{s}'")

    rest = s[4:]  # Skip "did:"
    parts = rest.split(":", 1)

    if len(parts) != 2:
        raise IdentityError(f"invalid DID format: expected 'did:method:id', got '{s}'")

    method_str, did_id = parts

    try:
        method = DidMethod(method_str)
    except ValueError:
        raise IdentityError(f"unknown DID method: {method_str}")

    if not did_id:
        raise IdentityError("DID identifier cannot be empty")

    return Did(method=method, id=did_id)


def create_did_from_key(public_key: bytes, method: DidMethod = DidMethod.KEY) -> Did:
    """
    Create a DID from an ML-DSA-65 public key.

    Args:
        public_key: ML-DSA-65 public key bytes (1952 bytes)
        method: DID method to use (KEY or LUX)

    Returns:
        New Did object

    Raises:
        IdentityError: If the public key is invalid

    Example:
        >>> did = create_did_from_key(public_key_bytes)
        >>> print(did)  # did:key:z6Mk...
    """
    if len(public_key) != MLDSA_PUBLIC_KEY_SIZE:
        raise IdentityError(
            f"invalid ML-DSA public key size: expected {MLDSA_PUBLIC_KEY_SIZE}, "
            f"got {len(public_key)}"
        )

    # Create multicodec-prefixed key
    prefixed = MULTICODEC_MLDSA65 + public_key

    # Encode with multibase (base58btc)
    encoded = base58_encode(prefixed)
    did_id = f"{MULTIBASE_BASE58BTC}{encoded}"

    return Did(method=method, id=did_id)


def create_did_from_web(domain: str, path: Optional[str] = None) -> Did:
    """
    Create a web DID from a domain and optional path.

    Args:
        domain: Domain name (e.g., "example.com")
        path: Optional path (e.g., "users/alice")

    Returns:
        New Did object with method=WEB

    Raises:
        IdentityError: If the domain is invalid

    Example:
        >>> did = create_did_from_web("example.com", "users/alice")
        >>> print(did)  # did:web:example.com:users:alice
    """
    if not domain:
        raise IdentityError("domain cannot be empty")

    if "/" in domain or ":" in domain:
        raise IdentityError(f"invalid domain for did:web: {domain}")

    if path:
        # Replace '/' with ':' per did:web spec
        path_parts = path.replace("/", ":")
        did_id = f"{domain}:{path_parts}"
    else:
        did_id = domain

    return Did(method=DidMethod.WEB, id=did_id)


class StakeRegistry(Protocol):
    """Protocol for stake registry implementations."""

    def get_stake(self, did: Did) -> int:
        """Get the staked amount for a DID."""
        ...

    def set_stake(self, did: Did, amount: int) -> None:
        """Set the staked amount for a DID."""
        ...

    def total_stake(self) -> int:
        """Get total staked amount across all DIDs."""
        ...


class InMemoryStakeRegistry:
    """In-memory stake registry for testing."""

    def __init__(self) -> None:
        self._stakes: Dict[str, int] = {}

    def get_stake(self, did: Did) -> int:
        """Get the staked amount for a DID."""
        return self._stakes.get(did.uri(), 0)

    def set_stake(self, did: Did, amount: int) -> None:
        """Set the staked amount for a DID."""
        self._stakes[did.uri()] = amount

    def total_stake(self) -> int:
        """Get total staked amount across all DIDs."""
        return sum(self._stakes.values())

    def has_sufficient_stake(self, did: Did, minimum: int) -> bool:
        """Check if a DID has sufficient stake."""
        return self.get_stake(did) >= minimum

    def stake_weight(self, did: Did) -> float:
        """Get the stake weight (0.0-1.0) for a DID relative to total."""
        stake = self.get_stake(did)
        total = self.total_stake()
        if total == 0:
            return 0.0
        return stake / total


@dataclass
class NodeIdentity:
    """
    Node identity combining DID with cryptographic keypair.

    Used for authenticated node participation in the ZAP network.
    """
    did: Did
    public_key: bytes
    stake: Optional[int] = None
    stake_registry: Optional[str] = None
    _signer: Optional[Any] = field(default=None, repr=False)

    def can_sign(self) -> bool:
        """Check if this node has signing capability."""
        return self._signer is not None

    def sign(self, message: bytes) -> bytes:
        """Sign a message with this node's private key."""
        if self._signer is None:
            raise IdentityError("no private key available for signing")
        return self._signer.sign(message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify a signature against this node's public key."""
        try:
            from .crypto import PQSignature, PQ_AVAILABLE
            if not PQ_AVAILABLE:
                raise IdentityError("verification requires pqcrypto")

            if self._signer is not None:
                return self._signer.verify(message, signature)
            else:
                verifier = PQSignature.from_public_key(self.public_key)
                return verifier.verify(message, signature)
        except ImportError:
            raise IdentityError("verification requires pqcrypto")

    def document(self) -> DidDocument:
        """Get the DID document for this node identity."""
        return self.did.document()

    def with_stake(self, amount: int) -> "NodeIdentity":
        """Set the stake amount for this node."""
        self.stake = amount
        return self

    def with_registry(self, registry: str) -> "NodeIdentity":
        """Set the stake registry reference."""
        self.stake_registry = registry
        return self


def generate_identity(method: DidMethod = DidMethod.LUX) -> NodeIdentity:
    """
    Generate a new node identity with fresh ML-DSA-65 keypair.

    Args:
        method: DID method to use (default: LUX)

    Returns:
        New NodeIdentity with signing capability

    Raises:
        IdentityError: If pqcrypto is not available

    Example:
        >>> identity = generate_identity()
        >>> print(identity.did)  # did:lux:z6Mk...
        >>> identity.can_sign()
        True
    """
    try:
        from .crypto import PQSignature, PQ_AVAILABLE
        if not PQ_AVAILABLE:
            raise IdentityError("identity generation requires pqcrypto")

        signer = PQSignature.generate()
        public_key = signer.public_key
        did = create_did_from_key(public_key, method=method)

        return NodeIdentity(
            did=did,
            public_key=public_key,
            _signer=signer,
        )
    except ImportError:
        raise IdentityError("identity generation requires pqcrypto")


# Export public API
__all__ = [
    "IdentityError",
    "DidMethod",
    "VerificationMethodType",
    "ServiceType",
    "ServiceEndpoint",
    "VerificationMethod",
    "Service",
    "DidDocument",
    "Did",
    "parse_did",
    "create_did_from_key",
    "create_did_from_web",
    "StakeRegistry",
    "InMemoryStakeRegistry",
    "NodeIdentity",
    "generate_identity",
    "MLDSA_PUBLIC_KEY_SIZE",
]
