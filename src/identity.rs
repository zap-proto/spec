//! W3C Decentralized Identifier (DID) Implementation
//!
//! Implements W3C DID Core 1.0 specification with support for:
//! - did:lux - Lux blockchain-anchored DIDs
//! - did:key - Self-certifying DIDs from cryptographic keys
//! - did:web - DNS-based DIDs
//!
//! # Example
//!
//! ```rust,ignore
//! use zap::identity::{Did, DidMethod, NodeIdentity};
//!
//! // Parse existing DID
//! let did = Did::parse("did:lux:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")?;
//!
//! // Create from ML-DSA public key
//! let did = Did::from_mldsa_key(&public_key_bytes)?;
//!
//! // Generate DID Document
//! let doc = did.document()?;
//!
//! // Create node identity
//! let identity = NodeIdentity::generate()?;
//! ```

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fmt;

#[cfg(feature = "pq")]
use crate::crypto::PQSignature;

/// Multibase prefix for base58btc encoding
const MULTIBASE_BASE58BTC: char = 'z';

/// Multicodec prefix for ML-DSA-65 public key (0xED = Ed25519, 0x1309 = ML-DSA-65)
/// Using 0x1309 as provisional multicodec for ML-DSA-65
const MULTICODEC_MLDSA65: [u8; 2] = [0x13, 0x09];

/// DID method identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DidMethod {
    /// Lux blockchain-anchored DID
    Lux,
    /// Self-certifying DID from cryptographic key
    Key,
    /// DNS-based DID
    Web,
}

impl DidMethod {
    /// Get the method string for DID URI
    pub fn as_str(&self) -> &'static str {
        match self {
            DidMethod::Lux => "lux",
            DidMethod::Key => "key",
            DidMethod::Web => "web",
        }
    }

    /// Parse method from string
    pub fn from_str(s: &str) -> Result<Self> {
        match s {
            "lux" => Ok(DidMethod::Lux),
            "key" => Ok(DidMethod::Key),
            "web" => Ok(DidMethod::Web),
            _ => Err(Error::Identity(format!("unknown DID method: {}", s))),
        }
    }
}

impl fmt::Display for DidMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// W3C Decentralized Identifier (DID)
///
/// A DID is a globally unique identifier that enables verifiable,
/// decentralized digital identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Did {
    /// The DID method (lux, key, web)
    pub method: DidMethod,
    /// The method-specific identifier
    pub id: String,
}

impl Did {
    /// Create a new DID with the specified method and ID
    pub fn new(method: DidMethod, id: String) -> Self {
        Self { method, id }
    }

    /// Parse a DID from a string in the format "did:method:id"
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let did = Did::parse("did:lux:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")?;
    /// assert_eq!(did.method, DidMethod::Lux);
    /// ```
    pub fn parse(s: &str) -> Result<Self> {
        // DID syntax: did:method:method-specific-id
        if !s.starts_with("did:") {
            return Err(Error::Identity(format!(
                "invalid DID: must start with 'did:', got '{}'",
                s
            )));
        }

        let rest = &s[4..]; // Skip "did:"
        let parts: Vec<&str> = rest.splitn(2, ':').collect();

        if parts.len() != 2 {
            return Err(Error::Identity(format!(
                "invalid DID format: expected 'did:method:id', got '{}'",
                s
            )));
        }

        let method = DidMethod::from_str(parts[0])?;
        let id = parts[1].to_string();

        if id.is_empty() {
            return Err(Error::Identity("DID identifier cannot be empty".to_string()));
        }

        Ok(Self { method, id })
    }

    /// Create a DID from an ML-DSA-65 public key
    ///
    /// The resulting DID uses the did:key method with multibase-encoded
    /// multicodec-prefixed public key.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let signer = PQSignature::generate()?;
    /// let did = Did::from_mldsa_key(&signer.public_key_bytes())?;
    /// println!("DID: {}", did); // did:key:z6Mk...
    /// ```
    pub fn from_mldsa_key(public_key: &[u8]) -> Result<Self> {
        // Expected ML-DSA-65 public key size
        const MLDSA_PUBLIC_KEY_SIZE: usize = 1952;

        if public_key.len() != MLDSA_PUBLIC_KEY_SIZE {
            return Err(Error::Identity(format!(
                "invalid ML-DSA public key size: expected {}, got {}",
                MLDSA_PUBLIC_KEY_SIZE,
                public_key.len()
            )));
        }

        // Create multicodec-prefixed key
        let mut prefixed = Vec::with_capacity(MULTICODEC_MLDSA65.len() + public_key.len());
        prefixed.extend_from_slice(&MULTICODEC_MLDSA65);
        prefixed.extend_from_slice(public_key);

        // Encode with multibase (base58btc)
        let encoded = bs58::encode(&prefixed).into_string();
        let id = format!("{}{}", MULTIBASE_BASE58BTC, encoded);

        Ok(Self {
            method: DidMethod::Key,
            id,
        })
    }

    /// Create a Lux blockchain-anchored DID from an ML-DSA public key
    pub fn from_mldsa_key_lux(public_key: &[u8]) -> Result<Self> {
        let key_did = Self::from_mldsa_key(public_key)?;
        Ok(Self {
            method: DidMethod::Lux,
            id: key_did.id,
        })
    }

    /// Create a web DID from a domain and optional path
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let did = Did::from_web("example.com", Some("users/alice"))?;
    /// assert_eq!(did.to_string(), "did:web:example.com:users:alice");
    /// ```
    pub fn from_web(domain: &str, path: Option<&str>) -> Result<Self> {
        if domain.is_empty() {
            return Err(Error::Identity("domain cannot be empty".to_string()));
        }

        // Validate domain (basic check)
        if domain.contains('/') || domain.contains(':') {
            return Err(Error::Identity(format!(
                "invalid domain for did:web: {}",
                domain
            )));
        }

        let id = match path {
            Some(p) if !p.is_empty() => {
                // Replace '/' with ':' per did:web spec
                let path_parts = p.replace('/', ":");
                format!("{}:{}", domain, path_parts)
            }
            _ => domain.to_string(),
        };

        Ok(Self {
            method: DidMethod::Web,
            id,
        })
    }

    /// Get the full DID URI string
    pub fn uri(&self) -> String {
        format!("did:{}:{}", self.method, self.id)
    }

    /// Generate a W3C DID Document for this DID
    ///
    /// The document includes verification methods and service endpoints.
    pub fn document(&self) -> Result<DidDocument> {
        let did_uri = self.uri();

        // Create verification method based on DID type
        let verification_method = match self.method {
            DidMethod::Key | DidMethod::Lux => {
                // Extract public key from multibase-encoded identifier
                let key_material = self.extract_key_material()?;
                VerificationMethod {
                    id: format!("{}#keys-1", did_uri),
                    type_: VerificationMethodType::JsonWebKey2020,
                    controller: did_uri.clone(),
                    public_key_multibase: Some(self.id.clone()),
                    public_key_jwk: None,
                    blockchain_account_id: if self.method == DidMethod::Lux {
                        Some(format!("lux:{}", hex::encode(&key_material[..20])))
                    } else {
                        None
                    },
                }
            }
            DidMethod::Web => VerificationMethod {
                id: format!("{}#keys-1", did_uri),
                type_: VerificationMethodType::JsonWebKey2020,
                controller: did_uri.clone(),
                public_key_multibase: None,
                public_key_jwk: None,
                blockchain_account_id: None,
            },
        };

        // Create default service endpoint for ZAP protocol
        let service = Service {
            id: format!("{}#zap-agent", did_uri),
            type_: ServiceType::ZapAgent,
            service_endpoint: ServiceEndpoint::Uri(format!("zap://{}", self.id)),
        };

        Ok(DidDocument {
            context: vec![
                "https://www.w3.org/ns/did/v1".to_string(),
                "https://w3id.org/security/suites/jws-2020/v1".to_string(),
            ],
            id: did_uri.clone(),
            controller: None,
            verification_method: vec![verification_method],
            authentication: vec![format!("{}#keys-1", did_uri)],
            assertion_method: vec![format!("{}#keys-1", did_uri)],
            key_agreement: vec![],
            capability_invocation: vec![format!("{}#keys-1", did_uri)],
            capability_delegation: vec![],
            service: vec![service],
        })
    }

    /// Extract the raw key material from a did:key or did:lux identifier
    fn extract_key_material(&self) -> Result<Vec<u8>> {
        if self.id.is_empty() {
            return Err(Error::Identity("empty DID identifier".to_string()));
        }

        // Check multibase prefix
        let first_char = self.id.chars().next().unwrap();
        if first_char != MULTIBASE_BASE58BTC {
            return Err(Error::Identity(format!(
                "unsupported multibase encoding: expected '{}', got '{}'",
                MULTIBASE_BASE58BTC, first_char
            )));
        }

        // Decode base58btc (skip the multibase prefix)
        let decoded = bs58::decode(&self.id[1..])
            .into_vec()
            .map_err(|e| Error::Identity(format!("invalid base58btc encoding: {}", e)))?;

        // Skip multicodec prefix (2 bytes for ML-DSA-65)
        if decoded.len() < 2 {
            return Err(Error::Identity("DID identifier too short".to_string()));
        }

        // Verify multicodec prefix matches ML-DSA-65
        if decoded[0..2] != MULTICODEC_MLDSA65 {
            // Allow other key types, just return raw material
            return Ok(decoded);
        }

        Ok(decoded[2..].to_vec())
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.uri())
    }
}

impl std::str::FromStr for Did {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Did::parse(s)
    }
}

/// W3C DID Document
///
/// A DID Document contains information associated with a DID,
/// including verification methods and service endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDocument {
    /// JSON-LD context
    #[serde(rename = "@context")]
    pub context: Vec<String>,

    /// The DID subject
    pub id: String,

    /// Optional controller DID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<String>,

    /// Verification methods (public keys)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verification_method: Vec<VerificationMethod>,

    /// Authentication verification methods
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authentication: Vec<String>,

    /// Assertion/credential issuance verification methods
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assertion_method: Vec<String>,

    /// Key agreement verification methods
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_agreement: Vec<String>,

    /// Capability invocation verification methods
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_invocation: Vec<String>,

    /// Capability delegation verification methods
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_delegation: Vec<String>,

    /// Service endpoints
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service: Vec<Service>,
}

impl DidDocument {
    /// Get the primary verification method
    pub fn primary_verification_method(&self) -> Option<&VerificationMethod> {
        self.verification_method.first()
    }

    /// Get a verification method by ID
    pub fn get_verification_method(&self, id: &str) -> Option<&VerificationMethod> {
        self.verification_method.iter().find(|vm| vm.id == id)
    }

    /// Get a service by ID
    pub fn get_service(&self, id: &str) -> Option<&Service> {
        self.service.iter().find(|s| s.id == id)
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| Error::Identity(format!("JSON serialization failed: {}", e)))
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| Error::Identity(format!("JSON deserialization failed: {}", e)))
    }
}

/// Verification method type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationMethodType {
    /// JSON Web Key 2020
    JsonWebKey2020,
    /// Multikey (new W3C standard)
    Multikey,
    /// ML-DSA-65 Verification Key 2024 (post-quantum)
    #[serde(rename = "MlDsa65VerificationKey2024")]
    MlDsa65VerificationKey2024,
}

/// Verification method (public key) in DID Document
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethod {
    /// Verification method ID (e.g., "did:example:123#keys-1")
    pub id: String,

    /// Verification method type
    #[serde(rename = "type")]
    pub type_: VerificationMethodType,

    /// Controller DID
    pub controller: String,

    /// Public key in multibase encoding
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,

    /// Public key as JWK
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<serde_json::Value>,

    /// Blockchain account ID (for Lux DIDs)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blockchain_account_id: Option<String>,
}

/// Service type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceType {
    /// ZAP Agent service
    ZapAgent,
    /// DID Communication
    #[serde(rename = "DIDCommMessaging")]
    DidCommMessaging,
    /// Linked Domains
    LinkedDomains,
    /// Credential Registry
    CredentialRegistry,
}

/// Service endpoint
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServiceEndpoint {
    /// Single URI endpoint
    Uri(String),
    /// Multiple URI endpoints
    Uris(Vec<String>),
    /// Structured endpoint with additional properties
    Structured {
        uri: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        accept: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        routing_keys: Option<Vec<String>>,
    },
}

/// Service endpoint in DID Document
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    /// Service ID
    pub id: String,

    /// Service type
    #[serde(rename = "type")]
    pub type_: ServiceType,

    /// Service endpoint URI or structured endpoint
    pub service_endpoint: ServiceEndpoint,
}

/// Node identity combining DID with cryptographic keypair
///
/// Used for authenticated node participation in the ZAP network.
#[derive(Debug, Clone)]
pub struct NodeIdentity {
    /// The node's DID
    pub did: Did,

    /// ML-DSA-65 public key bytes
    pub public_key: Vec<u8>,

    /// Optional staked amount (in smallest unit)
    pub stake: Option<u64>,

    /// Optional stake registry reference
    pub stake_registry: Option<String>,

    #[cfg(feature = "pq")]
    /// ML-DSA-65 signer (private key)
    signer: Option<PQSignature>,

    #[cfg(not(feature = "pq"))]
    /// Placeholder for when pq feature is disabled
    _signer: std::marker::PhantomData<()>,
}

impl NodeIdentity {
    /// Create a new node identity from an existing DID and public key
    pub fn new(did: Did, public_key: Vec<u8>) -> Self {
        Self {
            did,
            public_key,
            stake: None,
            stake_registry: None,
            #[cfg(feature = "pq")]
            signer: None,
            #[cfg(not(feature = "pq"))]
            _signer: std::marker::PhantomData,
        }
    }

    /// Generate a new node identity with fresh ML-DSA-65 keypair
    #[cfg(feature = "pq")]
    pub fn generate() -> Result<Self> {
        let signer = PQSignature::generate()?;
        let public_key = signer.public_key_bytes();
        let did = Did::from_mldsa_key_lux(&public_key)?;

        Ok(Self {
            did,
            public_key,
            stake: None,
            stake_registry: None,
            signer: Some(signer),
        })
    }

    /// Generate a new node identity (stub when pq feature is disabled)
    #[cfg(not(feature = "pq"))]
    pub fn generate() -> Result<Self> {
        Err(Error::Identity(
            "node identity generation requires 'pq' feature".to_string(),
        ))
    }

    /// Sign a message with this node's private key
    #[cfg(feature = "pq")]
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let signer = self
            .signer
            .as_ref()
            .ok_or_else(|| Error::Identity("no private key available for signing".to_string()))?;
        signer.sign(message)
    }

    /// Sign a message (stub when pq feature is disabled)
    #[cfg(not(feature = "pq"))]
    pub fn sign(&self, _message: &[u8]) -> Result<Vec<u8>> {
        Err(Error::Identity(
            "signing requires 'pq' feature".to_string(),
        ))
    }

    /// Verify a signature against this node's public key
    #[cfg(feature = "pq")]
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        let verifier = match &self.signer {
            Some(s) => s.verify(message, signature)?,
            None => {
                let v = PQSignature::from_public_key(&self.public_key)?;
                v.verify(message, signature)?;
            }
        };
        Ok(verifier)
    }

    /// Verify a signature (stub when pq feature is disabled)
    #[cfg(not(feature = "pq"))]
    pub fn verify(&self, _message: &[u8], _signature: &[u8]) -> Result<()> {
        Err(Error::Identity(
            "verification requires 'pq' feature".to_string(),
        ))
    }

    /// Set the stake amount for this node
    pub fn with_stake(mut self, amount: u64) -> Self {
        self.stake = Some(amount);
        self
    }

    /// Set the stake registry reference
    pub fn with_registry(mut self, registry: String) -> Self {
        self.stake_registry = Some(registry);
        self
    }

    /// Get the DID document for this node identity
    pub fn document(&self) -> Result<DidDocument> {
        self.did.document()
    }

    /// Check if this node has signing capability
    pub fn can_sign(&self) -> bool {
        #[cfg(feature = "pq")]
        {
            self.signer.is_some()
        }
        #[cfg(not(feature = "pq"))]
        {
            false
        }
    }
}

/// Trait for stake registry implementations
///
/// A stake registry tracks staked amounts for DIDs and can be used
/// for weighted consensus and reputation systems.
pub trait StakeRegistry: Send + Sync {
    /// Get the staked amount for a DID
    fn get_stake(&self, did: &Did) -> Result<u64>;

    /// Set the staked amount for a DID
    fn set_stake(&mut self, did: &Did, amount: u64) -> Result<()>;

    /// Check if a DID has sufficient stake
    fn has_sufficient_stake(&self, did: &Did, minimum: u64) -> Result<bool> {
        Ok(self.get_stake(did)? >= minimum)
    }

    /// Get total staked amount across all DIDs
    fn total_stake(&self) -> Result<u64>;

    /// Get the stake weight (0.0-1.0) for a DID relative to total
    fn stake_weight(&self, did: &Did) -> Result<f64> {
        let stake = self.get_stake(did)?;
        let total = self.total_stake()?;
        if total == 0 {
            return Ok(0.0);
        }
        Ok(stake as f64 / total as f64)
    }
}

/// In-memory stake registry for testing
#[derive(Debug, Default)]
pub struct InMemoryStakeRegistry {
    stakes: std::collections::HashMap<String, u64>,
}

impl InMemoryStakeRegistry {
    /// Create a new empty stake registry
    pub fn new() -> Self {
        Self::default()
    }
}

impl StakeRegistry for InMemoryStakeRegistry {
    fn get_stake(&self, did: &Did) -> Result<u64> {
        Ok(*self.stakes.get(&did.uri()).unwrap_or(&0))
    }

    fn set_stake(&mut self, did: &Did, amount: u64) -> Result<()> {
        self.stakes.insert(did.uri(), amount);
        Ok(())
    }

    fn total_stake(&self) -> Result<u64> {
        Ok(self.stakes.values().sum())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_parse_lux() {
        let did = Did::parse("did:lux:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap();
        assert_eq!(did.method, DidMethod::Lux);
        assert_eq!(did.id, "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
    }

    #[test]
    fn test_did_parse_key() {
        let did = Did::parse("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap();
        assert_eq!(did.method, DidMethod::Key);
    }

    #[test]
    fn test_did_parse_web() {
        let did = Did::parse("did:web:example.com:users:alice").unwrap();
        assert_eq!(did.method, DidMethod::Web);
        assert_eq!(did.id, "example.com:users:alice");
    }

    #[test]
    fn test_did_parse_invalid() {
        assert!(Did::parse("not-a-did").is_err());
        assert!(Did::parse("did:unknown:abc").is_err());
        assert!(Did::parse("did:lux:").is_err());
    }

    #[test]
    fn test_did_from_web() {
        let did = Did::from_web("example.com", Some("users/alice")).unwrap();
        assert_eq!(did.uri(), "did:web:example.com:users:alice");

        let did2 = Did::from_web("example.com", None).unwrap();
        assert_eq!(did2.uri(), "did:web:example.com");
    }

    #[test]
    fn test_did_method_display() {
        assert_eq!(DidMethod::Lux.to_string(), "lux");
        assert_eq!(DidMethod::Key.to_string(), "key");
        assert_eq!(DidMethod::Web.to_string(), "web");
    }

    #[test]
    fn test_did_document_generation() {
        let did = Did::parse("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap();
        let doc = did.document().unwrap();

        assert_eq!(doc.id, "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        assert!(!doc.verification_method.is_empty());
        assert!(!doc.authentication.is_empty());
        assert!(!doc.service.is_empty());
    }

    #[test]
    fn test_did_document_json_roundtrip() {
        let did = Did::parse("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap();
        let doc = did.document().unwrap();

        let json = doc.to_json().unwrap();
        let parsed = DidDocument::from_json(&json).unwrap();

        assert_eq!(doc.id, parsed.id);
        assert_eq!(doc.verification_method.len(), parsed.verification_method.len());
    }

    #[test]
    fn test_stake_registry() {
        let mut registry = InMemoryStakeRegistry::new();
        let did = Did::parse("did:lux:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap();

        assert_eq!(registry.get_stake(&did).unwrap(), 0);

        registry.set_stake(&did, 1000).unwrap();
        assert_eq!(registry.get_stake(&did).unwrap(), 1000);

        assert!(registry.has_sufficient_stake(&did, 500).unwrap());
        assert!(!registry.has_sufficient_stake(&did, 2000).unwrap());

        assert_eq!(registry.total_stake().unwrap(), 1000);
    }

    #[test]
    fn test_stake_weight() {
        let mut registry = InMemoryStakeRegistry::new();
        let did1 = Did::parse("did:lux:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap();
        let did2 = Did::parse("did:lux:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doL").unwrap();

        registry.set_stake(&did1, 750).unwrap();
        registry.set_stake(&did2, 250).unwrap();

        let weight1 = registry.stake_weight(&did1).unwrap();
        let weight2 = registry.stake_weight(&did2).unwrap();

        assert!((weight1 - 0.75).abs() < 0.001);
        assert!((weight2 - 0.25).abs() < 0.001);
    }

    #[test]
    fn test_node_identity_new() {
        let did = Did::parse("did:lux:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap();
        let identity = NodeIdentity::new(did.clone(), vec![0u8; 1952]);

        assert_eq!(identity.did, did);
        assert_eq!(identity.stake, None);
        assert!(!identity.can_sign());
    }

    #[test]
    fn test_node_identity_with_stake() {
        let did = Did::parse("did:lux:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap();
        let identity = NodeIdentity::new(did, vec![0u8; 1952])
            .with_stake(5000)
            .with_registry("lux:mainnet".to_string());

        assert_eq!(identity.stake, Some(5000));
        assert_eq!(identity.stake_registry, Some("lux:mainnet".to_string()));
    }

    #[cfg(feature = "pq")]
    #[test]
    fn test_node_identity_generate() {
        let identity = NodeIdentity::generate().unwrap();

        assert!(identity.can_sign());
        assert_eq!(identity.did.method, DidMethod::Lux);
        assert!(!identity.public_key.is_empty());

        // Test signing
        let message = b"test message";
        let signature = identity.sign(message).unwrap();
        identity.verify(message, &signature).unwrap();
    }

    #[cfg(feature = "pq")]
    #[test]
    fn test_did_from_mldsa_key() {
        use crate::crypto::PQSignature;

        let signer = PQSignature::generate().unwrap();
        let public_key = signer.public_key_bytes();

        let did = Did::from_mldsa_key(&public_key).unwrap();
        assert_eq!(did.method, DidMethod::Key);
        assert!(did.id.starts_with('z'));

        // Verify we can generate document
        let doc = did.document().unwrap();
        assert!(!doc.verification_method.is_empty());
    }
}
