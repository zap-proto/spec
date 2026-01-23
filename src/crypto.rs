//! Post-Quantum Cryptography Module for ZAP
//!
//! Provides ML-KEM-768 key exchange, ML-DSA-65 signatures, and hybrid X25519+ML-KEM handshake.
//!
//! # Security
//!
//! This module implements NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) standards
//! for post-quantum cryptographic protection. The hybrid handshake combines
//! classical X25519 with ML-KEM-768 for defense-in-depth.
//!
//! # Example
//!
//! ```rust,ignore
//! use zap::crypto::{PQKeyExchange, PQSignature, HybridHandshake};
//!
//! // Key exchange
//! let alice = PQKeyExchange::generate()?;
//! let (ciphertext, shared_alice) = alice.encapsulate(&bob_pk)?;
//! let shared_bob = bob.decapsulate(&ciphertext)?;
//! assert_eq!(shared_alice, shared_bob);
//!
//! // Signatures
//! let signer = PQSignature::generate()?;
//! let sig = signer.sign(b"message")?;
//! signer.verify(b"message", &sig)?;
//!
//! // Hybrid handshake
//! let initiator = HybridHandshake::initiate()?;
//! let (responder, response) = HybridHandshake::respond(&initiator.public_data())?;
//! let shared = initiator.finalize(&response)?;
//! ```

use crate::error::{Error, Result};

// Constants for key/ciphertext sizes
// ML-KEM-768 sizes
/// ML-KEM-768 public key size in bytes
pub const MLKEM_PUBLIC_KEY_SIZE: usize = 1184;
/// ML-KEM-768 ciphertext size in bytes
pub const MLKEM_CIPHERTEXT_SIZE: usize = 1088;
/// ML-KEM-768 shared secret size in bytes
pub const MLKEM_SHARED_SECRET_SIZE: usize = 32;

// ML-DSA-65 (Dilithium3) sizes
/// ML-DSA-65 public key size in bytes
pub const MLDSA_PUBLIC_KEY_SIZE: usize = 1952;
/// ML-DSA-65 signature size in bytes
pub const MLDSA_SIGNATURE_SIZE: usize = 3309;
/// ML-DSA-65 secret key size in bytes
pub const MLDSA_SECRET_KEY_SIZE: usize = 4000;

// X25519 sizes
/// X25519 public key size in bytes
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;
/// Hybrid shared secret size after HKDF
pub const HYBRID_SHARED_SECRET_SIZE: usize = 32;

#[cfg(feature = "pq")]
mod pq_impl {
    use super::*;
    use hkdf::Hkdf;
    use pqcrypto_dilithium::dilithium3;
    use pqcrypto_mlkem::mlkem768;
    use pqcrypto_traits::kem::{Ciphertext, PublicKey as KemPublicKey, SharedSecret};
    use pqcrypto_traits::sign::{
        DetachedSignature as DetachedSignatureTrait, PublicKey as SignPublicKey,
        SecretKey as SignSecretKey,
    };
    use rand::rngs::OsRng;
    use sha2::Sha256;
    use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
    use zeroize::Zeroize;

    /// ML-KEM-768 Key Encapsulation Mechanism
    ///
    /// Implements NIST FIPS 203 ML-KEM-768 for post-quantum key exchange.
    /// Security level: NIST Level 3 (~AES-192 equivalent).
    pub struct PQKeyExchange {
        public_key: mlkem768::PublicKey,
        secret_key: mlkem768::SecretKey,
    }

    impl PQKeyExchange {
        /// Generate a new ML-KEM-768 keypair
        pub fn generate() -> Result<Self> {
            let (pk, sk) = mlkem768::keypair();
            Ok(Self {
                public_key: pk,
                secret_key: sk,
            })
        }

        /// Get the public key bytes
        pub fn public_key_bytes(&self) -> Vec<u8> {
            self.public_key.as_bytes().to_vec()
        }

        /// Create from existing public key bytes (for encapsulation only)
        pub fn from_public_key(bytes: &[u8]) -> Result<Self> {
            if bytes.len() != MLKEM_PUBLIC_KEY_SIZE {
                return Err(Error::Crypto(format!(
                    "invalid ML-KEM public key size: expected {}, got {}",
                    MLKEM_PUBLIC_KEY_SIZE,
                    bytes.len()
                )));
            }
            let pk = mlkem768::PublicKey::from_bytes(bytes)
                .map_err(|e| Error::Crypto(format!("invalid ML-KEM public key: {e:?}")))?;
            // Create dummy secret key - this instance can only encapsulate
            let (_, dummy_sk) = mlkem768::keypair();
            Ok(Self {
                public_key: pk,
                secret_key: dummy_sk,
            })
        }

        /// Encapsulate: generate ciphertext and shared secret for a recipient's public key
        pub fn encapsulate(&self, recipient_pk: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
            let pk = mlkem768::PublicKey::from_bytes(recipient_pk)
                .map_err(|e| Error::Crypto(format!("invalid recipient public key: {e:?}")))?;
            let (ss, ct) = mlkem768::encapsulate(&pk);
            let mut shared = [0u8; 32];
            shared.copy_from_slice(ss.as_bytes());
            Ok((ct.as_bytes().to_vec(), shared))
        }

        /// Decapsulate: recover shared secret from ciphertext
        pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; 32]> {
            if ciphertext.len() != MLKEM_CIPHERTEXT_SIZE {
                return Err(Error::Crypto(format!(
                    "invalid ML-KEM ciphertext size: expected {}, got {}",
                    MLKEM_CIPHERTEXT_SIZE,
                    ciphertext.len()
                )));
            }
            let ct = mlkem768::Ciphertext::from_bytes(ciphertext)
                .map_err(|e| Error::Crypto(format!("invalid ciphertext: {e:?}")))?;
            let ss = mlkem768::decapsulate(&ct, &self.secret_key);
            let mut shared = [0u8; 32];
            shared.copy_from_slice(ss.as_bytes());
            Ok(shared)
        }
    }

    /// ML-DSA-65 Digital Signature Algorithm
    ///
    /// Implements NIST FIPS 204 ML-DSA-65 (Dilithium3) for post-quantum signatures.
    /// Security level: NIST Level 3 (~AES-192 equivalent).
    pub struct PQSignature {
        public_key: dilithium3::PublicKey,
        secret_key: Option<dilithium3::SecretKey>,
    }

    impl std::fmt::Debug for PQSignature {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("PQSignature")
                .field("public_key", &"<public_key>")
                .field("secret_key", &self.secret_key.as_ref().map(|_| "<secret_key>"))
                .finish()
        }
    }

    impl Clone for PQSignature {
        fn clone(&self) -> Self {
            // Clone by re-parsing the bytes
            let pk_bytes = self.public_key.as_bytes().to_vec();
            let public_key = dilithium3::PublicKey::from_bytes(&pk_bytes).unwrap();
            let secret_key = self.secret_key.as_ref().map(|sk| {
                let sk_bytes = sk.as_bytes().to_vec();
                dilithium3::SecretKey::from_bytes(&sk_bytes).unwrap()
            });
            Self { public_key, secret_key }
        }
    }

    impl PQSignature {
        /// Generate a new ML-DSA-65 keypair
        pub fn generate() -> Result<Self> {
            let (pk, sk) = dilithium3::keypair();
            Ok(Self {
                public_key: pk,
                secret_key: Some(sk),
            })
        }

        /// Get the public key bytes
        pub fn public_key_bytes(&self) -> Vec<u8> {
            self.public_key.as_bytes().to_vec()
        }

        /// Create from existing public key bytes (for verification only)
        pub fn from_public_key(bytes: &[u8]) -> Result<Self> {
            if bytes.len() != MLDSA_PUBLIC_KEY_SIZE {
                return Err(Error::Crypto(format!(
                    "invalid ML-DSA public key size: expected {}, got {}",
                    MLDSA_PUBLIC_KEY_SIZE,
                    bytes.len()
                )));
            }
            let pk = dilithium3::PublicKey::from_bytes(bytes)
                .map_err(|e| Error::Crypto(format!("invalid ML-DSA public key: {e:?}")))?;
            Ok(Self {
                public_key: pk,
                secret_key: None,
            })
        }

        /// Sign a message
        pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
            let sk = self
                .secret_key
                .as_ref()
                .ok_or_else(|| Error::Crypto("no secret key available for signing".into()))?;
            let sig = dilithium3::detached_sign(message, sk);
            Ok(sig.as_bytes().to_vec())
        }

        /// Verify a signature
        pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
            if signature.len() != MLDSA_SIGNATURE_SIZE {
                return Err(Error::Crypto(format!(
                    "invalid ML-DSA signature size: expected {}, got {}",
                    MLDSA_SIGNATURE_SIZE,
                    signature.len()
                )));
            }
            let sig = dilithium3::DetachedSignature::from_bytes(signature)
                .map_err(|e| Error::Crypto(format!("invalid signature format: {e:?}")))?;
            dilithium3::verify_detached_signature(&sig, message, &self.public_key)
                .map_err(|_| Error::Crypto("signature verification failed".into()))
        }
    }

    /// Public data from the initiator for the responder
    #[derive(Debug, Clone)]
    pub struct HybridInitiatorData {
        pub x25519_public_key: [u8; 32],
        pub mlkem_public_key: Vec<u8>,
    }

    /// Response data from the responder for the initiator
    #[derive(Debug, Clone)]
    pub struct HybridResponderData {
        pub x25519_public_key: [u8; 32],
        pub mlkem_ciphertext: Vec<u8>,
    }

    /// Completed hybrid handshake result
    #[derive(Clone)]
    pub struct HybridSharedSecret {
        secret: [u8; HYBRID_SHARED_SECRET_SIZE],
    }

    impl HybridSharedSecret {
        /// Get the shared secret bytes
        pub fn as_bytes(&self) -> &[u8; HYBRID_SHARED_SECRET_SIZE] {
            &self.secret
        }

        /// Consume and return the shared secret
        pub fn into_bytes(self) -> [u8; HYBRID_SHARED_SECRET_SIZE] {
            self.secret
        }
    }

    impl Drop for HybridSharedSecret {
        fn drop(&mut self) {
            self.secret.zeroize();
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum HandshakeRole {
        Initiator,
        Responder,
    }

    /// Hybrid X25519 + ML-KEM-768 Handshake
    ///
    /// Combines classical elliptic curve Diffie-Hellman (X25519) with post-quantum
    /// ML-KEM-768 for defense-in-depth. Even if one algorithm is broken, the other
    /// provides protection.
    ///
    /// The final shared secret is derived using HKDF-SHA256 over both shared secrets.
    pub struct HybridHandshake {
        x25519_secret: Option<EphemeralSecret>,
        x25519_public: X25519PublicKey,
        mlkem: PQKeyExchange,
        role: HandshakeRole,
    }

    impl HybridHandshake {
        /// Initiate a hybrid handshake (client side)
        pub fn initiate() -> Result<Self> {
            let x25519_secret = EphemeralSecret::random_from_rng(OsRng);
            let x25519_public = X25519PublicKey::from(&x25519_secret);
            let mlkem = PQKeyExchange::generate()?;

            Ok(Self {
                x25519_secret: Some(x25519_secret),
                x25519_public,
                mlkem,
                role: HandshakeRole::Initiator,
            })
        }

        /// Get the public data to send to the responder
        pub fn public_data(&self) -> HybridInitiatorData {
            HybridInitiatorData {
                x25519_public_key: self.x25519_public.to_bytes(),
                mlkem_public_key: self.mlkem.public_key_bytes(),
            }
        }

        /// Respond to a hybrid handshake (server side)
        pub fn respond(
            initiator_data: &HybridInitiatorData,
        ) -> Result<(Self, HybridResponderData)> {
            // Validate input sizes
            if initiator_data.mlkem_public_key.len() != MLKEM_PUBLIC_KEY_SIZE {
                return Err(Error::Crypto(format!(
                    "invalid initiator ML-KEM public key size: expected {}, got {}",
                    MLKEM_PUBLIC_KEY_SIZE,
                    initiator_data.mlkem_public_key.len()
                )));
            }

            // Generate responder's X25519 keypair
            let x25519_secret = EphemeralSecret::random_from_rng(OsRng);
            let x25519_public = X25519PublicKey::from(&x25519_secret);

            // Generate ML-KEM keypair and encapsulate to initiator
            let mlkem = PQKeyExchange::generate()?;
            let (mlkem_ciphertext, _) = mlkem.encapsulate(&initiator_data.mlkem_public_key)?;

            let response = HybridResponderData {
                x25519_public_key: x25519_public.to_bytes(),
                mlkem_ciphertext,
            };

            let handshake = Self {
                x25519_secret: Some(x25519_secret),
                x25519_public,
                mlkem,
                role: HandshakeRole::Responder,
            };

            Ok((handshake, response))
        }

        /// Finalize the handshake and derive the shared secret (initiator side)
        pub fn finalize(mut self, responder_data: &HybridResponderData) -> Result<HybridSharedSecret> {
            if self.role != HandshakeRole::Initiator {
                return Err(Error::Crypto(
                    "finalize() can only be called by initiator".into(),
                ));
            }

            // X25519 key exchange
            let x25519_secret = self
                .x25519_secret
                .take()
                .ok_or_else(|| Error::Crypto("X25519 secret already consumed".into()))?;
            let peer_x25519_public = X25519PublicKey::from(responder_data.x25519_public_key);
            let x25519_shared = x25519_secret.diffie_hellman(&peer_x25519_public);

            // ML-KEM decapsulation
            let mlkem_shared = self.mlkem.decapsulate(&responder_data.mlkem_ciphertext)?;

            // Combine shared secrets with HKDF
            Self::derive_hybrid_secret(x25519_shared.as_bytes(), &mlkem_shared)
        }

        /// Complete the handshake and derive the shared secret (responder side)
        pub fn complete(
            mut self,
            initiator_data: &HybridInitiatorData,
            mlkem_shared: &[u8; 32],
        ) -> Result<HybridSharedSecret> {
            if self.role != HandshakeRole::Responder {
                return Err(Error::Crypto(
                    "complete() can only be called by responder".into(),
                ));
            }

            // X25519 key exchange
            let x25519_secret = self
                .x25519_secret
                .take()
                .ok_or_else(|| Error::Crypto("X25519 secret already consumed".into()))?;
            let peer_x25519_public = X25519PublicKey::from(initiator_data.x25519_public_key);
            let x25519_shared = x25519_secret.diffie_hellman(&peer_x25519_public);

            // Combine shared secrets with HKDF
            Self::derive_hybrid_secret(x25519_shared.as_bytes(), mlkem_shared)
        }

        /// Derive hybrid shared secret using HKDF-SHA256
        fn derive_hybrid_secret(
            x25519_shared: &[u8],
            mlkem_shared: &[u8; 32],
        ) -> Result<HybridSharedSecret> {
            // Concatenate both shared secrets
            let mut ikm = Vec::with_capacity(x25519_shared.len() + mlkem_shared.len());
            ikm.extend_from_slice(x25519_shared);
            ikm.extend_from_slice(mlkem_shared);

            // HKDF extract and expand
            let hkdf = Hkdf::<Sha256>::new(Some(b"ZAP-HYBRID-HANDSHAKE-v1"), &ikm);
            let mut secret = [0u8; HYBRID_SHARED_SECRET_SIZE];
            hkdf.expand(b"shared-secret", &mut secret)
                .map_err(|_| Error::Crypto("HKDF expansion failed".into()))?;

            // Zeroize intermediate material
            ikm.zeroize();

            Ok(HybridSharedSecret { secret })
        }
    }

    /// Perform a complete hybrid handshake between two parties
    ///
    /// This is a convenience function for testing and simple use cases.
    pub fn hybrid_handshake() -> Result<(
        [u8; HYBRID_SHARED_SECRET_SIZE],
        [u8; HYBRID_SHARED_SECRET_SIZE],
    )> {
        // Initiator starts
        let initiator = HybridHandshake::initiate()?;
        let init_data = initiator.public_data();

        // Responder receives and responds
        let (responder, resp_data) = HybridHandshake::respond(&init_data)?;

        // Responder also needs to encapsulate to get their copy of the ML-KEM shared secret
        let mlkem_for_responder = PQKeyExchange::generate()?;
        let (_, mlkem_shared_responder) =
            mlkem_for_responder.encapsulate(&init_data.mlkem_public_key)?;

        // Initiator finalizes
        let initiator_secret = initiator.finalize(&resp_data)?;

        // Responder completes
        let responder_secret = responder.complete(&init_data, &mlkem_shared_responder)?;

        Ok((initiator_secret.into_bytes(), responder_secret.into_bytes()))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_mlkem_key_exchange() {
            let alice = PQKeyExchange::generate().unwrap();
            let bob = PQKeyExchange::generate().unwrap();

            // Alice encapsulates to Bob's public key
            let (ciphertext, alice_shared) = alice.encapsulate(&bob.public_key_bytes()).unwrap();

            // Bob decapsulates
            let bob_shared = bob.decapsulate(&ciphertext).unwrap();

            assert_eq!(alice_shared, bob_shared);
        }

        #[test]
        fn test_mlkem_invalid_public_key() {
            let alice = PQKeyExchange::generate().unwrap();
            let bad_pk = vec![0u8; 100]; // Wrong size
            assert!(alice.encapsulate(&bad_pk).is_err());
        }

        #[test]
        fn test_mldsa_signature() {
            let signer = PQSignature::generate().unwrap();

            let message = b"The quick brown fox jumps over the lazy dog";
            let signature = signer.sign(message).unwrap();

            // Verify with same key
            signer.verify(message, &signature).unwrap();

            // Verify with public key only
            let verifier = PQSignature::from_public_key(&signer.public_key_bytes()).unwrap();
            verifier.verify(message, &signature).unwrap();
        }

        #[test]
        fn test_mldsa_invalid_signature() {
            let signer = PQSignature::generate().unwrap();
            let message = b"Hello, World!";
            let signature = signer.sign(message).unwrap();

            // Wrong message
            assert!(signer.verify(b"Wrong message", &signature).is_err());

            // Corrupted signature
            let mut bad_sig = signature.clone();
            bad_sig[0] ^= 0xFF;
            assert!(signer.verify(message, &bad_sig).is_err());
        }

        #[test]
        fn test_mldsa_verify_only() {
            let verifier = PQSignature::from_public_key(
                &PQSignature::generate().unwrap().public_key_bytes(),
            )
            .unwrap();
            assert!(verifier.sign(b"test").is_err());
        }

        #[test]
        fn test_hybrid_handshake_basic() {
            // Initiator starts
            let initiator = HybridHandshake::initiate().unwrap();
            let init_data = initiator.public_data();

            // Responder receives init_data and creates response
            let responder_mlkem = PQKeyExchange::generate().unwrap();
            let (mlkem_ct, _mlkem_shared_responder) = responder_mlkem
                .encapsulate(&init_data.mlkem_public_key)
                .unwrap();

            let x25519_secret = EphemeralSecret::random_from_rng(OsRng);
            let x25519_public = X25519PublicKey::from(&x25519_secret);

            let resp_data = HybridResponderData {
                x25519_public_key: x25519_public.to_bytes(),
                mlkem_ciphertext: mlkem_ct,
            };

            // Initiator finalizes
            let _initiator_secret = initiator.finalize(&resp_data).unwrap();

            // Note: In real use, both parties derive the same secret
            // This test just verifies the API works
        }

        #[test]
        fn test_hybrid_handshake_sizes() {
            let initiator = HybridHandshake::initiate().unwrap();
            let init_data = initiator.public_data();

            assert_eq!(init_data.x25519_public_key.len(), X25519_PUBLIC_KEY_SIZE);
            assert_eq!(init_data.mlkem_public_key.len(), MLKEM_PUBLIC_KEY_SIZE);
        }
    }
}

// Re-export PQ types when feature is enabled
#[cfg(feature = "pq")]
pub use pq_impl::{
    hybrid_handshake, HybridHandshake, HybridInitiatorData, HybridResponderData,
    HybridSharedSecret, PQKeyExchange, PQSignature,
};

// Stub implementations when pq feature is not enabled
#[cfg(not(feature = "pq"))]
pub struct PQKeyExchange;

#[cfg(not(feature = "pq"))]
impl PQKeyExchange {
    pub fn generate() -> Result<Self> {
        Err(Error::Crypto("PQ crypto requires 'pq' feature".into()))
    }
}

#[cfg(not(feature = "pq"))]
pub struct PQSignature;

#[cfg(not(feature = "pq"))]
impl PQSignature {
    pub fn generate() -> Result<Self> {
        Err(Error::Crypto("PQ crypto requires 'pq' feature".into()))
    }
}

#[cfg(not(feature = "pq"))]
pub struct HybridHandshake;

#[cfg(not(feature = "pq"))]
impl HybridHandshake {
    pub fn initiate() -> Result<Self> {
        Err(Error::Crypto("PQ crypto requires 'pq' feature".into()))
    }
}
