//! Post-Quantum Cryptography Module for ZAP
//!
//! One library, one implementation: pure-Rust pqcrypto crates.
//! ML-KEM-768 (FIPS 203) for key exchange and Dilithium3 for signatures,
//! gated behind the `pq` feature. X25519 always uses x25519-dalek.
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

/// ML-KEM-768 public key size in bytes
pub const MLKEM_PUBLIC_KEY_SIZE: usize = 1184;
/// ML-KEM-768 ciphertext size in bytes
pub const MLKEM_CIPHERTEXT_SIZE: usize = 1088;
/// ML-KEM-768 shared secret size in bytes
pub const MLKEM_SHARED_SECRET_SIZE: usize = 32;
/// ML-DSA-65 public key size in bytes
pub const MLDSA_PUBLIC_KEY_SIZE: usize = 1952;
/// ML-DSA-65 signature size in bytes
pub const MLDSA_SIGNATURE_SIZE: usize = 3309;
/// ML-DSA-65 secret key size in bytes
pub const MLDSA_SECRET_KEY_SIZE: usize = 4032;
/// X25519 public key size in bytes
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;
/// Hybrid shared secret size after HKDF
pub const HYBRID_SHARED_SECRET_SIZE: usize = 32;

// ── Backend detection ────────────────────────────────────────────────

/// Which PQ backend is active.
///
/// - `"pq"` — Rust pqcrypto crates (ML-KEM-768 + Dilithium3)
/// - `"unavailable"` — no PQ feature enabled
pub const PQ_BACKEND: &str = if cfg!(feature = "pq") {
    "pq"
} else {
    "unavailable"
};

// ── pqcrypto backend ─────────────────────────────────────────────────

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

    pub struct PQKeyExchange {
        public_key: mlkem768::PublicKey,
        secret_key: mlkem768::SecretKey,
    }

    impl PQKeyExchange {
        pub fn generate() -> Result<Self> {
            let (pk, sk) = mlkem768::keypair();
            Ok(Self {
                public_key: pk,
                secret_key: sk,
            })
        }

        pub fn public_key_bytes(&self) -> Vec<u8> {
            self.public_key.as_bytes().to_vec()
        }

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
            let (_, dummy_sk) = mlkem768::keypair();
            Ok(Self {
                public_key: pk,
                secret_key: dummy_sk,
            })
        }

        pub fn encapsulate(&self, recipient_pk: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
            let pk = mlkem768::PublicKey::from_bytes(recipient_pk)
                .map_err(|e| Error::Crypto(format!("invalid recipient public key: {e:?}")))?;
            let (ss, ct) = mlkem768::encapsulate(&pk);
            let mut shared = [0u8; 32];
            shared.copy_from_slice(ss.as_bytes());
            Ok((ct.as_bytes().to_vec(), shared))
        }

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

    pub struct PQSignature {
        public_key: dilithium3::PublicKey,
        secret_key: Option<dilithium3::SecretKey>,
    }

    impl std::fmt::Debug for PQSignature {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("PQSignature")
                .field("public_key", &"<public_key>")
                .field(
                    "secret_key",
                    &self.secret_key.as_ref().map(|_| "<secret_key>"),
                )
                .finish()
        }
    }

    impl Clone for PQSignature {
        fn clone(&self) -> Self {
            let pk_bytes = self.public_key.as_bytes().to_vec();
            let public_key = dilithium3::PublicKey::from_bytes(&pk_bytes).unwrap();
            let secret_key = self.secret_key.as_ref().map(|sk| {
                let sk_bytes = sk.as_bytes().to_vec();
                dilithium3::SecretKey::from_bytes(&sk_bytes).unwrap()
            });
            Self {
                public_key,
                secret_key,
            }
        }
    }

    impl PQSignature {
        pub fn generate() -> Result<Self> {
            let (pk, sk) = dilithium3::keypair();
            Ok(Self {
                public_key: pk,
                secret_key: Some(sk),
            })
        }

        pub fn public_key_bytes(&self) -> Vec<u8> {
            self.public_key.as_bytes().to_vec()
        }

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

        pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
            let sk = self
                .secret_key
                .as_ref()
                .ok_or_else(|| Error::Crypto("no secret key available for signing".into()))?;
            let sig = dilithium3::detached_sign(message, sk);
            Ok(sig.as_bytes().to_vec())
        }

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

    #[derive(Debug, Clone)]
    pub struct HybridInitiatorData {
        pub x25519_public_key: [u8; 32],
        pub mlkem_public_key: Vec<u8>,
    }

    #[derive(Debug, Clone)]
    pub struct HybridResponderData {
        pub x25519_public_key: [u8; 32],
        pub mlkem_ciphertext: Vec<u8>,
    }

    #[derive(Clone)]
    pub struct HybridSharedSecret {
        secret: [u8; HYBRID_SHARED_SECRET_SIZE],
    }

    impl HybridSharedSecret {
        pub fn as_bytes(&self) -> &[u8; HYBRID_SHARED_SECRET_SIZE] {
            &self.secret
        }
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

    pub struct HybridHandshake {
        x25519_secret: Option<EphemeralSecret>,
        x25519_public: X25519PublicKey,
        mlkem: PQKeyExchange,
        role: HandshakeRole,
    }

    impl HybridHandshake {
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

        pub fn public_data(&self) -> HybridInitiatorData {
            HybridInitiatorData {
                x25519_public_key: self.x25519_public.to_bytes(),
                mlkem_public_key: self.mlkem.public_key_bytes(),
            }
        }

        pub fn respond(
            initiator_data: &HybridInitiatorData,
        ) -> Result<(Self, HybridResponderData)> {
            if initiator_data.mlkem_public_key.len() != MLKEM_PUBLIC_KEY_SIZE {
                return Err(Error::Crypto(format!(
                    "invalid initiator ML-KEM public key size: expected {}, got {}",
                    MLKEM_PUBLIC_KEY_SIZE,
                    initiator_data.mlkem_public_key.len()
                )));
            }
            let x25519_secret = EphemeralSecret::random_from_rng(OsRng);
            let x25519_public = X25519PublicKey::from(&x25519_secret);
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

        pub fn finalize(
            mut self,
            responder_data: &HybridResponderData,
        ) -> Result<HybridSharedSecret> {
            if self.role != HandshakeRole::Initiator {
                return Err(Error::Crypto(
                    "finalize() can only be called by initiator".into(),
                ));
            }
            let x25519_secret = self
                .x25519_secret
                .take()
                .ok_or_else(|| Error::Crypto("X25519 secret already consumed".into()))?;
            let peer = X25519PublicKey::from(responder_data.x25519_public_key);
            let x25519_shared = x25519_secret.diffie_hellman(&peer);
            let mlkem_shared = self.mlkem.decapsulate(&responder_data.mlkem_ciphertext)?;
            Self::derive_hybrid_secret(x25519_shared.as_bytes(), &mlkem_shared)
        }

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
            let x25519_secret = self
                .x25519_secret
                .take()
                .ok_or_else(|| Error::Crypto("X25519 secret already consumed".into()))?;
            let peer = X25519PublicKey::from(initiator_data.x25519_public_key);
            let x25519_shared = x25519_secret.diffie_hellman(&peer);
            Self::derive_hybrid_secret(x25519_shared.as_bytes(), mlkem_shared)
        }

        fn derive_hybrid_secret(
            x25519_shared: &[u8],
            mlkem_shared: &[u8; 32],
        ) -> Result<HybridSharedSecret> {
            let mut ikm = Vec::with_capacity(x25519_shared.len() + mlkem_shared.len());
            ikm.extend_from_slice(x25519_shared);
            ikm.extend_from_slice(mlkem_shared);
            let hkdf = Hkdf::<Sha256>::new(Some(b"ZAP-HYBRID-HANDSHAKE-v1"), &ikm);
            let mut secret = [0u8; HYBRID_SHARED_SECRET_SIZE];
            hkdf.expand(b"shared-secret", &mut secret)
                .map_err(|_| Error::Crypto("HKDF expansion failed".into()))?;
            ikm.zeroize();
            Ok(HybridSharedSecret { secret })
        }
    }

    pub fn hybrid_handshake() -> Result<(
        [u8; HYBRID_SHARED_SECRET_SIZE],
        [u8; HYBRID_SHARED_SECRET_SIZE],
    )> {
        let initiator = HybridHandshake::initiate()?;
        let init_data = initiator.public_data();
        let (responder, resp_data) = HybridHandshake::respond(&init_data)?;
        let mlkem_for_responder = PQKeyExchange::generate()?;
        let (_, mlkem_shared_responder) =
            mlkem_for_responder.encapsulate(&init_data.mlkem_public_key)?;
        let initiator_secret = initiator.finalize(&resp_data)?;
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
            let (ciphertext, alice_shared) = alice.encapsulate(&bob.public_key_bytes()).unwrap();
            let bob_shared = bob.decapsulate(&ciphertext).unwrap();
            assert_eq!(alice_shared, bob_shared);
        }

        #[test]
        fn test_mldsa_signature() {
            let signer = PQSignature::generate().unwrap();
            let message = b"The quick brown fox jumps over the lazy dog";
            let signature = signer.sign(message).unwrap();
            signer.verify(message, &signature).unwrap();
            let verifier = PQSignature::from_public_key(&signer.public_key_bytes()).unwrap();
            verifier.verify(message, &signature).unwrap();
        }
    }
}

// ── Re-exports ───────────────────────────────────────────────────────

#[cfg(feature = "pq")]
pub use pq_impl::{
    hybrid_handshake, HybridHandshake, HybridInitiatorData, HybridResponderData,
    HybridSharedSecret, PQKeyExchange, PQSignature,
};

// Feature-gated fallbacks when the `pq` feature is not enabled
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
