//! Hybrid identity: Ed25519 + ML-DSA-65 + X-Wing static keypair.
//!
//! Wire format mirrors the Go implementation in `luxfi/zwing`:
//! `[Ed25519 pk: 32][ML-DSA-65 pk: 1952][X-Wing pk: 1216]` = 3200 bytes.
//! Signature wire = `[Ed25519 sig: 64][ML-DSA-65 sig: 3309]` = 3373 bytes.

use ed25519_dalek::{Signer, Verifier};
use pqcrypto_mldsa::mldsa65::{
    detached_sign_ctx as ml_sign_ctx, keypair as ml_keypair,
    verify_detached_signature_ctx as ml_verify_ctx, DetachedSignature as MlSig, PublicKey as MlPub,
    SecretKey as MlSec,
};
use pqcrypto_traits::sign::{
    DetachedSignature as KemDetachedSig, PublicKey as KemSignPub, SecretKey as KemSignSec,
};
use rand::rngs::OsRng;
use sha2::{Digest as Sha2Digest, Sha256};

use super::errors::{Error, Result};
use super::kem::{XWingPrivateKey, XWingPublicKey};
use super::XWING_PUBLIC_KEY_SIZE;

/// Ed25519 public key length (FIPS 186-5).
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;
/// Ed25519 signature length.
pub const ED25519_SIGNATURE_SIZE: usize = 64;
/// ML-DSA-65 public key length (FIPS 204).
pub const MLDSA65_PUBLIC_KEY_SIZE: usize = 1952;
/// FIPS 204 final ML-DSA-65 detached-signature length, matching the Go
/// (cloudflare/circl mldsa65), Python (dilithium-py), and TS
/// (@noble/post-quantum ml-dsa65) implementations exactly. Cross-
/// language handshakes between Rust and the others verify under each
/// other byte-for-byte.
pub const MLDSA65_SIGNATURE_SIZE: usize = 3309;

/// Total wire size of `IdentityPublic`.
pub const IDENTITY_PUBLIC_SIZE: usize =
    ED25519_PUBLIC_KEY_SIZE + MLDSA65_PUBLIC_KEY_SIZE + XWING_PUBLIC_KEY_SIZE;

/// Total wire size of an identity signature.
pub const SIGNATURE_SIZE: usize = ED25519_SIGNATURE_SIZE + MLDSA65_SIGNATURE_SIZE;

/// Z-Wing protocol context bound into every identity signature so a
/// signature minted under one Lux protocol cannot be replayed onto
/// another.
pub const ZWING_DOMAIN: &[u8] = b"lux.zwing.v1";

/// Long-term Z-Wing identity: Ed25519 + ML-DSA-65 hybrid signing keys
/// plus an X-Wing static KEM keypair.
pub struct Identity {
    pub(crate) ed_sk: ed25519_dalek::SigningKey,
    pub(crate) ed_pk: ed25519_dalek::VerifyingKey,
    pub(crate) ml_sk: MlSec,
    pub(crate) ml_pk: MlPub,
    pub(crate) xwing: XWingPrivateKey,
}

/// Public half of an `Identity` — what peers exchange.
#[derive(Clone)]
pub struct IdentityPublic {
    pub(crate) ed_pk: ed25519_dalek::VerifyingKey,
    pub(crate) ml_pk: MlPub,
    pub(crate) xwing_pub: XWingPublicKey,
}

impl Identity {
    /// Generate a fresh identity from `OsRng`.
    pub fn generate() -> Self {
        let ed_sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let ed_pk = ed_sk.verifying_key();
        let (ml_pk, ml_sk) = ml_keypair();
        let xwing = XWingPrivateKey::generate();
        Self {
            ed_sk,
            ed_pk,
            ml_sk,
            ml_pk,
            xwing,
        }
    }

    /// Public half.
    pub fn public(&self) -> IdentityPublic {
        IdentityPublic {
            ed_pk: self.ed_pk,
            ml_pk: self.ml_pk.clone(),
            xwing_pub: self.xwing.public(),
        }
    }

    /// Reference to the underlying X-Wing private key.
    pub fn xwing(&self) -> &XWingPrivateKey {
        &self.xwing
    }

    /// Sign `(ctx, message)` with both Ed25519 and ML-DSA-65. Output is
    /// the concatenation `[Ed25519 sig: 64][ML-DSA-65 sig: 3309]`.
    ///
    /// The ML-DSA-65 detached signature is produced with the FIPS 204
    /// `ctx = ZWING_DOMAIN` parameter, exactly matching the Go side's
    /// `DSAPriv.SignCtx(rand, digest, []byte("lux.zwing.v1"))` and the
    /// Python/TS sides' `ML_DSA_65.sign(..., ctx=ZWING_DOMAIN)` so
    /// Rust-produced signatures verify under any other Z-Wing peer.
    pub fn sign(&self, ctx: &[u8], message: &[u8]) -> Vec<u8> {
        let digest = identity_digest(ctx, message);
        let ed_sig = self.ed_sk.sign(&digest);
        let ml_sig = ml_sign_ctx(&digest, ZWING_DOMAIN, &self.ml_sk);
        let mut out = Vec::with_capacity(SIGNATURE_SIZE);
        out.extend_from_slice(&ed_sig.to_bytes());
        out.extend_from_slice(ml_sig.as_bytes());
        out
    }
}

impl IdentityPublic {
    /// Marshal to the canonical wire bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(IDENTITY_PUBLIC_SIZE);
        out.extend_from_slice(self.ed_pk.as_bytes());
        out.extend_from_slice(self.ml_pk.as_bytes());
        out.extend_from_slice(&self.xwing_pub.to_bytes());
        out
    }

    /// Parse from the canonical wire bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != IDENTITY_PUBLIC_SIZE {
            return Err(Error::InvalidWireFormat);
        }
        let mut off = 0;
        let ed_arr: [u8; ED25519_PUBLIC_KEY_SIZE] =
            data[off..off + ED25519_PUBLIC_KEY_SIZE].try_into().unwrap();
        let ed_pk = ed25519_dalek::VerifyingKey::from_bytes(&ed_arr)
            .map_err(|e| Error::Crypto(format!("ed25519 pubkey: {e}")))?;
        off += ED25519_PUBLIC_KEY_SIZE;

        let ml_pk = MlPub::from_bytes(&data[off..off + MLDSA65_PUBLIC_KEY_SIZE])
            .map_err(|e| Error::Crypto(format!("ml-dsa pubkey: {e:?}")))?;
        off += MLDSA65_PUBLIC_KEY_SIZE;

        let xwing_pub = XWingPublicKey::from_bytes(&data[off..off + XWING_PUBLIC_KEY_SIZE])?;
        Ok(Self {
            ed_pk,
            ml_pk,
            xwing_pub,
        })
    }

    /// Verify a signature produced by `Identity::sign`.
    pub fn verify(&self, ctx: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        if signature.len() != SIGNATURE_SIZE {
            return Err(Error::SignatureInvalid);
        }
        let digest = identity_digest(ctx, message);
        let ed_sig_bytes: [u8; ED25519_SIGNATURE_SIZE] =
            signature[..ED25519_SIGNATURE_SIZE].try_into().unwrap();
        let ed_sig = ed25519_dalek::Signature::from_bytes(&ed_sig_bytes);
        self.ed_pk
            .verify(&digest, &ed_sig)
            .map_err(|_| Error::SignatureInvalid)?;

        let ml_sig = MlSig::from_bytes(&signature[ED25519_SIGNATURE_SIZE..])
            .map_err(|_| Error::SignatureInvalid)?;
        ml_verify_ctx(&ml_sig, &digest, ZWING_DOMAIN, &self.ml_pk)
            .map_err(|_| Error::SignatureInvalid)?;
        Ok(())
    }

    /// X-Wing static public key.
    pub fn xwing(&self) -> &XWingPublicKey {
        &self.xwing_pub
    }

    /// Constant-time comparison of two public identities.
    pub fn equals(&self, other: &IdentityPublic) -> bool {
        // Ed25519 raw key bytes.
        let ed_ok = constant_time_eq(self.ed_pk.as_bytes(), other.ed_pk.as_bytes());
        let ml_ok = constant_time_eq(self.ml_pk.as_bytes(), other.ml_pk.as_bytes());
        let xw_ok = constant_time_eq(&self.xwing_pub.to_bytes(), &other.xwing_pub.to_bytes());
        ed_ok && ml_ok && xw_ok
    }
}

/// Bind `(ZWING_DOMAIN || len(ctx) || ctx || message)` into a SHA-256
/// digest. Same construction as the Go `identityDigest`.
pub fn identity_digest(ctx: &[u8], message: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ZWING_DOMAIN);
    h.update([ctx.len() as u8]);
    h.update(ctx);
    h.update(message);
    let out = h.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out);
    digest
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_round_trip() {
        let id = Identity::generate();
        let pub_ = id.public();
        let sig = id.sign(b"ctx", b"hello");
        pub_.verify(b"ctx", b"hello", &sig).unwrap();
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let id = Identity::generate();
        let pub_ = id.public();
        let sig = id.sign(b"ctx", b"hello");
        assert_eq!(
            pub_.verify(b"ctx", b"goodbye", &sig).unwrap_err(),
            Error::SignatureInvalid
        );
    }

    #[test]
    fn verify_rejects_wrong_ctx() {
        let id = Identity::generate();
        let pub_ = id.public();
        let sig = id.sign(b"ctx", b"hello");
        assert_eq!(
            pub_.verify(b"other", b"hello", &sig).unwrap_err(),
            Error::SignatureInvalid
        );
    }

    #[test]
    fn verify_rejects_short_sig() {
        let id = Identity::generate();
        let pub_ = id.public();
        assert_eq!(
            pub_.verify(b"ctx", b"hello", b"too short").unwrap_err(),
            Error::SignatureInvalid
        );
    }

    #[test]
    fn marshal_round_trip() {
        let id = Identity::generate();
        let pub_ = id.public();
        let bytes = pub_.to_bytes();
        let parsed = IdentityPublic::from_bytes(&bytes).unwrap();
        assert!(pub_.equals(&parsed));
        assert_eq!(parsed.to_bytes(), bytes);
    }

    #[test]
    fn equals_distinct_identities_differ() {
        let a = Identity::generate();
        let b = Identity::generate();
        assert!(!a.public().equals(&b.public()));
    }

    #[test]
    fn identity_public_size_constant() {
        let id = Identity::generate();
        assert_eq!(id.public().to_bytes().len(), IDENTITY_PUBLIC_SIZE);
    }
}
