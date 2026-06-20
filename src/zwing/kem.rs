//! IETF X-Wing KEM — full Rust implementation matching the Go wire
//! format byte-for-byte.
//!
//! Public key wire = ML-KEM-768 pk (1184) || X25519 pk (32) = 1216 bytes.
//! Ciphertext wire = ML-KEM-768 ct (1088) || X25519 ephemeral pk (32) = 1120 bytes.
//! Shared secret  = SHA3-256("\./X-Wing" || ssM || ssX || ctX || pkX) = 32 bytes.

use pqcrypto_mlkem::mlkem768::{
    self, decapsulate as mlkem_decapsulate, encapsulate as mlkem_encapsulate,
    keypair as mlkem_keypair, PublicKey as MlkemPublicKey, SecretKey as MlkemSecretKey,
};
use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertext, PublicKey as KemPublicKey, SecretKey as KemSecretKey,
    SharedSecret as KemSharedSecret,
};
use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};
use zeroize::Zeroize;

use super::errors::{Error, Result};
use super::{
    combine_xwing, MLKEM768_CIPHERTEXT_SIZE, MLKEM768_PUBLIC_KEY_SIZE, X25519_POINT_SIZE,
    XWING_CIPHERTEXT_SIZE, XWING_PUBLIC_KEY_SIZE, XWING_SHARED_SIZE,
};

/// X-Wing recipient public key.
#[derive(Clone)]
pub struct XWingPublicKey {
    pub(crate) mlkem_pub: MlkemPublicKey,
    pub(crate) x25519_pub: [u8; X25519_POINT_SIZE],
}

impl XWingPublicKey {
    /// Marshal to wire bytes: ML-KEM-768 pk || X25519 pk.
    pub fn to_bytes(&self) -> [u8; XWING_PUBLIC_KEY_SIZE] {
        let mut out = [0u8; XWING_PUBLIC_KEY_SIZE];
        out[..MLKEM768_PUBLIC_KEY_SIZE].copy_from_slice(self.mlkem_pub.as_bytes());
        out[MLKEM768_PUBLIC_KEY_SIZE..].copy_from_slice(&self.x25519_pub);
        out
    }

    /// Parse from wire bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != XWING_PUBLIC_KEY_SIZE {
            return Err(Error::InvalidWireFormat);
        }
        let mlkem_pub = MlkemPublicKey::from_bytes(&data[..MLKEM768_PUBLIC_KEY_SIZE])
            .map_err(|e| Error::Crypto(format!("ml-kem pubkey parse: {e:?}")))?;
        let mut x25519_pub = [0u8; X25519_POINT_SIZE];
        x25519_pub.copy_from_slice(&data[MLKEM768_PUBLIC_KEY_SIZE..]);
        Ok(Self {
            mlkem_pub,
            x25519_pub,
        })
    }
}

/// X-Wing recipient secret key (and the matching public material that
/// the combiner needs).
pub struct XWingPrivateKey {
    pub(crate) mlkem_sk: MlkemSecretKey,
    pub(crate) mlkem_pub: MlkemPublicKey,
    pub(crate) x25519_sk: XStaticSecret,
    pub(crate) x25519_pub: [u8; X25519_POINT_SIZE],
}

impl XWingPrivateKey {
    /// Generate a fresh X-Wing keypair from `OsRng`.
    pub fn generate() -> Self {
        let (mlkem_pub, mlkem_sk) = mlkem_keypair();
        let mut sk_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut sk_bytes);
        let x25519_sk = XStaticSecret::from(sk_bytes);
        sk_bytes.zeroize();
        let x25519_pub_arr: [u8; 32] = (&XPublicKey::from(&x25519_sk)).to_bytes();
        Self {
            mlkem_sk,
            mlkem_pub,
            x25519_sk,
            x25519_pub: x25519_pub_arr,
        }
    }

    /// Public half of this keypair.
    pub fn public(&self) -> XWingPublicKey {
        XWingPublicKey {
            mlkem_pub: self.mlkem_pub.clone(),
            x25519_pub: self.x25519_pub,
        }
    }
}

/// Encapsulate to `recipient`. Returns (ciphertext, 32-byte shared
/// secret). Uses `OsRng` internally.
pub fn xwing_encapsulate(recipient: &XWingPublicKey) -> Result<(Vec<u8>, [u8; XWING_SHARED_SIZE])> {
    // ML-KEM encapsulation.
    let (ss_m, ct_m) = mlkem_encapsulate(&recipient.mlkem_pub);

    // X25519 ephemeral.
    let mut eph_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut eph_bytes);
    let eph_sk = XStaticSecret::from(eph_bytes);
    eph_bytes.zeroize();
    let eph_pub_arr: [u8; 32] = (&XPublicKey::from(&eph_sk)).to_bytes();
    let recipient_pub = XPublicKey::from(recipient.x25519_pub);
    let ss_x = eph_sk.diffie_hellman(&recipient_pub);

    let ss_m_arr: [u8; 32] = ss_m
        .as_bytes()
        .try_into()
        .map_err(|_| Error::Crypto("ml-kem shared not 32 bytes".into()))?;
    let ss_x_arr: [u8; 32] = (*ss_x.as_bytes()).into();
    let shared = combine_xwing(&ss_m_arr, &ss_x_arr, &eph_pub_arr, &recipient.x25519_pub);

    let mut wire = Vec::with_capacity(XWING_CIPHERTEXT_SIZE);
    wire.extend_from_slice(ct_m.as_bytes());
    wire.extend_from_slice(&eph_pub_arr);

    Ok((wire, shared))
}

/// Decapsulate the wire ciphertext using `sk`.
pub fn xwing_decapsulate(
    sk: &XWingPrivateKey,
    ciphertext: &[u8],
) -> Result<[u8; XWING_SHARED_SIZE]> {
    if ciphertext.len() != XWING_CIPHERTEXT_SIZE {
        return Err(Error::InvalidWireFormat);
    }
    let mlkem_ct =
        pqcrypto_mlkem::mlkem768::Ciphertext::from_bytes(&ciphertext[..MLKEM768_CIPHERTEXT_SIZE])
            .map_err(|e| Error::Crypto(format!("ml-kem ct parse: {e:?}")))?;
    let mut eph_pub = [0u8; X25519_POINT_SIZE];
    eph_pub.copy_from_slice(&ciphertext[MLKEM768_CIPHERTEXT_SIZE..]);

    let ss_m = mlkem_decapsulate(&mlkem_ct, &sk.mlkem_sk);

    // X25519 with the ephemeral public key.
    let eph_pub_point = XPublicKey::from(eph_pub);
    let ss_x = sk.x25519_sk.diffie_hellman(&eph_pub_point);

    let ss_m_arr: [u8; 32] = ss_m
        .as_bytes()
        .try_into()
        .map_err(|_| Error::Crypto("ml-kem shared not 32 bytes".into()))?;
    let ss_x_arr: [u8; 32] = (*ss_x.as_bytes()).into();
    let shared = combine_xwing(&ss_m_arr, &ss_x_arr, &eph_pub, &sk.x25519_pub);
    Ok(shared)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xwing_round_trip() {
        let sk = XWingPrivateKey::generate();
        let pk = sk.public();
        let (ct, ss_a) = xwing_encapsulate(&pk).unwrap();
        let ss_b = xwing_decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss_a, ss_b);
    }

    #[test]
    fn pubkey_roundtrip() {
        let sk = XWingPrivateKey::generate();
        let pk = sk.public();
        let bytes = pk.to_bytes();
        let parsed = XWingPublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.x25519_pub, pk.x25519_pub);
        assert_eq!(parsed.to_bytes(), bytes);
    }

    #[test]
    fn pubkey_size_rejected() {
        assert!(XWingPublicKey::from_bytes(&[]).is_err());
        assert!(XWingPublicKey::from_bytes(&[0u8; 100]).is_err());
    }

    #[test]
    fn ciphertext_size_rejected() {
        let sk = XWingPrivateKey::generate();
        assert!(xwing_decapsulate(&sk, &[]).is_err());
        assert!(xwing_decapsulate(&sk, &[0u8; 50]).is_err());
    }
}
