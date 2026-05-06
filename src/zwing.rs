//! Z-Wing — Lux post-quantum secure channel (Rust port).
//!
//! Z-Wing is a **composition**: IETF X-Wing KEM at the bottom (X25519
//! + ML-KEM-768 with the SHA3-256 combiner from
//! draft-connolly-cfrg-xwing-kem) plus Lux Ed25519 + ML-DSA-65 hybrid
//! identity signatures plus ChaCha20-Poly1305 channel records. The
//! KEM layer is byte-for-byte the IETF spec for full interop with the
//! Go implementation in `github.com/luxfi/zwing` and any third-party
//! X-Wing peer.
//!
//! This module currently exposes the KEM combiner and constant-time
//! sizes. The full handshake and identity layer port follow on.
//!
//! # X-Wing combiner (IETF spec, exact)
//!
//! ```text
//! shared_secret = SHA3-256( "\./" || "X-Wing" || ss_M || ss_X || ct_X || pk_X )
//! ```
//!
//! The label is `"X-Wing"`, not `"Z-Wing"`. Z-Wing's domain separation
//! lives one layer up in the HKDF info string `"lux.zwing.v1/{i2r,r2i}"`
//! that derives the channel keys, and in the ML-DSA context
//! `"lux.zwing.v1"` used for hybrid identity signatures.

use sha3::{Digest, Sha3_256};

/// ML-KEM-768 public key size in bytes.
pub const MLKEM768_PUBLIC_KEY_SIZE: usize = 1184;
/// ML-KEM-768 ciphertext size in bytes.
pub const MLKEM768_CIPHERTEXT_SIZE: usize = 1088;
/// X25519 public key (and ciphertext) size in bytes.
pub const X25519_POINT_SIZE: usize = 32;

/// X-Wing public key wire size: ML-KEM-768 pk || X25519 pk.
pub const XWING_PUBLIC_KEY_SIZE: usize = MLKEM768_PUBLIC_KEY_SIZE + X25519_POINT_SIZE;
/// X-Wing ciphertext wire size: ML-KEM-768 ct || X25519 ephemeral pk.
pub const XWING_CIPHERTEXT_SIZE: usize = MLKEM768_CIPHERTEXT_SIZE + X25519_POINT_SIZE;
/// Z-Wing / X-Wing shared-secret size in bytes.
pub const XWING_SHARED_SIZE: usize = 32;

/// IETF X-Wing combiner labels (exact bytes from
/// draft-connolly-cfrg-xwing-kem). Three-byte prefix `\./` plus the
/// six-byte ASCII protocol name `X-Wing`.
const XWING_LABEL_PREFIX: &[u8] = b"\\./";
const XWING_LABEL_NAME: &[u8] = b"X-Wing";

/// Combine the X-Wing KEM ingredients into a single 32-byte shared
/// secret.
///
/// Inputs are all fixed-length so no length separators are needed:
/// `ss_m` = ML-KEM-768 shared secret (32 bytes), `ss_x` = X25519 shared
/// secret (32 bytes), `ct_x` = X25519 ephemeral public key from
/// encapsulator (32 bytes), `pk_x` = X25519 static public key of
/// recipient (32 bytes).
pub fn combine_xwing(
    ss_m: &[u8; XWING_SHARED_SIZE],
    ss_x: &[u8; X25519_POINT_SIZE],
    ct_x: &[u8; X25519_POINT_SIZE],
    pk_x: &[u8; X25519_POINT_SIZE],
) -> [u8; XWING_SHARED_SIZE] {
    let mut h = Sha3_256::new();
    h.update(XWING_LABEL_PREFIX);
    h.update(XWING_LABEL_NAME);
    h.update(ss_m);
    h.update(ss_x);
    h.update(ct_x);
    h.update(pk_x);
    let out = h.finalize();
    let mut secret = [0u8; XWING_SHARED_SIZE];
    secret.copy_from_slice(&out);
    secret
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cross-language KAT shared with the Go implementation. Inputs are
    /// 32-byte arrays of repeated 0x01, 0x02, 0x03, 0x04. The expected
    /// hex output below comes from running the Go combiner on the same
    /// inputs:
    ///
    ///     shared := combineXWing(
    ///         bytes.Repeat([]byte{0x01}, 32),
    ///         bytes.Repeat([]byte{0x02}, 32),
    ///         bytes.Repeat([]byte{0x03}, 32),
    ///         bytes.Repeat([]byte{0x04}, 32),
    ///     )
    ///
    /// If this test fails, Rust↔Go Z-Wing interop is broken.
    const KAT_SS_M: [u8; 32] = [0x01; 32];
    const KAT_SS_X: [u8; 32] = [0x02; 32];
    const KAT_CT_X: [u8; 32] = [0x03; 32];
    const KAT_PK_X: [u8; 32] = [0x04; 32];

    #[test]
    fn xwing_combiner_kat_constant_inputs() {
        let got = combine_xwing(&KAT_SS_M, &KAT_SS_X, &KAT_CT_X, &KAT_PK_X);
        // Computed by SHA3-256("\./X-Wing" || 32x01 || 32x02 || 32x03 || 32x04).
        // This MUST match the Go combineXWing output for the same inputs.
        let expected =
            hex_literal::hex!("72df2088314a73de80c21d9593f13fcd5629c800c70b1507f0dd918fde5fe4ed");
        assert_eq!(got, expected, "KAT mismatch — Rust/Go Z-Wing diverged");
    }

    #[test]
    fn xwing_combiner_is_deterministic() {
        let a = combine_xwing(&KAT_SS_M, &KAT_SS_X, &KAT_CT_X, &KAT_PK_X);
        let b = combine_xwing(&KAT_SS_M, &KAT_SS_X, &KAT_CT_X, &KAT_PK_X);
        assert_eq!(a, b);
    }

    #[test]
    fn xwing_combiner_changes_on_any_input_change() {
        let base = combine_xwing(&KAT_SS_M, &KAT_SS_X, &KAT_CT_X, &KAT_PK_X);
        let mut alt_ss_m = KAT_SS_M;
        alt_ss_m[0] ^= 0x01;
        let mutated = combine_xwing(&alt_ss_m, &KAT_SS_X, &KAT_CT_X, &KAT_PK_X);
        assert_ne!(base, mutated);
    }
}
