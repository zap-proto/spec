//! ZAP capability runtime — the delegation-token authority primitive.
//!
//! A [`Capability`] is a signed, attenuable token of authority. It grants a
//! holder a bitmask of permissions over a target, with optional caveats.
//! Caps form a chain: a parent's holder issues an attenuated child whose
//! permissions are a subset of the parent's. [`Verifier::verify_chain`] walks
//! the chain back to a root, checking each signature, the permission
//! intersection, expiry, revocation, and the delegation gate.
//!
//! This is a faithful Rust port of the canonical Go runtime
//! (`github.com/zap-proto/go/cap`). The wire bytes, the canonical signed
//! bytes, and the CapID are **byte-identical** across the two runtimes — a
//! cap signed in Go verifies in Rust and vice versa. The cross-language KAT
//! in `tests/cap_kat.rs` proves this against a Go-produced fixture.
//!
//! # Design (decomplected)
//!
//! - [`wire`]   — ZAP fixed-offset (de)serialization. One concern: bytes.
//! - [`Caveat`] / [`Permission`] / [`Scheme`] — codecs & constants.
//! - [`Capability`] — the value: field accessors, `canonical_bytes`, `cap_id`.
//! - [`Signer`] — pluggable signing (Ed25519 mandatory, ML-DSA-65 real,
//!   secp256k1/hybrid fail-closed rather than fabricated).
//! - [`Verifier`] — policy: `verify` (single cap) and `verify_chain`
//!   (SPEC §2.3 invariants). Scheme dispatch is FAIL-CLOSED.
//!
//! Spec: `zap-spec/SPEC.md` §2.3/§3/§4, `capabilities.zap`,
//! `capabilities_kinds.md`.

#![allow(clippy::module_name_repetitions)]

use core::fmt;

use ed25519_dalek::{Signer as _, Verifier as _};
use pqcrypto_mldsa::mldsa65::{
    detached_sign as ml_sign, keypair as ml_keypair, verify_detached_signature as ml_verify,
    DetachedSignature as MlSig, PublicKey as MlPub, SecretKey as MlSec,
};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
use sha2::{Digest, Sha256};

// ============================================================================
// Wire constants (frozen v1.1 — see capabilities.zap / SPEC §6).
// ============================================================================

/// Fixed signature footer width. Sized at v1.1 to hold any of: secp256k1
/// ECDSA (65B), Ed25519 (64B), ML-DSA-65 (3309B, FIPS 204 §5.2), or hybrid
/// Ed25519+ML-DSA-65. 3408 = 213*16 (16-byte aligned) with 99B headroom over
/// ML-DSA-65. Schemes shorter than this are zero-padded on the right; the
/// algorithm tag lives at `Sig[SIG_SIZE-1]`.
pub const SIG_SIZE: usize = 3408;

/// Offset of the algorithm-tag byte within the signature footer. The byte at
/// `Sig[ALG_TAG_OFFSET]` selects the verification primitive; it is part of
/// the signed payload, so a tag flip changes the signature.
pub const ALG_TAG_OFFSET: usize = SIG_SIZE - 1;

/// Length of the fixed-header prefix the signature covers: `Capability` bytes
/// `[0..164)` — Kind through the Caveats list pointer, NOT including `Sig`.
pub const SIGNED_HEADER_LEN: usize = 164;

/// Total size of the `Capability` ZAP struct (164 header + 3408 sig).
pub const CAPABILITY_STRUCT_SIZE: usize = SIGNED_HEADER_LEN + SIG_SIZE; // 3572

// Field offsets within the Capability fixed header (from capabilities.zap /
// the generated capabilities_zap.go). These are wire contract.
const OFF_KIND: usize = 0;
const OFF_TARGET: usize = 4;
const OFF_HOLDER: usize = 36;
const OFF_ISSUER: usize = 68;
const OFF_PERMISSIONS: usize = 100;
const OFF_PARENT: usize = 108;
const OFF_ISSUED_AT: usize = 140;
const OFF_EXPIRES_AT: usize = 148;
const OFF_CAVEATS: usize = 156; // list pointer: relOffset:u32 || length:u32
const OFF_SIG: usize = 164;

const ED25519_SIG_LEN: usize = 64;
const ED25519_PUB_LEN: usize = 32;
const MLDSA65_SIG_LEN: usize = 3309;

// ============================================================================
// Errors
// ============================================================================

/// Errors returned by the cap runtime. Mirrors the Go `cap` error surface so
/// behaviour (and test expectations) line up one-for-one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapError {
    /// Buffer shorter than the ZAP header / declared size.
    TooShort,
    /// Magic bytes were not `ZAP\0`.
    BadMagic,
    /// Caveat list framing is malformed.
    BadCaveats,
    /// Signature did not verify against the issuer key.
    SigMismatch,
    /// Cap has expired at the supplied time.
    Expired,
    /// Cap (or an ancestor) is revoked.
    Revoked,
    /// A chain link is broken (parent ID / issuer-holder linkage / root).
    ChainBroken,
    /// A child's permissions are not a subset of its parent's.
    PermsExceedParent,
    /// The parent does not authorize attenuation (no `PermAttenuate`, not
    /// `Delegate` kind). SPEC §2.3 step 3d.
    NotDelegable,
    /// The requested op bit is not set in the leaf permission mask.
    OpNotPermitted,
    /// Target does not match the supplied target / parent target.
    TargetMismatch,
    /// Holder does not match the supplied holder.
    HolderMismatch,
    /// Issuer key could not be resolved.
    IssuerUnknown,
    /// A caveat was violated (reserved for caveat evaluation hooks).
    CaveatViolation,
    /// The signature scheme tag is one this verifier does not implement
    /// (or `Reserved`/unknown). Fail-closed per SPEC §2.3 step 3c.
    UnhandledScheme,
    /// A signer was required but not supplied.
    MissingSigner,
    /// A scheme the runtime cannot honestly produce was requested (e.g.
    /// secp256k1/hybrid). We never fabricate crypto.
    SchemeUnavailable(Scheme),
}

impl fmt::Display for CapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => write!(f, "cap: buffer too short"),
            Self::BadMagic => write!(f, "cap: bad magic"),
            Self::BadCaveats => write!(f, "cap: caveat block malformed"),
            Self::SigMismatch => write!(f, "cap: signature does not verify"),
            Self::Expired => write!(f, "cap: expired"),
            Self::Revoked => write!(f, "cap: revoked"),
            Self::ChainBroken => write!(f, "cap: chain link broken"),
            Self::PermsExceedParent => write!(f, "cap: permissions exceed parent"),
            Self::NotDelegable => write!(f, "cap: parent does not permit attenuation"),
            Self::OpNotPermitted => write!(f, "cap: op not in permission mask"),
            Self::TargetMismatch => write!(f, "cap: target does not match"),
            Self::HolderMismatch => write!(f, "cap: holder does not match"),
            Self::IssuerUnknown => write!(f, "cap: issuer key unknown"),
            Self::CaveatViolation => write!(f, "cap: caveat violated"),
            Self::UnhandledScheme => write!(f, "cap: signature scheme not handled"),
            Self::MissingSigner => write!(f, "cap: signer required"),
            Self::SchemeUnavailable(s) => {
                write!(
                    f,
                    "cap: signature scheme {s:?} not available in this runtime"
                )
            }
        }
    }
}

impl std::error::Error for CapError {}

/// Convenience result alias.
pub type Result<T> = core::result::Result<T, CapError>;

// ============================================================================
// Scheme / Kind / Caveat-kind enums (capabilities_kinds.md — wire contract).
// ============================================================================

/// Wire-level signature algorithm tag (the byte at `Sig[ALG_TAG_OFFSET]`).
/// Verifiers fail-closed on [`Scheme::Reserved`] and on unknown values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Scheme {
    /// 0x00 — MUST NOT appear in valid caps; verifiers refuse it.
    Reserved = 0x00,
    /// 0x01 — secp256k1 ECDSA (R||S||v), 65 bytes.
    Secp256k1 = 0x01,
    /// 0x02 — Ed25519 (RFC 8032), 64 bytes. Mandatory-to-implement.
    Ed25519 = 0x02,
    /// 0x03 — ML-DSA-65 (FIPS 204 Level-3), 3309 bytes.
    MlDsa65 = 0x03,
    /// 0x04 — hybrid Ed25519 || ML-DSA-65 (64 + 3309 bytes).
    Hybrid = 0x04,
}

impl Scheme {
    /// Map a wire tag byte to a known scheme, or `None` for unknown/reserved.
    /// Per SPEC §2.3 step 3c the valid set is exactly `{0x01,0x02,0x03,0x04}`.
    #[must_use]
    pub fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0x01 => Some(Self::Secp256k1),
            0x02 => Some(Self::Ed25519),
            0x03 => Some(Self::MlDsa65),
            0x04 => Some(Self::Hybrid),
            _ => None, // 0x00 Reserved and everything else: fail-closed.
        }
    }

    /// The wire tag byte for this scheme.
    #[must_use]
    pub fn tag(self) -> u8 {
        self as u8
    }
}

/// `CapKind` — the authority profile a capability confers (`Capability.Kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CapKind {
    /// 0x00 — reserved, must not be used.
    Reserved = 0x00,
    /// 0x01 — IAM session (replaces bearer JWT session tokens).
    IamSession = 0x01,
    /// 0x02 — IAM API key (client-credentials).
    IamApiKey = 0x02,
    /// 0x10 — KMS access (read/list).
    KmsAccess = 0x10,
    /// 0x11 — KMS signing authority.
    KmsSign = 0x11,
    /// 0x20 — MPC threshold-signing intent.
    MpcSign = 0x20,
    /// 0x30 — ATS order placement authority.
    AtsOrder = 0x30,
    /// 0x40 — cross-chain transfer authority.
    BridgeXfer = 0x40,
    /// 0x50 — validator stake-backed authority.
    Stake = 0x50,
    /// 0xFF — meta: ability to attenuate-and-reissue (delegation).
    Delegate = 0xFF,
}

impl CapKind {
    /// The raw u32 wire value.
    #[must_use]
    pub fn value(self) -> u32 {
        self as u32
    }
}

/// `CaveatKind` — the class of a caveat (`Caveat.Kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CaveatKind {
    /// 0x00 — u64 unix-seconds expiry.
    ExpiresAt = 0x00,
    /// 0x01 — u64 max amount (smallest denomination).
    MaxAmount = 0x01,
    /// 0x02 — id32 destination chain identifier.
    DestChain = 0x02,
    /// 0x03 — u32 ops-per-minute || u32 burst.
    RateLimit = 0x03,
    /// 0x04 — 1B AF || 1B prefix-len || addr bytes.
    IpCidr = 0x04,
    /// 0x05 — id32 allowed asset (repeat for multi).
    AssetId = 0x05,
    /// 0x06 — u64 op bitmask, intersected with parent.
    OpAllow = 0x06,
    /// 0x07 — u8 remaining chain hops.
    MaxDepth = 0x07,
    /// 0x08 — id32 target-service principal pubkey hash.
    Audience = 0x08,
    /// 0x09 — id32 single-use binding.
    NonceHash = 0x09,
}

impl CaveatKind {
    /// Map a raw wire u32 to a known caveat kind, or `None` if unknown.
    /// Verifiers MUST refuse unknown caveat kinds (fail-closed).
    #[must_use]
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0x00 => Some(Self::ExpiresAt),
            0x01 => Some(Self::MaxAmount),
            0x02 => Some(Self::DestChain),
            0x03 => Some(Self::RateLimit),
            0x04 => Some(Self::IpCidr),
            0x05 => Some(Self::AssetId),
            0x06 => Some(Self::OpAllow),
            0x07 => Some(Self::MaxDepth),
            0x08 => Some(Self::Audience),
            0x09 => Some(Self::NonceHash),
            _ => None,
        }
    }

    /// The raw u32 wire value.
    #[must_use]
    pub fn value(self) -> u32 {
        self as u32
    }
}

/// Cross-cutting permission bits (top 32 of `Capability.Permissions`, identical
/// across every CapKind). The low 32 bits are per-kind and owned by consumers.
pub mod perm {
    /// `1<<32` — holder may mint child caps with subset permissions. SPEC
    /// §2.3 step 3d requires this (or `Delegate` kind) on any parent that is
    /// attenuated.
    pub const ATTENUATE: u64 = 1 << 32;
    /// `1<<33` — holder may read the audit trail for the target.
    pub const AUDIT: u64 = 1 << 33;
    /// `1<<63` — root-of-trust marker (root caps only).
    pub const ROOT: u64 = 1 << 63;
}

// ============================================================================
// Caveat
// ============================================================================

/// One constraint attached to a capability. Caveats are AND-composed across a
/// chain: a child may add caveats but never remove a parent's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caveat {
    /// The caveat class (see [`CaveatKind`]). Stored as the raw u32 so that
    /// unknown kinds round-trip on the wire even though verifiers refuse them.
    pub kind: u32,
    /// Kind-specific binary payload.
    pub value: Vec<u8>,
}

impl Caveat {
    /// Construct a caveat from a typed kind and value.
    #[must_use]
    pub fn new(kind: CaveatKind, value: impl Into<Vec<u8>>) -> Self {
        Self {
            kind: kind.value(),
            value: value.into(),
        }
    }

    /// Append this caveat's canonical encoding to `dst`:
    /// `Kind:u32-LE || len(Value):u32-LE || Value`.
    fn append_canonical(&self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(&self.kind.to_le_bytes());
        dst.extend_from_slice(&(self.value.len() as u32).to_le_bytes());
        dst.extend_from_slice(&self.value);
    }
}

// ============================================================================
// Wire codec — byte-identical to the Go ZAP builder/reader.
// ============================================================================

/// ZAP fixed-offset serialization for the capability message family. Kept in
/// its own module so the "produce/consume bytes" concern never braids with
/// policy or crypto. Every layout decision here mirrors the canonical Go
/// runtime (`github.com/zap-proto/go`) so the bytes match across languages.
mod wire {
    use super::{
        CapError, Caveat, Result, ALG_TAG_OFFSET, CAPABILITY_STRUCT_SIZE, OFF_CAVEATS,
        OFF_EXPIRES_AT, OFF_HOLDER, OFF_ISSUED_AT, OFF_ISSUER, OFF_KIND, OFF_PARENT,
        OFF_PERMISSIONS, OFF_SIG, OFF_TARGET, SIG_SIZE,
    };

    /// ZAP wire header is 16 bytes: magic[4] || version:u16 || flags:u16 ||
    /// rootOffset:u32 || size:u32.
    pub const HEADER_SIZE: usize = 16;
    const MAGIC: &[u8; 4] = b"ZAP\0";
    /// This runtime emits Version1 (matching `github.com/zap-proto/go`'s
    /// pure-stdlib baseline `Builder`, which `cap` uses). The data segment is
    /// version-independent.
    const VERSION1: u16 = 1;
    const ALIGNMENT: usize = 8;

    #[inline]
    fn align_up(pos: usize, alignment: usize) -> usize {
        let rem = pos % alignment;
        if rem == 0 {
            pos
        } else {
            pos + (alignment - rem)
        }
    }

    /// Encode a single `Caveat` as its own self-contained ZAP buffer, exactly
    /// as Go's `NewCaveatView` does: header(16) + object(12: Kind:u32 @0,
    /// Value bytes-ptr @4) + value payload appended after the fixed section.
    fn encode_caveat(cv: &Caveat) -> Vec<u8> {
        // Object fixed section is 12 bytes (caveatViewSize). Root object lives
        // at offset 16 (right after the header; 16 % 8 == 0, no align pad).
        const CAVEAT_OBJ_SIZE: usize = 12;
        const VALUE_FIELD_OFF: usize = 4; // Caveat.Value @4

        let obj_start = HEADER_SIZE; // 16
        let mut buf = vec![0u8; obj_start + CAVEAT_OBJ_SIZE]; // header + fixed
                                                              // Kind at object offset 0.
        buf[obj_start..obj_start + 4].copy_from_slice(&cv.kind.to_le_bytes());

        if cv.value.is_empty() {
            // Null bytes pointer: relOffset=0, len=0 (already zero-filled).
        } else {
            // Deferred value data is written immediately after the 12-byte
            // fixed section (Go's ObjectBuilder.Finish writes deferred bytes at
            // the current position with no extra alignment).
            let data_pos = buf.len(); // == obj_start + 12 == 28
            let field_abs = obj_start + VALUE_FIELD_OFF; // 20
            let rel_off = (data_pos - field_abs) as u32; // 8
            buf[field_abs..field_abs + 4].copy_from_slice(&rel_off.to_le_bytes());
            buf[field_abs + 4..field_abs + 8]
                .copy_from_slice(&(cv.value.len() as u32).to_le_bytes());
            buf.extend_from_slice(&cv.value);
        }

        finalize_header(&mut buf, obj_start);
        buf
    }

    /// Patch the ZAP header (rootOffset + size) of a finished buffer.
    fn finalize_header(buf: &mut [u8], root_offset: usize) {
        let size = buf.len() as u32;
        buf[0..4].copy_from_slice(MAGIC);
        buf[4..6].copy_from_slice(&VERSION1.to_le_bytes());
        // flags [6..8) stay zero.
        buf[8..12].copy_from_slice(&(root_offset as u32).to_le_bytes());
        buf[12..16].copy_from_slice(&size.to_le_bytes());
    }

    /// Write a u32-LE at an object-relative offset.
    #[inline]
    fn put_u32(buf: &mut [u8], obj_start: usize, off: usize, v: u32) {
        buf[obj_start + off..obj_start + off + 4].copy_from_slice(&v.to_le_bytes());
    }
    /// Write a u64-LE at an object-relative offset.
    #[inline]
    fn put_u64(buf: &mut [u8], obj_start: usize, off: usize, v: u64) {
        buf[obj_start + off..obj_start + off + 8].copy_from_slice(&v.to_le_bytes());
    }
    /// Write a 32-byte id at an object-relative offset.
    #[inline]
    fn put_id32(buf: &mut [u8], obj_start: usize, off: usize, v: &[u8; 32]) {
        buf[obj_start + off..obj_start + off + 32].copy_from_slice(v);
    }

    /// Build the full wire bytes for a capability with the supplied signature
    /// footer already known. The fields are written into the fixed section;
    /// the caveats list and its in-header pointer are laid out exactly as the
    /// Go builder does so `canonical_bytes` matches byte-for-byte.
    ///
    /// Layout (root object at offset 16, fixed section 3572 bytes):
    /// - `[16 + OFF_*)` fixed scalar/id fields.
    /// - `[16 + OFF_CAVEATS)` list pointer: relOffset:u32 || length:u32.
    /// - `[16 + OFF_SIG)` the 3408-byte signature footer.
    /// - caveat list elements appended after the fixed section, 8-byte
    ///   aligned; each element is `len:u32-LE || caveat_zap_buffer`.
    #[allow(clippy::too_many_arguments)]
    pub fn encode_capability(
        kind: u32,
        target: &[u8; 32],
        holder: &[u8; 32],
        issuer: &[u8; 32],
        permissions: u64,
        parent: &[u8; 32],
        issued_at: u64,
        expires_at: u64,
        caveats: &[Caveat],
        sig: &[u8; SIG_SIZE],
    ) -> Vec<u8> {
        let obj_start = HEADER_SIZE; // 16
                                     // Reserve header + the full fixed section up front (zero-filled), so
                                     // the caveat list lands strictly after every fixed field. This mirrors
                                     // Go's StartObject pre-extension.
        let fixed_end = obj_start + CAPABILITY_STRUCT_SIZE; // 16 + 3572 = 3588
        let mut buf = vec![0u8; fixed_end];

        put_u32(&mut buf, obj_start, OFF_KIND, kind);
        put_id32(&mut buf, obj_start, OFF_TARGET, target);
        put_id32(&mut buf, obj_start, OFF_HOLDER, holder);
        put_id32(&mut buf, obj_start, OFF_ISSUER, issuer);
        put_u64(&mut buf, obj_start, OFF_PERMISSIONS, permissions);
        put_id32(&mut buf, obj_start, OFF_PARENT, parent);
        put_u64(&mut buf, obj_start, OFF_ISSUED_AT, issued_at);
        put_u64(&mut buf, obj_start, OFF_EXPIRES_AT, expires_at);
        // Sig footer at OFF_SIG (already within the reserved fixed section).
        buf[obj_start + OFF_SIG..obj_start + OFF_SIG + SIG_SIZE].copy_from_slice(sig);

        // Caveats list: align to 8, lay out elements, patch the in-header
        // pointer. Go's StartList aligns the builder position to 8 before the
        // first element. With a 3572-byte fixed section, that pad is a constant
        // 4 bytes => list starts at 3592 deterministically.
        if caveats.is_empty() {
            // SetList(len=0) writes relOffset=0, length=0. Already zero-filled.
        } else {
            let list_start = align_up(buf.len(), ALIGNMENT); // 3588 -> 3592
            buf.resize(list_start, 0); // append the alignment pad bytes
            for cv in caveats {
                let elem = encode_caveat(cv);
                buf.extend_from_slice(&(elem.len() as u32).to_le_bytes());
                buf.extend_from_slice(&elem);
            }
            let field_abs = obj_start + OFF_CAVEATS; // 172
            let rel_off = (list_start - field_abs) as u32; // 3592 - 172 = 3420
            buf[field_abs..field_abs + 4].copy_from_slice(&rel_off.to_le_bytes());
            buf[field_abs + 4..field_abs + 8]
                .copy_from_slice(&(caveats.len() as u32).to_le_bytes());
        }

        finalize_header(&mut buf, obj_start);
        buf
    }

    /// A parsed, validated capability buffer. Holds the raw bytes and the
    /// root-object offset; all field reads are zero-copy slices off `raw`.
    #[derive(Clone)]
    pub struct CapBuf {
        pub raw: Vec<u8>,
        pub root: usize,
    }

    /// Read a little-endian u32 from a ZAP header field.
    fn read_u32(buf: &[u8], off: usize) -> u32 {
        u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
    }

    impl CapBuf {
        /// Parse and structurally validate a capability buffer. Checks ZAP
        /// framing (magic, version, declared size) and that the Sig field is
        /// in bounds, then eagerly walks the caveat list to catch bad framing
        /// up front. Cryptographic verification lives in [`super::Verifier`].
        pub fn parse(b: &[u8]) -> Result<Self> {
            if b.len() < HEADER_SIZE {
                return Err(CapError::TooShort);
            }
            if &b[0..4] != MAGIC {
                return Err(CapError::BadMagic);
            }
            let version = u16::from_le_bytes([b[4], b[5]]);
            // Accept v1 and v2 like the Go reader (data segment is identical).
            if version != 1 && version != 2 {
                return Err(CapError::BadMagic);
            }
            let size = read_u32(b, 12) as usize;
            if size < HEADER_SIZE || size > b.len() {
                return Err(CapError::TooShort);
            }
            let raw = b[..size].to_vec();
            let root = read_u32(&raw, 8) as usize;
            // Sig must occupy SIG_SIZE bytes inside the buffer.
            let sig_abs = root + OFF_SIG;
            if root < HEADER_SIZE || sig_abs + SIG_SIZE > raw.len() {
                return Err(CapError::TooShort);
            }
            let cb = Self { raw, root };
            // Eager caveat-framing walk.
            let n = cb.num_caveats();
            for i in 0..n {
                if cb.caveat_at(i).is_none() {
                    return Err(CapError::BadCaveats);
                }
            }
            Ok(cb)
        }

        #[inline]
        fn obj_u32(&self, field_off: usize) -> u32 {
            let pos = self.root + field_off;
            if pos + 4 > self.raw.len() {
                return 0;
            }
            read_u32(&self.raw, pos)
        }

        #[inline]
        fn obj_u64(&self, field_off: usize) -> u64 {
            let pos = self.root + field_off;
            if pos + 8 > self.raw.len() {
                return 0;
            }
            u64::from_le_bytes(self.raw[pos..pos + 8].try_into().unwrap())
        }

        #[inline]
        fn obj_id32(&self, field_off: usize) -> [u8; 32] {
            let pos = self.root + field_off;
            let mut out = [0u8; 32];
            if pos + 32 <= self.raw.len() {
                out.copy_from_slice(&self.raw[pos..pos + 32]);
            }
            out
        }

        pub fn kind(&self) -> u32 {
            self.obj_u32(OFF_KIND)
        }
        pub fn target(&self) -> [u8; 32] {
            self.obj_id32(OFF_TARGET)
        }
        pub fn holder(&self) -> [u8; 32] {
            self.obj_id32(OFF_HOLDER)
        }
        pub fn issuer(&self) -> [u8; 32] {
            self.obj_id32(OFF_ISSUER)
        }
        pub fn permissions(&self) -> u64 {
            self.obj_u64(OFF_PERMISSIONS)
        }
        pub fn parent(&self) -> [u8; 32] {
            self.obj_id32(OFF_PARENT)
        }
        pub fn issued_at(&self) -> u64 {
            self.obj_u64(OFF_ISSUED_AT)
        }
        pub fn expires_at(&self) -> u64 {
            self.obj_u64(OFF_EXPIRES_AT)
        }

        /// Signature footer (the SIG_SIZE bytes at OFF_SIG).
        pub fn sig(&self) -> [u8; SIG_SIZE] {
            let mut out = [0u8; SIG_SIZE];
            let pos = self.root + OFF_SIG;
            if pos + SIG_SIZE <= self.raw.len() {
                out.copy_from_slice(&self.raw[pos..pos + SIG_SIZE]);
            }
            out
        }

        /// Algorithm tag byte at `Sig[ALG_TAG_OFFSET]`.
        pub fn alg_tag(&self) -> u8 {
            let pos = self.root + OFF_SIG + ALG_TAG_OFFSET;
            if pos < self.raw.len() {
                self.raw[pos]
            } else {
                0
            }
        }

        /// Caveat list length (from the in-header list pointer).
        pub fn num_caveats(&self) -> usize {
            let pos = self.root + OFF_CAVEATS;
            if pos + 8 > self.raw.len() {
                return 0;
            }
            let rel = read_u32(&self.raw, pos);
            if rel == 0 {
                return 0;
            }
            let len = read_u32(&self.raw, pos + 4) as usize;
            // Defensive: a length larger than the buffer cannot be honest.
            if len > self.raw.len() {
                return 0;
            }
            len
        }

        /// Absolute byte offset where the caveat list elements begin.
        fn caveats_list_off(&self) -> Option<usize> {
            let pos = self.root + OFF_CAVEATS;
            if pos + 8 > self.raw.len() {
                return None;
            }
            let rel = read_u32(&self.raw, pos);
            if rel == 0 {
                return None;
            }
            let abs = pos + rel as usize;
            if abs < HEADER_SIZE || abs >= self.raw.len() {
                return None;
            }
            Some(abs)
        }

        /// Decode the i-th caveat by walking the length-prefixed element list
        /// and parsing the element's own ZAP sub-buffer. Returns `None` on any
        /// framing error (which `parse` turns into `BadCaveats`).
        pub fn caveat_at(&self, i: usize) -> Option<Caveat> {
            let n = self.num_caveats();
            if i >= n {
                return None;
            }
            let mut p = self.caveats_list_off()?;
            let data = &self.raw;
            // Skip to the i-th element.
            for _ in 0..i {
                if p + 4 > data.len() {
                    return None;
                }
                let sz = read_u32(data, p) as usize;
                p += 4 + sz;
            }
            if p + 4 > data.len() {
                return None;
            }
            let sz = read_u32(data, p) as usize;
            let start = p + 4;
            let end = start + sz;
            if end > data.len() {
                return None;
            }
            decode_caveat_buf(&data[start..end])
        }

        /// All caveats in list order.
        pub fn caveats(&self) -> Vec<Caveat> {
            let n = self.num_caveats();
            let mut out = Vec::with_capacity(n);
            for i in 0..n {
                match self.caveat_at(i) {
                    Some(cv) => out.push(cv),
                    None => break,
                }
            }
            out
        }
    }

    /// Parse a standalone caveat ZAP buffer (the element payload) into a
    /// [`Caveat`]. Mirrors Go's `CaveatView`: Kind:u32 @0, Value bytes @4.
    fn decode_caveat_buf(b: &[u8]) -> Option<Caveat> {
        if b.len() < HEADER_SIZE {
            return None;
        }
        if &b[0..4] != MAGIC {
            return None;
        }
        let size = read_u32(b, 12) as usize;
        if size < HEADER_SIZE || size > b.len() {
            return None;
        }
        let root = read_u32(b, 8) as usize;
        if root < HEADER_SIZE || root + 4 > size {
            return None;
        }
        let kind = read_u32(b, root);
        // Value bytes pointer at object offset 4.
        let vpos = root + 4;
        if vpos + 8 > size {
            return None;
        }
        let rel = read_u32(b, vpos);
        let value = if rel == 0 {
            Vec::new()
        } else {
            let len = read_u32(b, vpos + 4) as usize;
            let abs = vpos + rel as usize;
            if abs < HEADER_SIZE || abs + len > size {
                return None;
            }
            b[abs..abs + len].to_vec()
        };
        Some(Caveat { kind, value })
    }
}

pub use wire::HEADER_SIZE;

// ============================================================================
// Capability — the value.
// ============================================================================

/// A signed, attenuable token of authority. Wrap raw wire bytes with
/// [`Capability::parse`], or mint one with [`issue`] / [`Capability::attenuate`].
#[derive(Clone)]
pub struct Capability {
    buf: wire::CapBuf,
}

impl Capability {
    /// Parse and structurally validate a wire buffer. Does NOT verify the
    /// signature (use [`Verifier`]).
    pub fn parse(b: &[u8]) -> Result<Self> {
        Ok(Self {
            buf: wire::CapBuf::parse(b)?,
        })
    }

    /// The underlying wire bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.buf.raw
    }

    /// `Kind` field (raw u32).
    #[must_use]
    pub fn kind(&self) -> u32 {
        self.buf.kind()
    }
    /// 32-byte target hash.
    #[must_use]
    pub fn target(&self) -> [u8; 32] {
        self.buf.target()
    }
    /// 32-byte holder hash.
    #[must_use]
    pub fn holder(&self) -> [u8; 32] {
        self.buf.holder()
    }
    /// 32-byte issuer hash.
    #[must_use]
    pub fn issuer(&self) -> [u8; 32] {
        self.buf.issuer()
    }
    /// Permission bitmask.
    #[must_use]
    pub fn permissions(&self) -> u64 {
        self.buf.permissions()
    }
    /// 32-byte parent cap ID (zero == root).
    #[must_use]
    pub fn parent(&self) -> [u8; 32] {
        self.buf.parent()
    }
    /// Unix-second issued-at.
    #[must_use]
    pub fn issued_at(&self) -> u64 {
        self.buf.issued_at()
    }
    /// Unix-second expiry (zero == never).
    #[must_use]
    pub fn expires_at(&self) -> u64 {
        self.buf.expires_at()
    }
    /// Number of caveats.
    #[must_use]
    pub fn num_caveats(&self) -> usize {
        self.buf.num_caveats()
    }
    /// The i-th caveat, if present.
    #[must_use]
    pub fn caveat_at(&self, i: usize) -> Option<Caveat> {
        self.buf.caveat_at(i)
    }
    /// All caveats in list order.
    #[must_use]
    pub fn caveats(&self) -> Vec<Caveat> {
        self.buf.caveats()
    }
    /// The full SIG_SIZE-byte signature footer.
    #[must_use]
    pub fn signature(&self) -> [u8; SIG_SIZE] {
        self.buf.sig()
    }
    /// The algorithm tag byte the verifier dispatches on.
    #[must_use]
    pub fn alg_tag(&self) -> u8 {
        self.buf.alg_tag()
    }

    /// The exact bytes the signature is computed over (SPEC §3):
    /// `Capability[0..164)` read verbatim from the wire buffer, followed by
    /// each caveat encoded `Kind:u32-LE || len:u32-LE || Value` in list order.
    /// Excludes `Sig` and the ZAP heap indirection bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let hdr_off = self.buf.root;
        let caveats = self.buf.caveats();
        let cav_len: usize = caveats.iter().map(|c| 8 + c.value.len()).sum();
        let mut out = Vec::with_capacity(SIGNED_HEADER_LEN + cav_len);
        out.extend_from_slice(&self.buf.raw[hdr_off..hdr_off + SIGNED_HEADER_LEN]);
        for cv in &caveats {
            cv.append_canonical(&mut out);
        }
        out
    }

    /// Canonical 32-byte identifier: `SHA-256(canonical_bytes || Sig)`
    /// (SPEC §4). Revocation keys on this, and the chain walk matches each
    /// child's `Parent` to its parent's `cap_id`.
    #[must_use]
    pub fn cap_id(&self) -> [u8; 32] {
        let mut buf = self.canonical_bytes();
        buf.extend_from_slice(&self.buf.sig());
        hash32(&buf)
    }

    /// Derive an attenuated child cap from this parent: intersect permissions,
    /// add caveats, narrow expiry. The child's `Issuer` = this parent's
    /// `Holder`; `signer` MUST hold the parent's holder key. Refuses at mint
    /// time anything its own verifier would reject (SPEC §7).
    ///
    /// `expires_at == 0` inherits the parent's expiry; a non-zero value is
    /// clamped down to the parent's (a child never outlives its parent).
    pub fn attenuate(
        &self,
        holder: [u8; 32],
        permissions: u64,
        caveats: Vec<Caveat>,
        expires_at: u64,
        signer: &dyn Signer,
    ) -> Result<Capability> {
        // The signer must be the parent's holder — only the holder may
        // delegate authority downward.
        if signer.public() != self.holder() {
            return Err(CapError::ChainBroken);
        }
        // Delegation gate (SPEC §2.3 step 3d), enforced at mint.
        if self.permissions() & perm::ATTENUATE == 0 && self.kind() != CapKind::Delegate.value() {
            return Err(CapError::NotDelegable);
        }
        let parent_expiry = self.expires_at();
        let child_expiry = if expires_at == 0 {
            parent_expiry
        } else if parent_expiry != 0 && expires_at > parent_expiry {
            parent_expiry
        } else {
            expires_at
        };
        let issuance = Issuance {
            kind: self.kind(),
            target: self.target(),
            holder,
            permissions: permissions & self.permissions(),
            parent: self.cap_id(),
            issued_at: now_unix(),
            expires_at: child_expiry,
            caveats,
        };
        build_signed(&issuance, signer)
    }
}

impl fmt::Debug for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Capability")
            .field("kind", &format_args!("{:#x}", self.kind()))
            .field("permissions", &format_args!("{:#x}", self.permissions()))
            .field("num_caveats", &self.num_caveats())
            .field("cap_id", &hex_short(&self.cap_id()))
            .finish()
    }
}

// ============================================================================
// Issuance / Issue / build
// ============================================================================

/// A request to mint a new capability.
#[derive(Debug, Clone)]
pub struct Issuance {
    /// `CapKind` raw value.
    pub kind: u32,
    /// 32-byte target hash.
    pub target: [u8; 32],
    /// 32-byte holder hash.
    pub holder: [u8; 32],
    /// Permission bitmask.
    pub permissions: u64,
    /// 32-byte parent cap ID (zero == root).
    pub parent: [u8; 32],
    /// Unix-second issued-at (0 == use current time).
    pub issued_at: u64,
    /// Unix-second expiry (0 == never).
    pub expires_at: u64,
    /// Caveats.
    pub caveats: Vec<Caveat>,
}

impl Default for Issuance {
    fn default() -> Self {
        Self {
            kind: 0,
            target: [0u8; 32],
            holder: [0u8; 32],
            permissions: 0,
            parent: [0u8; 32],
            issued_at: 0,
            expires_at: 0,
            caveats: Vec::new(),
        }
    }
}

/// Mint a new root capability signed by `signer`. The signer's public hash
/// becomes the cap's `Issuer`. `parent` stays as supplied (zero for a true
/// root). To derive a child from an existing parent, use
/// [`Capability::attenuate`].
pub fn issue(mut issuance: Issuance, signer: &dyn Signer) -> Result<Capability> {
    if issuance.issued_at == 0 {
        issuance.issued_at = now_unix();
    }
    build_signed(&issuance, signer)
}

/// Serialize a capability with a zero placeholder signature, compute the
/// canonical bytes, sign them, patch the footer in place, and parse the
/// result. The signed payload is computed from the just-built buffer via the
/// same code path the verifier uses — no build/verify asymmetry (SPEC §7).
fn build_signed(issuance: &Issuance, signer: &dyn Signer) -> Result<Capability> {
    let issuer = signer.public();
    let zero_sig = [0u8; SIG_SIZE];
    let unsigned = wire::encode_capability(
        issuance.kind,
        &issuance.target,
        &issuance.holder,
        &issuer,
        issuance.permissions,
        &issuance.parent,
        issuance.issued_at,
        issuance.expires_at,
        &issuance.caveats,
        &zero_sig,
    );
    // CanonicalBytes from the unsigned buffer (Sig is excluded from the scope,
    // so the zero placeholder does not affect it).
    let pre = Capability::parse(&unsigned)?;
    let canonical = pre.canonical_bytes();
    let sig = signer.sign(&canonical)?;
    // Rebuild with the real signature. (Patching in place would also work, but
    // a clean rebuild keeps the wire-layout logic in one place.)
    let signed = wire::encode_capability(
        issuance.kind,
        &issuance.target,
        &issuance.holder,
        &issuer,
        issuance.permissions,
        &issuance.parent,
        issuance.issued_at,
        issuance.expires_at,
        &issuance.caveats,
        &sig,
    );
    Capability::parse(&signed)
}

// ============================================================================
// Signer — pluggable, fail-closed on schemes we cannot honestly produce.
// ============================================================================

/// Abstracts an issuer's signing key. Implementations write their scheme tag
/// at `sig[ALG_TAG_OFFSET]` before returning so verifiers can dispatch on it.
pub trait Signer {
    /// Sign `payload` (the cap's canonical bytes), returning the SIG_SIZE
    /// footer with the algorithm tag set at `ALG_TAG_OFFSET`.
    fn sign(&self, payload: &[u8]) -> Result<[u8; SIG_SIZE]>;

    /// The canonical 32-byte hash of the signer's public key. Must match the
    /// cap's `Issuer` for verification to succeed.
    fn public(&self) -> [u8; 32];
}

/// Ed25519 signer (mandatory-to-implement scheme). The 64-byte signature is
/// placed at the leading bytes of the footer, the rest zero-padded, with the
/// `Ed25519` tag at `ALG_TAG_OFFSET`. The public hash is `SHA-256(pubkey)`.
pub struct Ed25519Signer {
    sk: ed25519_dalek::SigningKey,
    pk: ed25519_dalek::VerifyingKey,
    public_hash: [u8; 32],
}

impl Ed25519Signer {
    /// Build from a 32-byte seed (deterministic — used for KATs and tests).
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let sk = ed25519_dalek::SigningKey::from_bytes(seed);
        let pk = sk.verifying_key();
        let public_hash = hash32(pk.as_bytes());
        Self {
            sk,
            pk,
            public_hash,
        }
    }

    /// Generate a fresh keypair from the OS RNG.
    #[must_use]
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key();
        let public_hash = hash32(pk.as_bytes());
        Self {
            sk,
            pk,
            public_hash,
        }
    }

    /// The raw 32-byte Ed25519 public key (register this with a verifier's
    /// issuer-key lookup).
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        *self.pk.as_bytes()
    }
}

impl Signer for Ed25519Signer {
    fn sign(&self, payload: &[u8]) -> Result<[u8; SIG_SIZE]> {
        let mut out = [0u8; SIG_SIZE];
        let sig = self.sk.sign(payload);
        out[..ED25519_SIG_LEN].copy_from_slice(&sig.to_bytes());
        out[ALG_TAG_OFFSET] = Scheme::Ed25519.tag();
        Ok(out)
    }

    fn public(&self) -> [u8; 32] {
        self.public_hash
    }
}

/// ML-DSA-65 signer (FIPS 204 Level-3, post-quantum). The 3309-byte detached
/// signature is placed at the leading bytes of the footer, zero-padded, with
/// the `MlDsa65` tag at `ALG_TAG_OFFSET`. Public hash is `SHA-256(pk_bytes)`.
///
/// Real crypto via `pqcrypto-mldsa` — no fabrication. Signing is over the raw
/// canonical-bytes payload (FIPS 204 pure mode, empty context), matching the
/// payload an Ed25519 cap signs so the signed scope is scheme-independent
/// (SPEC §3).
pub struct MlDsa65Signer {
    sk: MlSec,
    pk: MlPub,
    public_hash: [u8; 32],
}

impl MlDsa65Signer {
    /// Generate a fresh ML-DSA-65 keypair.
    #[must_use]
    pub fn generate() -> Self {
        let (pk, sk) = ml_keypair();
        let public_hash = hash32(pk.as_bytes());
        Self {
            sk,
            pk,
            public_hash,
        }
    }

    /// The raw FIPS 204 public-key bytes (1952 B) — register with a verifier.
    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        self.pk.as_bytes().to_vec()
    }
}

impl Signer for MlDsa65Signer {
    fn sign(&self, payload: &[u8]) -> Result<[u8; SIG_SIZE]> {
        let mut out = [0u8; SIG_SIZE];
        let sig = ml_sign(payload, &self.sk);
        let sb = sig.as_bytes();
        // FIPS 204 ML-DSA-65 detached signatures are exactly 3309 bytes.
        if sb.len() != MLDSA65_SIG_LEN {
            return Err(CapError::SchemeUnavailable(Scheme::MlDsa65));
        }
        out[..MLDSA65_SIG_LEN].copy_from_slice(sb);
        out[ALG_TAG_OFFSET] = Scheme::MlDsa65.tag();
        Ok(out)
    }

    fn public(&self) -> [u8; 32] {
        self.public_hash
    }
}

// ============================================================================
// Verifier — policy + fail-closed scheme dispatch.
// ============================================================================

/// Built-in Ed25519 verification (mandatory-to-implement bootstrap path).
fn verify_ed25519(pub_key: &[u8], payload: &[u8], sig: &[u8; SIG_SIZE]) -> Result<()> {
    if pub_key.len() != ED25519_PUB_LEN {
        return Err(CapError::SigMismatch);
    }
    let pk_arr: [u8; ED25519_PUB_LEN] = pub_key.try_into().unwrap();
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk_arr).map_err(|_| CapError::SigMismatch)?;
    let sig_arr: [u8; ED25519_SIG_LEN] = sig[..ED25519_SIG_LEN].try_into().unwrap();
    let ed_sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    vk.verify(payload, &ed_sig)
        .map_err(|_| CapError::SigMismatch)
}

/// Built-in ML-DSA-65 verification (FIPS 204, pure/empty-context mode).
fn verify_mldsa65(pub_key: &[u8], payload: &[u8], sig: &[u8; SIG_SIZE]) -> Result<()> {
    let pk = MlPub::from_bytes(pub_key).map_err(|_| CapError::SigMismatch)?;
    let ml_sig = MlSig::from_bytes(&sig[..MLDSA65_SIG_LEN]).map_err(|_| CapError::SigMismatch)?;
    ml_verify(&ml_sig, payload, &pk).map_err(|_| CapError::SigMismatch)
}

/// A consumer-supplied verification hook for non-bootstrap schemes
/// (secp256k1 / hybrid, or a custom ML-DSA path). Returning
/// [`CapError::UnhandledScheme`] declines the tag and lets the dispatcher try
/// its built-in path; returning anything else is final.
pub type SchemeVerifyFn<'a> = dyn Fn(Scheme, &[u8], &[u8], &[u8; SIG_SIZE]) -> Result<()> + 'a;

/// Holds the policy dependencies cap validation needs. Construct with
/// [`Verifier::new`] (bootstrap Ed25519 + ML-DSA-65) and chain the
/// `with_*` builders to wire revocation, issuer-key resolution, and a custom
/// scheme hook.
#[derive(Default)]
pub struct Verifier<'a> {
    /// Returns `true` to reject a cap by ID regardless of signature/expiry.
    is_revoked: Option<Box<dyn Fn(&[u8; 32]) -> bool + 'a>>,
    /// Resolves a 32-byte issuer hash to raw public-key bytes, or
    /// [`CapError::IssuerUnknown`].
    issuer_key: Option<Box<dyn Fn(&[u8; 32]) -> Result<Vec<u8>> + 'a>>,
    /// Optional first-refusal dispatch for non-bootstrap schemes.
    scheme_verify: Option<Box<SchemeVerifyFn<'a>>>,
}

impl<'a> Verifier<'a> {
    /// A verifier with no policy wired. Signature verification will fail with
    /// [`CapError::IssuerUnknown`] until an issuer-key resolver is set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Wire the revocation lookup.
    #[must_use]
    pub fn with_is_revoked(mut self, f: impl Fn(&[u8; 32]) -> bool + 'a) -> Self {
        self.is_revoked = Some(Box::new(f));
        self
    }

    /// Wire the issuer-hash → public-key resolver.
    #[must_use]
    pub fn with_issuer_key(mut self, f: impl Fn(&[u8; 32]) -> Result<Vec<u8>> + 'a) -> Self {
        self.issuer_key = Some(Box::new(f));
        self
    }

    /// Wire a custom scheme-verification hook (e.g. secp256k1 / hybrid).
    #[must_use]
    pub fn with_scheme_verify(
        mut self,
        f: impl Fn(Scheme, &[u8], &[u8], &[u8; SIG_SIZE]) -> Result<()> + 'a,
    ) -> Self {
        self.scheme_verify = Some(Box::new(f));
        self
    }

    /// The verifier-side dispatcher. Reads the tag at `sig[ALG_TAG_OFFSET]`
    /// and routes to the right primitive, FAIL-CLOSED (SPEC §2.3 step 3c):
    ///
    /// 1. `Reserved` (0x00) and any tag outside `{0x01..0x04}` are rejected
    ///    immediately with [`CapError::UnhandledScheme`]. No fallback.
    /// 2. A wired `scheme_verify` hook gets first refusal on a known tag;
    ///    anything other than `UnhandledScheme` from it is final.
    /// 3. Built-in bootstrap: `Ed25519` and `MlDsa65` verify here when the
    ///    hook is absent or declined. Other known-but-unhooked schemes
    ///    (`Secp256k1`, `Hybrid`) return `UnhandledScheme` — never downgraded,
    ///    never fabricated.
    fn verify_sig(&self, pub_key: &[u8], payload: &[u8], sig: &[u8; SIG_SIZE]) -> Result<()> {
        let tag = sig[ALG_TAG_OFFSET];
        let scheme = match Scheme::from_tag(tag) {
            Some(s) => s,
            None => return Err(CapError::UnhandledScheme), // fail-closed gate
        };
        if let Some(hook) = &self.scheme_verify {
            match hook(scheme, pub_key, payload, sig) {
                Err(CapError::UnhandledScheme) => { /* fall through to built-ins */ }
                other => return other,
            }
        }
        match scheme {
            Scheme::Ed25519 => verify_ed25519(pub_key, payload, sig),
            Scheme::MlDsa65 => verify_mldsa65(pub_key, payload, sig),
            // secp256k1 / hybrid have no built-in primitive in this runtime —
            // a consumer must wire a hook. We refuse rather than downgrade.
            Scheme::Secp256k1 | Scheme::Hybrid | Scheme::Reserved => Err(CapError::UnhandledScheme),
        }
    }

    /// Validate a single cap independent of chain context: caveat framing,
    /// expiry at `now`, revocation, and signature against the resolved issuer
    /// key. Does NOT walk the parent chain (use [`Self::verify_chain`]).
    pub fn verify(&self, cap: &Capability, now: i64) -> Result<()> {
        // Caveat framing: every element must parse, and every kind must be
        // known (fail-closed on unknown CaveatKind — SPEC §2.3 step 4).
        let n = cap.num_caveats();
        for i in 0..n {
            let cv = cap.caveat_at(i).ok_or(CapError::BadCaveats)?;
            if CaveatKind::from_u32(cv.kind).is_none() {
                return Err(CapError::CaveatViolation);
            }
        }

        // Expiry (0 == never).
        let exp = cap.expires_at();
        if exp != 0 && now as u64 > exp {
            return Err(CapError::Expired);
        }

        // Revocation.
        let id = cap.cap_id();
        if let Some(rev) = &self.is_revoked {
            if rev(&id) {
                return Err(CapError::Revoked);
            }
        }

        // Signature.
        let issuer_key = self.issuer_key.as_ref().ok_or(CapError::IssuerUnknown)?;
        let pub_key = issuer_key(&cap.issuer())?;
        if pub_key.is_empty() {
            return Err(CapError::IssuerUnknown);
        }
        self.verify_sig(&pub_key, &cap.canonical_bytes(), &cap.signature())
    }

    /// Validate a cap proof end-to-end against `op`/`target`/`holder` at
    /// `now`. `chain` is the parents nearest-to-leaf first: `chain[0]` is the
    /// leaf's parent, `chain[len-1]` the root. An empty chain means the leaf
    /// must itself be a root.
    ///
    /// Enforces every SPEC §2.3 invariant:
    /// - leaf valid (sig/expiry/revocation), grants `op`, matches
    ///   `target`/`holder`;
    /// - each link valid on its own merits;
    /// - child permissions ⊆ parent permissions (monotonic narrowing);
    /// - child issuer == parent holder (chain linkage);
    /// - parent authorizes attenuation (`PermAttenuate` or `Delegate` kind) —
    ///   the delegation gate, defense-in-depth at verify time;
    /// - target invariant across the whole chain;
    /// - the root link has `Parent == zero`.
    pub fn verify_chain(
        &self,
        leaf: &Capability,
        chain: &[Capability],
        op: u64,
        target: &[u8; 32],
        holder: &[u8; 32],
        now: i64,
    ) -> Result<()> {
        self.verify(leaf, now)?;
        if &leaf.target() != target {
            return Err(CapError::TargetMismatch);
        }
        if &leaf.holder() != holder {
            return Err(CapError::HolderMismatch);
        }
        if leaf.permissions() & op == 0 {
            return Err(CapError::OpNotPermitted);
        }

        let zero = [0u8; 32];
        let mut prev = leaf;
        for (i, link) in chain.iter().enumerate() {
            // The current cap's Parent must equal this link's ID.
            if prev.parent() != link.cap_id() {
                return Err(CapError::ChainBroken);
            }
            // This link must be valid on its own merits.
            self.verify(link, now)?;
            // Monotonic: child permissions ⊆ parent permissions.
            if prev.permissions() & link.permissions() != prev.permissions() {
                return Err(CapError::PermsExceedParent);
            }
            // Chain linkage: child issuer == parent holder.
            if prev.issuer() != link.holder() {
                return Err(CapError::ChainBroken);
            }
            // Delegation gate (SPEC §2.3 step 3d).
            if link.permissions() & perm::ATTENUATE == 0 && link.kind() != CapKind::Delegate.value()
            {
                return Err(CapError::NotDelegable);
            }
            // Target invariant across the chain.
            if &link.target() != target {
                return Err(CapError::TargetMismatch);
            }
            // The last link must be a root (Parent zero).
            if i == chain.len() - 1 && link.parent() != zero {
                return Err(CapError::ChainBroken);
            }
            prev = link;
        }
        // Empty chain: leaf must itself be a root.
        if chain.is_empty() && leaf.parent() != zero {
            return Err(CapError::ChainBroken);
        }
        Ok(())
    }

    /// Verify a revocation record, dispatching on its tag byte exactly as cap
    /// signatures do (fail-closed). The caller resolves the original cap's
    /// issuer hash to a public key first.
    pub fn verify_revocation(&self, r: &Revocation, issuer_pub: &[u8]) -> Result<()> {
        if issuer_pub.is_empty() {
            return Err(CapError::IssuerUnknown);
        }
        self.verify_sig(
            issuer_pub,
            &revocation_payload(&r.cap_id, r.revoked_at),
            &r.revoker_sig,
        )
    }
}

// ============================================================================
// Revocation
// ============================================================================

/// An on-the-wire kill-entry for a cap. Listing a `cap_id` kills that cap and
/// every transitive descendant (the verifier walks each parent in the chain).
#[derive(Clone)]
pub struct Revocation {
    /// The revoked cap's `cap_id`.
    pub cap_id: [u8; 32],
    /// Unix-second time of revocation.
    pub revoked_at: i64,
    /// Issuer signature over `cap_id || revoked_at:u64-LE`.
    pub revoker_sig: [u8; SIG_SIZE],
}

impl fmt::Debug for Revocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The 3408-byte signature footer has no derived Debug; show its tag.
        f.debug_struct("Revocation")
            .field("cap_id", &hex_short(&self.cap_id))
            .field("revoked_at", &self.revoked_at)
            .field(
                "scheme_tag",
                &format_args!("{:#x}", self.revoker_sig[ALG_TAG_OFFSET]),
            )
            .finish()
    }
}

/// The 40-byte canonical payload a revocation signs: `cap_id || revoked_at`.
fn revocation_payload(cap_id: &[u8; 32], revoked_at: i64) -> Vec<u8> {
    let mut out = Vec::with_capacity(40);
    out.extend_from_slice(cap_id);
    out.extend_from_slice(&(revoked_at as u64).to_le_bytes());
    out
}

/// Produce a revocation for `cap` signed by `signer`. The signer MUST be the
/// cap's original issuer — only the issuer can revoke.
pub fn revoke(cap: &Capability, now: i64, signer: &dyn Signer) -> Result<Revocation> {
    if signer.public() != cap.issuer() {
        return Err(CapError::ChainBroken);
    }
    let id = cap.cap_id();
    let sig = signer.sign(&revocation_payload(&id, now))?;
    Ok(Revocation {
        cap_id: id,
        revoked_at: now,
        revoker_sig: sig,
    })
}

/// Verify a revocation under `issuer_pub` using the bootstrap dispatch
/// (Ed25519 + ML-DSA-65, fail-closed on unknown/reserved). For secp256k1 /
/// hybrid revocations, use [`Verifier::verify_revocation`] with a hook wired.
pub fn verify_revocation(r: &Revocation, issuer_pub: &[u8]) -> Result<()> {
    Verifier::new().verify_revocation(r, issuer_pub)
}

// ============================================================================
// Helpers
// ============================================================================

/// The package's canonical 32-byte hash (SHA-256). Spec-mandated for CapID
/// (SPEC §4): in every target language's stdlib, so cross-language CapIDs are
/// trivially reproducible.
#[must_use]
pub fn hash32(b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b);
    let out = h.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&out);
    id
}

/// Current unix time in seconds. Used when an issuance leaves `issued_at`/
/// expiry at 0.
fn now_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex_short(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(16);
    for byte in &b[..8] {
        s.push_str(&format!("{byte:02x}"));
    }
    s.push('…');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_target_holder() -> ([u8; 32], [u8; 32]) {
        let mut target = [0u8; 32];
        let mut holder = [0u8; 32];
        for i in 0..32 {
            target[i] = i as u8;
            holder[i] = 255 - i as u8;
        }
        (target, holder)
    }

    /// Snapshot the (issuer-hash, raw-pubkey) of each signer into an owned
    /// table and return a `'static`-friendly resolver closure. Owning the data
    /// avoids borrowing the temporary `&[&signer]` array at the call site.
    fn issuer_key_for(signers: &[&Ed25519Signer]) -> impl Fn(&[u8; 32]) -> Result<Vec<u8>> {
        let table: Vec<([u8; 32], Vec<u8>)> = signers
            .iter()
            .map(|s| (s.public(), s.public_key().to_vec()))
            .collect();
        move |h: &[u8; 32]| {
            for (hash, pk) in &table {
                if hash == h {
                    return Ok(pk.clone());
                }
            }
            Err(CapError::IssuerUnknown)
        }
    }

    #[test]
    fn issue_round_trip() {
        let signer = Ed25519Signer::generate();
        let (target, holder) = fixed_target_holder();
        let cap = issue(
            Issuance {
                kind: CapKind::IamSession.value(),
                target,
                holder,
                permissions: 0xDEAD_BEEF_CAFE_BABE,
                issued_at: 1_700_000_000,
                expires_at: 2_000_000_000,
                caveats: vec![
                    Caveat::new(CaveatKind::MaxAmount, 1_000_000u64.to_le_bytes().to_vec()),
                    Caveat::new(CaveatKind::RateLimit, {
                        let mut v = Vec::new();
                        v.extend_from_slice(&60u32.to_le_bytes());
                        v.extend_from_slice(&10u32.to_le_bytes());
                        v
                    }),
                    Caveat::new(CaveatKind::IpCidr, b"10.0.0.0/8".to_vec()),
                ],
                ..Default::default()
            },
            &signer,
        )
        .unwrap();

        assert_eq!(cap.kind(), CapKind::IamSession.value());
        assert_eq!(cap.target(), target);
        assert_eq!(cap.holder(), holder);
        assert_eq!(cap.issuer(), signer.public());
        assert_eq!(cap.permissions(), 0xDEAD_BEEF_CAFE_BABE);
        assert_eq!(cap.issued_at(), 1_700_000_000);
        assert_eq!(cap.expires_at(), 2_000_000_000);
        assert_eq!(cap.num_caveats(), 3);
        assert_eq!(cap.caveat_at(0).unwrap().value, 1_000_000u64.to_le_bytes());
        assert_eq!(cap.caveat_at(2).unwrap().value, b"10.0.0.0/8");

        // Round-trips through parse.
        let re = Capability::parse(cap.bytes()).unwrap();
        assert_eq!(re.kind(), cap.kind());
        assert_eq!(re.cap_id(), cap.cap_id());
    }

    #[test]
    fn verify_accepts_fresh() {
        let signer = Ed25519Signer::generate();
        let cap = issue(
            Issuance {
                kind: CapKind::KmsAccess.value(),
                permissions: 0xFF,
                expires_at: 2_000_000_000,
                ..Default::default()
            },
            &signer,
        )
        .unwrap();
        let v = Verifier::new().with_issuer_key(issuer_key_for(&[&signer]));
        v.verify(&cap, 1_700_000_000).unwrap();
    }

    #[test]
    fn verify_rejects_expired() {
        let signer = Ed25519Signer::generate();
        let cap = issue(
            Issuance {
                permissions: 0xFF,
                expires_at: 1_700_000_000,
                ..Default::default()
            },
            &signer,
        )
        .unwrap();
        let v = Verifier::new().with_issuer_key(issuer_key_for(&[&signer]));
        assert_eq!(
            v.verify(&cap, 1_700_000_001).unwrap_err(),
            CapError::Expired
        );
    }

    #[test]
    fn verify_rejects_revoked() {
        let signer = Ed25519Signer::generate();
        let cap = issue(
            Issuance {
                permissions: 1,
                ..Default::default()
            },
            &signer,
        )
        .unwrap();
        let id = cap.cap_id();
        let v = Verifier::new()
            .with_issuer_key(issuer_key_for(&[&signer]))
            .with_is_revoked(move |c| *c == id);
        assert_eq!(v.verify(&cap, 1).unwrap_err(), CapError::Revoked);
    }

    #[test]
    fn verify_rejects_unknown_issuer() {
        let signer = Ed25519Signer::generate();
        let other = Ed25519Signer::generate();
        let cap = issue(
            Issuance {
                permissions: 1,
                ..Default::default()
            },
            &signer,
        )
        .unwrap();
        let v = Verifier::new().with_issuer_key(issuer_key_for(&[&other]));
        assert_eq!(v.verify(&cap, 1).unwrap_err(), CapError::IssuerUnknown);
    }

    #[test]
    fn verify_rejects_tampered_header() {
        let signer = Ed25519Signer::generate();
        let cap = issue(
            Issuance {
                permissions: 0xFF,
                expires_at: 2_000_000_000,
                ..Default::default()
            },
            &signer,
        )
        .unwrap();
        let mut raw = cap.bytes().to_vec();
        // Flip a permission bit (inside the signed header).
        let root = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]) as usize;
        raw[root + OFF_PERMISSIONS] ^= 0x01;
        let tc = Capability::parse(&raw).unwrap();
        let v = Verifier::new().with_issuer_key(issuer_key_for(&[&signer]));
        assert_eq!(v.verify(&tc, 1).unwrap_err(), CapError::SigMismatch);
    }

    #[test]
    fn signature_excludes_sig_pad() {
        let signer = Ed25519Signer::generate();
        let cap = issue(
            Issuance {
                permissions: 0xFF,
                expires_at: 2_000_000_000,
                ..Default::default()
            },
            &signer,
        )
        .unwrap();
        let before = cap.canonical_bytes();
        let mut raw = cap.bytes().to_vec();
        let root = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]) as usize;
        // Scribble a pad byte inside the footer (after the 64-byte sig, before
        // the tag). Canonical bytes must be unchanged, and verify still passes.
        raw[root + OFF_SIG + 100] ^= 0xFF;
        let c2 = Capability::parse(&raw).unwrap();
        assert_eq!(before, c2.canonical_bytes());
        let v = Verifier::new().with_issuer_key(issuer_key_for(&[&signer]));
        v.verify(&c2, 1).unwrap();
    }

    #[test]
    fn attenuate_intersects_permissions() {
        let root = Ed25519Signer::generate();
        let child = Ed25519Signer::generate();
        let mut target = [0u8; 32];
        target[0] = 0xAB;
        let parent = issue(
            Issuance {
                kind: CapKind::AtsOrder.value(),
                target,
                holder: root.public(),
                permissions: perm::ATTENUATE | 0b1111_0000,
                expires_at: 2_000_000_000,
                ..Default::default()
            },
            &root,
        )
        .unwrap();
        let leaf = parent
            .attenuate(
                child.public(),
                0b1010_0110,
                vec![Caveat::new(
                    CaveatKind::MaxAmount,
                    100u64.to_le_bytes().to_vec(),
                )],
                0,
                &root,
            )
            .unwrap();
        assert_eq!(leaf.permissions(), 0b1111_0000 & 0b1010_0110);
        assert_eq!(leaf.parent(), parent.cap_id());
        assert_eq!(leaf.issuer(), root.public());
        assert_eq!(leaf.target(), target);
        assert_eq!(leaf.expires_at(), parent.expires_at());
    }

    #[test]
    fn attenuate_requires_parent_holder_key() {
        let root = Ed25519Signer::generate();
        let imposter = Ed25519Signer::generate();
        let holder = Ed25519Signer::generate();
        let parent = issue(
            Issuance {
                permissions: 0xFF,
                holder: root.public(),
                expires_at: 2_000_000_000,
                ..Default::default()
            },
            &root,
        )
        .unwrap();
        let err = parent
            .attenuate(holder.public(), 0xFF, vec![], 0, &imposter)
            .unwrap_err();
        assert_eq!(err, CapError::ChainBroken);
    }

    #[test]
    fn attenuate_refuses_without_perm_attenuate() {
        let root = Ed25519Signer::generate();
        let holder = Ed25519Signer::generate();
        let parent = issue(
            Issuance {
                kind: CapKind::IamSession.value(),
                holder: root.public(),
                permissions: 0xFF, // no ATTENUATE, not Delegate
                expires_at: 2_000_000_000,
                ..Default::default()
            },
            &root,
        )
        .unwrap();
        let err = parent
            .attenuate(holder.public(), 0x0F, vec![], 0, &root)
            .unwrap_err();
        assert_eq!(err, CapError::NotDelegable);
    }

    #[test]
    fn attenuate_allowed_for_delegate_kind() {
        let root = Ed25519Signer::generate();
        let holder = Ed25519Signer::generate();
        let parent = issue(
            Issuance {
                kind: CapKind::Delegate.value(),
                holder: root.public(),
                permissions: 0xFF, // no ATTENUATE, but kind == Delegate
                expires_at: 2_000_000_000,
                ..Default::default()
            },
            &root,
        )
        .unwrap();
        parent
            .attenuate(holder.public(), 0x0F, vec![], 0, &root)
            .unwrap();
    }

    #[test]
    fn attenuate_caps_expiry_downward() {
        let root = Ed25519Signer::generate();
        let holder = Ed25519Signer::generate();
        let parent = issue(
            Issuance {
                permissions: perm::ATTENUATE | 0xFF,
                holder: root.public(),
                expires_at: 1000,
                ..Default::default()
            },
            &root,
        )
        .unwrap();
        let leaf = parent
            .attenuate(holder.public(), perm::ATTENUATE | 0xFF, vec![], 9999, &root)
            .unwrap();
        assert_eq!(leaf.expires_at(), 1000);
    }

    #[test]
    fn verify_chain_happy_path() {
        let root = Ed25519Signer::generate();
        let mid = Ed25519Signer::generate();
        let leaf_s = Ed25519Signer::generate();
        let mut target = [0u8; 32];
        target[31] = 0xEE;
        let root_cap = issue(
            Issuance {
                kind: CapKind::MpcSign.value(),
                target,
                holder: root.public(),
                permissions: perm::ATTENUATE | 0xFF,
                expires_at: 2_000_000_000,
                ..Default::default()
            },
            &root,
        )
        .unwrap();
        let mid_cap = root_cap
            .attenuate(mid.public(), perm::ATTENUATE | 0x0F, vec![], 0, &root)
            .unwrap();
        let leaf_cap = mid_cap
            .attenuate(leaf_s.public(), 0x07, vec![], 0, &mid)
            .unwrap();
        let v = Verifier::new().with_issuer_key(issuer_key_for(&[&root, &mid, &leaf_s]));
        let chain = vec![mid_cap, root_cap];
        v.verify_chain(
            &leaf_cap,
            &chain,
            0x04,
            &target,
            &leaf_s.public(),
            1_700_000_000,
        )
        .unwrap();
    }

    #[test]
    fn verify_chain_rejects_revoked_parent() {
        let root = Ed25519Signer::generate();
        let mid = Ed25519Signer::generate();
        let leaf_s = Ed25519Signer::generate();
        let mut target = [0u8; 32];
        target[0] = 0x01;
        let root_cap = issue(
            Issuance {
                holder: root.public(),
                target,
                permissions: perm::ATTENUATE | 0xFF,
                expires_at: 2_000_000_000,
                ..Default::default()
            },
            &root,
        )
        .unwrap();
        let mid_cap = root_cap
            .attenuate(mid.public(), perm::ATTENUATE | 0x0F, vec![], 0, &root)
            .unwrap();
        let leaf_cap = mid_cap
            .attenuate(leaf_s.public(), 0x07, vec![], 0, &mid)
            .unwrap();
        let revoked = mid_cap.cap_id();
        let v = Verifier::new()
            .with_issuer_key(issuer_key_for(&[&root, &mid, &leaf_s]))
            .with_is_revoked(move |c| *c == revoked);
        let chain = vec![mid_cap, root_cap];
        let err = v
            .verify_chain(
                &leaf_cap,
                &chain,
                0x04,
                &target,
                &leaf_s.public(),
                1_700_000_000,
            )
            .unwrap_err();
        assert_eq!(err, CapError::Revoked);
    }

    #[test]
    fn verify_chain_rejects_broken_link() {
        let root = Ed25519Signer::generate();
        let mid = Ed25519Signer::generate();
        let leaf_s = Ed25519Signer::generate();
        let other = Ed25519Signer::generate();
        let target = [0u8; 32];
        let root_cap = issue(
            Issuance {
                holder: root.public(),
                target,
                permissions: perm::ATTENUATE | 0xFF,
                expires_at: 2_000_000_000,
                ..Default::default()
            },
            &root,
        )
        .unwrap();
        let mid_cap = root_cap
            .attenuate(mid.public(), perm::ATTENUATE | 0x0F, vec![], 0, &root)
            .unwrap();
        let leaf_cap = mid_cap
            .attenuate(leaf_s.public(), 0x07, vec![], 0, &mid)
            .unwrap();
        let bogus = issue(
            Issuance {
                holder: other.public(),
                target,
                permissions: perm::ATTENUATE | 0xFF,
                expires_at: 2_000_000_000,
                ..Default::default()
            },
            &other,
        )
        .unwrap();
        let v = Verifier::new().with_issuer_key(issuer_key_for(&[&root, &mid, &leaf_s, &other]));
        let chain = vec![bogus, root_cap];
        let err = v
            .verify_chain(
                &leaf_cap,
                &chain,
                0x04,
                &target,
                &leaf_s.public(),
                1_700_000_000,
            )
            .unwrap_err();
        assert_eq!(err, CapError::ChainBroken);
    }

    #[test]
    fn verify_chain_rejects_op_not_permitted() {
        let root = Ed25519Signer::generate();
        let holder = Ed25519Signer::generate();
        let target = [0u8; 32];
        let cap = issue(
            Issuance {
                holder: holder.public(),
                target,
                permissions: 0b0010,
                expires_at: 2_000_000_000,
                ..Default::default()
            },
            &root,
        )
        .unwrap();
        let v = Verifier::new().with_issuer_key(issuer_key_for(&[&root, &holder]));
        let err = v
            .verify_chain(&cap, &[], 0b0100, &target, &holder.public(), 1)
            .unwrap_err();
        assert_eq!(err, CapError::OpNotPermitted);
    }

    #[test]
    fn verify_chain_empty_requires_root() {
        let root = Ed25519Signer::generate();
        let holder = Ed25519Signer::generate();
        let target = [0u8; 32];
        let cap = issue(
            Issuance {
                holder: holder.public(),
                target,
                permissions: 0xFF,
                expires_at: 2_000_000_000,
                ..Default::default()
            },
            &root,
        )
        .unwrap();
        let v = Verifier::new().with_issuer_key(issuer_key_for(&[&root, &holder]));
        v.verify_chain(&cap, &[], 0x01, &target, &holder.public(), 1)
            .unwrap();

        // Tamper Parent to non-zero: must now fail (sig breaks first, which is
        // still a rejection — we only assert "not Ok").
        let mut raw = cap.bytes().to_vec();
        let r = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]) as usize;
        raw[r + OFF_PARENT] = 0x99;
        let bad = Capability::parse(&raw).unwrap();
        assert!(v
            .verify_chain(&bad, &[], 0x01, &target, &holder.public(), 1)
            .is_err());
    }

    #[test]
    fn verify_chain_rejects_undelegated_parent() {
        // Parent lacks ATTENUATE; mid issued directly (bypassing the mint gate)
        // with a correct chain shape. verify_chain must independently enforce
        // the delegation gate.
        let root = Ed25519Signer::generate();
        let mid = Ed25519Signer::generate();
        let mut target = [0u8; 32];
        target[0] = 0x7E;
        let root_cap = issue(
            Issuance {
                kind: CapKind::IamSession.value(),
                holder: root.public(),
                target,
                permissions: 0x0F, // no ATTENUATE
                expires_at: 2_000_000_000,
                ..Default::default()
            },
            &root,
        )
        .unwrap();
        let mid_cap = issue(
            Issuance {
                kind: CapKind::IamSession.value(),
                holder: mid.public(),
                target,
                permissions: 0x07,
                parent: root_cap.cap_id(),
                expires_at: 2_000_000_000,
                ..Default::default()
            },
            &root,
        )
        .unwrap();
        let v = Verifier::new().with_issuer_key(issuer_key_for(&[&root, &mid]));
        let chain = vec![root_cap];
        let err = v
            .verify_chain(
                &mid_cap,
                &chain,
                0x01,
                &target,
                &mid.public(),
                1_700_000_000,
            )
            .unwrap_err();
        assert_eq!(err, CapError::NotDelegable);
    }

    #[test]
    fn verify_fails_closed_on_unknown_scheme() {
        let signer = Ed25519Signer::generate();
        let cap = issue(
            Issuance {
                permissions: 1,
                expires_at: 2_000_000_000,
                ..Default::default()
            },
            &signer,
        )
        .unwrap();
        let v = Verifier::new().with_issuer_key(issuer_key_for(&[&signer]));
        for tag in [0x00u8, 0x01, 0x04, 0x7F, 0xFF] {
            // 0x01 (secp256k1) and 0x04 (hybrid) are "known" tags but have no
            // built-in primitive => must also be refused (UnhandledScheme),
            // never downgraded to ed25519.
            let mut raw = cap.bytes().to_vec();
            let r = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]) as usize;
            raw[r + OFF_SIG + ALG_TAG_OFFSET] = tag;
            let bad = Capability::parse(&raw).unwrap();
            assert_eq!(
                v.verify(&bad, 1).unwrap_err(),
                CapError::UnhandledScheme,
                "tag {tag:#x} should be unhandled"
            );
        }
    }

    #[test]
    fn scheme_from_tag_known_set() {
        for s in 0u16..=0xFF {
            let tag = s as u8;
            let known = matches!(tag, 0x01 | 0x02 | 0x03 | 0x04);
            assert_eq!(Scheme::from_tag(tag).is_some(), known, "tag {tag:#x}");
        }
        assert!(Scheme::from_tag(0x00).is_none());
    }

    #[test]
    fn revoke_and_verify() {
        let signer = Ed25519Signer::generate();
        let cap = issue(
            Issuance {
                permissions: 1,
                expires_at: 2_000_000_000,
                ..Default::default()
            },
            &signer,
        )
        .unwrap();
        let r = revoke(&cap, 1_234_567_890, &signer).unwrap();
        assert_eq!(r.cap_id, cap.cap_id());
        assert_eq!(r.revoked_at, 1_234_567_890);
        verify_revocation(&r, &signer.public_key()).unwrap();
    }

    #[test]
    fn revoke_requires_issuer_key() {
        let signer = Ed25519Signer::generate();
        let imposter = Ed25519Signer::generate();
        let cap = issue(
            Issuance {
                permissions: 1,
                expires_at: 2_000_000_000,
                ..Default::default()
            },
            &signer,
        )
        .unwrap();
        assert_eq!(
            revoke(&cap, 1, &imposter).unwrap_err(),
            CapError::ChainBroken
        );
    }

    #[test]
    fn verify_revocation_rejects_tampered() {
        let signer = Ed25519Signer::generate();
        let cap = issue(
            Issuance {
                permissions: 1,
                expires_at: 2_000_000_000,
                ..Default::default()
            },
            &signer,
        )
        .unwrap();
        let mut r = revoke(&cap, 100, &signer).unwrap();
        r.revoked_at = 200; // tamper
        assert!(verify_revocation(&r, &signer.public_key()).is_err());
    }

    #[test]
    fn verify_revocation_fails_closed() {
        let signer = Ed25519Signer::generate();
        let cap = issue(
            Issuance {
                permissions: 1,
                expires_at: 2_000_000_000,
                ..Default::default()
            },
            &signer,
        )
        .unwrap();
        let r = revoke(&cap, 100, &signer).unwrap();
        for tag in [0x00u8, 0x7F, 0xFF] {
            let mut bad = r.clone();
            bad.revoker_sig[ALG_TAG_OFFSET] = tag;
            assert_eq!(
                verify_revocation(&bad, &signer.public_key()).unwrap_err(),
                CapError::UnhandledScheme,
                "tag {tag:#x}"
            );
        }
    }

    #[test]
    fn mldsa65_sign_verify_round_trip() {
        // Real PQ crypto end-to-end through the cap lifecycle.
        let signer = MlDsa65Signer::generate();
        let pubkey = signer.public_key();
        let cap = issue(
            Issuance {
                kind: CapKind::KmsSign.value(),
                permissions: perm::ATTENUATE | 0x07,
                expires_at: 2_000_000_000,
                caveats: vec![Caveat::new(
                    CaveatKind::MaxAmount,
                    42u64.to_le_bytes().to_vec(),
                )],
                ..Default::default()
            },
            &signer,
        )
        .unwrap();
        assert_eq!(cap.alg_tag(), Scheme::MlDsa65.tag());
        let v = Verifier::new().with_issuer_key(move |_| Ok(pubkey.clone()));
        v.verify(&cap, 1_700_000_000).unwrap();

        // Tampering the header breaks the PQ signature too.
        let mut raw = cap.bytes().to_vec();
        let r = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]) as usize;
        raw[r + OFF_PERMISSIONS] ^= 0x01;
        let tc = Capability::parse(&raw).unwrap();
        let pubkey2 = signer.public_key();
        let v2 = Verifier::new().with_issuer_key(move |_| Ok(pubkey2.clone()));
        assert_eq!(
            v2.verify(&tc, 1_700_000_000).unwrap_err(),
            CapError::SigMismatch
        );
    }

    #[test]
    fn caveat_all_kinds_round_trip() {
        let signer = Ed25519Signer::generate();
        let mut id = [0u8; 32];
        for (i, b) in id.iter_mut().enumerate() {
            *b = i as u8;
        }
        let cases = vec![
            Caveat::new(
                CaveatKind::ExpiresAt,
                2_000_000_000u64.to_le_bytes().to_vec(),
            ),
            Caveat::new(CaveatKind::MaxAmount, 42u64.to_le_bytes().to_vec()),
            Caveat::new(CaveatKind::DestChain, id.to_vec()),
            Caveat::new(CaveatKind::RateLimit, {
                let mut v = Vec::new();
                v.extend_from_slice(&120u32.to_le_bytes());
                v.extend_from_slice(&30u32.to_le_bytes());
                v
            }),
            Caveat::new(CaveatKind::IpCidr, b"192.168.0.0/16".to_vec()),
            Caveat::new(CaveatKind::AssetId, id.to_vec()),
            Caveat::new(CaveatKind::OpAllow, 0xF0F0F0F0u64.to_le_bytes().to_vec()),
            Caveat::new(CaveatKind::MaxDepth, vec![0x05]),
            Caveat::new(CaveatKind::Audience, id.to_vec()),
            Caveat::new(CaveatKind::NonceHash, id.to_vec()),
        ];
        let cap = issue(
            Issuance {
                permissions: 1,
                expires_at: 2_000_000_000,
                caveats: cases.clone(),
                ..Default::default()
            },
            &signer,
        )
        .unwrap();
        assert_eq!(cap.num_caveats(), cases.len());
        for (i, want) in cases.iter().enumerate() {
            let got = cap.caveat_at(i).unwrap();
            assert_eq!(got.kind, want.kind, "caveat {i} kind");
            assert_eq!(got.value, want.value, "caveat {i} value");
        }
        // And it verifies (all kinds are known).
        let v = Verifier::new().with_issuer_key(issuer_key_for(&[&signer]));
        v.verify(&cap, 1_700_000_000).unwrap();
    }
}
