//! Z-Wing typed errors. Mirrors the Go `errors.go` set so cross-language
//! diagnostics can match strings.

use std::fmt;

/// Result alias for Z-Wing operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Every error a Z-Wing operation can return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// 1-RTT handshake failed for some unrecoverable reason.
    HandshakeFailed,
    /// Remote peer's identity did not match the pinned `expected_remote`.
    IdentityMismatch,
    /// Hybrid Ed25519 + ML-DSA-65 signature verification failed.
    SignatureInvalid,
    /// Frame is larger than `MAX_FRAME_SIZE`.
    MessageTooLarge,
    /// Underlying reader returned fewer bytes than required.
    ShortRead,
    /// Wire-format encoding violated structure invariants (zero-length
    /// frame, trailing garbage, length mismatch, …).
    InvalidWireFormat,
    /// `Channel` was already closed.
    ChannelClosed,
    /// 64-bit AEAD nonce counter exhausted (5.8e11 years at 1 record/ns).
    SequenceExhausted,
    /// Caller passed a `Config` without a local identity.
    ConfigMissingId,
    /// AEAD authentication tag failed to verify.
    CiphertextCorrupted,
    /// X-Wing decapsulation rejected the ciphertext shape or X25519 point.
    DecapsulationFailed,
    /// Wrapping I/O error from the transport.
    Io(String),
    /// Catch-all for upstream crypto failures.
    Crypto(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::HandshakeFailed => f.write_str("zwing: handshake failed"),
            Error::IdentityMismatch => {
                f.write_str("zwing: remote identity does not match expected")
            }
            Error::SignatureInvalid => f.write_str("zwing: signature verification failed"),
            Error::MessageTooLarge => f.write_str("zwing: message exceeds maximum size"),
            Error::ShortRead => f.write_str("zwing: short read"),
            Error::InvalidWireFormat => f.write_str("zwing: invalid wire format"),
            Error::ChannelClosed => f.write_str("zwing: channel closed"),
            Error::SequenceExhausted => f.write_str("zwing: AEAD sequence number exhausted"),
            Error::ConfigMissingId => f.write_str("zwing: config missing LocalIdentity"),
            Error::CiphertextCorrupted => f.write_str("zwing: AEAD authentication failed"),
            Error::DecapsulationFailed => f.write_str("zwing: X-Wing decapsulation failed"),
            Error::Io(m) => write!(f, "zwing: io: {m}"),
            Error::Crypto(m) => write!(f, "zwing: crypto: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}
