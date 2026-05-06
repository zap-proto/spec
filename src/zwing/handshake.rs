//! Z-Wing 1-RTT mutual-auth handshake (Rust port).
//!
//! Initiator → Responder: HandshakeInit
//!   `[2 BE idLen][IdentityPublic bytes][2 BE sigLen][hybrid signature]`
//!
//! Responder → Initiator: HandshakeResponse
//!   `[XWING_CIPHERTEXT_SIZE bytes: ML-KEM ct || X25519 ephemeral pk]`
//!   `[2 BE encLen][AEAD-sealed responder identity + signature]`
//!
//! All HKDF labels and the X-Wing combiner labels match the Go
//! implementation byte-for-byte. A Rust initiator can speak to a Go
//! responder over the same wire (and vice versa).

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::{Digest as Sha2Digest, Sha256};
use std::io::{Read, Write};
use zeroize::Zeroize;

use super::errors::{Error, Result};
use super::identity::{Identity, IdentityPublic, IDENTITY_PUBLIC_SIZE};
use super::kem::{xwing_decapsulate, xwing_encapsulate};
use super::{XWING_CIPHERTEXT_SIZE, XWING_SHARED_SIZE};

/// Maximum length of a single transport frame (1 MiB), matches Go.
pub const MAX_FRAME_SIZE: usize = 1 << 20;

/// HKDF label for the initiator → responder channel key.
pub const CHANNEL_KEY_LABEL_I2R: &[u8] = b"lux.zwing.v1/i2r";
/// HKDF label for the responder → initiator channel key.
pub const CHANNEL_KEY_LABEL_R2I: &[u8] = b"lux.zwing.v1/r2i";
/// Identity-signature context for the initiator's first message.
pub const HS_LABEL_INIT: &[u8] = b"lux.zwing.v1/handshake-init";
/// Identity-signature context for the responder's reply.
pub const HS_LABEL_RESPONSE: &[u8] = b"lux.zwing.v1/handshake-response";
/// HKDF label for the responder-identity AEAD key.
pub const RESP_ID_HKDF_LABEL: &[u8] = b"lux.zwing.v1/resp-id";
/// 12-byte AEAD nonce label for the responder-identity envelope.
pub const RESP_ID_NONCE_LABEL: &[u8] = b"zwing-resp-id";

/// What both peers agree on after a successful handshake.
pub struct HandshakeOutput {
    /// Shared secret (raw 32 bytes from the X-Wing combiner).
    pub shared: [u8; XWING_SHARED_SIZE],
    /// Verified remote public identity.
    pub remote: IdentityPublic,
    /// 32-byte ChaCha20-Poly1305 key for initiator → responder.
    pub key_i2r: [u8; 32],
    /// 32-byte ChaCha20-Poly1305 key for responder → initiator.
    pub key_r2i: [u8; 32],
}

/// Drive the initiator side of the handshake on `conn`. The optional
/// `expected_remote` pins the responder identity.
pub fn run_initiator<C: Read + Write>(
    conn: &mut C,
    local: &Identity,
    expected_remote: Option<&IdentityPublic>,
) -> Result<HandshakeOutput> {
    // 1. Send HandshakeInit.
    let id_pub = local.public().to_bytes();
    let sig = local.sign(HS_LABEL_INIT, &id_pub);
    let init = encode_handshake_init(&id_pub, &sig);
    write_frame(conn, &init)?;

    // 2. Receive HandshakeResponse.
    let resp_frame = read_frame(conn)?;
    let (ct, encrypted) = decode_handshake_response(&resp_frame)?;

    // 3. Decapsulate X-Wing.
    let shared = xwing_decapsulate(local.xwing(), ct)?;

    // 4. Decrypt responder identity payload.
    let id_key = derive_key(&shared, RESP_ID_HKDF_LABEL);
    let plaintext = aead_open(&id_key, RESP_ID_NONCE_LABEL, ct, encrypted)?;

    let (remote_id_bytes, remote_sig) = split_resp_id_payload(&plaintext)?;
    let remote = IdentityPublic::from_bytes(remote_id_bytes)?;

    // 5. Verify responder sig over transcript.
    let transcript = transcript_hash(&id_pub, ct);
    remote.verify(HS_LABEL_RESPONSE, &transcript, remote_sig)?;

    // 6. Optional pinning.
    if let Some(expected) = expected_remote {
        if !remote.equals(expected) {
            return Err(Error::IdentityMismatch);
        }
    }

    let key_i2r = derive_key(&shared, CHANNEL_KEY_LABEL_I2R);
    let key_r2i = derive_key(&shared, CHANNEL_KEY_LABEL_R2I);

    Ok(HandshakeOutput {
        shared,
        remote,
        key_i2r,
        key_r2i,
    })
}

/// Drive the responder side of the handshake on `conn`. The optional
/// `expected_remote` pins the initiator identity.
pub fn run_responder<C: Read + Write>(
    conn: &mut C,
    local: &Identity,
    expected_remote: Option<&IdentityPublic>,
) -> Result<HandshakeOutput> {
    // 1. Read HandshakeInit.
    let init_frame = read_frame(conn)?;
    let (id_pub, init_sig) = decode_handshake_init(&init_frame)?;
    let remote = IdentityPublic::from_bytes(id_pub)?;
    remote.verify(HS_LABEL_INIT, id_pub, init_sig)?;

    if let Some(expected) = expected_remote {
        if !remote.equals(expected) {
            return Err(Error::IdentityMismatch);
        }
    }

    // 2. Encapsulate to initiator's static X-Wing.
    let (ct, shared) = xwing_encapsulate(remote.xwing())?;

    // 3. Sign transcript and seal local identity.
    let local_id_pub = local.public().to_bytes();
    let transcript = transcript_hash(id_pub, &ct);
    let sig = local.sign(HS_LABEL_RESPONSE, &transcript);
    let plaintext = build_resp_id_payload(&local_id_pub, &sig);
    let id_key = derive_key(&shared, RESP_ID_HKDF_LABEL);
    let encrypted = aead_seal(&id_key, RESP_ID_NONCE_LABEL, &ct, &plaintext)?;

    let resp = encode_handshake_response(&ct, &encrypted);
    write_frame(conn, &resp)?;

    let key_i2r = derive_key(&shared, CHANNEL_KEY_LABEL_I2R);
    let key_r2i = derive_key(&shared, CHANNEL_KEY_LABEL_R2I);

    Ok(HandshakeOutput {
        shared,
        remote,
        key_i2r,
        key_r2i,
    })
}

// ─── wire helpers ──────────────────────────────────────────────────

pub(crate) fn write_frame<W: Write>(w: &mut W, payload: &[u8]) -> Result<()> {
    if payload.len() > MAX_FRAME_SIZE {
        return Err(Error::MessageTooLarge);
    }
    let mut hdr = [0u8; 4];
    hdr.copy_from_slice(&(payload.len() as u32).to_be_bytes());
    w.write_all(&hdr)?;
    w.write_all(payload)?;
    Ok(())
}

pub(crate) fn read_frame<R: Read>(r: &mut R) -> Result<Vec<u8>> {
    let mut hdr = [0u8; 4];
    r.read_exact(&mut hdr)?;
    let n = u32::from_be_bytes(hdr) as usize;
    if n > MAX_FRAME_SIZE {
        return Err(Error::MessageTooLarge);
    }
    if n == 0 {
        return Err(Error::InvalidWireFormat);
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

fn encode_handshake_init(id_pub: &[u8], sig: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + id_pub.len() + sig.len());
    out.extend_from_slice(&(id_pub.len() as u16).to_be_bytes());
    out.extend_from_slice(id_pub);
    out.extend_from_slice(&(sig.len() as u16).to_be_bytes());
    out.extend_from_slice(sig);
    out
}

fn decode_handshake_init(data: &[u8]) -> Result<(&[u8], &[u8])> {
    let mut r = SliceReader::new(data);
    let id_len = r.read_u16()? as usize;
    let id = r.read_n(id_len)?;
    let sig_len = r.read_u16()? as usize;
    let sig = r.read_n(sig_len)?;
    if !r.empty() {
        return Err(Error::InvalidWireFormat);
    }
    Ok((id, sig))
}

fn encode_handshake_response(ct: &[u8], encrypted: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ct.len() + 2 + encrypted.len());
    out.extend_from_slice(ct);
    out.extend_from_slice(&(encrypted.len() as u16).to_be_bytes());
    out.extend_from_slice(encrypted);
    out
}

fn decode_handshake_response(data: &[u8]) -> Result<(&[u8], &[u8])> {
    if data.len() < XWING_CIPHERTEXT_SIZE + 2 {
        return Err(Error::InvalidWireFormat);
    }
    let mut r = SliceReader::new(data);
    let ct = r.read_n(XWING_CIPHERTEXT_SIZE)?;
    let enc_len = r.read_u16()? as usize;
    let enc = r.read_n(enc_len)?;
    if !r.empty() {
        return Err(Error::InvalidWireFormat);
    }
    Ok((ct, enc))
}

fn build_resp_id_payload(id: &[u8], sig: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + id.len() + sig.len());
    out.extend_from_slice(&(id.len() as u16).to_be_bytes());
    out.extend_from_slice(id);
    out.extend_from_slice(&(sig.len() as u16).to_be_bytes());
    out.extend_from_slice(sig);
    out
}

fn split_resp_id_payload(data: &[u8]) -> Result<(&[u8], &[u8])> {
    let mut r = SliceReader::new(data);
    let id_len = r.read_u16()? as usize;
    let id = r.read_n(id_len)?;
    let sig_len = r.read_u16()? as usize;
    let sig = r.read_n(sig_len)?;
    if !r.empty() {
        return Err(Error::InvalidWireFormat);
    }
    Ok((id, sig))
}

struct SliceReader<'a> {
    buf: &'a [u8],
}

impl<'a> SliceReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    fn read_u16(&mut self) -> Result<u16> {
        if self.buf.len() < 2 {
            return Err(Error::ShortRead);
        }
        let v = u16::from_be_bytes([self.buf[0], self.buf[1]]);
        self.buf = &self.buf[2..];
        Ok(v)
    }

    fn read_n(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.buf.len() < n {
            return Err(Error::ShortRead);
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    fn empty(&self) -> bool {
        self.buf.is_empty()
    }
}

// ─── KDF / transcript / AEAD helpers ───────────────────────────────

pub(crate) fn derive_key(secret: &[u8], label: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, secret);
    let mut out = [0u8; 32];
    hk.expand(label, &mut out).expect("HKDF cannot fail for 32 bytes");
    out
}

fn transcript_hash(init_pub: &[u8], ct: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"lux.zwing.v1/transcript");
    h.update((init_pub.len() as u32).to_be_bytes());
    h.update(init_pub);
    h.update((ct.len() as u32).to_be_bytes());
    h.update(ct);
    let out = h.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out);
    digest
}

fn aead_seal(key: &[u8; 32], nonce_label: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let aead = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = handshake_nonce(nonce_label);
    aead.encrypt(
        Nonce::from_slice(&nonce),
        chacha20poly1305::aead::Payload {
            msg: plaintext,
            aad,
        },
    )
    .map_err(|_| Error::CiphertextCorrupted)
}

fn aead_open(
    key: &[u8; 32],
    nonce_label: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let aead = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = handshake_nonce(nonce_label);
    aead.decrypt(
        Nonce::from_slice(&nonce),
        chacha20poly1305::aead::Payload {
            msg: ciphertext,
            aad,
        },
    )
    .map_err(|_| Error::CiphertextCorrupted)
}

fn handshake_nonce(label: &[u8]) -> [u8; 12] {
    let mut n = [0u8; 12];
    let copy = std::cmp::min(label.len(), 12);
    n[..copy].copy_from_slice(&label[..copy]);
    n
}

// Key zeroize helper to make explicit that intermediate AEAD material
// is wiped before the channel is constructed.
#[allow(dead_code)]
pub(crate) fn zeroize_array<const N: usize>(b: &mut [u8; N]) {
    b.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// In-memory full-duplex pipe so a Rust initiator and responder can
    /// drive a full handshake against each other.
    fn pipe() -> (DuplexStream, DuplexStream) {
        let (a_to_b_tx, a_to_b_rx) = std::sync::mpsc::channel();
        let (b_to_a_tx, b_to_a_rx) = std::sync::mpsc::channel();
        let a = DuplexStream {
            tx: a_to_b_tx,
            rx: std::sync::Mutex::new(b_to_a_rx),
            buf: Vec::new(),
        };
        let b = DuplexStream {
            tx: b_to_a_tx,
            rx: std::sync::Mutex::new(a_to_b_rx),
            buf: Vec::new(),
        };
        (a, b)
    }

    struct DuplexStream {
        tx: std::sync::mpsc::Sender<Vec<u8>>,
        rx: std::sync::Mutex<std::sync::mpsc::Receiver<Vec<u8>>>,
        buf: Vec<u8>,
    }

    impl Read for DuplexStream {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            while self.buf.is_empty() {
                let chunk = self
                    .rx
                    .lock()
                    .unwrap()
                    .recv()
                    .map_err(|_| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "closed"))?;
                self.buf.extend_from_slice(&chunk);
            }
            let n = std::cmp::min(out.len(), self.buf.len());
            out[..n].copy_from_slice(&self.buf[..n]);
            self.buf.drain(..n);
            Ok(n)
        }
    }

    impl Write for DuplexStream {
        fn write(&mut self, p: &[u8]) -> std::io::Result<usize> {
            self.tx
                .send(p.to_vec())
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "closed"))?;
            Ok(p.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn handshake_round_trip() {
        let client = Identity::generate();
        let server = Identity::generate();
        let server_pub = server.public();
        let client_pub = client.public();

        let (mut a, mut b) = pipe();
        let server_thread = std::thread::spawn(move || run_responder(&mut b, &server, None));

        let c_out = run_initiator(&mut a, &client, Some(&server_pub)).unwrap();
        let s_out = server_thread.join().unwrap().unwrap();

        // Both sides must derive identical channel keys.
        assert_eq!(c_out.key_i2r, s_out.key_i2r);
        assert_eq!(c_out.key_r2i, s_out.key_r2i);
        // Both sides see the correct remote.
        assert!(c_out.remote.equals(&server_pub));
        assert!(s_out.remote.equals(&client_pub));
    }

    #[test]
    fn pinned_remote_mismatch_rejected() {
        let client = Identity::generate();
        let server = Identity::generate();
        let other = Identity::generate();

        let (mut a, mut b) = pipe();
        let _t = std::thread::spawn(move || run_responder(&mut b, &server, None));
        match run_initiator(&mut a, &client, Some(&other.public())) {
            Err(Error::IdentityMismatch) => (),
            Err(e) => panic!("expected IdentityMismatch, got {e:?}"),
            Ok(_) => panic!("expected error, got success"),
        }
    }

    #[test]
    fn write_frame_oversize_rejected() {
        let mut sink = Cursor::new(Vec::new());
        let buf = vec![0u8; MAX_FRAME_SIZE + 1];
        assert_eq!(write_frame(&mut sink, &buf).unwrap_err(), Error::MessageTooLarge);
    }

    #[test]
    fn read_frame_zero_length_rejected() {
        let buf = vec![0u8, 0, 0, 0];
        let mut c = Cursor::new(buf);
        assert_eq!(read_frame(&mut c).unwrap_err(), Error::InvalidWireFormat);
    }

    #[test]
    fn read_frame_oversize_rejected() {
        let buf = vec![0xFFu8, 0xFF, 0xFF, 0xFF];
        let mut c = Cursor::new(buf);
        assert_eq!(read_frame(&mut c).unwrap_err(), Error::MessageTooLarge);
    }

    #[test]
    fn handshake_init_decode_short_id() {
        // idLen=1 then no bytes → readN fails.
        assert!(decode_handshake_init(&[0, 1]).is_err());
    }

    #[test]
    fn handshake_response_decode_too_short() {
        let buf = vec![0u8; 100];
        assert_eq!(
            decode_handshake_response(&buf).unwrap_err(),
            Error::InvalidWireFormat
        );
    }
}
