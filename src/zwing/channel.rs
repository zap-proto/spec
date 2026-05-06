//! Z-Wing post-handshake encrypted channel. Mirrors the Go
//! `channel.go`: ChaCha20-Poly1305 with sequence-numbered nonces (high
//! 4 bytes zero, low 8 bytes BE counter) and length-prefixed frames.

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use std::io::{Read, Write};
use zeroize::Zeroize;

use super::errors::{Error, Result};
use super::handshake::{read_frame, write_frame, HandshakeOutput, MAX_FRAME_SIZE};
use super::identity::IdentityPublic;

/// Re-export so callers don't need to dig into `handshake` for the limit.
pub use super::handshake::MAX_FRAME_SIZE as CHANNEL_MAX_FRAME_SIZE;

const CHACHA_OVERHEAD: usize = 16;
const NONCE_LEN: usize = 12;

/// A post-handshake Z-Wing secure channel that wraps an arbitrary
/// `Read + Write` transport (TCP, Unix pipe, RNS link, …).
pub struct Channel<C: Read + Write> {
    inner: C,
    remote: IdentityPublic,
    rx: ChaCha20Poly1305,
    tx: ChaCha20Poly1305,
    rx_seq: u64,
    tx_seq: u64,
    rx_overflow: Vec<u8>,
}

impl<C: Read + Write> Channel<C> {
    /// Build a channel from the handshake output. `initiator = true`
    /// makes this side use `key_i2r` for transmit and `key_r2i` for
    /// receive; the responder is the mirror.
    pub fn new(inner: C, mut out: HandshakeOutput, initiator: bool) -> Self {
        let (tx_key, rx_key) = if initiator {
            (out.key_i2r, out.key_r2i)
        } else {
            (out.key_r2i, out.key_i2r)
        };
        let tx = ChaCha20Poly1305::new(Key::from_slice(&tx_key));
        let rx = ChaCha20Poly1305::new(Key::from_slice(&rx_key));
        let remote = out.remote.clone();
        // Wipe handshake-side keys now that the AEADs hold the material.
        out.key_i2r.zeroize();
        out.key_r2i.zeroize();
        out.shared.zeroize();
        Self {
            inner,
            remote,
            rx,
            tx,
            rx_seq: 0,
            tx_seq: 0,
            rx_overflow: Vec::new(),
        }
    }

    /// Verified remote public identity.
    pub fn remote(&self) -> &IdentityPublic {
        &self.remote
    }

    /// Encrypt and write a single application record. Records larger
    /// than `MAX_FRAME_SIZE - CHACHA_OVERHEAD` are split.
    pub fn send(&mut self, plaintext: &[u8]) -> Result<()> {
        let max_plain = MAX_FRAME_SIZE - CHACHA_OVERHEAD;
        let mut written = 0;
        while written < plaintext.len() {
            let end = std::cmp::min(written + max_plain, plaintext.len());
            let chunk = &plaintext[written..end];

            if self.tx_seq == u64::MAX {
                return Err(Error::SequenceExhausted);
            }
            let nonce = nonce_for(self.tx_seq);
            let ct = self
                .tx
                .encrypt(Nonce::from_slice(&nonce), chunk)
                .map_err(|_| Error::CiphertextCorrupted)?;
            self.tx_seq += 1;
            write_frame(&mut self.inner, &ct)?;
            written = end;
        }
        Ok(())
    }

    /// Read one full plaintext record. If `out` is smaller than the
    /// decrypted record, the overflow is buffered for the next call.
    pub fn recv(&mut self, out: &mut Vec<u8>) -> Result<usize> {
        if !self.rx_overflow.is_empty() {
            out.extend_from_slice(&self.rx_overflow);
            let n = self.rx_overflow.len();
            self.rx_overflow.clear();
            return Ok(n);
        }
        let frame = read_frame(&mut self.inner)?;
        if self.rx_seq == u64::MAX {
            return Err(Error::SequenceExhausted);
        }
        let nonce = nonce_for(self.rx_seq);
        let pt = self
            .rx
            .decrypt(Nonce::from_slice(&nonce), frame.as_slice())
            .map_err(|_| Error::CiphertextCorrupted)?;
        self.rx_seq += 1;
        out.extend_from_slice(&pt);
        Ok(pt.len())
    }
}

/// Build the 12-byte ChaCha20-Poly1305 nonce from a 64-bit counter:
/// high 4 bytes zero, low 8 bytes BE counter — same as the Go impl.
pub fn nonce_for(seq: u64) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[NONCE_LEN - 8..].copy_from_slice(&seq.to_be_bytes());
    n
}

#[cfg(test)]
mod tests {
    use super::super::handshake::{run_initiator, run_responder};
    use super::super::identity::Identity;
    use super::*;
    use std::io::{Read, Write};

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
                    .map_err(|_| {
                        std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "closed")
                    })?;
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
    fn full_e2e_handshake_then_aead() {
        let client = Identity::generate();
        let server = Identity::generate();

        let (mut a, mut b) = pipe();
        let server_thread = std::thread::spawn(move || {
            let server_local = Identity { ..server };
            let out = run_responder(&mut b, &server_local, None).unwrap();
            let mut chan = Channel::new(b, out, false);

            // Echo loop: read one record, send it back, exit.
            let mut buf = Vec::new();
            chan.recv(&mut buf).unwrap();
            chan.send(&buf).unwrap();
        });

        let out = run_initiator(&mut a, &client, None).unwrap();
        let mut chan = Channel::new(a, out, true);

        chan.send(b"z-wing rust e2e").unwrap();
        let mut buf = Vec::new();
        chan.recv(&mut buf).unwrap();
        assert_eq!(buf, b"z-wing rust e2e");
        server_thread.join().unwrap();
    }

    #[test]
    fn nonce_for_low_byte_carries_counter() {
        let n = nonce_for(0);
        assert_eq!(n, [0u8; 12]);
        let n = nonce_for(1);
        assert_eq!(n[11], 1);
        let n = nonce_for(u64::MAX);
        for i in 4..12 {
            assert_eq!(n[i], 0xFF);
        }
    }
}
