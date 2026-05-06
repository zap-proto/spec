//! End-to-end interop test: Rust Z-Wing client ↔ Go Z-Wing server.
//!
//! Spawns the Go test server binary at `/tmp/zwing-test-server` (built
//! from `~/work/lux/zwing/cmd/zwing-test-server`), reads its listen
//! address and identity hex from stdout, opens a TCP socket, and runs
//! a full handshake + AEAD echo round trip.
//!
//! The test is skipped if the binary isn't present so it stays
//! cargo-clean on machines without the Go side built.

#![cfg(feature = "zwing")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Command, Stdio};

use zap::zwing::{run_initiator, Channel, Identity, IdentityPublic};

const SERVER_BIN: &str = "/tmp/zwing-test-server";

#[test]
fn rust_client_to_go_server_handshake_and_echo() {
    if !Path::new(SERVER_BIN).exists() {
        eprintln!("skipping: {SERVER_BIN} missing — build the Go side first");
        return;
    }

    let mut server = Command::new(SERVER_BIN)
        .arg("-addr")
        .arg("127.0.0.1:0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn go server");

    let stdout = server.stdout.take().expect("stdout");
    let mut reader = BufReader::new(stdout);
    let mut addr = String::new();
    reader.read_line(&mut addr).unwrap();
    let mut pub_hex = String::new();
    reader.read_line(&mut pub_hex).unwrap();
    let addr = addr.trim().to_string();
    let pub_hex = pub_hex.trim().to_string();
    assert!(!addr.is_empty());
    assert!(!pub_hex.is_empty());

    let pub_bytes = hex::decode(&pub_hex).expect("hex");
    let server_pub = IdentityPublic::from_bytes(&pub_bytes).expect("identity parse");

    let client = Identity::generate();
    let mut sock = TcpStream::connect(&addr).expect("connect");
    sock.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .ok();

    let out = run_initiator(&mut sock, &client, Some(&server_pub)).expect("handshake");
    let mut chan = Channel::new(sock, out, true);

    let payload = b"hello from Rust initiator";
    chan.send(payload).expect("send");
    let mut buf = Vec::new();
    chan.recv(&mut buf).expect("recv");
    assert_eq!(buf, payload);

    let status = server.wait_with_output().expect("wait");
    if !status.status.success() {
        panic!(
            "go server exit={:?}\nstderr:\n{}",
            status.status,
            String::from_utf8_lossy(&status.stderr)
        );
    }
}
