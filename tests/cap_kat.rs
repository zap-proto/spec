//! Cross-language Known-Answer Test for the ZAP capability runtime.
//!
//! The fixture `tests/testdata/cap_go_kat.hex` was produced by the canonical
//! Go reference runtime (`github.com/zap-proto/go/cap`) with a FIXED ed25519
//! seed (32 x 0x42) and FIXED cap inputs. This test proves that:
//!
//!   1. The Rust port decodes Go's wire bytes.
//!   2. Rust's `canonical_bytes()` is byte-identical to Go's `CanonicalBytes`.
//!   3. Rust's `cap_id()` (SHA-256(canonical || sig)) matches Go's CapID.
//!   4. The Ed25519 signature Go produced VERIFIES in Rust under the known
//!      public key — i.e. a Go-signed capability is accepted by the Rust
//!      verifier.
//!   5. A single-bit tamper of the signed header makes verification FAIL.
//!
//! This is the interop contract: caps cross the Go<->Rust boundary unchanged.

#![cfg(feature = "zwing")] // cap requires ed25519-dalek + pqcrypto-mldsa (zwing deps)

use std::collections::HashMap;

use zap::cap::{hash32, CapError, Capability, Verifier};

const FIXTURE: &str = include_str!("testdata/cap_go_kat.hex");

/// Parse the `label.field=hexvalue` fixture into a map keyed by `label.field`.
fn parse_fixture() -> HashMap<String, Vec<u8>> {
    let mut map = HashMap::new();
    for line in FIXTURE.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, val) = line
            .split_once('=')
            .expect("fixture line must be key=value");
        let bytes = hex::decode(val.trim()).expect("fixture value must be hex");
        map.insert(key.to_string(), bytes);
    }
    map
}

fn get<'a>(m: &'a HashMap<String, Vec<u8>>, k: &str) -> &'a [u8] {
    m.get(k)
        .unwrap_or_else(|| panic!("missing fixture key {k}"))
}

/// Run the full KAT for one labelled case in the fixture.
fn check_case(m: &HashMap<String, Vec<u8>>, label: &str) {
    let wire = get(m, &format!("{label}.wire"));
    let go_canonical = get(m, &format!("{label}.canonical"));
    let go_cap_id = get(m, &format!("{label}.cap_id"));
    let go_sig = get(m, &format!("{label}.sig"));
    let go_pubkey = get(m, &format!("{label}.ed25519_pubkey")); // raw 32-byte ed25519 pk
    let go_issuer_hash = get(m, &format!("{label}.issuer_hash")); // SHA-256(pubkey)

    // (1) Rust decodes Go's bytes.
    let cap = Capability::parse(wire).expect("rust must parse go-produced wire bytes");

    // (2) Canonical bytes match Go byte-for-byte.
    assert_eq!(
        cap.canonical_bytes(),
        go_canonical,
        "[{label}] canonical_bytes diverged from Go"
    );

    // (3) cap_id matches Go.
    assert_eq!(
        cap.cap_id().as_slice(),
        go_cap_id,
        "[{label}] cap_id diverged from Go"
    );

    // Sanity: the signature footer Rust reads off the wire equals Go's.
    assert_eq!(
        cap.signature().as_slice(),
        go_sig,
        "[{label}] on-wire signature footer mismatch"
    );

    // Sanity: issuer hash in the cap equals SHA-256(go_pubkey) and Go's value.
    let pk_arr: [u8; 32] = go_pubkey.try_into().expect("pubkey is 32 bytes");
    assert_eq!(
        hash32(&pk_arr).as_slice(),
        go_issuer_hash,
        "[{label}] issuer hash != SHA-256(pubkey)"
    );
    assert_eq!(
        cap.issuer().as_slice(),
        go_issuer_hash,
        "[{label}] cap.issuer() != Go issuer hash"
    );

    // (4) The Go-produced Ed25519 signature VERIFIES in Rust.
    let pk_for_verify = go_pubkey.to_vec();
    let verifier = Verifier::new().with_issuer_key(move |_issuer| Ok(pk_for_verify.clone()));
    verifier
        .verify(&cap, 1_700_000_000)
        .unwrap_or_else(|e| panic!("[{label}] Go-signed cap failed Rust verify: {e}"));

    // (5) Tamper one byte of the signed header (Kind, at root+0) -> verify FAILS.
    let mut tampered = wire.to_vec();
    let root = u32::from_le_bytes([tampered[8], tampered[9], tampered[10], tampered[11]]) as usize;
    tampered[root] ^= 0x01; // flip a bit in Kind (inside the signed [0..164) header)
    let tcap = Capability::parse(&tampered).expect("tampered buffer still parses structurally");
    let pk2 = go_pubkey.to_vec();
    let verifier2 = Verifier::new().with_issuer_key(move |_| Ok(pk2.clone()));
    assert_eq!(
        verifier2.verify(&tcap, 1_700_000_000).unwrap_err(),
        CapError::SigMismatch,
        "[{label}] tampered header must fail signature verification"
    );
}

#[test]
fn go_signed_zero_caveat_cap_verifies_in_rust() {
    let m = parse_fixture();
    check_case(&m, "zero_caveat");
}

#[test]
fn go_signed_two_caveat_cap_verifies_in_rust() {
    // Exercises the caveat canonical codec AND the in-header list-pointer bytes
    // (relOffset 3420, length 2) — the subtle part of canonical-bytes parity.
    let m = parse_fixture();
    check_case(&m, "two_caveat");
}

#[test]
fn fixture_seed_is_the_documented_constant() {
    // Guards against the fixture being regenerated with a different seed.
    let m = parse_fixture();
    assert_eq!(get(&m, "zero_caveat.ed25519_seed"), [0x42u8; 32]);
    assert_eq!(get(&m, "two_caveat.ed25519_seed"), [0x42u8; 32]);
}
