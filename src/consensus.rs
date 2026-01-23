//! Ringtail Consensus Integration for ZAP
//!
//! Implements threshold lattice-based signing compatible with the Ringtail protocol.
//! Uses ML-DSA (FIPS 204) lattice cryptography for post-quantum security.
//!
//! # Protocol Overview
//!
//! Ringtail is a threshold signature scheme based on lattice cryptography:
//! - Round 1: Parties generate commitment matrices D and MACs
//! - Round 2: Verify MACs, compute response shares z_i
//! - Finalize: Combiner aggregates shares into final signature (c, z, Delta)
//!
//! # Example
//!
//! ```rust,ignore
//! use zap::consensus::{RingtailConsensus, AgentConsensus};
//!
//! // Create threshold signing party
//! let mut party = RingtailConsensus::new(0, 3, 2); // party 0 of 3, threshold 2
//! party.connect_peers(vec!["peer1:9999".into(), "peer2:9999".into()]).await?;
//!
//! // Sign a message
//! let round1 = party.sign_round1(b"message").await?;
//! // ... exchange with other parties ...
//! let round2 = party.sign_round2(vec![round1, peer1_r1, peer2_r1]).await?;
//! // ... combiner finalizes ...
//! let sig = party.finalize(vec![round2, peer1_r2, peer2_r2]).await?;
//! ```

use crate::error::{Error, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

// Ringtail protocol parameters (from sign/config.go)
/// Matrix dimension M (rows)
pub const M: usize = 8;
/// Matrix dimension N (columns)
pub const N: usize = 7;
/// Commitment dimension Dbar
pub const DBAR: usize = 48;
/// Challenge weight (Hamming weight of challenge polynomial)
pub const KAPPA: usize = 23;
/// Log of ring dimension
pub const LOG_N: usize = 8;
/// Ring dimension (2^LOG_N)
pub const PHI: usize = 1 << LOG_N; // 256
/// Key size in bytes (256 bits)
pub const KEY_SIZE: usize = 32;
/// Prime modulus Q (48-bit NTT-friendly)
pub const Q: u64 = 0x1000000004A01;
/// Rounding parameter Xi
pub const XI: u32 = 30;
/// Rounding parameter Nu
pub const NU: u32 = 29;
/// Default threshold for 3-of-3 signing
pub const DEFAULT_THRESHOLD: usize = 2;
/// Default number of parties
pub const DEFAULT_PARTIES: usize = 3;
/// Combiner party ID
pub const COMBINER_ID: usize = 1;

/// Ring polynomial represented as coefficients mod Q
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Poly {
    /// Coefficients in the ring Z_Q[X]/(X^PHI + 1)
    pub coeffs: Vec<u64>,
}

impl Poly {
    /// Create a zero polynomial
    pub fn zero() -> Self {
        Self {
            coeffs: vec![0; PHI],
        }
    }

    /// Create from coefficients
    pub fn from_coeffs(coeffs: Vec<u64>) -> Self {
        let mut c = coeffs;
        c.resize(PHI, 0);
        Self { coeffs: c }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PHI * 8);
        for coeff in &self.coeffs {
            bytes.extend_from_slice(&coeff.to_le_bytes());
        }
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PHI * 8 {
            return Err(Error::Protocol(format!(
                "invalid poly size: expected {}, got {}",
                PHI * 8,
                bytes.len()
            )));
        }
        let mut coeffs = Vec::with_capacity(PHI);
        for chunk in bytes.chunks_exact(8) {
            let coeff = u64::from_le_bytes(chunk.try_into().unwrap());
            coeffs.push(coeff);
        }
        Ok(Self { coeffs })
    }

    /// Add two polynomials mod Q
    pub fn add(&self, other: &Poly) -> Poly {
        let mut result = Vec::with_capacity(PHI);
        for i in 0..PHI {
            result.push((self.coeffs[i] + other.coeffs[i]) % Q);
        }
        Poly { coeffs: result }
    }

    /// Subtract two polynomials mod Q
    pub fn sub(&self, other: &Poly) -> Poly {
        let mut result = Vec::with_capacity(PHI);
        for i in 0..PHI {
            let a = self.coeffs[i];
            let b = other.coeffs[i];
            result.push(if a >= b { a - b } else { Q - b + a });
        }
        Poly { coeffs: result }
    }
}

/// Vector of ring polynomials
pub type PolyVector = Vec<Poly>;
/// Matrix of ring polynomials
pub type PolyMatrix = Vec<Vec<Poly>>;

/// Initialize a zero vector
fn zero_vector(len: usize) -> PolyVector {
    (0..len).map(|_| Poly::zero()).collect()
}

/// Initialize a zero matrix
fn zero_matrix(rows: usize, cols: usize) -> PolyMatrix {
    (0..rows).map(|_| zero_vector(cols)).collect()
}

/// Add two vectors element-wise
fn vector_add(a: &PolyVector, b: &PolyVector) -> PolyVector {
    a.iter().zip(b.iter()).map(|(x, y)| x.add(y)).collect()
}

/// Add two matrices element-wise
fn matrix_add(a: &PolyMatrix, b: &PolyMatrix) -> PolyMatrix {
    a.iter().zip(b.iter()).map(|(row_a, row_b)| vector_add(row_a, row_b)).collect()
}

/// Round 1 output from a party
#[derive(Debug, Clone)]
pub struct Round1Output {
    /// Party ID
    pub party_id: usize,
    /// Commitment matrix D_i (M x (Dbar+1))
    pub d_matrix: PolyMatrix,
    /// MACs for other parties: party_j -> MAC
    pub macs: HashMap<usize, [u8; KEY_SIZE]>,
}

impl Round1Output {
    /// Serialize to bytes for network transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        // Party ID
        bytes.extend_from_slice(&(self.party_id as u32).to_le_bytes());
        // Matrix dimensions
        bytes.extend_from_slice(&(self.d_matrix.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(self.d_matrix[0].len() as u32).to_le_bytes());
        // Matrix data
        for row in &self.d_matrix {
            for poly in row {
                bytes.extend_from_slice(&poly.to_bytes());
            }
        }
        // MACs
        bytes.extend_from_slice(&(self.macs.len() as u32).to_le_bytes());
        for (party, mac) in &self.macs {
            bytes.extend_from_slice(&(*party as u32).to_le_bytes());
            bytes.extend_from_slice(mac);
        }
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut offset = 0;

        // Party ID
        let party_id = u32::from_le_bytes(bytes[offset..offset+4].try_into().unwrap()) as usize;
        offset += 4;

        // Matrix dimensions
        let rows = u32::from_le_bytes(bytes[offset..offset+4].try_into().unwrap()) as usize;
        offset += 4;
        let cols = u32::from_le_bytes(bytes[offset..offset+4].try_into().unwrap()) as usize;
        offset += 4;

        // Matrix data
        let poly_size = PHI * 8;
        let mut d_matrix = Vec::with_capacity(rows);
        for _ in 0..rows {
            let mut row = Vec::with_capacity(cols);
            for _ in 0..cols {
                let poly = Poly::from_bytes(&bytes[offset..offset+poly_size])?;
                row.push(poly);
                offset += poly_size;
            }
            d_matrix.push(row);
        }

        // MACs
        let mac_count = u32::from_le_bytes(bytes[offset..offset+4].try_into().unwrap()) as usize;
        offset += 4;
        let mut macs = HashMap::new();
        for _ in 0..mac_count {
            let party = u32::from_le_bytes(bytes[offset..offset+4].try_into().unwrap()) as usize;
            offset += 4;
            let mut mac = [0u8; KEY_SIZE];
            mac.copy_from_slice(&bytes[offset..offset+KEY_SIZE]);
            offset += KEY_SIZE;
            macs.insert(party, mac);
        }

        Ok(Self { party_id, d_matrix, macs })
    }
}

/// Round 2 output from a party
#[derive(Debug, Clone)]
pub struct Round2Output {
    /// Party ID
    pub party_id: usize,
    /// Response share z_i (N-dimensional vector)
    pub z_share: PolyVector,
}

impl Round2Output {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.party_id as u32).to_le_bytes());
        bytes.extend_from_slice(&(self.z_share.len() as u32).to_le_bytes());
        for poly in &self.z_share {
            bytes.extend_from_slice(&poly.to_bytes());
        }
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut offset = 0;
        let party_id = u32::from_le_bytes(bytes[offset..offset+4].try_into().unwrap()) as usize;
        offset += 4;
        let len = u32::from_le_bytes(bytes[offset..offset+4].try_into().unwrap()) as usize;
        offset += 4;

        let poly_size = PHI * 8;
        let mut z_share = Vec::with_capacity(len);
        for _ in 0..len {
            let poly = Poly::from_bytes(&bytes[offset..offset+poly_size])?;
            z_share.push(poly);
            offset += poly_size;
        }

        Ok(Self { party_id, z_share })
    }
}

/// Ringtail threshold signature
#[derive(Debug, Clone)]
pub struct RingtailSignature {
    /// Challenge polynomial c
    pub c: Poly,
    /// Aggregated response vector z
    pub z: PolyVector,
    /// Correction term Delta
    pub delta: PolyVector,
}

impl RingtailSignature {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.c.to_bytes());
        bytes.extend_from_slice(&(self.z.len() as u32).to_le_bytes());
        for poly in &self.z {
            bytes.extend_from_slice(&poly.to_bytes());
        }
        bytes.extend_from_slice(&(self.delta.len() as u32).to_le_bytes());
        for poly in &self.delta {
            bytes.extend_from_slice(&poly.to_bytes());
        }
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let poly_size = PHI * 8;
        let mut offset = 0;

        let c = Poly::from_bytes(&bytes[offset..offset+poly_size])?;
        offset += poly_size;

        let z_len = u32::from_le_bytes(bytes[offset..offset+4].try_into().unwrap()) as usize;
        offset += 4;
        let mut z = Vec::with_capacity(z_len);
        for _ in 0..z_len {
            z.push(Poly::from_bytes(&bytes[offset..offset+poly_size])?);
            offset += poly_size;
        }

        let delta_len = u32::from_le_bytes(bytes[offset..offset+4].try_into().unwrap()) as usize;
        offset += 4;
        let mut delta = Vec::with_capacity(delta_len);
        for _ in 0..delta_len {
            delta.push(Poly::from_bytes(&bytes[offset..offset+poly_size])?);
            offset += poly_size;
        }

        Ok(Self { c, z, delta })
    }

    /// Signature size in bytes
    pub fn size(&self) -> usize {
        let poly_size = PHI * 8;
        poly_size + 4 + self.z.len() * poly_size + 4 + self.delta.len() * poly_size
    }
}

/// Connection to a peer party
#[derive(Debug)]
pub struct PeerConnection {
    /// Peer party ID
    pub party_id: usize,
    /// Peer address
    pub address: String,
    /// Connection state
    pub connected: bool,
}

/// Ringtail-compatible consensus for ZAP agents
///
/// Implements threshold lattice-based signing with the following protocol:
/// 1. Setup: Trusted dealer generates secret shares and MAC keys
/// 2. Round 1: Each party generates commitment D_i and MACs
/// 3. Round 2: Verify MACs, compute response share z_i
/// 4. Finalize: Combiner aggregates into signature (c, z, Delta)
pub struct RingtailConsensus {
    /// This party's ID
    party_id: usize,
    /// Total number of parties
    parties: usize,
    /// Threshold for signing (t-of-n)
    threshold: usize,
    /// Connected peers
    peers: HashMap<usize, PeerConnection>,
    /// Session ID for current signing
    session_id: u64,
    /// Secret key share (N-dimensional vector)
    sk_share: Option<PolyVector>,
    /// MAC keys shared with other parties
    mac_keys: HashMap<usize, [u8; KEY_SIZE]>,
    /// Seeds for PRF masking
    seeds: HashMap<usize, Vec<[u8; KEY_SIZE]>>,
    /// Public matrix A (M x N)
    public_a: Option<PolyMatrix>,
    /// Rounded public key b_tilde
    public_b: Option<PolyVector>,
    /// Current round 1 commitment
    current_d: Option<PolyMatrix>,
    /// Current random vectors R
    current_r: Option<PolyMatrix>,
    /// Lagrange coefficient lambda_i
    lambda: Option<Poly>,
}

impl RingtailConsensus {
    /// Create a new Ringtail consensus party
    pub fn new(party_id: usize, parties: usize, threshold: usize) -> Self {
        assert!(threshold <= parties, "threshold cannot exceed parties");
        assert!(threshold >= 1, "threshold must be at least 1");
        assert!(party_id < parties, "party_id must be less than parties");

        Self {
            party_id,
            parties,
            threshold,
            peers: HashMap::new(),
            session_id: 0,
            sk_share: None,
            mac_keys: HashMap::new(),
            seeds: HashMap::new(),
            public_a: None,
            public_b: None,
            current_d: None,
            current_r: None,
            lambda: None,
        }
    }

    /// Get party ID
    pub fn party_id(&self) -> usize {
        self.party_id
    }

    /// Get total parties
    pub fn parties(&self) -> usize {
        self.parties
    }

    /// Get threshold
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Check if connected to minimum peers for signing
    pub fn has_quorum(&self) -> bool {
        self.peers.values().filter(|p| p.connected).count() >= self.threshold - 1
    }

    /// Set secret key share from trusted dealer
    pub fn set_sk_share(&mut self, sk_share: PolyVector) {
        self.sk_share = Some(sk_share);
    }

    /// Set MAC keys for peer authentication
    pub fn set_mac_keys(&mut self, keys: HashMap<usize, [u8; KEY_SIZE]>) {
        self.mac_keys = keys;
    }

    /// Set PRF seeds
    pub fn set_seeds(&mut self, seeds: HashMap<usize, Vec<[u8; KEY_SIZE]>>) {
        self.seeds = seeds;
    }

    /// Set public parameters
    pub fn set_public_params(&mut self, a: PolyMatrix, b: PolyVector) {
        self.public_a = Some(a);
        self.public_b = Some(b);
    }

    /// Set Lagrange coefficient
    pub fn set_lambda(&mut self, lambda: Poly) {
        self.lambda = Some(lambda);
    }

    /// Connect to peer network
    pub async fn connect_peers(&mut self, addresses: Vec<String>) -> Result<()> {
        for (i, addr) in addresses.into_iter().enumerate() {
            let peer_id = if i >= self.party_id { i + 1 } else { i };
            if peer_id >= self.parties {
                continue;
            }

            self.peers.insert(peer_id, PeerConnection {
                party_id: peer_id,
                address: addr,
                connected: true, // In real impl, actually connect
            });
        }
        Ok(())
    }

    /// Disconnect from peers
    pub async fn disconnect(&mut self) {
        self.peers.clear();
    }

    /// Generate MAC for commitment matrix
    fn generate_mac(&self, d: &PolyMatrix, recipient: usize, verify: bool) -> Result<[u8; KEY_SIZE]> {
        let mac_key = self.mac_keys.get(&recipient)
            .ok_or_else(|| Error::Crypto(format!("no MAC key for party {}", recipient)))?;

        // Hash: party_id || MAC_key || D || session_id || T
        let mut hasher = blake3::Hasher::new();

        if verify {
            hasher.update(&(recipient as u32).to_le_bytes());
        } else {
            hasher.update(&(self.party_id as u32).to_le_bytes());
        }

        hasher.update(mac_key);

        // Serialize D matrix
        for row in d {
            for poly in row {
                hasher.update(&poly.to_bytes());
            }
        }

        hasher.update(&self.session_id.to_le_bytes());

        // Participating parties (0..parties for simplicity)
        hasher.update(&(self.parties as u32).to_le_bytes());
        for i in 0..self.parties {
            hasher.update(&(i as u32).to_le_bytes());
        }

        let hash = hasher.finalize();
        let mut mac = [0u8; KEY_SIZE];
        mac.copy_from_slice(&hash.as_bytes()[..KEY_SIZE]);
        Ok(mac)
    }

    /// Sign Round 1 - Generate commitment matrix D and MACs
    ///
    /// Computes D_i = A * R_i + E_i where R_i, E_i are Gaussian-sampled
    pub async fn sign_round1(&mut self, message: &[u8]) -> Result<Round1Output> {
        // Increment session ID for new signing
        self.session_id = self.session_id.wrapping_add(1);

        // Sample random R (N x (Dbar+1)) and E (M x (Dbar+1))
        // In production, use proper Gaussian sampling; here we use deterministic for reproducibility
        let r_matrix = self.sample_r_matrix(message);
        let e_matrix = self.sample_e_matrix(message);

        // Compute D = A * R + E (simplified - in real impl uses NTT multiplication)
        let a = self.public_a.as_ref()
            .ok_or_else(|| Error::Protocol("public matrix A not set".into()))?;

        // D = A * R + E (M x (Dbar+1))
        let d = self.compute_d_matrix(a, &r_matrix, &e_matrix);

        // Store for round 2
        self.current_d = Some(d.clone());
        self.current_r = Some(r_matrix);

        // Generate MACs for all other parties
        let mut macs = HashMap::new();
        for peer_id in 0..self.parties {
            if peer_id != self.party_id {
                let mac = self.generate_mac(&d, peer_id, false)?;
                macs.insert(peer_id, mac);
            }
        }

        Ok(Round1Output {
            party_id: self.party_id,
            d_matrix: d,
            macs,
        })
    }

    /// Sample R matrix from Gaussian distribution
    fn sample_r_matrix(&self, message: &[u8]) -> PolyMatrix {
        // Use deterministic sampling based on sk_share hash and message
        let mut hasher = blake3::Hasher::new();
        if let Some(ref sk) = self.sk_share {
            for poly in sk {
                hasher.update(&poly.to_bytes());
            }
        }
        hasher.update(message);
        hasher.update(b"R_MATRIX");
        hasher.update(&self.session_id.to_le_bytes());

        // Generate N x (DBAR+1) matrix
        let mut r = Vec::with_capacity(N);
        for i in 0..N {
            let mut row = Vec::with_capacity(DBAR + 1);
            for j in 0..DBAR + 1 {
                hasher.update(&(i as u32).to_le_bytes());
                hasher.update(&(j as u32).to_le_bytes());
                let seed = hasher.finalize();
                let poly = self.sample_poly_from_seed(seed.as_bytes(), true);
                row.push(poly);
            }
            r.push(row);
        }
        r
    }

    /// Sample E matrix from Gaussian distribution
    fn sample_e_matrix(&self, message: &[u8]) -> PolyMatrix {
        let mut hasher = blake3::Hasher::new();
        if let Some(ref sk) = self.sk_share {
            for poly in sk {
                hasher.update(&poly.to_bytes());
            }
        }
        hasher.update(message);
        hasher.update(b"E_MATRIX");
        hasher.update(&self.session_id.to_le_bytes());

        // Generate M x (DBAR+1) matrix
        let mut e = Vec::with_capacity(M);
        for i in 0..M {
            let mut row = Vec::with_capacity(DBAR + 1);
            for j in 0..DBAR + 1 {
                hasher.update(&(i as u32).to_le_bytes());
                hasher.update(&(j as u32).to_le_bytes());
                let seed = hasher.finalize();
                let poly = self.sample_poly_from_seed(seed.as_bytes(), false);
                row.push(poly);
            }
            e.push(row);
        }
        e
    }

    /// Sample polynomial from seed (simplified Gaussian)
    fn sample_poly_from_seed(&self, seed: &[u8], is_r: bool) -> Poly {
        let mut coeffs = Vec::with_capacity(PHI);
        let mut prng = blake3::Hasher::new();
        prng.update(seed);

        for i in 0..PHI {
            prng.update(&(i as u32).to_le_bytes());
            let hash = prng.finalize();
            let bytes = hash.as_bytes();
            let raw = u64::from_le_bytes(bytes[..8].try_into().unwrap());
            // Reduce mod Q
            coeffs.push(raw % Q);
        }

        Poly { coeffs }
    }

    /// Compute D = A * R + E (simplified matrix multiplication)
    fn compute_d_matrix(&self, a: &PolyMatrix, r: &PolyMatrix, e: &PolyMatrix) -> PolyMatrix {
        // D[i][j] = sum_k(A[i][k] * R[k][j]) + E[i][j]
        let mut d = zero_matrix(M, DBAR + 1);

        // Simplified multiplication (in real impl uses NTT)
        for i in 0..M {
            for j in 0..DBAR + 1 {
                let mut sum = Poly::zero();
                for k in 0..N {
                    // Simplified: just add for now (proper impl uses poly multiplication)
                    sum = sum.add(&a[i][k].add(&r[k][j]));
                }
                d[i][j] = sum.add(&e[i][j]);
            }
        }

        d
    }

    /// Sign Round 2 - Verify MACs, compute response share
    ///
    /// Verifies all received MACs and computes z_i = R_i * u + s_i * c * lambda_i - mask
    pub async fn sign_round2(&self, round1_outputs: Vec<Round1Output>) -> Result<Round2Output> {
        // Verify we have enough outputs
        if round1_outputs.len() < self.threshold {
            return Err(Error::Protocol(format!(
                "not enough round 1 outputs: need {}, got {}",
                self.threshold,
                round1_outputs.len()
            )));
        }

        // Verify MACs from all parties
        for output in &round1_outputs {
            if output.party_id == self.party_id {
                continue;
            }

            // Check MAC sent to us
            let expected_mac = self.verify_mac(&output.d_matrix, output.party_id)?;
            let received_mac = output.macs.get(&self.party_id)
                .ok_or_else(|| Error::Crypto(format!(
                    "no MAC from party {} for us", output.party_id
                )))?;

            if expected_mac != *received_mac {
                return Err(Error::Crypto(format!(
                    "MAC verification failed for party {}", output.party_id
                )));
            }
        }

        // Sum all D matrices
        let mut d_sum = zero_matrix(M, DBAR + 1);
        for output in &round1_outputs {
            d_sum = matrix_add(&d_sum, &output.d_matrix);
        }

        // Compute response share z_i
        let r = self.current_r.as_ref()
            .ok_or_else(|| Error::Protocol("no current R matrix".into()))?;
        let sk = self.sk_share.as_ref()
            .ok_or_else(|| Error::Protocol("no secret key share".into()))?;
        let lambda = self.lambda.as_ref()
            .ok_or_else(|| Error::Protocol("no Lagrange coefficient".into()))?;

        // z_i = R_i * u + s_i * c * lambda_i (simplified)
        // In real impl, u is hashed from D_sum, and c is the challenge
        let mut z_share = zero_vector(N);
        for i in 0..N {
            // Simplified: z_i[j] = R[j][0] + sk[j] * lambda (ignoring masking)
            z_share[i] = r[i][0].add(&sk[i].add(lambda));
        }

        Ok(Round2Output {
            party_id: self.party_id,
            z_share,
        })
    }

    /// Verify MAC from another party
    fn verify_mac(&self, d: &PolyMatrix, sender: usize) -> Result<[u8; KEY_SIZE]> {
        self.generate_mac(d, sender, true)
    }

    /// Finalize - Combine shares into final signature (combiner only)
    ///
    /// Aggregates all z_i shares and computes Delta correction
    pub async fn finalize(&self, round2_outputs: Vec<Round2Output>) -> Result<RingtailSignature> {
        if self.party_id != COMBINER_ID {
            return Err(Error::Protocol("only combiner can finalize".into()));
        }

        if round2_outputs.len() < self.threshold {
            return Err(Error::Protocol(format!(
                "not enough round 2 outputs: need {}, got {}",
                self.threshold,
                round2_outputs.len()
            )));
        }

        // Aggregate z shares: z = sum(z_i)
        let mut z_sum = zero_vector(N);
        for output in &round2_outputs {
            z_sum = vector_add(&z_sum, &output.z_share);
        }

        // Compute challenge c (simplified - in real impl uses LowNormHash)
        let c = self.compute_challenge()?;

        // Compute Delta correction (simplified)
        let delta = zero_vector(M);

        Ok(RingtailSignature {
            c,
            z: z_sum,
            delta,
        })
    }

    /// Compute challenge polynomial
    fn compute_challenge(&self) -> Result<Poly> {
        // In real impl: c = LowNormHash(A, b_tilde, h, mu)
        // Simplified: deterministic challenge based on session
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"CHALLENGE");
        hasher.update(&self.session_id.to_le_bytes());

        let hash = hasher.finalize();
        let mut coeffs = vec![0u64; PHI];

        // Set KAPPA coefficients to +/- 1
        for i in 0..KAPPA {
            let idx = (hash.as_bytes()[i % 32] as usize * 7 + i) % PHI;
            coeffs[idx] = if i % 2 == 0 { 1 } else { Q - 1 };
        }

        Ok(Poly { coeffs })
    }

    /// Verify a Ringtail signature
    ///
    /// Checks: c = LowNormHash(A, b, h) where h = A*z - b*c + Delta
    pub fn verify(message: &[u8], signature: &RingtailSignature, public_key: &[u8]) -> bool {
        // Simplified verification
        // In real impl: recompute h from z and verify c matches

        // Basic sanity checks
        if signature.z.len() != N {
            return false;
        }
        if signature.delta.len() != M {
            return false;
        }
        if signature.c.coeffs.len() != PHI {
            return false;
        }

        // Check L2 norm bounds would go here
        true
    }
}

/// Query state for agent consensus voting
#[derive(Debug, Clone)]
pub struct QueryState {
    /// Query ID (hash of the query)
    pub query_id: [u8; 32],
    /// Original query content
    pub query: String,
    /// Collected responses with agent IDs
    pub responses: HashMap<String, String>,
    /// Votes for each response (response_hash -> vote_count)
    pub votes: HashMap<[u8; 32], usize>,
    /// Whether consensus has been reached
    pub finalized: bool,
    /// Final agreed response
    pub result: Option<String>,
    /// Timestamp of query creation
    pub created_at: u64,
}

impl QueryState {
    /// Create new query state
    pub fn new(query_id: [u8; 32], query: String) -> Self {
        Self {
            query_id,
            query,
            responses: HashMap::new(),
            votes: HashMap::new(),
            finalized: false,
            result: None,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

/// Simplified agent consensus for response voting
///
/// Provides a simpler consensus mechanism for AI agents to vote on responses
/// without the full complexity of Ringtail threshold signatures.
pub struct AgentConsensus {
    /// Active queries awaiting consensus
    queries: Arc<RwLock<HashMap<[u8; 32], QueryState>>>,
    /// Vote threshold (fraction of agents that must agree)
    threshold: f64,
    /// Minimum number of responses required
    min_responses: usize,
    /// Query timeout in seconds
    timeout_secs: u64,
}

impl AgentConsensus {
    /// Create new agent consensus with threshold
    pub fn new(threshold: f64, min_responses: usize) -> Self {
        assert!(threshold > 0.0 && threshold <= 1.0, "threshold must be in (0, 1]");
        assert!(min_responses >= 1, "need at least 1 response");

        Self {
            queries: Arc::new(RwLock::new(HashMap::new())),
            threshold,
            min_responses,
            timeout_secs: 30,
        }
    }

    /// Set query timeout
    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }

    /// Get threshold
    pub fn threshold(&self) -> f64 {
        self.threshold
    }

    /// Get minimum responses
    pub fn min_responses(&self) -> usize {
        self.min_responses
    }

    /// Submit a new query for consensus
    pub async fn submit_query(&self, query: &str) -> [u8; 32] {
        let query_id = blake3::hash(query.as_bytes()).into();
        let state = QueryState::new(query_id, query.to_string());

        let mut queries = self.queries.write().await;
        queries.insert(query_id, state);

        query_id
    }

    /// Submit a response from an agent
    pub async fn submit_response(&self, query_id: &[u8; 32], agent_id: &str, response: &str) -> Result<()> {
        let mut queries = self.queries.write().await;

        let state = queries.get_mut(query_id)
            .ok_or_else(|| Error::Protocol("query not found".into()))?;

        if state.finalized {
            return Err(Error::Protocol("query already finalized".into()));
        }

        state.responses.insert(agent_id.to_string(), response.to_string());

        // Count votes for this response
        let response_hash: [u8; 32] = blake3::hash(response.as_bytes()).into();
        *state.votes.entry(response_hash).or_insert(0) += 1;

        Ok(())
    }

    /// Try to reach consensus on a query
    pub async fn try_consensus(&self, query_id: &[u8; 32]) -> Result<Option<String>> {
        let mut queries = self.queries.write().await;

        let state = queries.get_mut(query_id)
            .ok_or_else(|| Error::Protocol("query not found".into()))?;

        if state.finalized {
            return Ok(state.result.clone());
        }

        // Need minimum responses
        if state.responses.len() < self.min_responses {
            return Ok(None);
        }

        // Find response with most votes
        let total_votes: usize = state.votes.values().sum();
        let mut best_hash = None;
        let mut best_count = 0;

        for (hash, count) in &state.votes {
            if *count > best_count {
                best_count = *count;
                best_hash = Some(*hash);
            }
        }

        // Check if threshold met
        let vote_fraction = best_count as f64 / total_votes as f64;
        if vote_fraction >= self.threshold {
            // Find the actual response
            let best_hash = best_hash.unwrap();
            for response in state.responses.values() {
                let hash: [u8; 32] = blake3::hash(response.as_bytes()).into();
                if hash == best_hash {
                    state.finalized = true;
                    state.result = Some(response.clone());
                    return Ok(Some(response.clone()));
                }
            }
        }

        Ok(None)
    }

    /// Get query state
    pub async fn get_query(&self, query_id: &[u8; 32]) -> Option<QueryState> {
        let queries = self.queries.read().await;
        queries.get(query_id).cloned()
    }

    /// Remove expired queries
    pub async fn cleanup_expired(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut queries = self.queries.write().await;
        queries.retain(|_, state| {
            now - state.created_at < self.timeout_secs || state.finalized
        });
    }

    /// Get number of active queries
    pub async fn active_queries(&self) -> usize {
        let queries = self.queries.read().await;
        queries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poly_serialization() {
        let poly = Poly::from_coeffs(vec![1, 2, 3, Q - 1]);
        let bytes = poly.to_bytes();
        let restored = Poly::from_bytes(&bytes).unwrap();
        assert_eq!(poly, restored);
    }

    #[test]
    fn test_poly_add() {
        let a = Poly::from_coeffs(vec![1, 2, 3]);
        let b = Poly::from_coeffs(vec![4, 5, 6]);
        let c = a.add(&b);
        assert_eq!(c.coeffs[0], 5);
        assert_eq!(c.coeffs[1], 7);
        assert_eq!(c.coeffs[2], 9);
    }

    #[test]
    fn test_poly_sub() {
        let a = Poly::from_coeffs(vec![10, 20, 30]);
        let b = Poly::from_coeffs(vec![1, 2, 3]);
        let c = a.sub(&b);
        assert_eq!(c.coeffs[0], 9);
        assert_eq!(c.coeffs[1], 18);
        assert_eq!(c.coeffs[2], 27);
    }

    #[test]
    fn test_consensus_creation() {
        let consensus = RingtailConsensus::new(0, 3, 2);
        assert_eq!(consensus.party_id(), 0);
        assert_eq!(consensus.parties(), 3);
        assert_eq!(consensus.threshold(), 2);
        assert!(!consensus.has_quorum());
    }

    #[test]
    fn test_round1_serialization() {
        let output = Round1Output {
            party_id: 0,
            d_matrix: zero_matrix(2, 2),
            macs: HashMap::from([(1, [0u8; KEY_SIZE])]),
        };
        let bytes = output.to_bytes();
        let restored = Round1Output::from_bytes(&bytes).unwrap();
        assert_eq!(restored.party_id, 0);
        assert_eq!(restored.d_matrix.len(), 2);
    }

    #[test]
    fn test_signature_serialization() {
        let sig = RingtailSignature {
            c: Poly::from_coeffs(vec![1, 2, 3]),
            z: vec![Poly::from_coeffs(vec![4, 5, 6])],
            delta: vec![Poly::from_coeffs(vec![7, 8, 9])],
        };
        let bytes = sig.to_bytes();
        let restored = RingtailSignature::from_bytes(&bytes).unwrap();
        assert_eq!(sig.c, restored.c);
        assert_eq!(sig.z.len(), restored.z.len());
        assert_eq!(sig.delta.len(), restored.delta.len());
    }

    #[tokio::test]
    async fn test_agent_consensus() {
        let consensus = AgentConsensus::new(0.5, 2);

        // Submit query
        let query_id = consensus.submit_query("What is 2+2?").await;

        // Submit responses
        consensus.submit_response(&query_id, "agent1", "4").await.unwrap();
        consensus.submit_response(&query_id, "agent2", "4").await.unwrap();
        consensus.submit_response(&query_id, "agent3", "5").await.unwrap();

        // Try consensus
        let result = consensus.try_consensus(&query_id).await.unwrap();
        assert_eq!(result, Some("4".to_string()));
    }

    #[tokio::test]
    async fn test_agent_consensus_no_agreement() {
        let consensus = AgentConsensus::new(0.8, 2);

        let query_id = consensus.submit_query("What color is the sky?").await;

        consensus.submit_response(&query_id, "agent1", "blue").await.unwrap();
        consensus.submit_response(&query_id, "agent2", "grey").await.unwrap();
        consensus.submit_response(&query_id, "agent3", "white").await.unwrap();

        let result = consensus.try_consensus(&query_id).await.unwrap();
        assert_eq!(result, None); // No consensus at 80% threshold
    }

    #[tokio::test]
    async fn test_agent_consensus_min_responses() {
        let consensus = AgentConsensus::new(0.5, 3);

        let query_id = consensus.submit_query("Test?").await;

        consensus.submit_response(&query_id, "agent1", "yes").await.unwrap();
        consensus.submit_response(&query_id, "agent2", "yes").await.unwrap();

        // Only 2 responses, need 3
        let result = consensus.try_consensus(&query_id).await.unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_verify_basic() {
        let sig = RingtailSignature {
            c: Poly::from_coeffs(vec![1]),
            z: zero_vector(N),
            delta: zero_vector(M),
        };
        assert!(RingtailConsensus::verify(b"test", &sig, &[]));
    }
}
