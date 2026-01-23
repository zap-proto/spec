/**
 * Post-Quantum Cryptography Module for ZAP
 *
 * Provides ML-KEM-768 key exchange, ML-DSA-65 signatures, and hybrid X25519+ML-KEM handshake.
 *
 * Security:
 *   This module implements NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) standards
 *   for post-quantum cryptographic protection. The hybrid handshake combines
 *   classical X25519 with ML-KEM-768 for defense-in-depth.
 *
 * Note:
 *   Full PQ crypto requires liboqs-node or similar native bindings.
 *   This module provides the interface and stubs - implement with actual
 *   PQ library when available in production.
 *
 * @example
 * ```typescript
 * import { PQKeyExchange, PQSignature, HybridHandshake } from '@hanzo/zap/crypto';
 *
 * // Key exchange
 * const alice = await PQKeyExchange.generate();
 * const bob = await PQKeyExchange.generate();
 * const [ciphertext, sharedAlice] = await alice.encapsulate(bob.publicKey);
 * const sharedBob = await bob.decapsulate(ciphertext);
 * // sharedAlice === sharedBob
 *
 * // Signatures
 * const signer = await PQSignature.generate();
 * const sig = await signer.sign(new TextEncoder().encode('message'));
 * await signer.verify(new TextEncoder().encode('message'), sig);
 *
 * // Hybrid handshake
 * const initiator = await HybridHandshake.initiate();
 * const [responder, response] = await HybridHandshake.respond(initiator.publicData);
 * const sharedInit = await initiator.finalize(response);
 * ```
 */

// Constants
export const MLKEM_PUBLIC_KEY_SIZE = 1184;
export const MLKEM_CIPHERTEXT_SIZE = 1088;
export const MLKEM_SHARED_SECRET_SIZE = 32;
export const MLDSA_PUBLIC_KEY_SIZE = 1952;
export const MLDSA_SIGNATURE_SIZE = 3293;
export const X25519_PUBLIC_KEY_SIZE = 32;
export const HYBRID_SHARED_SECRET_SIZE = 32;

/**
 * Cryptographic operation error.
 */
export class CryptoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CryptoError';
  }
}

/**
 * Check if Web Crypto API is available.
 */
export function isWebCryptoAvailable(): boolean {
  return typeof globalThis.crypto !== 'undefined' &&
         typeof globalThis.crypto.subtle !== 'undefined';
}

/**
 * Check if PQ crypto is available.
 * Note: Full implementation requires liboqs-node or similar.
 */
export function isPQAvailable(): boolean {
  // TODO: Check for actual PQ library availability
  return false;
}

/**
 * Public data from the initiator for the responder.
 */
export interface HybridInitiatorData {
  x25519PublicKey: Uint8Array;
  mlkemPublicKey: Uint8Array;
}

/**
 * Response data from the responder for the initiator.
 */
export interface HybridResponderData {
  x25519PublicKey: Uint8Array;
  mlkemCiphertext: Uint8Array;
}

/**
 * ML-KEM-768 Key Encapsulation Mechanism.
 *
 * Implements NIST FIPS 203 ML-KEM-768 for post-quantum key exchange.
 * Security level: NIST Level 3 (~AES-192 equivalent).
 *
 * Note: This is a stub implementation. For production use, integrate with
 * liboqs-node or another PQ crypto library.
 */
export class PQKeyExchange {
  private readonly _publicKey: Uint8Array;
  private readonly _secretKey: Uint8Array | null;

  private constructor(publicKey: Uint8Array, secretKey: Uint8Array | null) {
    this._publicKey = publicKey;
    this._secretKey = secretKey;
  }

  /**
   * Generate a new ML-KEM-768 keypair.
   *
   * @throws {CryptoError} If PQ crypto is not available.
   */
  static async generate(): Promise<PQKeyExchange> {
    if (!isPQAvailable()) {
      throw new CryptoError(
        'PQ crypto not available - requires liboqs-node or similar library'
      );
    }
    // TODO: Implement with actual PQ library
    // const { publicKey, secretKey } = await mlkem768.keypair();
    throw new CryptoError('PQ crypto not implemented');
  }

  /**
   * Create instance from public key (for encapsulation only).
   */
  static fromPublicKey(publicKey: Uint8Array): PQKeyExchange {
    if (publicKey.length !== MLKEM_PUBLIC_KEY_SIZE) {
      throw new CryptoError(
        `Invalid ML-KEM public key size: expected ${MLKEM_PUBLIC_KEY_SIZE}, got ${publicKey.length}`
      );
    }
    return new PQKeyExchange(publicKey, null);
  }

  /**
   * Get the public key bytes.
   */
  get publicKey(): Uint8Array {
    return this._publicKey;
  }

  /**
   * Encapsulate: generate ciphertext and shared secret for a recipient's public key.
   *
   * @param recipientPk - The recipient's ML-KEM public key.
   * @returns Tuple of [ciphertext, sharedSecret].
   */
  async encapsulate(recipientPk: Uint8Array): Promise<[Uint8Array, Uint8Array]> {
    if (!isPQAvailable()) {
      throw new CryptoError('PQ crypto not available');
    }
    if (recipientPk.length !== MLKEM_PUBLIC_KEY_SIZE) {
      throw new CryptoError(
        `Invalid recipient public key size: expected ${MLKEM_PUBLIC_KEY_SIZE}, got ${recipientPk.length}`
      );
    }
    // TODO: Implement with actual PQ library
    // const { ciphertext, sharedSecret } = await mlkem768.encapsulate(recipientPk);
    throw new CryptoError('PQ crypto not implemented');
  }

  /**
   * Decapsulate: recover shared secret from ciphertext.
   *
   * @param ciphertext - The ML-KEM ciphertext.
   * @returns The shared secret bytes.
   */
  async decapsulate(ciphertext: Uint8Array): Promise<Uint8Array> {
    if (!isPQAvailable()) {
      throw new CryptoError('PQ crypto not available');
    }
    if (this._secretKey === null) {
      throw new CryptoError('No secret key available for decapsulation');
    }
    if (ciphertext.length !== MLKEM_CIPHERTEXT_SIZE) {
      throw new CryptoError(
        `Invalid ML-KEM ciphertext size: expected ${MLKEM_CIPHERTEXT_SIZE}, got ${ciphertext.length}`
      );
    }
    // TODO: Implement with actual PQ library
    // const sharedSecret = await mlkem768.decapsulate(ciphertext, this._secretKey);
    throw new CryptoError('PQ crypto not implemented');
  }
}

/**
 * ML-DSA-65 Digital Signature Algorithm.
 *
 * Implements NIST FIPS 204 ML-DSA-65 (Dilithium3) for post-quantum signatures.
 * Security level: NIST Level 3 (~AES-192 equivalent).
 *
 * Note: This is a stub implementation. For production use, integrate with
 * liboqs-node or another PQ crypto library.
 */
export class PQSignature {
  private readonly _publicKey: Uint8Array;
  private readonly _secretKey: Uint8Array | null;

  private constructor(publicKey: Uint8Array, secretKey: Uint8Array | null) {
    this._publicKey = publicKey;
    this._secretKey = secretKey;
  }

  /**
   * Generate a new ML-DSA-65 keypair.
   *
   * @throws {CryptoError} If PQ crypto is not available.
   */
  static async generate(): Promise<PQSignature> {
    if (!isPQAvailable()) {
      throw new CryptoError(
        'PQ crypto not available - requires liboqs-node or similar library'
      );
    }
    // TODO: Implement with actual PQ library
    // const { publicKey, secretKey } = await dilithium3.keypair();
    throw new CryptoError('PQ crypto not implemented');
  }

  /**
   * Create instance from public key (for verification only).
   */
  static fromPublicKey(publicKey: Uint8Array): PQSignature {
    if (publicKey.length !== MLDSA_PUBLIC_KEY_SIZE) {
      throw new CryptoError(
        `Invalid ML-DSA public key size: expected ${MLDSA_PUBLIC_KEY_SIZE}, got ${publicKey.length}`
      );
    }
    return new PQSignature(publicKey, null);
  }

  /**
   * Get the public key bytes.
   */
  get publicKey(): Uint8Array {
    return this._publicKey;
  }

  /**
   * Sign a message.
   *
   * @param _message - The message bytes to sign.
   * @returns The signature bytes.
   */
  async sign(_message: Uint8Array): Promise<Uint8Array> {
    if (!isPQAvailable()) {
      throw new CryptoError('PQ crypto not available');
    }
    if (this._secretKey === null) {
      throw new CryptoError('No secret key available for signing');
    }
    // TODO: Implement with actual PQ library
    // const signature = await dilithium3.sign(_message, this._secretKey);
    throw new CryptoError('PQ crypto not implemented');
  }

  /**
   * Verify a signature.
   *
   * @param _message - The original message bytes.
   * @param signature - The signature bytes.
   * @returns True if valid.
   * @throws {CryptoError} If verification fails.
   */
  async verify(_message: Uint8Array, signature: Uint8Array): Promise<boolean> {
    if (!isPQAvailable()) {
      throw new CryptoError('PQ crypto not available');
    }
    if (signature.length !== MLDSA_SIGNATURE_SIZE) {
      throw new CryptoError(
        `Invalid ML-DSA signature size: expected ${MLDSA_SIGNATURE_SIZE}, got ${signature.length}`
      );
    }
    // TODO: Implement with actual PQ library
    // const valid = await dilithium3.verify(_message, signature, this._publicKey);
    throw new CryptoError('PQ crypto not implemented');
  }
}

/**
 * Handshake role.
 */
export type HandshakeRole = 'initiator' | 'responder';

/**
 * Hybrid X25519 + ML-KEM-768 Handshake.
 *
 * Combines classical elliptic curve Diffie-Hellman (X25519) with post-quantum
 * ML-KEM-768 for defense-in-depth. Even if one algorithm is broken, the other
 * provides protection.
 *
 * The final shared secret is derived using HKDF-SHA256 over both shared secrets.
 *
 * Note: X25519 is available via Web Crypto API, but ML-KEM requires liboqs-node.
 */
// Web Crypto types for Node.js (available in Node 18+)
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type WebCryptoKey = any;

export class HybridHandshake {
  private _x25519Private: WebCryptoKey | null;
  private readonly _x25519Public: Uint8Array;
  private readonly _mlkem: PQKeyExchange;
  private readonly _role: HandshakeRole;

  private constructor(
    x25519Private: WebCryptoKey | null,
    x25519Public: Uint8Array,
    mlkem: PQKeyExchange,
    role: HandshakeRole
  ) {
    this._x25519Private = x25519Private;
    this._x25519Public = x25519Public;
    this._mlkem = mlkem;
    this._role = role;
  }

  /**
   * Initiate a hybrid handshake (client side).
   *
   * @throws {CryptoError} If crypto is not available.
   */
  static async initiate(): Promise<HybridHandshake> {
    if (!isWebCryptoAvailable()) {
      throw new CryptoError('Web Crypto API not available');
    }
    if (!isPQAvailable()) {
      throw new CryptoError('PQ crypto not available');
    }

    // Generate X25519 keypair using Web Crypto
    const x25519KeyPair = (await crypto.subtle.generateKey(
      { name: 'X25519' },
      true,
      ['deriveBits']
    )) as { publicKey: WebCryptoKey; privateKey: WebCryptoKey };

    const x25519PublicRaw = await crypto.subtle.exportKey(
      'raw',
      x25519KeyPair.publicKey
    );

    // Generate ML-KEM keypair
    const mlkem = await PQKeyExchange.generate();

    return new HybridHandshake(
      x25519KeyPair.privateKey,
      new Uint8Array(x25519PublicRaw),
      mlkem,
      'initiator'
    );
  }

  /**
   * Get the public data to send to the responder.
   */
  get publicData(): HybridInitiatorData {
    return {
      x25519PublicKey: this._x25519Public,
      mlkemPublicKey: this._mlkem.publicKey,
    };
  }

  /**
   * Respond to a hybrid handshake (server side).
   *
   * @param initiatorData - Public data from the initiator.
   * @returns Tuple of [HybridHandshake, HybridResponderData].
   */
  static async respond(
    initiatorData: HybridInitiatorData
  ): Promise<[HybridHandshake, HybridResponderData]> {
    if (!isWebCryptoAvailable()) {
      throw new CryptoError('Web Crypto API not available');
    }
    if (!isPQAvailable()) {
      throw new CryptoError('PQ crypto not available');
    }

    // Validate input
    if (initiatorData.x25519PublicKey.length !== X25519_PUBLIC_KEY_SIZE) {
      throw new CryptoError(
        `Invalid X25519 public key size: expected ${X25519_PUBLIC_KEY_SIZE}, got ${initiatorData.x25519PublicKey.length}`
      );
    }
    if (initiatorData.mlkemPublicKey.length !== MLKEM_PUBLIC_KEY_SIZE) {
      throw new CryptoError(
        `Invalid ML-KEM public key size: expected ${MLKEM_PUBLIC_KEY_SIZE}, got ${initiatorData.mlkemPublicKey.length}`
      );
    }

    // Generate responder's X25519 keypair
    const x25519KeyPair = (await crypto.subtle.generateKey(
      { name: 'X25519' },
      true,
      ['deriveBits']
    )) as { publicKey: WebCryptoKey; privateKey: WebCryptoKey };

    const x25519PublicRaw = await crypto.subtle.exportKey(
      'raw',
      x25519KeyPair.publicKey
    );

    // Generate ML-KEM keypair and encapsulate to initiator
    const mlkem = await PQKeyExchange.generate();
    const [mlkemCiphertext] = await mlkem.encapsulate(initiatorData.mlkemPublicKey);

    const response: HybridResponderData = {
      x25519PublicKey: new Uint8Array(x25519PublicRaw),
      mlkemCiphertext,
    };

    const handshake = new HybridHandshake(
      x25519KeyPair.privateKey,
      new Uint8Array(x25519PublicRaw),
      mlkem,
      'responder'
    );

    return [handshake, response];
  }

  /**
   * Finalize the handshake and derive the shared secret (initiator side).
   *
   * @param responderData - Response data from the responder.
   * @returns The derived shared secret (32 bytes).
   */
  async finalize(responderData: HybridResponderData): Promise<Uint8Array> {
    if (this._role !== 'initiator') {
      throw new CryptoError('finalize() can only be called by initiator');
    }
    if (this._x25519Private === null) {
      throw new CryptoError('X25519 private key not available');
    }

    // Import peer's X25519 public key
    const peerX25519Public = await crypto.subtle.importKey(
      'raw',
      responderData.x25519PublicKey,
      { name: 'X25519' },
      false,
      []
    );

    // X25519 key exchange
    const x25519Shared = await crypto.subtle.deriveBits(
      { name: 'X25519', public: peerX25519Public },
      this._x25519Private,
      256
    );

    // ML-KEM decapsulation
    const mlkemShared = await this._mlkem.decapsulate(responderData.mlkemCiphertext);

    // Clear private key reference
    this._x25519Private = null;

    // Combine shared secrets with HKDF
    return this.deriveHybridSecret(new Uint8Array(x25519Shared), mlkemShared);
  }

  /**
   * Complete the handshake and derive the shared secret (responder side).
   *
   * @param initiatorData - Public data from the initiator.
   * @param mlkemShared - Optional pre-computed ML-KEM shared secret.
   * @returns The derived shared secret (32 bytes).
   */
  async complete(
    initiatorData: HybridInitiatorData,
    mlkemShared?: Uint8Array
  ): Promise<Uint8Array> {
    if (this._role !== 'responder') {
      throw new CryptoError('complete() can only be called by responder');
    }
    if (this._x25519Private === null) {
      throw new CryptoError('X25519 private key not available');
    }

    // Import peer's X25519 public key
    const peerX25519Public = await crypto.subtle.importKey(
      'raw',
      initiatorData.x25519PublicKey,
      { name: 'X25519' },
      false,
      []
    );

    // X25519 key exchange
    const x25519Shared = await crypto.subtle.deriveBits(
      { name: 'X25519', public: peerX25519Public },
      this._x25519Private,
      256
    );

    // Use provided ML-KEM shared secret or compute it
    let finalMlkemShared = mlkemShared;
    if (!finalMlkemShared) {
      [, finalMlkemShared] = await this._mlkem.encapsulate(initiatorData.mlkemPublicKey);
    }

    // Clear private key reference
    this._x25519Private = null;

    // Combine shared secrets with HKDF
    return this.deriveHybridSecret(new Uint8Array(x25519Shared), finalMlkemShared);
  }

  /**
   * Derive hybrid shared secret using HKDF-SHA256.
   */
  private async deriveHybridSecret(
    x25519Shared: Uint8Array,
    mlkemShared: Uint8Array
  ): Promise<Uint8Array> {
    // Concatenate both shared secrets
    const ikm = new Uint8Array(x25519Shared.length + mlkemShared.length);
    ikm.set(x25519Shared);
    ikm.set(mlkemShared, x25519Shared.length);

    // Import IKM as raw key material
    const ikmKey = await crypto.subtle.importKey(
      'raw',
      ikm,
      { name: 'HKDF' },
      false,
      ['deriveBits']
    );

    // HKDF extract and expand
    const salt = new TextEncoder().encode('ZAP-HYBRID-HANDSHAKE-v1');
    const info = new TextEncoder().encode('shared-secret');

    const derived = await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt,
        info,
      },
      ikmKey,
      HYBRID_SHARED_SECRET_SIZE * 8
    );

    return new Uint8Array(derived);
  }
}

/**
 * Perform a complete hybrid handshake between two parties.
 *
 * This is a convenience function for testing and simple use cases.
 *
 * @returns Tuple of [initiatorSecret, responderSecret] - both should be equal.
 */
export async function hybridHandshake(): Promise<[Uint8Array, Uint8Array]> {
  // Initiator starts
  const initiator = await HybridHandshake.initiate();
  const initData = initiator.publicData;

  // Responder receives and responds
  const [responder, respData] = await HybridHandshake.respond(initData);

  // Responder also encapsulates to get shared secret
  const mlkem = await PQKeyExchange.generate();
  const [, mlkemShared] = await mlkem.encapsulate(initData.mlkemPublicKey);

  // Initiator finalizes
  const initiatorSecret = await initiator.finalize(respData);

  // Responder completes
  const responderSecret = await responder.complete(initData, mlkemShared);

  return [initiatorSecret, responderSecret];
}
