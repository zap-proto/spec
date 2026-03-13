/**
 * Post-Quantum Cryptography Module for ZAP
 *
 * One library, one implementation: luxcrypto (libluxcrypto FFI).
 * Same PQ crypto from Lux blockchain to AI agents.
 *
 * Backend chain:
 *   1. luxcrypto (libluxcrypto.{dylib,so,dll}) — preferred, FIPS 203/204 via circl
 *   2. Unavailable → throws CryptoError
 *
 * X25519 always uses Web Crypto API (real Curve25519).
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

// ── Backend detection ────────────────────────────────────────────────

let _luxcrypto: typeof import('luxcrypto') | null = null;
let _pqAvailable = false;

try {
  // Dynamic import — only succeeds in Node.js with luxcrypto installed
  _luxcrypto = await import('luxcrypto');
  _pqAvailable = _luxcrypto.LUX_CRYPTO_AVAILABLE;
} catch {
  // luxcrypto not available (browser, missing lib, etc.)
}

// ── Constants ────────────────────────────────────────────────────────

export const MLKEM_PUBLIC_KEY_SIZE = 1184;
export const MLKEM_CIPHERTEXT_SIZE = 1088;
export const MLKEM_SHARED_SECRET_SIZE = 32;
export const MLDSA_PUBLIC_KEY_SIZE = 1952;
export const MLDSA_SIGNATURE_SIZE = 3309;
export const X25519_PUBLIC_KEY_SIZE = 32;
export const HYBRID_SHARED_SECRET_SIZE = 32;

export const PQ_BACKEND: string = _pqAvailable ? 'luxcrypto' : 'unavailable';

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
 * Check if PQ crypto is available (luxcrypto with libluxcrypto).
 */
export function isPQAvailable(): boolean {
  return _pqAvailable;
}

// ── Interfaces ───────────────────────────────────────────────────────

export interface HybridInitiatorData {
  x25519PublicKey: Uint8Array;
  mlkemPublicKey: Uint8Array;
}

export interface HybridResponderData {
  x25519PublicKey: Uint8Array;
  mlkemCiphertext: Uint8Array;
}

// ── ML-KEM-768 (FIPS 203) ───────────────────────────────────────────

/**
 * ML-KEM-768 Key Encapsulation Mechanism.
 *
 * Implements NIST FIPS 203 ML-KEM-768 via libluxcrypto (cloudflare/circl).
 * Security level: NIST Level 3 (~AES-192 equivalent).
 */
export class PQKeyExchange {
  private readonly _publicKey: Uint8Array;
  private readonly _secretKey: Uint8Array | null;

  private constructor(publicKey: Uint8Array, secretKey: Uint8Array | null) {
    this._publicKey = publicKey;
    this._secretKey = secretKey;
  }

  static async generate(): Promise<PQKeyExchange> {
    if (!_pqAvailable || !_luxcrypto) {
      throw new CryptoError(
        'PQ crypto not available — install luxcrypto and build libluxcrypto'
      );
    }
    const [pk, sk] = _luxcrypto.mlkem768.keypair();
    return new PQKeyExchange(pk, sk);
  }

  static fromPublicKey(publicKey: Uint8Array): PQKeyExchange {
    if (publicKey.length !== MLKEM_PUBLIC_KEY_SIZE) {
      throw new CryptoError(
        `Invalid ML-KEM public key size: expected ${MLKEM_PUBLIC_KEY_SIZE}, got ${publicKey.length}`
      );
    }
    return new PQKeyExchange(publicKey, null);
  }

  get publicKey(): Uint8Array {
    return this._publicKey;
  }

  async encapsulate(recipientPk: Uint8Array): Promise<[Uint8Array, Uint8Array]> {
    if (!_pqAvailable || !_luxcrypto) {
      throw new CryptoError('PQ crypto not available');
    }
    if (recipientPk.length !== MLKEM_PUBLIC_KEY_SIZE) {
      throw new CryptoError(
        `Invalid recipient public key size: expected ${MLKEM_PUBLIC_KEY_SIZE}, got ${recipientPk.length}`
      );
    }
    const [ct, ss] = _luxcrypto.mlkem768.encapsulate(recipientPk);
    return [ct, ss];
  }

  async decapsulate(ciphertext: Uint8Array): Promise<Uint8Array> {
    if (!_pqAvailable || !_luxcrypto) {
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
    return _luxcrypto.mlkem768.decapsulate(this._secretKey, ciphertext);
  }
}

// ── ML-DSA-65 (FIPS 204) ────────────────────────────────────────────

/**
 * ML-DSA-65 Digital Signature Algorithm.
 *
 * Implements NIST FIPS 204 ML-DSA-65 via libluxcrypto (cloudflare/circl).
 * Security level: NIST Level 3 (~AES-192 equivalent).
 */
export class PQSignature {
  private readonly _publicKey: Uint8Array;
  private readonly _secretKey: Uint8Array | null;

  private constructor(publicKey: Uint8Array, secretKey: Uint8Array | null) {
    this._publicKey = publicKey;
    this._secretKey = secretKey;
  }

  static async generate(): Promise<PQSignature> {
    if (!_pqAvailable || !_luxcrypto) {
      throw new CryptoError(
        'PQ crypto not available — install luxcrypto and build libluxcrypto'
      );
    }
    const [pk, sk] = _luxcrypto.mldsa65.keypair();
    return new PQSignature(pk, sk);
  }

  static fromPublicKey(publicKey: Uint8Array): PQSignature {
    if (publicKey.length !== MLDSA_PUBLIC_KEY_SIZE) {
      throw new CryptoError(
        `Invalid ML-DSA public key size: expected ${MLDSA_PUBLIC_KEY_SIZE}, got ${publicKey.length}`
      );
    }
    return new PQSignature(publicKey, null);
  }

  get publicKey(): Uint8Array {
    return this._publicKey;
  }

  async sign(message: Uint8Array): Promise<Uint8Array> {
    if (!_pqAvailable || !_luxcrypto) {
      throw new CryptoError('PQ crypto not available');
    }
    if (this._secretKey === null) {
      throw new CryptoError('No secret key available for signing');
    }
    return _luxcrypto.mldsa65.sign(this._secretKey, message);
  }

  async verify(message: Uint8Array, signature: Uint8Array): Promise<boolean> {
    if (!_pqAvailable || !_luxcrypto) {
      throw new CryptoError('PQ crypto not available');
    }
    if (signature.length !== MLDSA_SIGNATURE_SIZE) {
      throw new CryptoError(
        `Invalid ML-DSA signature size: expected ${MLDSA_SIGNATURE_SIZE}, got ${signature.length}`
      );
    }
    return _luxcrypto.mldsa65.verify(this._publicKey, message, signature);
  }
}

// ── Hybrid Handshake ─────────────────────────────────────────────────

export type HandshakeRole = 'initiator' | 'responder';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type WebCryptoKey = any;

/**
 * Hybrid X25519 + ML-KEM-768 Handshake.
 *
 * Combines classical elliptic curve Diffie-Hellman (X25519) with post-quantum
 * ML-KEM-768 for defense-in-depth. X25519 via Web Crypto, ML-KEM via luxcrypto.
 *
 * Final shared secret derived using HKDF-SHA256.
 */
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

  static async initiate(): Promise<HybridHandshake> {
    if (!isWebCryptoAvailable()) {
      throw new CryptoError('Web Crypto API not available');
    }
    if (!isPQAvailable()) {
      throw new CryptoError('PQ crypto not available');
    }

    const x25519KeyPair = (await crypto.subtle.generateKey(
      { name: 'X25519' },
      true,
      ['deriveBits']
    )) as { publicKey: WebCryptoKey; privateKey: WebCryptoKey };

    const x25519PublicRaw = await crypto.subtle.exportKey(
      'raw',
      x25519KeyPair.publicKey
    );

    const mlkem = await PQKeyExchange.generate();

    return new HybridHandshake(
      x25519KeyPair.privateKey,
      new Uint8Array(x25519PublicRaw),
      mlkem,
      'initiator'
    );
  }

  get publicData(): HybridInitiatorData {
    return {
      x25519PublicKey: this._x25519Public,
      mlkemPublicKey: this._mlkem.publicKey,
    };
  }

  static async respond(
    initiatorData: HybridInitiatorData
  ): Promise<[HybridHandshake, HybridResponderData]> {
    if (!isWebCryptoAvailable()) {
      throw new CryptoError('Web Crypto API not available');
    }
    if (!isPQAvailable()) {
      throw new CryptoError('PQ crypto not available');
    }

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

    const x25519KeyPair = (await crypto.subtle.generateKey(
      { name: 'X25519' },
      true,
      ['deriveBits']
    )) as { publicKey: WebCryptoKey; privateKey: WebCryptoKey };

    const x25519PublicRaw = await crypto.subtle.exportKey(
      'raw',
      x25519KeyPair.publicKey
    );

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

  async finalize(responderData: HybridResponderData): Promise<Uint8Array> {
    if (this._role !== 'initiator') {
      throw new CryptoError('finalize() can only be called by initiator');
    }
    if (this._x25519Private === null) {
      throw new CryptoError('X25519 private key not available');
    }

    const peerX25519Public = await crypto.subtle.importKey(
      'raw',
      responderData.x25519PublicKey,
      { name: 'X25519' },
      false,
      []
    );

    const x25519Shared = await crypto.subtle.deriveBits(
      { name: 'X25519', public: peerX25519Public },
      this._x25519Private,
      256
    );

    const mlkemShared = await this._mlkem.decapsulate(responderData.mlkemCiphertext);

    this._x25519Private = null;

    return this.deriveHybridSecret(new Uint8Array(x25519Shared), mlkemShared);
  }

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

    const peerX25519Public = await crypto.subtle.importKey(
      'raw',
      initiatorData.x25519PublicKey,
      { name: 'X25519' },
      false,
      []
    );

    const x25519Shared = await crypto.subtle.deriveBits(
      { name: 'X25519', public: peerX25519Public },
      this._x25519Private,
      256
    );

    let finalMlkemShared = mlkemShared;
    if (!finalMlkemShared) {
      [, finalMlkemShared] = await this._mlkem.encapsulate(initiatorData.mlkemPublicKey);
    }

    this._x25519Private = null;

    return this.deriveHybridSecret(new Uint8Array(x25519Shared), finalMlkemShared);
  }

  private async deriveHybridSecret(
    x25519Shared: Uint8Array,
    mlkemShared: Uint8Array
  ): Promise<Uint8Array> {
    const ikm = new Uint8Array(x25519Shared.length + mlkemShared.length);
    ikm.set(x25519Shared);
    ikm.set(mlkemShared, x25519Shared.length);

    const ikmKey = await crypto.subtle.importKey(
      'raw',
      ikm,
      { name: 'HKDF' },
      false,
      ['deriveBits']
    );

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
 */
export async function hybridHandshake(): Promise<[Uint8Array, Uint8Array]> {
  const initiator = await HybridHandshake.initiate();
  const initData = initiator.publicData;

  const [responder, respData] = await HybridHandshake.respond(initData);

  const mlkem = await PQKeyExchange.generate();
  const [, mlkemShared] = await mlkem.encapsulate(initData.mlkemPublicKey);

  const initiatorSecret = await initiator.finalize(respData);
  const responderSecret = await responder.complete(initData, mlkemShared);

  return [initiatorSecret, responderSecret];
}
