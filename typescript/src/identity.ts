/**
 * W3C Decentralized Identifier (DID) Implementation
 *
 * Implements W3C DID Core 1.0 specification with support for:
 * - did:lux - Lux blockchain-anchored DIDs
 * - did:key - Self-certifying DIDs from cryptographic keys
 * - did:web - DNS-based DIDs
 *
 * @example
 * ```typescript
 * import { Did, DidMethod, NodeIdentity, parseDid, createDidFromKey } from './identity';
 *
 * // Parse existing DID
 * const did = parseDid("did:lux:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
 *
 * // Create from ML-DSA public key
 * const did = createDidFromKey(publicKeyBytes);
 *
 * // Generate DID Document
 * const doc = did.document();
 *
 * // Generate node identity
 * const identity = await generateIdentity();
 * ```
 */

// Base58 alphabet (Bitcoin style)
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

// Multibase prefix for base58btc
const MULTIBASE_BASE58BTC = 'z';

// Multicodec prefix for ML-DSA-65 public key (provisional)
const MULTICODEC_MLDSA65 = new Uint8Array([0x13, 0x09]);

// Expected ML-DSA-65 public key size
export const MLDSA_PUBLIC_KEY_SIZE = 1952;

/**
 * Identity-related error
 */
export class IdentityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'IdentityError';
  }
}

/**
 * Encode bytes to base58 (Bitcoin alphabet)
 */
function base58Encode(data: Uint8Array): string {
  let num = BigInt(0);
  for (let i = 0; i < data.length; i++) {
    num = num * BigInt(256) + BigInt(data[i]!);
  }

  const result: string[] = [];
  while (num > BigInt(0)) {
    const remainder = Number(num % BigInt(58));
    num = num / BigInt(58);
    result.push(BASE58_ALPHABET[remainder]!);
  }

  // Handle leading zeros
  for (let i = 0; i < data.length; i++) {
    if (data[i] === 0) {
      result.push(BASE58_ALPHABET[0]!);
    } else {
      break;
    }
  }

  return result.reverse().join('');
}

/**
 * Decode base58 string to bytes
 */
function base58Decode(s: string): Uint8Array {
  let num = BigInt(0);
  for (const char of s) {
    const index = BASE58_ALPHABET.indexOf(char);
    if (index === -1) {
      throw new IdentityError(`invalid base58 character: ${char}`);
    }
    num = num * BigInt(58) + BigInt(index);
  }

  // Convert to bytes
  const bytes: number[] = [];
  while (num > BigInt(0)) {
    bytes.push(Number(num % BigInt(256)));
    num = num / BigInt(256);
  }

  // Handle leading ones (zeros in decoded)
  for (const char of s) {
    if (char === BASE58_ALPHABET[0]) {
      bytes.push(0);
    } else {
      break;
    }
  }

  return new Uint8Array(bytes.reverse());
}

/**
 * DID method identifier
 */
export enum DidMethod {
  Lux = 'lux',
  Key = 'key',
  Web = 'web',
}

/**
 * Verification method type
 */
export enum VerificationMethodType {
  JsonWebKey2020 = 'JsonWebKey2020',
  Multikey = 'Multikey',
  MlDsa65VerificationKey2024 = 'MlDsa65VerificationKey2024',
}

/**
 * Service type
 */
export enum ServiceType {
  ZapAgent = 'ZapAgent',
  DIDCommMessaging = 'DIDCommMessaging',
  LinkedDomains = 'LinkedDomains',
  CredentialRegistry = 'CredentialRegistry',
}

/**
 * Service endpoint configuration
 */
export interface ServiceEndpoint {
  uri: string;
  accept?: string[];
  routingKeys?: string[];
}

/**
 * Verification method (public key) in DID Document
 */
export interface VerificationMethod {
  id: string;
  type: VerificationMethodType;
  controller: string;
  publicKeyMultibase?: string;
  publicKeyJwk?: Record<string, unknown>;
  blockchainAccountId?: string;
}

/**
 * Service endpoint in DID Document
 */
export interface Service {
  id: string;
  type: ServiceType;
  serviceEndpoint: string | ServiceEndpoint;
}

/**
 * W3C DID Document
 */
export interface DidDocument {
  '@context': string[];
  id: string;
  controller?: string;
  verificationMethod?: VerificationMethod[];
  authentication?: string[];
  assertionMethod?: string[];
  keyAgreement?: string[];
  capabilityInvocation?: string[];
  capabilityDelegation?: string[];
  service?: Service[];
}

/**
 * W3C Decentralized Identifier (DID)
 */
export interface Did {
  method: DidMethod;
  id: string;
}

/**
 * Create a DID URI string
 */
export function didUri(did: Did): string {
  return `did:${did.method}:${did.id}`;
}

/**
 * Extract raw key material from did:key or did:lux identifier
 */
export function extractKeyMaterial(did: Did): Uint8Array {
  if (!did.id) {
    throw new IdentityError('empty DID identifier');
  }

  if (!did.id.startsWith(MULTIBASE_BASE58BTC)) {
    throw new IdentityError(
      `unsupported multibase encoding: expected '${MULTIBASE_BASE58BTC}', got '${did.id[0]}'`
    );
  }

  // Decode base58btc (skip multibase prefix)
  const decoded = base58Decode(did.id.slice(1));

  if (decoded.length < 2) {
    throw new IdentityError('DID identifier too short');
  }

  // Skip multicodec prefix if it matches ML-DSA-65
  if (decoded[0] === MULTICODEC_MLDSA65[0] && decoded[1] === MULTICODEC_MLDSA65[1]) {
    return decoded.slice(2);
  }

  return decoded;
}

/**
 * Generate a W3C DID Document for a DID
 */
export function generateDocument(did: Did): DidDocument {
  const uri = didUri(did);

  let verificationMethod: VerificationMethod;
  if (did.method === DidMethod.Key || did.method === DidMethod.Lux) {
    const keyMaterial = extractKeyMaterial(did);

    if (did.method === DidMethod.Lux) {
      // Create blockchain account ID from first 20 bytes
      const accountBytes = keyMaterial.slice(0, 20);
      const blockchainAccountId = `lux:${Array.from(accountBytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')}`;

      verificationMethod = {
        id: `${uri}#keys-1`,
        type: VerificationMethodType.JsonWebKey2020,
        controller: uri,
        publicKeyMultibase: did.id,
        blockchainAccountId,
      };
    } else {
      verificationMethod = {
        id: `${uri}#keys-1`,
        type: VerificationMethodType.JsonWebKey2020,
        controller: uri,
        publicKeyMultibase: did.id,
      };
    }
  } else {
    verificationMethod = {
      id: `${uri}#keys-1`,
      type: VerificationMethodType.JsonWebKey2020,
      controller: uri,
    };
  }

  const service: Service = {
    id: `${uri}#zap-agent`,
    type: ServiceType.ZapAgent,
    serviceEndpoint: `zap://${did.id}`,
  };

  return {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/jws-2020/v1',
    ],
    id: uri,
    verificationMethod: [verificationMethod],
    authentication: [`${uri}#keys-1`],
    assertionMethod: [`${uri}#keys-1`],
    capabilityInvocation: [`${uri}#keys-1`],
    service: [service],
  };
}

/**
 * Parse a DID from a string in the format "did:method:id"
 *
 * @param s - DID string to parse
 * @returns Parsed Did object
 * @throws IdentityError if the DID string is invalid
 *
 * @example
 * ```typescript
 * const did = parseDid("did:lux:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
 * console.log(did.method); // DidMethod.Lux
 * ```
 */
export function parseDid(s: string): Did {
  if (!s.startsWith('did:')) {
    throw new IdentityError(`invalid DID: must start with 'did:', got '${s}'`);
  }

  const rest = s.slice(4); // Skip "did:"
  const colonIndex = rest.indexOf(':');

  if (colonIndex === -1) {
    throw new IdentityError(`invalid DID format: expected 'did:method:id', got '${s}'`);
  }

  const methodStr = rest.slice(0, colonIndex);
  const didId = rest.slice(colonIndex + 1);

  let method: DidMethod;
  switch (methodStr) {
    case 'lux':
      method = DidMethod.Lux;
      break;
    case 'key':
      method = DidMethod.Key;
      break;
    case 'web':
      method = DidMethod.Web;
      break;
    default:
      throw new IdentityError(`unknown DID method: ${methodStr}`);
  }

  if (!didId) {
    throw new IdentityError('DID identifier cannot be empty');
  }

  return { method, id: didId };
}

/**
 * Create a DID from an ML-DSA-65 public key
 *
 * @param publicKey - ML-DSA-65 public key bytes (1952 bytes)
 * @param method - DID method to use (KEY or LUX)
 * @returns New Did object
 * @throws IdentityError if the public key is invalid
 *
 * @example
 * ```typescript
 * const did = createDidFromKey(publicKeyBytes);
 * console.log(didUri(did)); // did:key:z6Mk...
 * ```
 */
export function createDidFromKey(
  publicKey: Uint8Array,
  method: DidMethod = DidMethod.Key
): Did {
  if (publicKey.length !== MLDSA_PUBLIC_KEY_SIZE) {
    throw new IdentityError(
      `invalid ML-DSA public key size: expected ${MLDSA_PUBLIC_KEY_SIZE}, got ${publicKey.length}`
    );
  }

  // Create multicodec-prefixed key
  const prefixed = new Uint8Array(MULTICODEC_MLDSA65.length + publicKey.length);
  prefixed.set(MULTICODEC_MLDSA65, 0);
  prefixed.set(publicKey, MULTICODEC_MLDSA65.length);

  // Encode with multibase (base58btc)
  const encoded = base58Encode(prefixed);
  const id = `${MULTIBASE_BASE58BTC}${encoded}`;

  return { method, id };
}

/**
 * Create a web DID from a domain and optional path
 *
 * @param domain - Domain name (e.g., "example.com")
 * @param path - Optional path (e.g., "users/alice")
 * @returns New Did object with method=WEB
 * @throws IdentityError if the domain is invalid
 *
 * @example
 * ```typescript
 * const did = createDidFromWeb("example.com", "users/alice");
 * console.log(didUri(did)); // did:web:example.com:users:alice
 * ```
 */
export function createDidFromWeb(domain: string, path?: string): Did {
  if (!domain) {
    throw new IdentityError('domain cannot be empty');
  }

  if (domain.includes('/') || domain.includes(':')) {
    throw new IdentityError(`invalid domain for did:web: ${domain}`);
  }

  let id: string;
  if (path) {
    // Replace '/' with ':' per did:web spec
    const pathParts = path.replace(/\//g, ':');
    id = `${domain}:${pathParts}`;
  } else {
    id = domain;
  }

  return { method: DidMethod.Web, id };
}

/**
 * Stake registry interface
 */
export interface StakeRegistry {
  getStake(did: Did): Promise<bigint>;
  setStake(did: Did, amount: bigint): Promise<void>;
  totalStake(): Promise<bigint>;
  hasSufficientStake(did: Did, minimum: bigint): Promise<boolean>;
  stakeWeight(did: Did): Promise<number>;
}

/**
 * In-memory stake registry for testing
 */
export class InMemoryStakeRegistry implements StakeRegistry {
  private stakes: Map<string, bigint> = new Map();

  async getStake(did: Did): Promise<bigint> {
    return this.stakes.get(didUri(did)) ?? BigInt(0);
  }

  async setStake(did: Did, amount: bigint): Promise<void> {
    this.stakes.set(didUri(did), amount);
  }

  async totalStake(): Promise<bigint> {
    let total = BigInt(0);
    this.stakes.forEach((stake) => {
      total += stake;
    });
    return total;
  }

  async hasSufficientStake(did: Did, minimum: bigint): Promise<boolean> {
    const stake = await this.getStake(did);
    return stake >= minimum;
  }

  async stakeWeight(did: Did): Promise<number> {
    const stake = await this.getStake(did);
    const total = await this.totalStake();
    if (total === BigInt(0)) {
      return 0.0;
    }
    return Number(stake) / Number(total);
  }
}

/**
 * Signer interface for cryptographic operations
 */
export interface Signer {
  sign(message: Uint8Array): Promise<Uint8Array>;
  verify(message: Uint8Array, signature: Uint8Array): Promise<boolean>;
  publicKey: Uint8Array;
}

/**
 * Node identity combining DID with cryptographic keypair
 *
 * Used for authenticated node participation in the ZAP network.
 */
export class NodeIdentity {
  public readonly did: Did;
  public readonly publicKey: Uint8Array;
  public stake: bigint | undefined;
  public stakeRegistry: string | undefined;
  private signer: Signer | undefined;

  constructor(did: Did, publicKey: Uint8Array, signer?: Signer) {
    this.did = did;
    this.publicKey = publicKey;
    this.signer = signer;
  }

  /**
   * Check if this node has signing capability
   */
  canSign(): boolean {
    return this.signer !== undefined;
  }

  /**
   * Sign a message with this node's private key
   */
  async sign(message: Uint8Array): Promise<Uint8Array> {
    if (!this.signer) {
      throw new IdentityError('no private key available for signing');
    }
    return this.signer.sign(message);
  }

  /**
   * Verify a signature against this node's public key
   */
  async verify(message: Uint8Array, signature: Uint8Array): Promise<boolean> {
    if (this.signer) {
      return this.signer.verify(message, signature);
    }
    throw new IdentityError('verification requires a signer implementation');
  }

  /**
   * Get the DID document for this node identity
   */
  document(): DidDocument {
    return generateDocument(this.did);
  }

  /**
   * Get the DID URI string
   */
  uri(): string {
    return didUri(this.did);
  }

  /**
   * Set the stake amount for this node
   */
  withStake(amount: bigint): this {
    this.stake = amount;
    return this;
  }

  /**
   * Set the stake registry reference
   */
  withRegistry(registry: string): this {
    this.stakeRegistry = registry;
    return this;
  }
}

/**
 * Generate a new node identity with fresh ML-DSA-65 keypair
 *
 * Note: This requires a Signer implementation to be provided.
 * In production, use a proper cryptographic library.
 *
 * @param signer - Signer implementation with ML-DSA-65 keypair
 * @param method - DID method to use (default: LUX)
 * @returns New NodeIdentity with signing capability
 *
 * @example
 * ```typescript
 * // With a signer implementation
 * const identity = generateIdentity(signer);
 * console.log(identity.uri()); // did:lux:z6Mk...
 * identity.canSign(); // true
 * ```
 */
export function generateIdentity(
  signer: Signer,
  method: DidMethod = DidMethod.Lux
): NodeIdentity {
  const publicKey = signer.publicKey;

  if (publicKey.length !== MLDSA_PUBLIC_KEY_SIZE) {
    throw new IdentityError(
      `invalid ML-DSA public key size: expected ${MLDSA_PUBLIC_KEY_SIZE}, got ${publicKey.length}`
    );
  }

  const did = createDidFromKey(publicKey, method);
  return new NodeIdentity(did, publicKey, signer);
}

/**
 * Create a NodeIdentity from an existing DID and public key (verification only)
 *
 * @param did - Existing DID
 * @param publicKey - Public key bytes
 * @returns NodeIdentity without signing capability
 */
export function createNodeIdentity(did: Did, publicKey: Uint8Array): NodeIdentity {
  return new NodeIdentity(did, publicKey);
}
