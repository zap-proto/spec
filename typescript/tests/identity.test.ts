import { describe, it, expect } from 'vitest';
import {
  Did,
  DidDocument,
  DidMethod,
  VerificationMethod,
  VerificationMethodType,
  didUri,
  parseDid,
  createDidFromKey,
  createDidFromWeb,
  generateDocument,
  MLDSA_PUBLIC_KEY_SIZE,
} from '../src/identity.js';

describe('Did', () => {
  it('should create a did:lux DID', () => {
    const did: Did = { method: DidMethod.Lux, id: 'z6MkTest123' };
    expect(did.method).toBe(DidMethod.Lux);
    expect(did.id).toBe('z6MkTest123');
  });

  it('should create a did:key DID', () => {
    const did: Did = { method: DidMethod.Key, id: 'z6MkTestKey456' };
    expect(did.method).toBe(DidMethod.Key);
    expect(did.id).toBe('z6MkTestKey456');
  });

  it('should create a did:web DID', () => {
    const did: Did = { method: DidMethod.Web, id: 'example.com:user:alice' };
    expect(did.method).toBe(DidMethod.Web);
    expect(did.id).toBe('example.com:user:alice');
  });
});

describe('didUri', () => {
  it('should format DID URI', () => {
    const did: Did = { method: DidMethod.Lux, id: 'z6MkTest123' };
    expect(didUri(did)).toBe('did:lux:z6MkTest123');
  });
});

describe('parseDid', () => {
  it('should parse did:lux DID', () => {
    const did = parseDid('did:lux:z6MkTest123');
    expect(did.method).toBe(DidMethod.Lux);
    expect(did.id).toBe('z6MkTest123');
  });

  it('should parse did:key DID', () => {
    const did = parseDid('did:key:z6MkTestKey456');
    expect(did.method).toBe(DidMethod.Key);
    expect(did.id).toBe('z6MkTestKey456');
  });

  it('should parse did:web DID', () => {
    const did = parseDid('did:web:example.com:user:alice');
    expect(did.method).toBe(DidMethod.Web);
    expect(did.id).toBe('example.com:user:alice');
  });

  it('should throw on invalid DID', () => {
    expect(() => parseDid('invalid')).toThrow();
  });
});

describe('generateDocument', () => {
  it('should create a DID document', () => {
    const did: Did = { method: DidMethod.Lux, id: 'z6MkTest123' };
    const doc = generateDocument(did);
    expect(doc.id).toBe('did:lux:z6MkTest123');
  });

  it('should include context', () => {
    const did: Did = { method: DidMethod.Lux, id: 'z6MkTest123' };
    const doc = generateDocument(did);
    // Context can be string or array
    const context = doc['@context'];
    if (Array.isArray(context)) {
      expect(context).toContain('https://www.w3.org/ns/did/v1');
    } else {
      expect(context).toBe('https://www.w3.org/ns/did/v1');
    }
  });
});

describe('createDidFromKey', () => {
  it('should create did:key from ML-DSA public key', () => {
    // 1952-byte fake public key
    const publicKey = new Uint8Array(MLDSA_PUBLIC_KEY_SIZE);
    for (let i = 0; i < publicKey.length; i++) {
      publicKey[i] = i % 256;
    }
    const did = createDidFromKey(publicKey);

    expect(did.method).toBe(DidMethod.Key);
    expect(did.id.startsWith('z')).toBe(true);
  });

  it('should throw on invalid key length', () => {
    const shortKey = new Uint8Array(16);
    expect(() => createDidFromKey(shortKey)).toThrow();
  });
});

describe('createDidFromWeb', () => {
  it('should create did:web from domain', () => {
    const did = createDidFromWeb('example.com');
    expect(did.method).toBe(DidMethod.Web);
    expect(did.id).toBe('example.com');
  });

  it('should create did:web with path', () => {
    const did = createDidFromWeb('example.com', 'users:alice');
    expect(did.method).toBe(DidMethod.Web);
    expect(did.id).toContain('example.com');
  });
});
