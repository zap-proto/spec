import { describe, it, expect } from 'vitest';
import {
  encode,
  decode,
  extractFrames,
  ZAP_MAGIC,
  HEADER_SIZE,
  MAX_PAYLOAD_SIZE,
  PROTOCOL_VERSION,
  MessageType,
  isCapabilityRef,
} from '../src/protocol.js';

// ── Constants ─────────────────────────────────────────────────────────

describe('Protocol constants', () => {
  it('ZAP_MAGIC is [0x5A, 0x41, 0x50, 0x01]', () => {
    expect(ZAP_MAGIC).toEqual(new Uint8Array([0x5a, 0x41, 0x50, 0x01]));
  });

  it('HEADER_SIZE is 9', () => {
    expect(HEADER_SIZE).toBe(9);
  });

  it('MAX_PAYLOAD_SIZE is 16MB', () => {
    expect(MAX_PAYLOAD_SIZE).toBe(16 * 1024 * 1024);
  });

  it('PROTOCOL_VERSION is 1', () => {
    expect(PROTOCOL_VERSION).toBe(1);
  });
});

describe('MessageType', () => {
  it('has connection lifecycle types', () => {
    expect(MessageType.Init).toBe(0x01);
    expect(MessageType.InitAck).toBe(0x02);
  });

  it('has RPC types', () => {
    expect(MessageType.Push).toBe(0x10);
    expect(MessageType.Pull).toBe(0x11);
    expect(MessageType.Resolve).toBe(0x12);
    expect(MessageType.Reject).toBe(0x13);
    expect(MessageType.Release).toBe(0x14);
  });

  it('has MCP tool types', () => {
    expect(MessageType.ListTools).toBe(0x20);
    expect(MessageType.ListToolsResponse).toBe(0x21);
    expect(MessageType.CallTool).toBe(0x22);
    expect(MessageType.CallToolResponse).toBe(0x23);
  });

  it('has MCP resource types', () => {
    expect(MessageType.ListResources).toBe(0x30);
    expect(MessageType.ListResourcesResponse).toBe(0x31);
    expect(MessageType.ReadResource).toBe(0x32);
    expect(MessageType.ReadResourceResponse).toBe(0x33);
  });

  it('has MCP prompt types', () => {
    expect(MessageType.ListPrompts).toBe(0x40);
    expect(MessageType.ListPromptsResponse).toBe(0x41);
    expect(MessageType.GetPrompt).toBe(0x42);
    expect(MessageType.GetPromptResponse).toBe(0x43);
  });

  it('has control types', () => {
    expect(MessageType.Ping).toBe(0xf0);
    expect(MessageType.Pong).toBe(0xf1);
    expect(MessageType.Error).toBe(0xff);
  });
});

// ── Encode ────────────────────────────────────────────────────────────

describe('encode', () => {
  it('produces correct binary format', () => {
    const frame = encode(MessageType.Push, { hello: 'world' });

    expect(frame).toBeInstanceOf(Uint8Array);

    // Magic bytes
    expect(frame[0]).toBe(0x5a);
    expect(frame[1]).toBe(0x41);
    expect(frame[2]).toBe(0x50);
    expect(frame[3]).toBe(0x01);

    // Type
    expect(frame[4]).toBe(MessageType.Push);

    // Length (big-endian)
    const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
    const length = view.getUint32(5, false);
    const json = new TextDecoder().decode(frame.subarray(9));
    expect(length).toBe(json.length);

    // Payload
    expect(JSON.parse(json)).toEqual({ hello: 'world' });
  });

  it('handles empty object payload', () => {
    const frame = encode(MessageType.Ping, {});
    expect(frame.length).toBe(HEADER_SIZE + 2); // "{}" = 2 bytes
  });

  it('handles null payload', () => {
    const frame = encode(MessageType.Pong, null);
    expect(frame.length).toBe(HEADER_SIZE + 4); // "null" = 4 bytes
  });

  it('handles nested objects', () => {
    const payload = {
      method: 'tools/call',
      params: {
        name: 'fs',
        arguments: { action: 'read', path: '/tmp/test.txt' },
      },
    };
    const frame = encode(MessageType.Push, payload);
    const decoded = decode(frame);
    expect(decoded).not.toBeNull();
    expect(decoded!.payload).toEqual(payload);
  });

  it('handles arrays', () => {
    const payload = { tools: ['fs', 'exec', 'git'] };
    const frame = encode(MessageType.Resolve, payload);
    const decoded = decode(frame);
    expect(decoded!.payload).toEqual(payload);
  });

  it('handles unicode', () => {
    const payload = { text: 'Hello 世界 🌍' };
    const frame = encode(MessageType.Push, payload);
    const decoded = decode(frame);
    expect((decoded!.payload as Record<string, unknown>).text).toBe('Hello 世界 🌍');
  });

  it('handles large payloads', () => {
    const payload = { data: 'x'.repeat(100000) };
    const frame = encode(MessageType.Push, payload);
    const decoded = decode(frame);
    expect((decoded!.payload as Record<string, unknown>).data).toHaveLength(100000);
  });

  it('uses all message types', () => {
    for (const [name, type] of Object.entries(MessageType)) {
      const frame = encode(type as number, { test: name });
      const decoded = decode(frame);
      expect(decoded).not.toBeNull();
      expect(decoded!.type).toBe(type);
    }
  });
});

// ── Decode ────────────────────────────────────────────────────────────

describe('decode', () => {
  it('round-trips encode/decode', () => {
    const original = { id: 'req-1', method: 'tools/list', params: {} };
    const frame = encode(MessageType.Push, original);
    const decoded = decode(frame);
    expect(decoded).not.toBeNull();
    expect(decoded!.type).toBe(MessageType.Push);
    expect(decoded!.payload).toEqual(original);
    expect(decoded!.format).toBe('zap');
  });

  it('returns null for too-short buffer', () => {
    expect(decode(new Uint8Array(5))).toBeNull();
  });

  it('returns null for empty buffer', () => {
    expect(decode(new Uint8Array(0))).toBeNull();
  });

  it('returns null for wrong magic bytes', () => {
    const buf = new Uint8Array(20);
    buf[0] = 0xff; buf[1] = 0xff; buf[2] = 0xff; buf[3] = 0xff;
    expect(decode(buf)).toBeNull();
  });

  it('decodes LE format (hanzo-dev compat)', () => {
    // [length:4 LE][type:1][payload]
    const json = new TextEncoder().encode('{"test":true}');
    const totalLen = 1 + json.length; // type + payload

    const buf = new Uint8Array(4 + totalLen);
    const view = new DataView(buf.buffer);
    view.setUint32(0, totalLen, true); // little-endian
    buf[4] = MessageType.Push;
    buf.set(json, 5);

    const decoded = decode(buf);
    expect(decoded).not.toBeNull();
    expect(decoded!.type).toBe(MessageType.Push);
    expect(decoded!.payload).toEqual({ test: true });
    expect(decoded!.format).toBe('le');
  });

  it('decodes plain JSON fallback', () => {
    const json = new TextEncoder().encode('{"method":"tools/list"}');
    // Create a buffer that doesn't match magic or LE format
    // Plain JSON needs enough bytes to avoid being treated as LE
    const decoded = decode(json);
    // This may decode as LE or JSON depending on heuristics
    expect(decoded).not.toBeNull();
  });
});

// ── extractFrames ─────────────────────────────────────────────────────

describe('extractFrames', () => {
  it('extracts single frame', () => {
    const frame = encode(MessageType.Push, { id: 'r1' });
    const { frames, remaining } = extractFrames(frame);
    expect(frames).toHaveLength(1);
    expect(frames[0]!.type).toBe(MessageType.Push);
    expect(remaining.length).toBe(0);
  });

  it('extracts multiple frames', () => {
    const f1 = encode(MessageType.Push, { id: 'r1' });
    const f2 = encode(MessageType.Push, { id: 'r2' });
    const f3 = encode(MessageType.Resolve, { id: 'r1', result: 42 });

    const combined = new Uint8Array(f1.length + f2.length + f3.length);
    combined.set(f1, 0);
    combined.set(f2, f1.length);
    combined.set(f3, f1.length + f2.length);

    const { frames, remaining } = extractFrames(combined);
    expect(frames).toHaveLength(3);
    expect(remaining.length).toBe(0);
  });

  it('handles partial frame (returns remaining)', () => {
    const frame = encode(MessageType.Push, { id: 'r1' });
    // Truncate the last 5 bytes
    const partial = frame.subarray(0, frame.length - 5);
    const { frames, remaining } = extractFrames(partial);
    expect(frames).toHaveLength(0);
    expect(remaining.length).toBe(partial.length);
  });

  it('handles mixed complete + partial', () => {
    const f1 = encode(MessageType.Push, { id: 'r1' });
    const f2 = encode(MessageType.Resolve, { id: 'r1', result: 'ok' });
    const partial = f2.subarray(0, 5);

    const combined = new Uint8Array(f1.length + partial.length);
    combined.set(f1, 0);
    combined.set(partial, f1.length);

    const { frames, remaining } = extractFrames(combined);
    expect(frames).toHaveLength(1);
    expect(frames[0]!.type).toBe(MessageType.Push);
    expect(remaining.length).toBe(partial.length);
  });

  it('handles empty buffer', () => {
    const { frames, remaining } = extractFrames(new Uint8Array(0));
    expect(frames).toHaveLength(0);
    expect(remaining.length).toBe(0);
  });
});

// ── Capability References ─────────────────────────────────────────────

describe('isCapabilityRef', () => {
  it('identifies capability references', () => {
    expect(isCapabilityRef({ __cap: true, exportId: -1 })).toBe(true);
    expect(isCapabilityRef({ __cap: true, exportId: -1, methods: ['hello'] })).toBe(true);
  });

  it('rejects non-capability values', () => {
    expect(isCapabilityRef(null)).toBe(false);
    expect(isCapabilityRef(undefined)).toBe(false);
    expect(isCapabilityRef(42)).toBe(false);
    expect(isCapabilityRef('cap')).toBe(false);
    expect(isCapabilityRef({})).toBe(false);
    expect(isCapabilityRef({ __cap: false })).toBe(false);
  });
});
