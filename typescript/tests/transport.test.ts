import { describe, it, expect, vi } from 'vitest';
import { HttpBatchTransport, FetchTransport, PostMessageTransport } from '../src/transport.js';
import { encode, decode, MessageType } from '../src/protocol.js';

// ── HttpBatchTransport ────────────────────────────────────────────────

describe('HttpBatchTransport', () => {
  it('creates with correct defaults', () => {
    const transport = HttpBatchTransport.create('https://api.example.com/zap');
    expect(transport.connected).toBe(true);
  });

  it('queues messages for batch send', () => {
    const transport = HttpBatchTransport.create('https://api.example.com/zap');

    transport.send(MessageType.Push, { id: 'r1', method: 'listTools' });
    transport.send(MessageType.Push, { id: 'r2', method: 'callTool' });

    // Messages are queued, not sent
    expect(transport.connected).toBe(true);
  });

  it('flush sends all queued messages', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      arrayBuffer: async () => {
        // Return a ZAP frame response
        const frame = encode(MessageType.Resolve, { id: 'r1', result: 42 });
        return frame.buffer;
      },
    });
    vi.stubGlobal('fetch', mockFetch);

    const transport = HttpBatchTransport.create('https://api.example.com/zap');
    transport.send(MessageType.Push, { id: 'r1', method: 'listTools' });

    const frames = await transport.flush();

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [url, opts] = mockFetch.mock.calls[0]!;
    expect(url).toBe('https://api.example.com/zap');
    expect(opts.method).toBe('POST');

    // Check that binary ZAP frames were sent
    expect(opts.body).toBeInstanceOf(ArrayBuffer);

    vi.unstubAllGlobals();
  });

  it('flush with empty queue returns empty', async () => {
    const transport = HttpBatchTransport.create('https://api.example.com/zap');
    const frames = await transport.flush();
    expect(frames).toHaveLength(0);
  });

  it('close marks as disconnected', () => {
    const transport = HttpBatchTransport.create('https://api.example.com/zap');
    expect(transport.connected).toBe(true);
    transport.close();
    expect(transport.connected).toBe(false);
  });
});

// ── FetchTransport ────────────────────────────────────────────────────

describe('FetchTransport', () => {
  it('creates with auth token', () => {
    const transport = new FetchTransport('https://api.example.com', {
      token: 'test-token',
    });
    expect(transport.connected).toBe(true);
  });

  it('sendAsync maps message types to endpoints', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      text: async () => '{"tools":[]}',
    });
    vi.stubGlobal('fetch', mockFetch);

    const transport = new FetchTransport('https://api.example.com');
    await transport.sendAsync(MessageType.ListTools, {});

    const [url, opts] = mockFetch.mock.calls[0]!;
    expect(url).toBe('https://api.example.com/v1/tools');
    expect(opts.method).toBe('GET');

    vi.unstubAllGlobals();
  });

  it('sendAsync maps CallTool to POST', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      text: async () => '{"content":"result"}',
    });
    vi.stubGlobal('fetch', mockFetch);

    const transport = new FetchTransport('https://api.example.com');
    await transport.sendAsync(MessageType.CallTool, { name: 'fs', args: {} });

    const [url, opts] = mockFetch.mock.calls[0]!;
    expect(url).toBe('https://api.example.com/v1/tools/call');
    expect(opts.method).toBe('POST');

    vi.unstubAllGlobals();
  });

  it('emits message event on successful response', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      text: async () => '{"tools":[{"name":"fs"}]}',
    });
    vi.stubGlobal('fetch', mockFetch);

    const transport = new FetchTransport('https://api.example.com');
    const handler = vi.fn();
    transport.on('message', handler);

    await transport.sendAsync(MessageType.ListTools, {});

    expect(handler).toHaveBeenCalledTimes(1);
    const frame = handler.mock.calls[0]![0];
    expect(frame.payload).toEqual({ tools: [{ name: 'fs' }] });

    vi.unstubAllGlobals();
  });
});

// ── Protocol binary compatibility ─────────────────────────────────────

describe('Binary compatibility', () => {
  it('encode produces browser-compatible Uint8Array', () => {
    const frame = encode(MessageType.Push, { method: 'test' });

    // Must be Uint8Array (not Node Buffer)
    expect(frame).toBeInstanceOf(Uint8Array);

    // Must be decodable
    const decoded = decode(frame);
    expect(decoded).not.toBeNull();
    expect(decoded!.format).toBe('zap');
  });

  it('frames are self-describing via magic bytes', () => {
    const f1 = encode(MessageType.Push, { a: 1 });
    const f2 = encode(MessageType.Resolve, { b: 2 });

    // Verify magic at start of each frame
    expect(f1[0]).toBe(0x5a);
    expect(f2[0]).toBe(0x5a);

    // Different types
    expect(f1[4]).toBe(MessageType.Push);
    expect(f2[4]).toBe(MessageType.Resolve);
  });

  it('big-endian length is correct', () => {
    const payload = { data: 'x'.repeat(300) };
    const frame = encode(MessageType.Push, payload);
    const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
    const length = view.getUint32(5, false); // big-endian
    const actualPayload = frame.subarray(9);
    expect(length).toBe(actualPayload.length);
  });
});
