import { describe, it, expect, vi, beforeEach } from 'vitest';
import { RpcTarget, RpcSession, ExportTable, isRpcTarget } from '../src/rpc.js';
import { MessageType, type ZapFrame } from '../src/protocol.js';
import { Transport } from '../src/transport.js';

// ── Mock Transport ────────────────────────────────────────────────────

class MockTransport extends Transport {
  sent: Array<{ type: number; payload: unknown }> = [];
  _connected = true;

  get connected(): boolean {
    return this._connected;
  }

  send(type: number, payload: unknown): void {
    this.sent.push({ type, payload });
  }

  close(): void {
    this._connected = false;
    this.emit('close');
  }

  /** Simulate receiving a frame */
  receive(frame: ZapFrame): void {
    this.emit('message', frame);
  }
}

// ── Test RpcTarget ────────────────────────────────────────────────────

class TestApi extends RpcTarget {
  async hello(name: string): Promise<string> {
    return `Hello, ${name}!`;
  }

  async add(a: number, b: number): Promise<number> {
    return a + b;
  }

  async throws(): Promise<never> {
    throw new Error('boom');
  }

  private _secret(): string {
    return 'hidden';
  }
}

class SessionApi extends RpcTarget {
  readonly user: string;

  constructor(user: string) {
    super();
    this.user = user;
  }

  async whoami(): Promise<string> {
    return this.user;
  }
}

class AuthApi extends RpcTarget {
  async authenticate(token: string): Promise<SessionApi> {
    if (token !== 'valid') throw new Error('Invalid token');
    return new SessionApi('Alice');
  }
}

// ── Tests ─────────────────────────────────────────────────────────────

describe('RpcTarget', () => {
  it('is identified by isRpcTarget', () => {
    const target = new TestApi();
    expect(isRpcTarget(target)).toBe(true);
  });

  it('non-targets return false', () => {
    expect(isRpcTarget({})).toBe(false);
    expect(isRpcTarget(null)).toBe(false);
    expect(isRpcTarget('string')).toBe(false);
    expect(isRpcTarget(42)).toBe(false);
  });

  it('rpcMethods defaults to undefined (all public)', () => {
    const target = new TestApi();
    expect(target.rpcMethods).toBeUndefined();
  });
});

describe('ExportTable', () => {
  it('sets and gets main interface at ID 0', () => {
    const table = new ExportTable();
    const target = new TestApi();
    table.setMain(target);
    expect(table.get(0)).toBe(target);
  });

  it('assigns negative IDs for pass-by-ref', () => {
    const table = new ExportTable();
    const t1 = new TestApi();
    const t2 = new TestApi();
    const id1 = table.addPassByRef(t1);
    const id2 = table.addPassByRef(t2);
    expect(id1).toBe(-1);
    expect(id2).toBe(-2);
    expect(table.get(id1)).toBe(t1);
    expect(table.get(id2)).toBe(t2);
  });

  it('reserves positive IDs for push results', () => {
    const table = new ExportTable();
    expect(table.reservePush()).toBe(1);
    expect(table.reservePush()).toBe(2);
    expect(table.reservePush()).toBe(3);
  });

  it('releases exports', () => {
    const table = new ExportTable();
    const target = new TestApi();
    const id = table.addPassByRef(target);
    expect(table.get(id)).toBe(target);
    table.release(id);
    expect(table.get(id)).toBeUndefined();
  });
});

describe('RpcSession — server side', () => {
  let transport: MockTransport;
  let session: RpcSession;

  beforeEach(() => {
    transport = new MockTransport();
    session = new RpcSession(transport, { timeout: 5000 });
    session.serve(new TestApi());
  });

  it('handles Push and sends Resolve', async () => {
    transport.receive({
      type: MessageType.Push,
      payload: { id: 'r1', target: 0, method: 'hello', params: ['World'] },
      format: 'zap',
    });

    // Wait for async handler
    await new Promise((r) => setTimeout(r, 10));

    const resolve = transport.sent.find((s) => s.type === MessageType.Resolve);
    expect(resolve).toBeDefined();
    const payload = resolve!.payload as { id: string; result: string };
    expect(payload.id).toBe('r1');
    expect(payload.result).toBe('Hello, World!');
  });

  it('handles Push with multiple args', async () => {
    transport.receive({
      type: MessageType.Push,
      payload: { id: 'r2', target: 0, method: 'add', params: [3, 4] },
      format: 'zap',
    });

    await new Promise((r) => setTimeout(r, 10));

    const resolve = transport.sent.find((s) => s.type === MessageType.Resolve);
    expect(resolve).toBeDefined();
    expect((resolve!.payload as { result: number }).result).toBe(7);
  });

  it('sends Reject on method error', async () => {
    transport.receive({
      type: MessageType.Push,
      payload: { id: 'r3', target: 0, method: 'throws', params: [] },
      format: 'zap',
    });

    await new Promise((r) => setTimeout(r, 10));

    const reject = transport.sent.find((s) => s.type === MessageType.Reject);
    expect(reject).toBeDefined();
    const payload = reject!.payload as { id: string; error: { message: string } };
    expect(payload.id).toBe('r3');
    expect(payload.error.message).toBe('boom');
  });

  it('sends Reject for unknown method', async () => {
    transport.receive({
      type: MessageType.Push,
      payload: { id: 'r4', target: 0, method: 'nonexistent', params: [] },
      format: 'zap',
    });

    await new Promise((r) => setTimeout(r, 10));

    const reject = transport.sent.find((s) => s.type === MessageType.Reject);
    expect(reject).toBeDefined();
    expect((reject!.payload as { error: { message: string } }).error.message).toContain('Unknown method');
  });

  it('sends Reject for unknown export', async () => {
    transport.receive({
      type: MessageType.Push,
      payload: { id: 'r5', target: 99, method: 'hello', params: [] },
      format: 'zap',
    });

    await new Promise((r) => setTimeout(r, 10));

    const reject = transport.sent.find((s) => s.type === MessageType.Reject);
    expect(reject).toBeDefined();
    expect((reject!.payload as { error: { message: string } }).error.message).toContain('Unknown export');
  });

  it('responds to Ping with Pong', () => {
    transport.receive({
      type: MessageType.Ping,
      payload: {},
      format: 'zap',
    });

    const pong = transport.sent.find((s) => s.type === MessageType.Pong);
    expect(pong).toBeDefined();
  });

  it('returns capability reference for RpcTarget results', async () => {
    const authTransport = new MockTransport();
    const authSession = new RpcSession(authTransport, { timeout: 5000 });
    authSession.serve(new AuthApi());

    authTransport.receive({
      type: MessageType.Push,
      payload: { id: 'r6', target: 0, method: 'authenticate', params: ['valid'] },
      format: 'zap',
    });

    await new Promise((r) => setTimeout(r, 10));

    const resolve = authTransport.sent.find((s) => s.type === MessageType.Resolve);
    expect(resolve).toBeDefined();
    const result = (resolve!.payload as { result: { __cap: true; exportId: number } }).result;
    expect(result.__cap).toBe(true);
    expect(result.exportId).toBeLessThan(0); // negative = pass-by-ref
  });
});

describe('RpcSession — client side', () => {
  let transport: MockTransport;
  let session: RpcSession;

  beforeEach(() => {
    transport = new MockTransport();
    session = new RpcSession(transport, { timeout: 5000 });
  });

  it('stub methods send Push and resolve on Resolve', async () => {
    const stub = session.stub<{ hello(name: string): Promise<string> }>();

    const promise = stub.hello('World');

    // Check that Push was sent
    const push = transport.sent.find((s) => s.type === MessageType.Push);
    expect(push).toBeDefined();
    const req = push!.payload as { id: string; method: string; params: unknown[] };
    expect(req.method).toBe('hello');
    expect(req.params).toEqual(['World']);

    // Simulate server response
    transport.receive({
      type: MessageType.Resolve,
      payload: { id: req.id, result: 'Hello, World!' },
      format: 'zap',
    });

    const result = await promise;
    expect(result).toBe('Hello, World!');
  });

  it('stub methods reject on Reject', async () => {
    const stub = session.stub<{ fail(): Promise<void> }>();

    const promise = stub.fail();

    const push = transport.sent.find((s) => s.type === MessageType.Push);
    const req = push!.payload as { id: string };

    transport.receive({
      type: MessageType.Reject,
      payload: { id: req.id, error: { code: -1, message: 'test error' } },
      format: 'zap',
    });

    await expect(promise).rejects.toThrow('test error');
  });

  it('call times out', async () => {
    const shortSession = new RpcSession(transport, { timeout: 50 });
    const stub = shortSession.stub<{ slow(): Promise<void> }>();

    await expect(stub.slow()).rejects.toThrow('RPC timeout');
  });

  it('close rejects pending calls', async () => {
    const stub = session.stub<{ pending(): Promise<void> }>();
    const promise = stub.pending();

    session.close();

    await expect(promise).rejects.toThrow('Session closed');
  });
});

describe('RpcSession — MCP compat', () => {
  let transport: MockTransport;
  let session: RpcSession;

  beforeEach(() => {
    transport = new MockTransport();
    session = new RpcSession(transport, { timeout: 5000 });

    // Serve a target with MCP-style methods
    class McpApi extends RpcTarget {
      async listTools() { return [{ name: 'fs' }]; }
      async callTool(params: { name: string }) { return { content: `called ${params.name}` }; }
    }
    session.serve(new McpApi());
  });

  it('handles ListTools message type', async () => {
    transport.receive({
      type: MessageType.ListTools,
      payload: { id: 'mcp-1' },
      format: 'zap',
    });

    await new Promise((r) => setTimeout(r, 10));

    const resolve = transport.sent.find((s) => s.type === MessageType.Resolve);
    expect(resolve).toBeDefined();
  });

  it('handles CallTool message type', async () => {
    transport.receive({
      type: MessageType.CallTool,
      payload: { id: 'mcp-2', name: 'fs' },
      format: 'zap',
    });

    await new Promise((r) => setTimeout(r, 10));

    const resolve = transport.sent.find((s) => s.type === MessageType.Resolve);
    expect(resolve).toBeDefined();
  });
});
