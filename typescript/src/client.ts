/**
 * ZAP client — one-line setup, typed RPC, promise pipelining.
 *
 * @example
 * ```typescript
 * import { Client } from '@zap-proto/zap';
 *
 * // One-line binary WebSocket connection
 * const client = await Client.connect('zap://localhost:9999');
 *
 * // MCP operations
 * const tools = await client.listTools();
 * const result = await client.callTool('fs', { action: 'read', path: 'README.md' });
 *
 * // Typed RPC with promise pipelining
 * interface MyApi {
 *   authenticate(token: string): Promise<Session>;
 * }
 * interface Session {
 *   whoami(): Promise<string>;
 * }
 *
 * const api = client.as<MyApi>();
 * const session = api.authenticate(token);  // Not awaited!
 * const name = await session.whoami();      // Pipelined — one round trip
 *
 * // HTTP batch mode (serverless/edge)
 * const batch = Client.batch('https://api.example.com/zap', { token: '...' });
 * const p1 = batch.callTool('search', { query: 'hello' });
 * const p2 = batch.callTool('analyze', { text: '...' });
 * const [r1, r2] = await batch.flush([p1, p2]);
 * ```
 */

import type { Tool, Resource, ResourceContent, ServerInfo } from './types.js';
import { ZapError, ConnectionError, TimeoutError, ToolNotFoundError } from './error.js';
import { MessageType, encode, decode, type RpcRequest, type RpcResponse } from './protocol.js';
import {
  Transport as ZapTransport,
  WebSocketTransport,
  HttpBatchTransport,
  FetchTransport,
  createTransport,
  type TransportType,
} from './transport.js';
import { RpcSession, type RpcStub } from './rpc.js';

/** Client options */
export interface ClientOptions {
  /** Auth token for bearer authentication */
  token?: string;
  /** Transport type (default: auto-detect from URL scheme) */
  transport?: TransportType;
  /** Request timeout in ms (default: 30000) */
  timeout?: number;
  /** Custom headers */
  headers?: Record<string, string>;
  /** Reconnect on disconnect (WebSocket only, default: true) */
  reconnect?: boolean;
}

/** Tool call result */
export interface ToolCallResult<T = unknown> {
  content: T;
  isError?: boolean;
  metadata?: Record<string, unknown>;
}

/**
 * ZAP client with multi-transport support and typed RPC.
 *
 * Connects over WebSocket (binary ZAP), HTTP (JSON), or HTTP batch.
 * Supports Cap'n Web-style object capabilities and promise pipelining.
 */
export class Client {
  private transport: ZapTransport;
  private session: RpcSession;
  private serverInfo?: ServerInfo;
  private _url: string;

  private constructor(transport: ZapTransport, url: string, opts?: ClientOptions) {
    this.transport = transport;
    this._url = url;
    this.session = new RpcSession(transport, { timeout: opts?.timeout });
  }

  // ── Factory Methods ─────────────────────────────────────────────────

  /**
   * Connect to a ZAP server with binary protocol.
   *
   * Auto-detects transport from URL scheme:
   * - `zap://` → WebSocket binary
   * - `ws://` / `wss://` → WebSocket binary
   * - `http://` / `https://` → HTTP JSON
   */
  static async connect(url: string, opts?: ClientOptions): Promise<Client> {
    const transport = await createTransport(url, {
      token: opts?.token,
      headers: opts?.headers,
      type: opts?.transport,
    });

    const client = new Client(transport, url, opts);

    // Perform handshake if WebSocket
    if (transport instanceof WebSocketTransport) {
      await client.handshake();
    } else {
      // Try HTTP handshake
      try {
        const fetchT = transport as FetchTransport;
        const res = await fetchT.sendAsync(MessageType.Init, {
          client: { name: '@zap-proto/zap', version: '1.0.0' },
        });
        if (res && typeof res === 'object') {
          client.serverInfo = (res as Record<string, unknown>)['server'] as ServerInfo;
        }
      } catch {
        // Stateless mode — no handshake needed
      }
    }

    return client;
  }

  /**
   * Create an HTTP batch client — collect calls, flush in one request.
   *
   * Inspired by Cap'n Web's batch mode. Great for serverless/edge.
   */
  static batch(url: string, opts?: ClientOptions): BatchClient {
    const transport = HttpBatchTransport.create(url, {
      token: opts?.token,
      headers: opts?.headers,
    });
    return new BatchClient(transport, url, opts);
  }

  /**
   * Create a stateless HTTP client (no handshake).
   */
  static create(url: string, opts?: ClientOptions): Client {
    const transport = new FetchTransport(url, {
      token: opts?.token,
      headers: opts?.headers,
    });
    return new Client(transport, url, opts);
  }

  // ── Connection ──────────────────────────────────────────────────────

  /** Perform binary ZAP handshake */
  private async handshake(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new TimeoutError('Handshake timeout')), 10000);

      this.transport.on('message', function handler(frame) {
        if (frame.type === MessageType.InitAck) {
          clearTimeout(timer);
          // Remove this one-shot handler by overwriting
          resolve();
        }
      });

      this.transport.send(MessageType.Init, {
        client: { name: '@zap-proto/zap', version: '1.0.0' },
      });
    });
  }

  /** Get server info from handshake */
  get info(): ServerInfo | undefined {
    return this.serverInfo;
  }

  /** Check if connected */
  get connected(): boolean {
    return this.transport.connected;
  }

  /** Connection URL */
  get url(): string {
    return this._url;
  }

  // ── Typed RPC Stubs ─────────────────────────────────────────────────

  /**
   * Get a typed RPC stub for the server's main interface.
   *
   * Supports promise pipelining: if a method returns an RpcTarget,
   * you can chain method calls without awaiting.
   *
   * @example
   * ```typescript
   * interface Api {
   *   auth(token: string): Promise<Session>;
   * }
   * const api = client.as<Api>();
   * const user = await api.auth(token).whoami(); // pipelined!
   * ```
   */
  as<T>(): RpcStub<T> {
    return this.session.stub<T>();
  }

  // ── MCP Operations ──────────────────────────────────────────────────

  /** List available tools */
  async listTools(): Promise<Tool[]> {
    return this.rpc<Tool[]>('listTools');
  }

  /** Call a tool by name */
  async callTool<T = unknown>(
    name: string,
    args?: Record<string, unknown>,
    metadata?: Record<string, unknown>,
  ): Promise<ToolCallResult<T>> {
    return this.rpc<ToolCallResult<T>>('callTool', { name, args: args ?? {}, metadata });
  }

  /** List available resources */
  async listResources(): Promise<Resource[]> {
    return this.rpc<Resource[]>('listResources');
  }

  /** Read a resource by URI */
  async readResource(uri: string): Promise<ResourceContent> {
    return this.rpc<ResourceContent>('readResource', { uri });
  }

  // ── Lifecycle ───────────────────────────────────────────────────────

  /** Send ping to check connection */
  async ping(): Promise<void> {
    return new Promise<void>((resolve) => {
      this.transport.on('message', function handler(frame) {
        if (frame.type === MessageType.Pong) {
          resolve();
        }
      });
      this.transport.send(MessageType.Ping, {});
    });
  }

  /** Close the connection */
  close(): void {
    this.session.close();
  }

  // ── Internal ────────────────────────────────────────────────────────

  private async rpc<T>(method: string, params?: unknown): Promise<T> {
    const result = await this.session.call(0, method, params ? [params] : []);
    return result as T;
  }
}

// ── BatchClient ───────────────────────────────────────────────────────

/**
 * HTTP batch client — collect multiple calls, send in one HTTP request.
 *
 * @example
 * ```typescript
 * const batch = Client.batch('https://api.example.com/zap');
 * const p1 = batch.callTool('search', { query: 'hello' });
 * const p2 = batch.listTools();
 * const [results, tools] = await batch.flush([p1, p2]);
 * ```
 */
export class BatchClient {
  private transport: HttpBatchTransport;
  private session: RpcSession;
  private promises: Array<{ id: string; resolve: Function; reject: Function }> = [];
  private requestId = 0;

  constructor(transport: HttpBatchTransport, url: string, opts?: ClientOptions) {
    this.transport = transport;
    this.session = new RpcSession(transport, { timeout: opts?.timeout });
  }

  /** Call a tool (queued for batch) */
  callTool(name: string, args?: Record<string, unknown>): Promise<unknown> {
    return this.enqueue('callTool', { name, args: args ?? {} });
  }

  /** List tools (queued for batch) */
  listTools(): Promise<Tool[]> {
    return this.enqueue('listTools', {}) as Promise<Tool[]>;
  }

  /** Flush all queued calls in a single HTTP request */
  async flush<T extends unknown[]>(promises?: T): Promise<T> {
    const frames = await this.transport.flush();

    // Resolve pending promises from responses
    for (const frame of frames) {
      if (frame.type === MessageType.Resolve) {
        const res = frame.payload as RpcResponse;
        const pending = this.promises.find((p) => p.id === res.id);
        if (pending) {
          pending.resolve(res.result);
        }
      } else if (frame.type === MessageType.Reject) {
        const res = frame.payload as RpcResponse;
        const pending = this.promises.find((p) => p.id === res.id);
        if (pending) {
          pending.reject(new Error(res.error?.message ?? 'RPC error'));
        }
      }
    }

    if (promises) {
      return Promise.all(promises) as Promise<T>;
    }
    return [] as unknown as T;
  }

  private enqueue(method: string, params: unknown): Promise<unknown> {
    const id = `b${++this.requestId}`;

    const promise = new Promise((resolve, reject) => {
      this.promises.push({ id, resolve, reject });
    });

    this.transport.send(MessageType.Push, { id, target: 0, method, params });

    return promise;
  }

  close(): void {
    this.session.close();
  }
}
