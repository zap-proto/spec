/**
 * ZAP transport layer — adapters for WebSocket, HTTP batch, postMessage, TCP.
 *
 * Inspired by Cap'n Web's transport-agnostic design.
 * All transports implement the same interface, so the RPC layer
 * is completely transport-independent.
 */

import { encode, decode, extractFrames, MessageType, HEADER_SIZE, type ZapFrame } from './protocol.js';

// ── Transport Interface ───────────────────────────────────────────────

/** Events emitted by transports */
export interface TransportEvents {
  message: (frame: ZapFrame) => void;
  open: () => void;
  close: () => void;
  error: (err: Error) => void;
}

type EventHandler<K extends keyof TransportEvents> = TransportEvents[K];

/**
 * Abstract transport — send/receive ZAP binary frames.
 *
 * Implementations handle the specifics of WebSocket, HTTP, TCP, etc.
 * The RPC layer only sees `send()` and `on('message', ...)`.
 */
export abstract class Transport {
  private handlers = new Map<string, Set<Function>>();

  /** Send a ZAP frame */
  abstract send(type: number, payload: unknown): void;

  /** Close the transport */
  abstract close(): void;

  /** Whether the transport is connected */
  abstract get connected(): boolean;

  /** Subscribe to events */
  on<K extends keyof TransportEvents>(event: K, handler: EventHandler<K>): void {
    let set = this.handlers.get(event);
    if (!set) {
      set = new Set();
      this.handlers.set(event, set);
    }
    set.add(handler);
  }

  /** Unsubscribe from events */
  off<K extends keyof TransportEvents>(event: K, handler: EventHandler<K>): void {
    this.handlers.get(event)?.delete(handler);
  }

  /** Emit an event */
  protected emit<K extends keyof TransportEvents>(event: K, ...args: Parameters<TransportEvents[K]>): void {
    const set = this.handlers.get(event);
    if (set) {
      for (const handler of set) {
        (handler as Function)(...args);
      }
    }
  }
}

// ── WebSocket Transport ───────────────────────────────────────────────

export interface WebSocketTransportOptions {
  /** Reconnect on close (default: true) */
  reconnect?: boolean;
  /** Reconnect delay in ms (default: 3000) */
  reconnectDelay?: number;
  /** Connection timeout in ms (default: 10000) */
  connectTimeout?: number;
}

/**
 * WebSocket transport for ZAP.
 *
 * Works in both browser (native WebSocket) and Node.js (ws package
 * or Node 22+ built-in WebSocket).
 *
 * @example
 * ```typescript
 * const transport = await WebSocketTransport.connect('ws://localhost:9999');
 * transport.on('message', (frame) => console.log(frame));
 * transport.send(MessageType.Push, { method: 'tools/list' });
 * ```
 */
export class WebSocketTransport extends Transport {
  private ws: WebSocket;
  private _connected = false;
  private url: string;
  private opts: WebSocketTransportOptions;

  private constructor(ws: WebSocket, url: string, opts: WebSocketTransportOptions) {
    super();
    this.ws = ws;
    this.url = url;
    this.opts = opts;
    this._connected = ws.readyState === WebSocket.OPEN;
    this.attachHandlers(ws);
  }

  static async connect(url: string, opts: WebSocketTransportOptions = {}): Promise<WebSocketTransport> {
    const timeout = opts.connectTimeout ?? 10000;

    const ws = new WebSocket(url);
    ws.binaryType = 'arraybuffer';

    return new Promise<WebSocketTransport>((resolve, reject) => {
      const timer = setTimeout(() => {
        ws.close();
        reject(new Error(`WebSocket connection timeout: ${url}`));
      }, timeout);

      ws.onopen = () => {
        clearTimeout(timer);
        const transport = new WebSocketTransport(ws, url, opts);
        transport._connected = true;
        transport.emit('open');
        resolve(transport);
      };

      ws.onerror = (ev) => {
        clearTimeout(timer);
        reject(new Error(`WebSocket connection failed: ${url}`));
      };
    });
  }

  /** Wrap an existing WebSocket */
  static from(ws: WebSocket, opts: WebSocketTransportOptions = {}): WebSocketTransport {
    return new WebSocketTransport(ws, ws.url, opts);
  }

  get connected(): boolean {
    return this._connected && this.ws.readyState === WebSocket.OPEN;
  }

  send(type: number, payload: unknown): void {
    if (!this.connected) {
      throw new Error('WebSocket not connected');
    }
    const frame = encode(type, payload);
    this.ws.send(frame.buffer);
  }

  close(): void {
    this._connected = false;
    this.ws.close();
  }

  private attachHandlers(ws: WebSocket): void {
    ws.onmessage = (ev) => {
      let data: Uint8Array;
      if (ev.data instanceof ArrayBuffer) {
        data = new Uint8Array(ev.data);
      } else if (typeof ev.data === 'string') {
        data = new TextEncoder().encode(ev.data);
      } else {
        return;
      }

      const frame = decode(data);
      if (frame) {
        this.emit('message', frame);
      }
    };

    ws.onclose = () => {
      this._connected = false;
      this.emit('close');

      if (this.opts.reconnect !== false) {
        setTimeout(() => {
          WebSocketTransport.connect(this.url, this.opts)
            .then((t) => {
              // Transfer handlers (reconnected)
              this.ws = t.ws;
              this._connected = true;
              this.attachHandlers(this.ws);
              this.emit('open');
            })
            .catch(() => {
              // Will retry via close handler
            });
        }, this.opts.reconnectDelay ?? 3000);
      }
    };

    ws.onerror = () => {
      this.emit('error', new Error('WebSocket error'));
    };
  }
}

// ── HTTP Batch Transport ──────────────────────────────────────────────

/**
 * HTTP batch transport — send multiple RPC calls in a single HTTP request.
 *
 * Inspired by Cap'n Web's batch mode. Collects calls, sends them in one
 * POST, then distributes responses. Great for serverless/edge.
 *
 * @example
 * ```typescript
 * const batch = HttpBatchTransport.create('https://api.example.com/zap');
 * // Calls are queued until flush
 * batch.send(MessageType.Push, { id: 'r1', method: 'tools/list' });
 * batch.send(MessageType.Push, { id: 'r2', method: 'tools/call', params: { name: 'fs' } });
 * const responses = await batch.flush();
 * ```
 */
export class HttpBatchTransport extends Transport {
  private url: string;
  private headers: Record<string, string>;
  private queue: Array<{ type: number; payload: unknown }> = [];
  private _connected = true;

  private constructor(url: string, headers: Record<string, string>) {
    super();
    this.url = url;
    this.headers = headers;
  }

  static create(url: string, opts?: { token?: string; headers?: Record<string, string> }): HttpBatchTransport {
    const headers: Record<string, string> = {
      'Content-Type': 'application/x-zap',
      Accept: 'application/x-zap',
      ...opts?.headers,
    };
    if (opts?.token) {
      headers['Authorization'] = `Bearer ${opts.token}`;
    }
    return new HttpBatchTransport(url, headers);
  }

  get connected(): boolean {
    return this._connected;
  }

  /** Queue a message for batch send */
  send(type: number, payload: unknown): void {
    this.queue.push({ type, payload });
  }

  /** Flush all queued messages in a single HTTP POST */
  async flush(): Promise<ZapFrame[]> {
    if (this.queue.length === 0) return [];

    // Concatenate all frames into one binary blob
    const frames = this.queue.map((msg) => encode(msg.type, msg.payload));
    this.queue = [];

    const totalSize = frames.reduce((sum, f) => sum + f.length, 0);
    const body = new Uint8Array(totalSize);
    let offset = 0;
    for (const frame of frames) {
      body.set(frame, offset);
      offset += frame.length;
    }

    const res = await fetch(this.url, {
      method: 'POST',
      headers: this.headers,
      body: body.buffer,
    });

    if (!res.ok) {
      throw new Error(`HTTP batch failed: ${res.status} ${res.statusText}`);
    }

    const responseData = new Uint8Array(await res.arrayBuffer());
    const { frames: responseFrames } = extractFrames(responseData);

    // Emit each response frame
    for (const frame of responseFrames) {
      this.emit('message', frame);
    }

    return responseFrames;
  }

  close(): void {
    this._connected = false;
    this.queue = [];
  }
}

// ── postMessage Transport ─────────────────────────────────────────────

/**
 * postMessage transport — for browser extensions, iframes, Web Workers.
 *
 * ZAP frames are sent as ArrayBuffer via `postMessage()` transferable.
 * This enables zero-copy RPC between browser contexts.
 *
 * @example
 * ```typescript
 * // In a Web Worker:
 * const transport = new PostMessageTransport(self);
 *
 * // In the main thread:
 * const transport = new PostMessageTransport(worker);
 * ```
 */
export class PostMessageTransport extends Transport {
  private target: MessagePort | Worker | Window;
  private _connected = true;

  constructor(target: MessagePort | Worker | Window, opts?: { origin?: string }) {
    super();
    this.target = target;
    const origin = opts?.origin ?? '*';

    // Listen for incoming messages
    const handler = (ev: MessageEvent) => {
      if (opts?.origin && opts.origin !== '*' && ev.origin !== opts.origin) return;

      let data: Uint8Array | null = null;
      if (ev.data instanceof ArrayBuffer) {
        data = new Uint8Array(ev.data);
      } else if (ev.data?.type === 'zap' && ev.data.frame instanceof ArrayBuffer) {
        data = new Uint8Array(ev.data.frame);
      }

      if (data) {
        const frame = decode(data);
        if (frame) this.emit('message', frame);
      }
    };

    if ('addEventListener' in target) {
      target.addEventListener('message', handler as EventListener);
    }

    this.emit('open');
  }

  get connected(): boolean {
    return this._connected;
  }

  send(type: number, payload: unknown): void {
    const frame = encode(type, payload);
    // Transfer the underlying ArrayBuffer for zero-copy
    const buffer = frame.buffer.slice(frame.byteOffset, frame.byteOffset + frame.byteLength);
    if ('postMessage' in this.target) {
      (this.target as MessagePort).postMessage(
        { type: 'zap', frame: buffer },
        [buffer],
      );
    }
  }

  close(): void {
    this._connected = false;
    this.emit('close');
  }
}

// ── Fetch Transport (HTTP REST fallback) ──────────────────────────────

/**
 * HTTP REST transport — traditional request/response.
 *
 * Falls back to JSON over HTTP when binary transports aren't available.
 * Compatible with the existing ZAP HTTP API (`/v1/*` endpoints).
 */
export class FetchTransport extends Transport {
  private baseUrl: string;
  private headers: Record<string, string>;
  private _connected = true;

  constructor(url: string, opts?: { token?: string; headers?: Record<string, string> }) {
    super();
    this.baseUrl = url.replace(/\/$/, '');
    this.headers = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      ...opts?.headers,
    };
    if (opts?.token) {
      this.headers['Authorization'] = `Bearer ${opts.token}`;
    }
  }

  get connected(): boolean {
    return this._connected;
  }

  /** Send maps ZAP message types to HTTP endpoints */
  send(type: number, payload: unknown): void {
    // For fetch transport, use sendAsync and emit response
    this.sendAsync(type, payload).catch((err) => {
      this.emit('error', err instanceof Error ? err : new Error(String(err)));
    });
  }

  /** Async send with response */
  async sendAsync(type: number, payload: unknown): Promise<unknown> {
    const p = payload as Record<string, unknown>;
    let method = 'POST';
    let path = '/v1/rpc';
    let body: unknown = payload;

    // Map known types to REST endpoints
    switch (type) {
      case MessageType.Init:
        path = '/v1/init';
        break;
      case MessageType.ListTools:
        method = 'GET';
        path = '/v1/tools';
        body = undefined;
        break;
      case MessageType.CallTool:
        path = '/v1/tools/call';
        break;
      case MessageType.ListResources:
        method = 'GET';
        path = '/v1/resources';
        body = undefined;
        break;
      case MessageType.ReadResource:
        path = '/v1/resources/read';
        break;
      case MessageType.ListPrompts:
        method = 'GET';
        path = '/v1/prompts';
        body = undefined;
        break;
      case MessageType.GetPrompt:
        path = '/v1/prompts/get';
        break;
      case MessageType.Ping:
        method = 'GET';
        path = '/v1/health';
        body = undefined;
        break;
    }

    const res = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers: this.headers,
      body: body ? JSON.stringify(body) : undefined,
    });

    const text = await res.text();
    const result = text ? JSON.parse(text) : null;

    if (!res.ok) {
      const responseType = type + 1; // Convention: response type = request type + 1
      this.emit('message', {
        type: MessageType.Reject,
        payload: { error: { code: res.status, message: text } },
        format: 'json' as const,
      });
      return result;
    }

    // Emit as a ZAP frame
    const responseType = type + 1;
    this.emit('message', {
      type: responseType,
      payload: result,
      format: 'json' as const,
    });

    return result;
  }

  close(): void {
    this._connected = false;
  }
}

// ── Transport Factory ─────────────────────────────────────────────────

export type TransportType = 'websocket' | 'http' | 'http-batch' | 'postmessage' | 'auto';

/**
 * Auto-detect and create the best transport for a URL.
 *
 * - `ws://` / `wss://` → WebSocketTransport
 * - `http://` / `https://` → FetchTransport
 * - `zap://` → WebSocketTransport (port 9999)
 * - `zaps://` → WebSocketTransport (TLS)
 */
export async function createTransport(
  url: string,
  opts?: { token?: string; headers?: Record<string, string>; type?: TransportType },
): Promise<Transport> {
  const type = opts?.type ?? 'auto';

  const transportOpts = { token: opts?.token, headers: opts?.headers };

  if (type === 'http-batch') {
    return HttpBatchTransport.create(url, transportOpts);
  }

  if (type === 'http') {
    return new FetchTransport(url, transportOpts);
  }

  if (type === 'websocket' || url.startsWith('ws://') || url.startsWith('wss://')) {
    return WebSocketTransport.connect(url);
  }

  if (url.startsWith('zap://') || url.startsWith('zaps://')) {
    const wsUrl = url
      .replace(/^zaps:\/\//, 'wss://')
      .replace(/^zap:\/\//, 'ws://');
    return WebSocketTransport.connect(wsUrl);
  }

  // Default to fetch transport
  return new FetchTransport(url, transportOpts);
}
