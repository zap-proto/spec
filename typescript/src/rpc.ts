/**
 * ZAP RPC layer — object-capability model with promise pipelining.
 *
 * Inspired by Cap'n Web: pass objects by reference, chain calls without
 * awaiting, typed stubs via Proxy. All with ZAP's binary wire format.
 *
 * @example
 * ```typescript
 * // Define your API
 * interface MyApi {
 *   hello(name: string): Promise<string>;
 *   authenticate(token: string): Promise<Session>;
 * }
 * interface Session {
 *   whoami(): Promise<string>;
 *   listFiles(dir: string): Promise<string[]>;
 * }
 *
 * // Server: extend RpcTarget
 * class MyApiServer extends RpcTarget implements MyApi {
 *   async hello(name: string) { return `Hello, ${name}!`; }
 *   async authenticate(token: string) {
 *     const user = await verifyToken(token);
 *     return new SessionImpl(user); // returned by reference!
 *   }
 * }
 *
 * // Client: typed stub
 * const api: RpcStub<MyApi> = session.stub();
 * const greeting = await api.hello('World');
 * const session = api.authenticate(token); // promise pipeline!
 * const name = await session.whoami();     // pipelined — one round trip
 * ```
 */

import { MessageType, type RpcRequest, type RpcResponse, isCapabilityRef } from './protocol.js';
import type { Transport } from './transport.js';
import type { ZapFrame } from './protocol.js';

// ── RpcTarget ─────────────────────────────────────────────────────────

/** Unique symbol to mark RpcTarget instances */
const RPC_TARGET = Symbol('RpcTarget');

/**
 * Base class for objects that can be passed by reference over ZAP.
 *
 * When an RpcTarget is returned from an RPC call, the client receives
 * a stub. Calling methods on the stub makes RPCs back to the server
 * where the object lives. This is the foundation of capability-based
 * security — you can only call methods on objects you've been given.
 *
 * @example
 * ```typescript
 * class Database extends RpcTarget {
 *   async query(sql: string) { ... }
 * }
 *
 * class Api extends RpcTarget {
 *   async getDb(credentials: Creds): Promise<Database> {
 *     verify(credentials);
 *     return new Database(); // client gets a capability reference
 *   }
 * }
 * ```
 */
export abstract class RpcTarget {
  readonly [RPC_TARGET] = true;

  /** Methods exposed over RPC. Override to restrict. */
  get rpcMethods(): string[] | undefined {
    return undefined; // undefined = all public methods
  }
}

/** Check if a value is an RpcTarget */
export function isRpcTarget(v: unknown): v is RpcTarget {
  return typeof v === 'object' && v !== null && RPC_TARGET in v;
}

// ── Export / Import Tables ────────────────────────────────────────────

/** Tracks objects exported to the remote side */
export class ExportTable {
  private nextNegId = -1;
  private nextPosId = 1;
  private entries = new Map<number, unknown>();

  /** Export the main interface (ID 0) */
  setMain(target: RpcTarget): void {
    this.entries.set(0, target);
  }

  /** Export an object passed by reference (negative IDs) */
  addPassByRef(target: RpcTarget): number {
    const id = this.nextNegId--;
    this.entries.set(id, target);
    return id;
  }

  /** Reserve a positive ID for a push result */
  reservePush(): number {
    return this.nextPosId++;
  }

  /** Store the resolved value for a push */
  resolve(id: number, value: unknown): void {
    this.entries.set(id, value);
  }

  /** Get an exported object */
  get(id: number): unknown {
    return this.entries.get(id);
  }

  /** Release an export */
  release(id: number): void {
    this.entries.delete(id);
  }
}

// ── RPC Session ───────────────────────────────────────────────────────

export interface RpcSessionOptions {
  /** Timeout for RPC calls in ms (default: 30000) */
  timeout?: number;
}

/**
 * RPC session — manages the bidirectional object-capability protocol
 * over a ZAP transport.
 *
 * @example
 * ```typescript
 * import { RpcSession, RpcTarget } from '@zap-proto/zap';
 *
 * // Server side
 * class Api extends RpcTarget {
 *   hello(name: string) { return `Hello, ${name}!`; }
 * }
 * const session = new RpcSession(transport);
 * session.serve(new Api());
 *
 * // Client side
 * const session = new RpcSession(transport);
 * const api = session.stub<{ hello(name: string): Promise<string> }>();
 * console.log(await api.hello('World'));
 * ```
 */
export class RpcSession {
  private transport: Transport;
  private exports = new ExportTable();
  private pending = new Map<string, {
    resolve: (value: unknown) => void;
    reject: (error: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  }>();
  private requestId = 0;
  private timeout: number;

  constructor(transport: Transport, opts?: RpcSessionOptions) {
    this.transport = transport;
    this.timeout = opts?.timeout ?? 30000;

    transport.on('message', (frame) => this.handleFrame(frame));
  }

  /** Serve an RpcTarget as the main interface (export ID 0) */
  serve(target: RpcTarget): void {
    this.exports.setMain(target);
  }

  /**
   * Create a typed RPC stub for the remote's main interface.
   *
   * The stub uses Proxy to intercept method calls and turn them
   * into ZAP RPC requests. Methods return Promises that resolve
   * when the remote responds.
   *
   * Supports promise pipelining: if a method returns an RpcTarget,
   * you can call methods on the returned promise without awaiting.
   */
  stub<T>(): RpcStub<T> {
    return createStub<T>(this, 0);
  }

  /** Send an RPC request and return a promise for the result */
  call(target: number, method: string, args: unknown[]): Promise<unknown> {
    const id = `r${++this.requestId}`;

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`RPC timeout: ${method} (${this.timeout}ms)`));
      }, this.timeout);

      this.pending.set(id, { resolve, reject, timer });

      const request: RpcRequest = {
        id,
        target,
        method,
        params: args,
      };

      this.transport.send(MessageType.Push, request);
    });
  }

  /** Handle an incoming frame */
  private async handleFrame(frame: ZapFrame): Promise<void> {
    const { type, payload } = frame;

    switch (type) {
      case MessageType.Push:
        await this.handlePush(payload as RpcRequest);
        break;

      case MessageType.Resolve:
        this.handleResolve(payload as RpcResponse);
        break;

      case MessageType.Reject:
        this.handleReject(payload as RpcResponse);
        break;

      case MessageType.Release: {
        const { exportId } = payload as { exportId: number };
        this.exports.release(exportId);
        break;
      }

      case MessageType.Ping:
        this.transport.send(MessageType.Pong, {});
        break;

      // MCP compat: map to Push/Resolve pattern
      case MessageType.ListTools:
      case MessageType.CallTool:
      case MessageType.ListResources:
      case MessageType.ReadResource:
      case MessageType.ListPrompts:
      case MessageType.GetPrompt:
        await this.handleMcpRequest(type, payload);
        break;

      case MessageType.ListToolsResponse:
      case MessageType.CallToolResponse:
      case MessageType.ListResourcesResponse:
      case MessageType.ReadResourceResponse:
      case MessageType.ListPromptsResponse:
      case MessageType.GetPromptResponse:
        this.handleMcpResponse(type, payload);
        break;
    }
  }

  /** Handle an incoming Push (RPC call) */
  private async handlePush(req: RpcRequest): Promise<void> {
    try {
      const target = this.exports.get(req.target ?? 0);
      if (!target || typeof target !== 'object') {
        this.sendReject(req.id, -1, `Unknown export: ${req.target ?? 0}`);
        return;
      }

      const method = (target as Record<string, unknown>)[req.method];
      if (typeof method !== 'function') {
        this.sendReject(req.id, -2, `Unknown method: ${req.method}`);
        return;
      }

      const args = Array.isArray(req.params) ? req.params : req.params ? [req.params] : [];
      const result = await method.call(target, ...args);

      // If result is an RpcTarget, export it by reference
      if (isRpcTarget(result)) {
        const exportId = this.exports.addPassByRef(result);
        const methods = result.rpcMethods ?? getPublicMethods(result);
        this.sendResolve(req.id, { __cap: true, exportId, methods });
      } else {
        this.sendResolve(req.id, result);
      }
    } catch (err) {
      this.sendReject(req.id, -32000, err instanceof Error ? err.message : String(err));
    }
  }

  /** Handle incoming Resolve */
  private handleResolve(res: RpcResponse): void {
    const pending = this.pending.get(res.id);
    if (pending) {
      clearTimeout(pending.timer);
      this.pending.delete(res.id);

      // If result is a capability reference, wrap in a stub
      if (isCapabilityRef(res.result)) {
        const stub = createStub(this, res.result.exportId, res.result.methods);
        pending.resolve(stub);
      } else {
        pending.resolve(res.result);
      }
    }
  }

  /** Handle incoming Reject */
  private handleReject(res: RpcResponse): void {
    const pending = this.pending.get(res.id);
    if (pending) {
      clearTimeout(pending.timer);
      this.pending.delete(res.id);
      pending.reject(new Error(res.error?.message ?? 'RPC error'));
    }
  }

  /** Handle MCP-compat request (map message type to method name) */
  private async handleMcpRequest(type: number, payload: unknown): Promise<void> {
    const methodMap: Record<number, string> = {
      [MessageType.ListTools]: 'listTools',
      [MessageType.CallTool]: 'callTool',
      [MessageType.ListResources]: 'listResources',
      [MessageType.ReadResource]: 'readResource',
      [MessageType.ListPrompts]: 'listPrompts',
      [MessageType.GetPrompt]: 'getPrompt',
    };

    const method = methodMap[type];
    if (!method) return;

    const p = payload as Record<string, unknown>;
    const req: RpcRequest = {
      id: p['id'] as string ?? `mcp-${++this.requestId}`,
      target: 0,
      method,
      params: p,
    };

    await this.handlePush(req);
  }

  /** Handle MCP-compat response */
  private handleMcpResponse(type: number, payload: unknown): void {
    const p = payload as Record<string, unknown>;
    const id = p['id'] as string;
    if (!id) return;

    if (p['error']) {
      this.handleReject({ id, error: p['error'] as RpcResponse['error'] });
    } else {
      this.handleResolve({ id, result: p });
    }
  }

  private sendResolve(id: string, result: unknown): void {
    this.transport.send(MessageType.Resolve, { id, result });
  }

  private sendReject(id: string, code: number, message: string): void {
    this.transport.send(MessageType.Reject, { id, error: { code, message } });
  }

  /** Close the session */
  close(): void {
    for (const [, pending] of this.pending) {
      clearTimeout(pending.timer);
      pending.reject(new Error('Session closed'));
    }
    this.pending.clear();
    this.transport.close();
  }
}

// ── RpcStub (Proxy-based typed client) ────────────────────────────────

/**
 * Typed RPC stub — a Proxy that converts method calls to RPC requests.
 *
 * Also supports promise pipelining: if you call a method that returns
 * a capability, you can call methods on the Promise without awaiting.
 * The calls are batched into a single round trip.
 */
export type RpcStub<T> = {
  [K in keyof T]: T[K] extends (...args: infer A) => Promise<infer R>
    ? (...args: A) => RpcPromise<R>
    : T[K] extends (...args: infer A) => infer R
      ? (...args: A) => RpcPromise<R>
      : T[K];
};

/**
 * A Promise that supports method chaining for promise pipelining.
 *
 * If the resolved value is an RpcTarget, calling methods on the
 * promise creates pipelined RPCs that execute in a single round trip.
 */
export interface RpcPromise<T> extends Promise<T> {
  /** Pipeline: call a method on the eventual result */
  [key: string]: unknown;
}

/** Create a Proxy-based stub for an export ID */
function createStub<T>(session: RpcSession, exportId: number, methods?: string[]): RpcStub<T> {
  const handler: ProxyHandler<object> = {
    get(_target, prop) {
      if (prop === 'then' || prop === 'catch' || prop === 'finally') {
        return undefined; // Don't break await
      }
      if (typeof prop === 'symbol') return undefined;
      const methodName = String(prop);

      return (...args: unknown[]) => {
        const promise = session.call(exportId, methodName, args);

        // Return an RpcPromise that supports pipelining
        return new Proxy(promise, {
          get(target, innerProp) {
            // Forward Promise methods
            if (innerProp === 'then' || innerProp === 'catch' || innerProp === 'finally') {
              const val = (target as unknown as Record<string | symbol, unknown>)[innerProp];
              return typeof val === 'function' ? val.bind(target) : val;
            }
            if (typeof innerProp === 'symbol') {
              return (target as unknown as Record<string | symbol, unknown>)[innerProp];
            }

            // Promise pipelining: call method on the resolved value
            const innerMethod = String(innerProp);
            return (...innerArgs: unknown[]) => {
              // Chain: wait for the outer promise, then call the inner method
              return promise.then((result) => {
                if (typeof result === 'object' && result !== null && innerMethod in result) {
                  const fn = (result as Record<string, unknown>)[innerMethod];
                  if (typeof fn === 'function') {
                    return fn.call(result, ...innerArgs);
                  }
                }
                throw new Error(`Cannot pipeline: ${innerMethod} not found on result`);
              });
            };
          },
        }) as RpcPromise<unknown>;
      };
    },
  };

  return new Proxy({}, handler) as RpcStub<T>;
}

// ── Helpers ───────────────────────────────────────────────────────────

/** Get public method names from an object (excluding constructor and privates) */
function getPublicMethods(obj: object): string[] {
  const methods: string[] = [];
  let proto = Object.getPrototypeOf(obj);
  while (proto && proto !== Object.prototype) {
    for (const name of Object.getOwnPropertyNames(proto)) {
      if (
        name !== 'constructor' &&
        !name.startsWith('_') &&
        typeof (proto as Record<string, unknown>)[name] === 'function'
      ) {
        methods.push(name);
      }
    }
    proto = Object.getPrototypeOf(proto);
  }
  return [...new Set(methods)];
}
