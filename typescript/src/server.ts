/**
 * ZAP server — register RpcTarget objects and serve over any transport.
 *
 * @example
 * ```typescript
 * import { Server, RpcTarget } from '@zap-proto/zap';
 *
 * class MyApi extends RpcTarget {
 *   async hello(name: string) { return `Hello, ${name}!`; }
 *   async listTools() { return [{ name: 'greet', description: 'Greet someone' }]; }
 * }
 *
 * // WebSocket server
 * const server = new Server({ name: 'my-tools', version: '1.0.0' });
 * server.serve(new MyApi());
 * await server.listen(9999);
 *
 * // Or serve over an existing WebSocket
 * server.handleConnection(ws);
 * ```
 */

import { MessageType, encode, decode, extractFrames, type ZapFrame, type RpcRequest } from './protocol.js';
import { RpcSession, RpcTarget, isRpcTarget } from './rpc.js';
import { WebSocketTransport, type Transport as ZapTransport } from './transport.js';
import type { Tool, ServerInfo, ServerCapabilities } from './types.js';

export type { ToolHandler };

/** Tool handler function */
type ToolHandler = (
  name: string,
  args: Record<string, unknown>,
) => Promise<unknown> | unknown;

export interface ServerOptions {
  name: string;
  version: string;
  capabilities?: Partial<ServerCapabilities>;
}

/**
 * ZAP server that accepts connections and serves RpcTarget objects.
 *
 * Supports WebSocket and any transport that implements the Transport interface.
 * Handles ZAP binary protocol, MCP compatibility, and object-capability RPC.
 */
export class Server {
  private info: ServerInfo;
  private target?: RpcTarget;
  private tools = new Map<string, { tool: Tool; handler: ToolHandler }>();
  private sessions = new Set<RpcSession>();
  private wsServer?: unknown; // WebSocket.Server — kept generic for browser compat
  private _listening = false;

  constructor(opts: ServerOptions) {
    this.info = {
      name: opts.name,
      version: opts.version,
      capabilities: {
        tools: true,
        resources: opts.capabilities?.resources ?? false,
        prompts: opts.capabilities?.prompts ?? false,
        logging: opts.capabilities?.logging ?? false,
      },
    };
  }

  /** Serve an RpcTarget as the main interface */
  serve(target: RpcTarget): void {
    this.target = target;
  }

  /**
   * Register a tool (MCP-style).
   *
   * @example
   * ```typescript
   * server.registerTool({
   *   name: 'greet',
   *   description: 'Greet someone',
   *   schema: { type: 'object', properties: { name: { type: 'string' } } },
   *   handler: async (name, args) => `Hello, ${args.name}!`,
   * });
   * ```
   */
  registerTool(opts: {
    name: string;
    description: string;
    schema: Record<string, unknown>;
    handler: ToolHandler;
  }): void {
    const tool: Tool = {
      name: opts.name,
      description: opts.description,
      schema: opts.schema,
    };
    this.tools.set(opts.name, { tool, handler: opts.handler });
  }

  /**
   * Listen on a port (Node.js only — uses dynamic import of 'ws').
   *
   * @example
   * ```typescript
   * await server.listen(9999);
   * await server.listen(9999, { host: '127.0.0.1' });
   * ```
   */
  async listen(port: number, opts?: { host?: string }): Promise<void> {
    // Dynamic import for Node.js WebSocket server
    // This keeps the module browser-compatible when not calling listen()
    const { WebSocketServer } = await import('ws');
    const wss = new WebSocketServer({
      port,
      host: opts?.host ?? '127.0.0.1',
    });

    this.wsServer = wss;
    this._listening = true;

    wss.on('connection', (ws: WebSocket) => {
      this.handleWebSocket(ws);
    });

    return new Promise<void>((resolve) => {
      wss.on('listening', () => {
        resolve();
      });
    });
  }

  /** Handle a WebSocket connection (works in browser and Node) */
  handleWebSocket(ws: WebSocket): void {
    const transport = WebSocketTransport.from(ws, { reconnect: false });
    this.handleTransport(transport);
  }

  /** Handle any transport connection */
  handleTransport(transport: ZapTransport): void {
    // Create a combined target that merges RpcTarget + registered tools
    const combined = this.createCombinedTarget();
    const session = new RpcSession(transport);
    session.serve(combined);
    this.sessions.add(session);

    // Handle handshake
    transport.on('message', (frame) => {
      if (frame.type === MessageType.Init) {
        // Respond with server info + tool list
        const tools = Array.from(this.tools.values()).map((t) => t.tool);
        transport.send(MessageType.InitAck, {
          serverId: `zap-${Date.now().toString(36)}`,
          ...this.info,
          tools,
        });
      }
    });

    transport.on('close', () => {
      this.sessions.delete(session);
    });
  }

  /** Stop the server */
  async close(): Promise<void> {
    for (const session of this.sessions) {
      session.close();
    }
    this.sessions.clear();

    if (this.wsServer && typeof (this.wsServer as { close: Function }).close === 'function') {
      await new Promise<void>((resolve) => {
        (this.wsServer as { close: (cb: () => void) => void }).close(() => resolve());
      });
    }
    this._listening = false;
  }

  get listening(): boolean {
    return this._listening;
  }

  /** Create a combined RpcTarget that serves both custom target + registered tools */
  private createCombinedTarget(): RpcTarget {
    const server = this;

    class CombinedTarget extends RpcTarget {
      async listTools(): Promise<Tool[]> {
        // Merge tools from registered tools + custom target
        const tools = Array.from(server.tools.values()).map((t) => t.tool);
        if (server.target && 'listTools' in server.target) {
          const extra = await (server.target as { listTools: () => Promise<Tool[]> }).listTools();
          tools.push(...extra);
        }
        return tools;
      }

      async callTool(params: { name: string; args?: Record<string, unknown> }): Promise<unknown> {
        const entry = server.tools.get(params.name);
        if (entry) {
          return entry.handler(params.name, params.args ?? {});
        }
        // Delegate to custom target
        if (server.target && 'callTool' in server.target) {
          return (server.target as { callTool: Function }).callTool(params);
        }
        throw new Error(`Unknown tool: ${params.name}`);
      }

      async listResources(): Promise<unknown[]> {
        if (server.target && 'listResources' in server.target) {
          return (server.target as { listResources: () => Promise<unknown[]> }).listResources();
        }
        return [];
      }

      async readResource(params: { uri: string }): Promise<unknown> {
        if (server.target && 'readResource' in server.target) {
          return (server.target as { readResource: Function }).readResource(params);
        }
        throw new Error(`Resource not found: ${params.uri}`);
      }

      async listPrompts(): Promise<unknown[]> {
        if (server.target && 'listPrompts' in server.target) {
          return (server.target as { listPrompts: () => Promise<unknown[]> }).listPrompts();
        }
        return [];
      }

      async getPrompt(params: { name: string; args?: Record<string, string> }): Promise<unknown> {
        if (server.target && 'getPrompt' in server.target) {
          return (server.target as { getPrompt: Function }).getPrompt(params);
        }
        throw new Error(`Prompt not found: ${params.name}`);
      }
    }

    // Forward any custom methods from the user's target
    if (server.target) {
      const proto = Object.getPrototypeOf(server.target);
      for (const name of Object.getOwnPropertyNames(proto)) {
        if (
          name !== 'constructor' &&
          !name.startsWith('_') &&
          typeof proto[name] === 'function' &&
          !(name in CombinedTarget.prototype)
        ) {
          (CombinedTarget.prototype as unknown as Record<string, unknown>)[name] = function (...args: unknown[]) {
            return (server.target as unknown as Record<string, Function>)[name]!(...args);
          };
        }
      }
    }

    return new CombinedTarget();
  }
}
