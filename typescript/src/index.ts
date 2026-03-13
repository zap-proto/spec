/**
 * ZAP — Zero-Copy App Proto
 *
 * High-performance binary RPC for AI agent communication.
 * Object-capability model, promise pipelining, multi-transport.
 *
 * @example
 * ```typescript
 * // One-line client — auto-detects transport from URL
 * import { Client } from '@zap-proto/zap';
 * const client = await Client.connect('zap://localhost:9999');
 * const tools = await client.listTools();
 *
 * // Typed RPC with promise pipelining
 * interface Api { auth(token: string): Promise<Session> }
 * interface Session { whoami(): Promise<string> }
 * const api = client.as<Api>();
 * const name = await api.auth(token).whoami();  // one round trip!
 *
 * // HTTP batch mode (serverless/edge)
 * const batch = Client.batch('https://api.example.com/zap');
 * const p1 = batch.listTools();
 * const p2 = batch.callTool('search', { query: 'hello' });
 * await batch.flush([p1, p2]);
 *
 * // Server with RpcTarget (object-capability model)
 * import { Server, RpcTarget } from '@zap-proto/zap';
 * class MyApi extends RpcTarget {
 *   async hello(name: string) { return `Hello, ${name}!`; }
 * }
 * const server = new Server({ name: 'my-tools', version: '1.0.0' });
 * server.serve(new MyApi());
 * await server.listen(9999);
 * ```
 *
 * @packageDocumentation
 */

// Core client/server
export { Client, BatchClient } from './client.js';
export type { ClientOptions, ToolCallResult } from './client.js';
export { Server } from './server.js';
export type { ServerOptions, ToolHandler } from './server.js';
export { Gateway } from './gateway.js';

// RPC layer (Cap'n Web-inspired object capabilities)
export { RpcTarget, RpcSession, ExportTable, isRpcTarget } from './rpc.js';
export type { RpcStub, RpcPromise, RpcSessionOptions } from './rpc.js';

// Binary protocol
export {
  encode,
  decode,
  extractFrames,
  ZAP_MAGIC,
  HEADER_SIZE,
  MAX_PAYLOAD_SIZE,
  PROTOCOL_VERSION,
  MessageType,
  isCapabilityRef,
} from './protocol.js';
export type { ZapFrame, RpcRequest, RpcResponse, CapabilityRef, MessageTypeValue } from './protocol.js';

// Transport layer
export {
  Transport,
  WebSocketTransport,
  HttpBatchTransport,
  PostMessageTransport,
  FetchTransport,
  createTransport,
} from './transport.js';
export type { WebSocketTransportOptions, TransportType, TransportEvents } from './transport.js';

// Config
export type { Config, ServerConfig } from './config.js';
export { DEFAULT_CONFIG, loadConfigFromEnv, mergeConfig } from './config.js';

// Error types
export {
  ZapError,
  ConnectionError,
  TransportError,
  ProtocolError,
  TimeoutError,
  ServerError,
  ToolNotFoundError,
  ResourceNotFoundError,
  InvalidArgumentError,
} from './error.js';

// Domain types
export * from './types.js';
export * from './identity.js';
export * from './agent_consensus.js';
export * from './lux_consensus.js';

/** ZAP protocol version */
export const VERSION = '1.0.0';

/** Default port for ZAP connections */
export const DEFAULT_PORT = 9999;
