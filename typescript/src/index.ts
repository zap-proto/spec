/**
 * ZAP - Zero-copy Agent Protocol
 *
 * High-performance Cap'n Proto RPC for AI agent communication.
 *
 * @example
 * ```typescript
 * import { Client } from '@hanzo/zap';
 *
 * const client = await Client.connect('zap://localhost:9999');
 * const tools = await client.listTools();
 * const result = await client.callTool('search', { query: 'hello' });
 * ```
 *
 * @packageDocumentation
 */

export { Client } from './client.js';
export { Server } from './server.js';
export { Gateway } from './gateway.js';
export type { Config, ServerConfig } from './config.js';
export { DEFAULT_CONFIG, loadConfigFromEnv, mergeConfig } from './config.js';
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
export * from './types.js';
export * from './identity.js';
export * from './agent_consensus.js';
export * from './lux_consensus.js';

/** ZAP protocol version */
export const VERSION = '0.2.1';

/** Default port for ZAP connections */
export const DEFAULT_PORT = 9999;
