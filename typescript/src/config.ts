/**
 * ZAP configuration types
 */

import type { Transport, LogLevel } from './types.js';

/** Server configuration */
export interface ServerConfig {
  /** Server name */
  name: string;
  /** Server URL */
  url: string;
  /** Transport type */
  transport: Transport;
  /** Command for stdio transport */
  command?: string;
  /** Arguments for stdio transport */
  args?: string[];
  /** Environment variables */
  env?: Record<string, string>;
}

/** Gateway configuration */
export interface Config {
  /** Listen address */
  listen: string;
  /** Listen port */
  port: number;
  /** Configured servers */
  servers: ServerConfig[];
  /** Log level */
  logLevel: LogLevel;
  /** TLS certificate path */
  tlsCert?: string;
  /** TLS key path */
  tlsKey?: string;
  /** Maximum connections */
  maxConnections?: number;
  /** Connection timeout in milliseconds */
  connectionTimeout?: number;
  /** Request timeout in milliseconds */
  requestTimeout?: number;
}

/** Default configuration values */
export const DEFAULT_CONFIG: Config = {
  listen: '0.0.0.0',
  port: 9999,
  servers: [],
  logLevel: 'info',
  maxConnections: 1000,
  connectionTimeout: 30000,
  requestTimeout: 60000,
};

/** Load configuration from environment */
export function loadConfigFromEnv(): Partial<Config> {
  const config: Partial<Config> = {};
  const env = process.env;

  if (env['ZAP_LISTEN']) {
    config.listen = env['ZAP_LISTEN'];
  }

  if (env['ZAP_PORT']) {
    config.port = parseInt(env['ZAP_PORT'], 10);
  }

  if (env['ZAP_LOG_LEVEL']) {
    config.logLevel = env['ZAP_LOG_LEVEL'] as LogLevel;
  }

  if (env['ZAP_TLS_CERT']) {
    config.tlsCert = env['ZAP_TLS_CERT'];
  }

  if (env['ZAP_TLS_KEY']) {
    config.tlsKey = env['ZAP_TLS_KEY'];
  }

  if (env['ZAP_MAX_CONNECTIONS']) {
    config.maxConnections = parseInt(env['ZAP_MAX_CONNECTIONS'], 10);
  }

  return config;
}

/** Merge configurations with defaults */
export function mergeConfig(...configs: Partial<Config>[]): Config {
  return configs.reduce(
    (merged, config) => ({ ...merged, ...config }),
    { ...DEFAULT_CONFIG }
  ) as Config;
}
