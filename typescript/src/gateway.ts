/**
 * ZAP gateway implementation
 */

import type { Config, ServerConfig } from './config.js';
import type { Tool, Resource, ConnectedServer } from './types.js';
import { ZapError } from './error.js';

/** Gateway for aggregating multiple MCP servers */
export class Gateway {
  private config: Config;
  private servers: Map<string, ConnectedServer> = new Map();
  private running = false;

  constructor(config?: Partial<Config>) {
    this.config = {
      listen: '0.0.0.0',
      port: 9999,
      servers: [],
      logLevel: 'info',
      ...config,
    };
  }

  /** Start the gateway */
  async start(): Promise<void> {
    if (this.running) {
      throw new ZapError('Gateway already running');
    }

    this.running = true;
    const addr = `${this.config.listen}:${this.config.port}`;
    console.log(`ZAP gateway starting on ${addr}`);

    // Connect to configured servers
    for (const serverConfig of this.config.servers) {
      await this.connectServer(serverConfig);
    }

    // TODO: Start Cap'n Proto RPC server
    console.log(`ZAP gateway ready with ${this.servers.size} servers`);
  }

  /** Stop the gateway */
  async stop(): Promise<void> {
    if (!this.running) {
      return;
    }

    // Disconnect all servers
    for (const [id] of this.servers) {
      await this.disconnectServer(id);
    }

    this.running = false;
    console.log('ZAP gateway stopped');
  }

  /** Connect to an MCP server */
  async connectServer(config: ServerConfig): Promise<string> {
    const id = crypto.randomUUID();

    const server: ConnectedServer = {
      id,
      name: config.name,
      url: config.url,
      status: 'connecting',
      tools: 0,
      resources: 0,
    };

    this.servers.set(id, server);

    try {
      // TODO: Establish connection based on transport
      server.status = 'connected';
      console.log(`Connected to server: ${config.name}`);
    } catch (error) {
      server.status = 'error';
      throw new ZapError(`Failed to connect to ${config.name}: ${error}`);
    }

    return id;
  }

  /** Disconnect from a server */
  async disconnectServer(id: string): Promise<void> {
    const server = this.servers.get(id);
    if (!server) {
      throw new ZapError(`Server not found: ${id}`);
    }

    server.status = 'disconnected';
    this.servers.delete(id);
    console.log(`Disconnected from server: ${server.name}`);
  }

  /** List all connected servers */
  listServers(): ConnectedServer[] {
    return Array.from(this.servers.values());
  }

  /** Get server by ID */
  getServer(id: string): ConnectedServer | undefined {
    return this.servers.get(id);
  }

  /** List all tools from all servers */
  async listTools(): Promise<Tool[]> {
    const tools: Tool[] = [];

    for (const [, server] of this.servers) {
      if (server.status !== 'connected') {
        continue;
      }
      // TODO: Fetch tools from server via RPC
    }

    return tools;
  }

  /** Call a tool on a specific server */
  async callTool(
    serverId: string,
    _name: string,
    _args: Record<string, unknown>
  ): Promise<unknown> {
    const server = this.servers.get(serverId);
    if (!server) {
      throw new ZapError(`Server not found: ${serverId}`);
    }

    if (server.status !== 'connected') {
      throw new ZapError(`Server not connected: ${server.name}`);
    }

    // TODO: Implement RPC call
    return null;
  }

  /** List all resources from all servers */
  async listResources(): Promise<Resource[]> {
    const resources: Resource[] = [];

    for (const [, server] of this.servers) {
      if (server.status !== 'connected') {
        continue;
      }
      // TODO: Fetch resources from server via RPC
    }

    return resources;
  }

  /** Read a resource from a specific server */
  async readResource(serverId: string, _uri: string): Promise<unknown> {
    const server = this.servers.get(serverId);
    if (!server) {
      throw new ZapError(`Server not found: ${serverId}`);
    }

    if (server.status !== 'connected') {
      throw new ZapError(`Server not connected: ${server.name}`);
    }

    // TODO: Implement RPC call
    return null;
  }

  /** Check if gateway is running */
  isRunning(): boolean {
    return this.running;
  }

  /** Get gateway configuration */
  getConfig(): Config {
    return { ...this.config };
  }
}
