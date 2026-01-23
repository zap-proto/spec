/**
 * ZAP client implementation
 */

import type { Tool, Resource, ResourceContent } from './types.js';
import { ZapError } from './error.js';

/** ZAP client for connecting to ZAP gateways */
export class Client {
  private connected = false;

  private constructor(_url: string) {
    // URL stored for future RPC connection
  }

  /** Connect to a ZAP gateway */
  static async connect(url: string): Promise<Client> {
    const client = new Client(url);
    // TODO: Establish Cap'n Proto RPC connection
    client.connected = true;
    return client;
  }

  /** List available tools */
  async listTools(): Promise<Tool[]> {
    if (!this.connected) {
      throw new ZapError('Not connected');
    }
    // TODO: Implement RPC call
    return [];
  }

  /** Call a tool */
  async callTool(_name: string, _args: Record<string, unknown>): Promise<unknown> {
    if (!this.connected) {
      throw new ZapError('Not connected');
    }
    // TODO: Implement RPC call
    return null;
  }

  /** List available resources */
  async listResources(): Promise<Resource[]> {
    if (!this.connected) {
      throw new ZapError('Not connected');
    }
    // TODO: Implement RPC call
    return [];
  }

  /** Read a resource */
  async readResource(uri: string): Promise<ResourceContent> {
    if (!this.connected) {
      throw new ZapError('Not connected');
    }
    // TODO: Implement RPC call
    return { uri, mimeType: 'text/plain', content: '' };
  }

  /** Close the connection */
  async close(): Promise<void> {
    this.connected = false;
  }
}
