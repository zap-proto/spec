/**
 * ZAP server implementation
 */

import type { Config } from './config.js';

/** ZAP server */
export class Server {
  private config: Config;

  constructor(config?: Partial<Config>) {
    this.config = {
      listen: '0.0.0.0',
      port: 9999,
      servers: [],
      logLevel: 'info',
      ...config,
    };
  }

  /** Run the server */
  async run(): Promise<void> {
    const addr = `${this.config.listen}:${this.config.port}`;
    console.log(`ZAP server listening on ${addr}`);
    // TODO: Start Cap'n Proto RPC server
    await new Promise(() => {}); // Wait forever
  }
}
