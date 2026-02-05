/**
 * ZAP TypeScript Client Example
 *
 * This example demonstrates connecting to a ZAP gateway and using
 * the MCP operations: tools, resources, and prompts.
 *
 * Run with: npx ts-node examples/typescript/main.ts
 */

import { Client, Gateway, type Tool, type Resource, type Prompt } from '@zap-proto/zap';

async function main(): Promise<void> {
  console.log('ZAP Chat Client Example (TypeScript)');
  console.log('=====================================\n');

  // Connect to the ZAP gateway
  const client = await Client.connect('zap://localhost:9999');
  console.log('Connected to ZAP gateway\n');

  // Initialize the connection
  const serverInfo = await client.init();
  console.log(`Server: ${serverInfo.name} v${serverInfo.version}`);
  console.log(`Protocol: ${serverInfo.protocolVersion}\n`);

  // List available tools
  console.log('Available Tools:');
  console.log('----------------');
  const tools = await client.listTools();
  for (const tool of tools) {
    console.log(`  ${tool.name} - ${tool.description}`);
  }
  console.log();

  // Call a tool
  console.log("Calling 'search' tool...");
  const result = await client.callTool('search', {
    query: 'typescript programming',
    limit: 5
  });

  if (result.isError) {
    console.log(`Tool error: ${result.error}`);
  } else {
    console.log('Search results:');
    for (const content of result.content) {
      console.log(`  - ${content.text}`);
    }
  }
  console.log();

  // List resources
  console.log('Available Resources:');
  console.log('--------------------');
  const resources = await client.listResources();
  for (const resource of resources) {
    console.log(`  ${resource.uri} - ${resource.name}`);
  }
  console.log();

  // Read a resource
  console.log('Reading config resource...');
  const content = await client.readResource('file:///etc/zap/config.json');
  console.log(`Config: ${content.text}\n`);

  // List prompts
  console.log('Available Prompts:');
  console.log('------------------');
  const prompts = await client.listPrompts();
  for (const prompt of prompts) {
    console.log(`  ${prompt.name} - ${prompt.description ?? ''}`);
  }
  console.log();

  // Get a prompt
  console.log("Getting 'code-review' prompt...");
  const messages = await client.getPrompt('code-review', {
    language: 'typescript',
    file: 'main.ts'
  });

  console.log('Prompt messages:');
  for (const msg of messages) {
    const preview = msg.content.slice(0, 50);
    console.log(`  [${msg.role}] ${preview}...`);
  }

  console.log('\nDone!');
}

/**
 * Example: Running a ZAP gateway
 */
async function gatewayExample(): Promise<void> {
  console.log('Starting ZAP Gateway...');

  const gateway = new Gateway({
    host: '0.0.0.0',
    port: 9999
  });

  // Add MCP servers
  gateway.addServer(
    'filesystem',
    'stdio://npx @modelcontextprotocol/server-filesystem /data'
  );
  gateway.addServer(
    'database',
    'http://localhost:8080/mcp'
  );
  gateway.addServer(
    'search',
    'ws://localhost:9000/ws'
  );

  console.log('Gateway configured with 3 MCP servers');
  console.log('Starting on port 9999...');

  await gateway.start();
}

/**
 * Example: Using typed tool calls
 */
async function typedToolExample(): Promise<void> {
  const client = await Client.connect('zap://localhost:9999');

  // Define tool input/output types
  interface SearchInput {
    query: string;
    limit?: number;
    filters?: {
      category?: string;
      dateRange?: { start: string; end: string };
    };
  }

  interface SearchResult {
    id: string;
    title: string;
    snippet: string;
    score: number;
  }

  // Call with typed parameters
  const result = await client.callTool<SearchInput>('search', {
    query: 'machine learning',
    limit: 10,
    filters: {
      category: 'articles',
      dateRange: { start: '2024-01-01', end: '2024-12-31' }
    }
  });

  // Parse typed response
  const searchResults = result.content.map(c =>
    JSON.parse(c.text) as SearchResult
  );

  for (const item of searchResults) {
    console.log(`[${item.score.toFixed(2)}] ${item.title}`);
    console.log(`  ${item.snippet}\n`);
  }
}

/**
 * Example: Resource streaming
 */
async function streamingExample(): Promise<void> {
  const client = await Client.connect('zap://localhost:9999');

  console.log('Subscribing to live data...');

  // Subscribe to resource updates
  const subscription = client.subscribeResource('file:///data/live.json');

  for await (const update of subscription) {
    console.log(`Update received at ${new Date().toISOString()}:`);
    console.log(update.text);
    console.log();
  }
}

/**
 * Example: React hook usage (conceptual)
 */
function reactHookExample() {
  // This would be used in a React component:
  /*
  import { useZap, useTools, useResources } from '@zap-proto/zap/react';

  function ToolList() {
    const { client, connected, error } = useZap('zap://localhost:9999');
    const { tools, loading, refresh } = useTools(client);

    if (!connected) return <div>Connecting...</div>;
    if (error) return <div>Error: {error.message}</div>;
    if (loading) return <div>Loading tools...</div>;

    return (
      <div>
        <h2>Tools ({tools.length})</h2>
        <ul>
          {tools.map(tool => (
            <li key={tool.name}>
              <strong>{tool.name}</strong>: {tool.description}
            </li>
          ))}
        </ul>
        <button onClick={refresh}>Refresh</button>
      </div>
    );
  }
  */
  console.log('React hooks are available via @zap-proto/zap/react');
}

// Run the example
const arg = process.argv[2];

switch (arg) {
  case 'gateway':
    gatewayExample().catch(console.error);
    break;
  case 'typed':
    typedToolExample().catch(console.error);
    break;
  case 'streaming':
    streamingExample().catch(console.error);
    break;
  case 'react':
    reactHookExample();
    break;
  default:
    main().catch(console.error);
}
