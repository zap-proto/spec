# @zap-proto/zap

<p align="center">
  <strong>ZAP - Zero-Copy App Proto for TypeScript</strong>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@zap-proto/zap"><img src="https://img.shields.io/npm/v/@zap-proto/zap.svg" alt="npm"></a>
  <a href="https://www.npmjs.com/package/@zap-proto/zap"><img src="https://img.shields.io/node/v/@zap-proto/zap.svg" alt="Node"></a>
  <a href="https://github.com/zap-proto/zap/actions"><img src="https://github.com/zap-proto/zap/workflows/CI/badge.svg" alt="CI"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
</p>

High-performance Cap'n Proto RPC for AI agent communication.

## Installation

```bash
npm install @zap-proto/zap

# With pnpm (recommended)
pnpm add @zap-proto/zap

# With yarn
yarn add @zap-proto/zap
```

## Quick Start

```typescript
import { Client } from '@zap-proto/zap';

async function main() {
  // Connect to a ZAP gateway
  const client = await Client.connect('zap://localhost:9999');

  // List available tools
  const tools = await client.listTools();
  console.log('Available tools:', tools);

  // Call a tool
  const result = await client.callTool('search', {
    query: 'machine learning'
  });
  console.log('Result:', result);

  // Read a resource
  const content = await client.readResource('file:///data/config.json');
  console.log('Content:', content);

  // List prompts
  const prompts = await client.listPrompts();
  console.log('Prompts:', prompts);

  // Get a specific prompt
  const messages = await client.getPrompt('code-review', {
    file: 'main.ts'
  });
  console.log('Messages:', messages);
}

main();
```

## Features

- **Zero-copy serialization** via Cap'n Proto
- **Promise-based API** - Native async/await
- **Multi-transport** - TCP, WebSocket, HTTP/SSE
- **MCP compatible** - Works with Model Context Protocol servers
- **TypeScript-first** - Full type definitions included
- **Browser & Node.js** - Works in both environments

## Client API

### Connection

```typescript
import { Client } from '@zap-proto/zap';

// TCP connection (default)
const client = await Client.connect('zap://localhost:9999');

// WebSocket
const client = await Client.connect('ws://localhost:9999/ws');

// HTTP/SSE
const client = await Client.connect('http://localhost:8080/mcp');

// With options
const client = await Client.connect('zap://localhost:9999', {
  timeout: 30000,
  retries: 3
});
```

### Tools

```typescript
// List all available tools
const tools = await client.listTools();
for (const tool of tools) {
  console.log(`${tool.name}: ${tool.description}`);
}

// Call a tool with arguments
const result = await client.callTool('search', {
  query: 'hello world',
  limit: 10
});

// Handle tool result
if (result.isError) {
  console.error('Error:', result.error);
} else {
  console.log('Content:', result.content);
}
```

### Resources

```typescript
// List all resources
const resources = await client.listResources();
for (const resource of resources) {
  console.log(`${resource.uri}: ${resource.name}`);
}

// Read a resource
const content = await client.readResource('file:///data/config.json');
console.log(content.text); // or content.blob for binary

// Subscribe to resource updates
const subscription = client.subscribeResource('file:///data/live.json');
for await (const update of subscription) {
  console.log('Updated:', update);
}
```

### Prompts

```typescript
// List prompts
const prompts = await client.listPrompts();
for (const prompt of prompts) {
  console.log(`${prompt.name}: ${prompt.description}`);
}

// Get prompt with arguments
const messages = await client.getPrompt('code-review', {
  language: 'typescript',
  file: 'main.ts'
});
for (const msg of messages) {
  console.log(`${msg.role}: ${msg.content}`);
}
```

## Gateway

Run a ZAP gateway that aggregates multiple MCP servers:

```typescript
import { Gateway } from '@zap-proto/zap';

const gateway = new Gateway({
  host: '0.0.0.0',
  port: 9999
});

// Add MCP servers
gateway.addServer('filesystem', 'stdio://npx @modelcontextprotocol/server-filesystem /data');
gateway.addServer('database', 'http://localhost:8080/mcp');
gateway.addServer('search', 'ws://localhost:9000/ws');

// Start gateway
await gateway.start();
```

## Types

Full TypeScript definitions are included:

```typescript
import type {
  Tool,
  ToolResult,
  Resource,
  ResourceContent,
  Prompt,
  PromptMessage,
  ServerInfo
} from '@zap-proto/zap';

// Tool definition
interface Tool {
  name: string;
  description: string;
  inputSchema: JsonSchema;
}

// Resource definition
interface Resource {
  uri: string;
  name: string;
  description?: string;
  mimeType?: string;
}

// Prompt definition
interface Prompt {
  name: string;
  description?: string;
  arguments?: PromptArgument[];
}
```

## React Hooks (Optional)

```typescript
import { useZap, useTools, useResources } from '@zap-proto/zap/react';

function MyComponent() {
  const { client, connected } = useZap('zap://localhost:9999');
  const { tools, loading: toolsLoading } = useTools(client);
  const { resources, loading: resourcesLoading } = useResources(client);

  if (!connected) return <div>Connecting...</div>;

  return (
    <div>
      <h2>Tools ({tools.length})</h2>
      {tools.map(tool => (
        <div key={tool.name}>{tool.name}</div>
      ))}
    </div>
  );
}
```

## Browser Usage

```html
<script type="module">
import { Client } from 'https://esm.sh/@zap-proto/zap';

const client = await Client.connect('wss://api.example.com/zap');
const tools = await client.listTools();
console.log(tools);
</script>
```

## Development

```bash
# Clone the repository
git clone https://github.com/zap-proto/zap
cd zap/typescript

# Install dependencies
pnpm install

# Build
pnpm build

# Run tests
pnpm test

# Run tests with coverage
pnpm test -- --coverage

# Type checking
pnpm typecheck

# Linting
pnpm lint
```

## Links

- [GitHub](https://github.com/zap-proto/zap)
- [Documentation](https://zap-proto.github.io/zap)
- [npm](https://www.npmjs.com/package/@zap-proto/zap)
- [Hanzo AI](https://hanzo.ai)

## License

MIT
