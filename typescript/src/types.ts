/**
 * ZAP type definitions
 */

/** Tool definition */
export interface Tool {
  name: string;
  description: string;
  schema: Record<string, unknown>;
}

/** Resource definition */
export interface Resource {
  uri: string;
  name: string;
  description: string;
  mimeType: string;
}

/** Resource content */
export interface ResourceContent {
  uri: string;
  mimeType: string;
  content: string | Uint8Array;
}

/** Prompt definition */
export interface Prompt {
  name: string;
  description: string;
  arguments: PromptArgument[];
}

/** Prompt argument */
export interface PromptArgument {
  name: string;
  description: string;
  required: boolean;
}

/** Prompt message */
export interface PromptMessage {
  role: 'user' | 'assistant' | 'system';
  content: TextContent | ImageContent | ResourceContent;
}

/** Text content */
export interface TextContent {
  type: 'text';
  text: string;
}

/** Image content */
export interface ImageContent {
  type: 'image';
  data: Uint8Array;
  mimeType: string;
}

/** Server info */
export interface ServerInfo {
  name: string;
  version: string;
  capabilities: ServerCapabilities;
}

/** Server capabilities */
export interface ServerCapabilities {
  tools: boolean;
  resources: boolean;
  prompts: boolean;
  logging: boolean;
}

/** Connected server info */
export interface ConnectedServer {
  id: string;
  name: string;
  url: string;
  status: ServerStatus;
  tools: number;
  resources: number;
}

/** Server status */
export type ServerStatus = 'connecting' | 'connected' | 'disconnected' | 'error';

/** Transport type */
export type Transport = 'stdio' | 'http' | 'websocket' | 'zap' | 'unix';

/** Log level */
export type LogLevel = 'debug' | 'info' | 'warn' | 'error';
