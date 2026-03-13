/**
 * ZAP binary wire protocol — transport-agnostic, universal JavaScript.
 *
 * Wire format:
 *   [0x5A 0x41 0x50 0x01]  4 bytes  magic ("ZAP\x01")
 *   [type]                 1 byte   message type
 *   [length]               4 bytes  payload length (big-endian)
 *   [payload]              N bytes  JSON-encoded payload
 *
 * This module uses only Uint8Array/DataView — works in browsers,
 * Node.js, Cloudflare Workers, Deno, and any modern JS runtime.
 */

// ── Magic & Constants ─────────────────────────────────────────────────

/** ZAP protocol magic bytes */
export const ZAP_MAGIC = new Uint8Array([0x5a, 0x41, 0x50, 0x01]);

/** Header size: 4 (magic) + 1 (type) + 4 (length) = 9 bytes */
export const HEADER_SIZE = 9;

/** Maximum payload size (16 MB) */
export const MAX_PAYLOAD_SIZE = 16 * 1024 * 1024;

/** Protocol version */
export const PROTOCOL_VERSION = 1;

// ── Message Types ─────────────────────────────────────────────────────

/**
 * ZAP message types.
 *
 * 0x01-0x0F: Connection lifecycle
 * 0x10-0x1F: RPC operations (push/pull/resolve/reject/release)
 * 0x20-0x2F: MCP tool operations (backward compat)
 * 0x30-0x3F: MCP resource operations
 * 0x40-0x4F: MCP prompt operations
 * 0xF0-0xFF: Control
 */
export const MessageType = {
  // Connection lifecycle
  Init:     0x01,
  InitAck:  0x02,

  // RPC (Cap'n Web-inspired object-capability protocol)
  Push:     0x10,  // Call a method → creates an export entry
  Pull:     0x11,  // Request result delivery for a push
  Resolve:  0x12,  // Deliver resolved value
  Reject:   0x13,  // Deliver error
  Release:  0x14,  // Release a capability reference

  // MCP tool operations (backward compat with @hanzo/mcp)
  ListTools:          0x20,
  ListToolsResponse:  0x21,
  CallTool:           0x22,
  CallToolResponse:   0x23,

  // MCP resource operations
  ListResources:          0x30,
  ListResourcesResponse:  0x31,
  ReadResource:           0x32,
  ReadResourceResponse:   0x33,

  // MCP prompt operations
  ListPrompts:          0x40,
  ListPromptsResponse:  0x41,
  GetPrompt:            0x42,
  GetPromptResponse:    0x43,

  // Control
  Ping:   0xf0,
  Pong:   0xf1,
  Error:  0xff,
} as const;

export type MessageTypeValue = (typeof MessageType)[keyof typeof MessageType];

// ── Encode / Decode ───────────────────────────────────────────────────

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

/**
 * Encode a ZAP message into binary frame.
 *
 * @param type - Message type byte
 * @param payload - Object to JSON-serialize as payload
 * @returns Uint8Array containing the complete ZAP frame
 */
export function encode(type: number, payload: unknown): Uint8Array {
  const json = textEncoder.encode(JSON.stringify(payload));

  if (json.length > MAX_PAYLOAD_SIZE) {
    throw new Error(`ZAP payload exceeds max size: ${json.length} > ${MAX_PAYLOAD_SIZE}`);
  }

  const frame = new Uint8Array(HEADER_SIZE + json.length);
  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);

  // Magic bytes
  frame.set(ZAP_MAGIC, 0);
  // Type
  view.setUint8(4, type);
  // Payload length (big-endian)
  view.setUint32(5, json.length, false);
  // Payload
  frame.set(json, HEADER_SIZE);

  return frame;
}

/**
 * Decode a ZAP binary frame.
 *
 * Supports three wire formats (fallback chain):
 * 1. ZAP magic + BE length (canonical)
 * 2. LE length prefix + type (hanzo-dev compat)
 * 3. Plain JSON (MCP fallback)
 *
 * @param data - Binary frame data
 * @returns Decoded message or null if invalid
 */
export function decode(data: Uint8Array): ZapFrame | null {
  if (data.length < HEADER_SIZE) {
    // Try LE format (hanzo-dev compat): [length:4 LE][type:1][payload]
    if (data.length >= 5) {
      return decodeLegacyLE(data);
    }
    return null;
  }

  // Check magic bytes
  if (
    data[0] === 0x5a &&
    data[1] === 0x41 &&
    data[2] === 0x50 &&
    data[3] === 0x01
  ) {
    return decodeCanonical(data);
  }

  // Try LE format
  if (data.length >= 5) {
    const result = decodeLegacyLE(data);
    if (result) return result;
  }

  // Try plain JSON
  return decodePlainJSON(data);
}

/** Decode canonical ZAP format: [magic:4][type:1][length:4 BE][payload] */
function decodeCanonical(data: Uint8Array): ZapFrame | null {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const type = view.getUint8(4);
  const length = view.getUint32(5, false); // big-endian

  if (length > MAX_PAYLOAD_SIZE) return null;
  if (data.length < HEADER_SIZE + length) return null;

  const jsonBytes = data.subarray(HEADER_SIZE, HEADER_SIZE + length);
  const payload = length > 0 ? JSON.parse(textDecoder.decode(jsonBytes)) : null;

  return { type, payload, format: 'zap' };
}

/** Decode legacy LE format: [length:4 LE][type:1][payload] */
function decodeLegacyLE(data: Uint8Array): ZapFrame | null {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const totalLen = view.getUint32(0, true); // little-endian

  if (totalLen <= 0 || totalLen > MAX_PAYLOAD_SIZE || data.length < 4 + totalLen) {
    return null;
  }

  const type = view.getUint8(4);
  const payloadBytes = data.subarray(5, 4 + totalLen);

  try {
    const payload = payloadBytes.length > 0
      ? JSON.parse(textDecoder.decode(payloadBytes))
      : null;
    return { type, payload, format: 'le' };
  } catch {
    return null;
  }
}

/** Decode plain JSON (MCP stdio fallback) */
function decodePlainJSON(data: Uint8Array): ZapFrame | null {
  try {
    const payload = JSON.parse(textDecoder.decode(data));
    return { type: MessageType.Push, payload, format: 'json' };
  } catch {
    return null;
  }
}

/**
 * Incrementally extract complete frames from a buffer.
 * Returns extracted frames and the remaining buffer.
 */
export function extractFrames(buffer: Uint8Array): {
  frames: ZapFrame[];
  remaining: Uint8Array;
} {
  const frames: ZapFrame[] = [];
  let offset = 0;

  while (offset < buffer.length) {
    // Need at least magic (4) + type (1) + length (4) = 9 bytes
    if (buffer.length - offset < HEADER_SIZE) break;

    // Check for magic bytes
    if (
      buffer[offset] === 0x5a &&
      buffer[offset + 1] === 0x41 &&
      buffer[offset + 2] === 0x50 &&
      buffer[offset + 3] === 0x01
    ) {
      const view = new DataView(buffer.buffer, buffer.byteOffset + offset, buffer.byteLength - offset);
      const payloadLen = view.getUint32(5, false);

      if (payloadLen > MAX_PAYLOAD_SIZE) {
        // Corrupt frame — skip magic and try again
        offset += 4;
        continue;
      }

      const frameSize = HEADER_SIZE + payloadLen;
      if (buffer.length - offset < frameSize) break; // Incomplete frame

      const frameData = buffer.subarray(offset, offset + frameSize);
      const frame = decodeCanonical(frameData);
      if (frame) frames.push(frame);
      offset += frameSize;
    } else {
      // Skip byte and try to find next magic
      offset++;
    }
  }

  return {
    frames,
    remaining: buffer.subarray(offset),
  };
}

// ── Types ─────────────────────────────────────────────────────────────

/** Decoded ZAP frame */
export interface ZapFrame {
  type: number;
  payload: unknown;
  /** Which wire format was decoded */
  format: 'zap' | 'le' | 'json';
}

/** RPC request payload (inside a Push message) */
export interface RpcRequest {
  id: string;
  /** Target export ID (0 = main interface) */
  target?: number;
  method: string;
  params?: unknown;
  /** Pipeline: reference to result of a previous push */
  pipeline?: string;
}

/** RPC response payload (inside a Resolve/Reject message) */
export interface RpcResponse {
  id: string;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

/** Capability reference marker in JSON payloads */
export interface CapabilityRef {
  __cap: true;
  exportId: number;
  methods?: string[];
}

/** Check if a value is a capability reference */
export function isCapabilityRef(v: unknown): v is CapabilityRef {
  return typeof v === 'object' && v !== null && '__cap' in v && (v as CapabilityRef).__cap === true;
}
