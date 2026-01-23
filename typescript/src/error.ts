/**
 * ZAP error types
 */

/** Base ZAP error */
export class ZapError extends Error {
  readonly code: string;
  readonly details: Record<string, unknown> | undefined;

  constructor(
    message: string,
    code = 'ZAP_ERROR',
    details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'ZapError';
    this.code = code;
    this.details = details;
    Object.setPrototypeOf(this, ZapError.prototype);
  }
}

/** Connection error */
export class ConnectionError extends ZapError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'CONNECTION_ERROR', details);
    this.name = 'ConnectionError';
    Object.setPrototypeOf(this, ConnectionError.prototype);
  }
}

/** Transport error */
export class TransportError extends ZapError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'TRANSPORT_ERROR', details);
    this.name = 'TransportError';
    Object.setPrototypeOf(this, TransportError.prototype);
  }
}

/** Protocol error */
export class ProtocolError extends ZapError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'PROTOCOL_ERROR', details);
    this.name = 'ProtocolError';
    Object.setPrototypeOf(this, ProtocolError.prototype);
  }
}

/** Timeout error */
export class TimeoutError extends ZapError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'TIMEOUT_ERROR', details);
    this.name = 'TimeoutError';
    Object.setPrototypeOf(this, TimeoutError.prototype);
  }
}

/** Server error */
export class ServerError extends ZapError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'SERVER_ERROR', details);
    this.name = 'ServerError';
    Object.setPrototypeOf(this, ServerError.prototype);
  }
}

/** Tool not found error */
export class ToolNotFoundError extends ZapError {
  constructor(toolName: string) {
    super(`Tool not found: ${toolName}`, 'TOOL_NOT_FOUND', { toolName });
    this.name = 'ToolNotFoundError';
    Object.setPrototypeOf(this, ToolNotFoundError.prototype);
  }
}

/** Resource not found error */
export class ResourceNotFoundError extends ZapError {
  constructor(uri: string) {
    super(`Resource not found: ${uri}`, 'RESOURCE_NOT_FOUND', { uri });
    this.name = 'ResourceNotFoundError';
    Object.setPrototypeOf(this, ResourceNotFoundError.prototype);
  }
}

/** Invalid argument error */
export class InvalidArgumentError extends ZapError {
  constructor(argument: string, reason: string) {
    super(`Invalid argument '${argument}': ${reason}`, 'INVALID_ARGUMENT', {
      argument,
      reason,
    });
    this.name = 'InvalidArgumentError';
    Object.setPrototypeOf(this, InvalidArgumentError.prototype);
  }
}
