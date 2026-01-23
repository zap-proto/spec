import { describe, it, expect } from 'vitest';
import {
  ZapError,
  ConnectionError,
  TransportError,
  ProtocolError,
  TimeoutError,
  ServerError,
  ToolNotFoundError,
  ResourceNotFoundError,
  InvalidArgumentError,
} from '../src/error.js';

describe('ZapError', () => {
  it('should create a ZapError', () => {
    const error = new ZapError('Something went wrong');
    expect(error.message).toBe('Something went wrong');
    expect(error.name).toBe('ZapError');
  });

  it('should be instanceof Error', () => {
    const error = new ZapError('test');
    expect(error).toBeInstanceOf(Error);
  });
});

describe('ConnectionError', () => {
  it('should create a ConnectionError', () => {
    const error = new ConnectionError('Failed to connect');
    expect(error.message).toBe('Failed to connect');
    expect(error.name).toBe('ConnectionError');
  });

  it('should be instanceof ZapError', () => {
    const error = new ConnectionError('test');
    expect(error).toBeInstanceOf(ZapError);
  });
});

describe('TransportError', () => {
  it('should create a TransportError', () => {
    const error = new TransportError('Transport failed');
    expect(error.message).toBe('Transport failed');
    expect(error.name).toBe('TransportError');
  });

  it('should be instanceof ZapError', () => {
    const error = new TransportError('test');
    expect(error).toBeInstanceOf(ZapError);
  });
});

describe('ProtocolError', () => {
  it('should create a ProtocolError', () => {
    const error = new ProtocolError('Invalid protocol');
    expect(error.message).toBe('Invalid protocol');
    expect(error.name).toBe('ProtocolError');
  });

  it('should be instanceof ZapError', () => {
    const error = new ProtocolError('test');
    expect(error).toBeInstanceOf(ZapError);
  });
});

describe('TimeoutError', () => {
  it('should create a TimeoutError', () => {
    const error = new TimeoutError('Request timed out');
    expect(error.message).toBe('Request timed out');
    expect(error.name).toBe('TimeoutError');
  });

  it('should be instanceof ZapError', () => {
    const error = new TimeoutError('test');
    expect(error).toBeInstanceOf(ZapError);
  });
});

describe('ServerError', () => {
  it('should create a ServerError', () => {
    const error = new ServerError('Internal server error');
    expect(error.message).toBe('Internal server error');
    expect(error.name).toBe('ServerError');
  });

  it('should be instanceof ZapError', () => {
    const error = new ServerError('test');
    expect(error).toBeInstanceOf(ZapError);
  });
});

describe('ToolNotFoundError', () => {
  it('should create a ToolNotFoundError', () => {
    const error = new ToolNotFoundError('search');
    // Message includes tool name
    expect(error.message).toContain('search');
    expect(error.name).toBe('ToolNotFoundError');
  });

  it('should be instanceof ZapError', () => {
    const error = new ToolNotFoundError('test');
    expect(error).toBeInstanceOf(ZapError);
  });
});

describe('ResourceNotFoundError', () => {
  it('should create a ResourceNotFoundError', () => {
    const error = new ResourceNotFoundError('config.json');
    // Message includes resource name
    expect(error.message).toContain('config.json');
    expect(error.name).toBe('ResourceNotFoundError');
  });

  it('should be instanceof ZapError', () => {
    const error = new ResourceNotFoundError('test');
    expect(error).toBeInstanceOf(ZapError);
  });
});

describe('InvalidArgumentError', () => {
  it('should create an InvalidArgumentError', () => {
    const error = new InvalidArgumentError('count');
    // Message includes argument name
    expect(error.message).toContain('count');
    expect(error.name).toBe('InvalidArgumentError');
  });

  it('should be instanceof ZapError', () => {
    const error = new InvalidArgumentError('test');
    expect(error).toBeInstanceOf(ZapError);
  });
});

describe('Error inheritance chain', () => {
  it('should catch specific error types', () => {
    try {
      throw new ConnectionError('test');
    } catch (e) {
      if (e instanceof ConnectionError) {
        expect(true).toBe(true);
      } else {
        expect.fail('Should catch ConnectionError');
      }
    }
  });

  it('should catch ZapError for all error types', () => {
    const errors = [
      new ConnectionError('test'),
      new TransportError('test'),
      new ProtocolError('test'),
      new TimeoutError('test'),
      new ServerError('test'),
      new ToolNotFoundError('test'),
      new ResourceNotFoundError('test'),
      new InvalidArgumentError('test'),
    ];

    for (const error of errors) {
      expect(error).toBeInstanceOf(ZapError);
      expect(error).toBeInstanceOf(Error);
    }
  });
});
