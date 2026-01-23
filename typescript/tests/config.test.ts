import { describe, it, expect } from 'vitest';
import {
  DEFAULT_CONFIG,
  loadConfigFromEnv,
  mergeConfig,
  type Config,
  type ServerConfig,
} from '../src/config.js';

describe('DEFAULT_CONFIG', () => {
  it('should have default listen and port', () => {
    expect(DEFAULT_CONFIG.listen).toBe('0.0.0.0');
    expect(DEFAULT_CONFIG.port).toBe(9999);
  });

  it('should have default log level', () => {
    expect(DEFAULT_CONFIG.logLevel).toBe('info');
  });

  it('should have empty servers array', () => {
    expect(DEFAULT_CONFIG.servers).toEqual([]);
  });
});

describe('mergeConfig', () => {
  it('should merge partial config with defaults', () => {
    const partial: Partial<Config> = { listen: '127.0.0.1' };
    const merged = mergeConfig(partial);

    expect(merged.listen).toBe('127.0.0.1');
    expect(merged.port).toBe(DEFAULT_CONFIG.port);
  });

  it('should override all fields when provided', () => {
    const full: Partial<Config> = { listen: 'custom.com', port: 8888 };
    const merged = mergeConfig(full);

    expect(merged.listen).toBe('custom.com');
    expect(merged.port).toBe(8888);
  });

  it('should return defaults when no config provided', () => {
    const merged = mergeConfig({});

    expect(merged.listen).toBe(DEFAULT_CONFIG.listen);
    expect(merged.port).toBe(DEFAULT_CONFIG.port);
  });

  it('should merge multiple configs in order', () => {
    const config1: Partial<Config> = { listen: 'first.com' };
    const config2: Partial<Config> = { listen: 'second.com', port: 8000 };
    const merged = mergeConfig(config1, config2);

    expect(merged.listen).toBe('second.com');
    expect(merged.port).toBe(8000);
  });
});

describe('loadConfigFromEnv', () => {
  it('should return partial config object', () => {
    const config = loadConfigFromEnv();
    // Should return an object (might be empty if no env vars set)
    expect(typeof config).toBe('object');
  });
});
