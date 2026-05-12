/**
 * Tests for resolveFrontAuthMode: env-var-driven switch between Microsoft and
 * local front auth, with safe fallback on garbage input.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('../src/logger.js', () => ({
  default: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
  enableConsoleLogging: vi.fn(),
}));

import { resolveFrontAuthMode } from '../src/server.js';

describe('resolveFrontAuthMode', () => {
  afterEach(() => {
    delete process.env.MS365_MCP_FRONT_AUTH_MODE;
  });

  it("defaults to 'microsoft' when unset", () => {
    expect(resolveFrontAuthMode()).toBe('microsoft');
  });

  it("returns 'microsoft' when explicitly set", () => {
    process.env.MS365_MCP_FRONT_AUTH_MODE = 'microsoft';
    expect(resolveFrontAuthMode()).toBe('microsoft');
  });

  it("returns 'local' when set to 'local'", () => {
    process.env.MS365_MCP_FRONT_AUTH_MODE = 'local';
    expect(resolveFrontAuthMode()).toBe('local');
  });

  it('is case-insensitive', () => {
    process.env.MS365_MCP_FRONT_AUTH_MODE = 'LOCAL';
    expect(resolveFrontAuthMode()).toBe('local');
    process.env.MS365_MCP_FRONT_AUTH_MODE = 'Microsoft';
    expect(resolveFrontAuthMode()).toBe('microsoft');
  });

  it("falls back to 'microsoft' on unrecognized value (preserves safety)", () => {
    process.env.MS365_MCP_FRONT_AUTH_MODE = 'lcoal'; // typo
    expect(resolveFrontAuthMode()).toBe('microsoft');
  });
});
