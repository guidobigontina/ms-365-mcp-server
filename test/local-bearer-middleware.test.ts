/**
 * Tests for localBearerTokenAuthMiddleware: ensures /mcp accepts only valid
 * server-issued local access tokens when MS365_MCP_FRONT_AUTH_MODE=local.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../src/logger.js', () => ({
  default: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
  enableConsoleLogging: vi.fn(),
}));

import {
  _resetEphemeralSecretForTests,
  issueLocalToken,
  resolveSigningSecret,
} from '../src/lib/local-tokens.js';
import { localBearerTokenAuthMiddleware } from '../src/lib/microsoft-auth.js';

function makeReqRes(headers: Record<string, string> = {}) {
  const req: any = {
    headers,
    secure: false,
    get: (h: string) => (h.toLowerCase() === 'host' ? 'localhost:3000' : undefined),
  };
  const res: any = {
    statusCode: 200,
    headers: {} as Record<string, string>,
    status(c: number) {
      this.statusCode = c;
      return this;
    },
    set(name: string, value: string) {
      this.headers[name] = value;
      return this;
    },
    json(body: unknown) {
      this.body = body;
      return this;
    },
  };
  return { req, res };
}

describe('localBearerTokenAuthMiddleware', () => {
  beforeEach(() => {
    process.env.MS365_MCP_LOCAL_TOKEN_SECRET = 'k'.repeat(64);
    _resetEphemeralSecretForTests();
  });

  afterEach(() => {
    delete process.env.MS365_MCP_LOCAL_TOKEN_SECRET;
    _resetEphemeralSecretForTests();
  });

  it('rejects requests with no Authorization header', () => {
    const { req, res } = makeReqRes();
    const next = vi.fn();
    localBearerTokenAuthMiddleware(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
    expect(res.headers['WWW-Authenticate']).toContain('Bearer');
    expect(res.body.error).toBe('invalid_token');
  });

  it('rejects malformed authorization header', () => {
    const { req, res } = makeReqRes({ authorization: 'Bearer not.a.real.token' });
    const next = vi.fn();
    localBearerTokenAuthMiddleware(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
  });

  it('rejects refresh token used as access (wrong typ)', () => {
    const refresh = issueLocalToken(
      { subject: 'me', type: 'refresh', ttlSeconds: 60 },
      resolveSigningSecret()
    );
    const { req, res } = makeReqRes({ authorization: `Bearer ${refresh}` });
    const next = vi.fn();
    localBearerTokenAuthMiddleware(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
  });

  it('accepts a valid access token and attaches localAuth', () => {
    const access = issueLocalToken(
      { subject: 'home-account-X', type: 'access', ttlSeconds: 60 },
      resolveSigningSecret()
    );
    const { req, res } = makeReqRes({ authorization: `Bearer ${access}` });
    const next = vi.fn();
    localBearerTokenAuthMiddleware(req, res, next);
    expect(next).toHaveBeenCalled();
    expect(req.localAuth?.sub).toBe('home-account-X');
    expect(req.localAuth?.typ).toBe('access');
  });

  it('rejects expired access token with WWW-Authenticate', () => {
    const expired = issueLocalToken(
      { subject: 'home-account-Y', type: 'access', ttlSeconds: -120 },
      resolveSigningSecret()
    );
    const { req, res } = makeReqRes({ authorization: `Bearer ${expired}` });
    const next = vi.fn();
    localBearerTokenAuthMiddleware(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
    expect(res.headers['WWW-Authenticate']).toContain('Bearer');
    expect(res.headers['WWW-Authenticate']).toContain('expired');
  });
});
