/**
 * Unit tests for the local-tokens module that backs MS365_MCP_FRONT_AUTH_MODE=local.
 *
 * What we're checking:
 *  - tokens we issue verify cleanly with the same secret;
 *  - tampered tokens, wrong-secret tokens, and tokens past their TTL are
 *    rejected with the right error codes;
 *  - the access/refresh `typ` claim is enforced when callers ask for it;
 *  - TTL and signing-secret env vars are read with sensible fallbacks.
 *
 * No real tokens or secrets are logged.
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
  DEFAULT_TTL_SECONDS,
  LocalTokenError,
  _resetEphemeralSecretForTests,
  issueLocalToken,
  resolveSigningSecret,
  resolveTtlSeconds,
  verifyLocalToken,
} from '../src/lib/local-tokens.js';

const SECRET_A = Buffer.from('a'.repeat(64), 'utf8');
const SECRET_B = Buffer.from('b'.repeat(64), 'utf8');

describe('local-tokens: issue + verify', () => {
  afterEach(() => {
    delete process.env.MS365_MCP_LOCAL_TOKEN_SECRET;
    delete process.env.MS365_MCP_FRONT_TOKEN_TTL_SECONDS;
    _resetEphemeralSecretForTests();
  });

  it('issues a 3-segment JWT-shaped token', () => {
    const token = issueLocalToken(
      { subject: 'home-account-1', type: 'access', ttlSeconds: 60 },
      SECRET_A
    );
    expect(token.split('.')).toHaveLength(3);
  });

  it('verifies a freshly issued token', () => {
    const token = issueLocalToken(
      { subject: 'home-account-1', type: 'access', ttlSeconds: 60 },
      SECRET_A
    );
    const payload = verifyLocalToken(token, SECRET_A, { expectedType: 'access' });
    expect(payload.sub).toBe('home-account-1');
    expect(payload.typ).toBe('access');
    expect(payload.iss).toBe('ms-365-mcp-server');
    expect(payload.aud).toBe('ms-365-mcp-server/mcp');
    expect(payload.exp - payload.iat).toBe(60);
  });

  it('rejects token signed with a different secret', () => {
    const token = issueLocalToken(
      { subject: 'sub', type: 'access', ttlSeconds: 60 },
      SECRET_A
    );
    expect(() => verifyLocalToken(token, SECRET_B)).toThrowError(LocalTokenError);
    try {
      verifyLocalToken(token, SECRET_B);
    } catch (e) {
      expect((e as LocalTokenError).code).toBe('bad_signature');
    }
  });

  it('rejects tampered payload', () => {
    const token = issueLocalToken(
      { subject: 'sub', type: 'access', ttlSeconds: 60 },
      SECRET_A
    );
    const [h, p, s] = token.split('.');
    const decoded = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
    decoded.sub = 'attacker';
    const tampered = `${h}.${Buffer.from(JSON.stringify(decoded), 'utf8').toString('base64url')}.${s}`;
    expect(() => verifyLocalToken(tampered, SECRET_A)).toThrowError(LocalTokenError);
  });

  it('rejects malformed token (not 3 segments)', () => {
    expect(() => verifyLocalToken('not.a.jwt.token', SECRET_A)).toThrowError(LocalTokenError);
    expect(() => verifyLocalToken('only.two', SECRET_A)).toThrowError(LocalTokenError);
  });

  it('rejects expired token', () => {
    const token = issueLocalToken(
      { subject: 'sub', type: 'access', ttlSeconds: -120 },
      SECRET_A
    );
    expect(() => verifyLocalToken(token, SECRET_A)).toThrowError(LocalTokenError);
    try {
      verifyLocalToken(token, SECRET_A);
    } catch (e) {
      expect((e as LocalTokenError).code).toBe('expired');
    }
  });

  it('enforces expectedType (access vs refresh)', () => {
    const refresh = issueLocalToken(
      { subject: 'sub', type: 'refresh', ttlSeconds: 600 },
      SECRET_A
    );
    expect(() =>
      verifyLocalToken(refresh, SECRET_A, { expectedType: 'access' })
    ).toThrowError(LocalTokenError);
    expect(verifyLocalToken(refresh, SECRET_A, { expectedType: 'refresh' }).typ).toBe('refresh');
  });

  it('rejects wrong-alg header', () => {
    // Forge a token with alg=none — should be rejected even if we re-sign with the secret
    const hdr = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' }), 'utf8').toString(
      'base64url'
    );
    const pl = Buffer.from(
      JSON.stringify({
        iss: 'ms-365-mcp-server',
        aud: 'ms-365-mcp-server/mcp',
        sub: 'x',
        typ: 'access',
        iat: 0,
        exp: 9999999999,
        jti: 'jti',
      }),
      'utf8'
    ).toString('base64url');
    const forged = `${hdr}.${pl}.`;
    expect(() => verifyLocalToken(forged, SECRET_A)).toThrowError(LocalTokenError);
  });
});

describe('local-tokens: env var resolution', () => {
  afterEach(() => {
    delete process.env.MS365_MCP_LOCAL_TOKEN_SECRET;
    delete process.env.MS365_MCP_FRONT_TOKEN_TTL_SECONDS;
    _resetEphemeralSecretForTests();
  });

  it('resolveTtlSeconds falls back to default when unset', () => {
    expect(resolveTtlSeconds()).toBe(DEFAULT_TTL_SECONDS);
  });

  it('resolveTtlSeconds reads a positive integer env var', () => {
    process.env.MS365_MCP_FRONT_TOKEN_TTL_SECONDS = '3600';
    expect(resolveTtlSeconds()).toBe(3600);
  });

  it('resolveTtlSeconds falls back on garbage input', () => {
    process.env.MS365_MCP_FRONT_TOKEN_TTL_SECONDS = 'not-a-number';
    expect(resolveTtlSeconds()).toBe(DEFAULT_TTL_SECONDS);
  });

  it('resolveTtlSeconds falls back on zero / negative', () => {
    process.env.MS365_MCP_FRONT_TOKEN_TTL_SECONDS = '0';
    expect(resolveTtlSeconds()).toBe(DEFAULT_TTL_SECONDS);
    process.env.MS365_MCP_FRONT_TOKEN_TTL_SECONDS = '-30';
    expect(resolveTtlSeconds()).toBe(DEFAULT_TTL_SECONDS);
  });

  it('resolveSigningSecret prefers env var when long enough', () => {
    process.env.MS365_MCP_LOCAL_TOKEN_SECRET = 'a'.repeat(64);
    const a = resolveSigningSecret();
    expect(a.toString('utf8')).toBe('a'.repeat(64));
    // calling twice returns the same value
    expect(resolveSigningSecret().toString('utf8')).toBe('a'.repeat(64));
  });

  it('resolveSigningSecret rejects a too-short env var and uses ephemeral', () => {
    process.env.MS365_MCP_LOCAL_TOKEN_SECRET = 'short';
    const s1 = resolveSigningSecret();
    expect(s1.length).toBe(32); // 32 random bytes
  });

  it('ephemeral secret is stable within a process', () => {
    const s1 = resolveSigningSecret();
    const s2 = resolveSigningSecret();
    expect(s1.equals(s2)).toBe(true);
  });
});

describe('local-tokens: round-trip with resolved secret', () => {
  beforeEach(() => {
    process.env.MS365_MCP_LOCAL_TOKEN_SECRET = 'x'.repeat(64);
    _resetEphemeralSecretForTests();
  });
  afterEach(() => {
    delete process.env.MS365_MCP_LOCAL_TOKEN_SECRET;
    _resetEphemeralSecretForTests();
  });

  it('issues and verifies using the resolved secret (no explicit secret arg)', () => {
    const token = issueLocalToken({ subject: 'me', type: 'access', ttlSeconds: 60 });
    const payload = verifyLocalToken(token);
    expect(payload.sub).toBe('me');
  });
});
