import crypto from 'node:crypto';
import logger from '../logger.js';

const ISSUER = 'ms-365-mcp-server';
const AUDIENCE = 'ms-365-mcp-server/mcp';

export const DEFAULT_TTL_SECONDS = 604800; // 7 days

export type LocalTokenType = 'access' | 'refresh';

export interface LocalTokenPayload {
  iss: string;
  aud: string;
  sub: string;
  typ: LocalTokenType;
  iat: number;
  exp: number;
  jti: string;
}

export interface IssueOptions {
  subject: string;
  type: LocalTokenType;
  ttlSeconds: number;
}

function base64UrlEncode(input: Buffer | string): string {
  const buf = typeof input === 'string' ? Buffer.from(input, 'utf8') : input;
  return buf.toString('base64url');
}

function base64UrlDecode(input: string): Buffer {
  return Buffer.from(input, 'base64url');
}

function timingSafeEqualStrings(a: string, b: string): boolean {
  const aBuf = Buffer.from(a, 'utf8');
  const bBuf = Buffer.from(b, 'utf8');
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

/**
 * Reads MS365_MCP_FRONT_TOKEN_TTL_SECONDS env var, falling back to the default.
 * Values that fail to parse as a positive integer fall back to the default.
 */
export function resolveTtlSeconds(): number {
  const raw = process.env.MS365_MCP_FRONT_TOKEN_TTL_SECONDS?.trim();
  if (!raw) return DEFAULT_TTL_SECONDS;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    logger.warn(
      `Invalid MS365_MCP_FRONT_TOKEN_TTL_SECONDS=${raw}; falling back to default ${DEFAULT_TTL_SECONDS}s`
    );
    return DEFAULT_TTL_SECONDS;
  }
  return parsed;
}

/**
 * Returns the secret used to sign local tokens.
 * Order of resolution:
 *  1. MS365_MCP_LOCAL_TOKEN_SECRET (preferred for stable signing across restarts)
 *  2. ephemeral process-wide random secret (logged as a warning — tokens won't survive restarts)
 *
 * The cached ephemeral secret is held in module-level state so repeated calls
 * within one process return the same value.
 */
let cachedEphemeralSecret: Buffer | null = null;

export function resolveSigningSecret(): Buffer {
  const envSecret = process.env.MS365_MCP_LOCAL_TOKEN_SECRET;
  if (envSecret && envSecret.length >= 32) {
    return Buffer.from(envSecret, 'utf8');
  }
  if (envSecret && envSecret.length < 32) {
    logger.warn(
      'MS365_MCP_LOCAL_TOKEN_SECRET is set but shorter than 32 bytes; rejecting and generating an ephemeral secret'
    );
  }
  if (!cachedEphemeralSecret) {
    cachedEphemeralSecret = crypto.randomBytes(32);
    logger.warn(
      'No MS365_MCP_LOCAL_TOKEN_SECRET configured — generated an ephemeral signing secret. Local tokens will not survive a server restart.'
    );
  }
  return cachedEphemeralSecret;
}

/**
 * For tests: reset cached ephemeral secret so the next resolve regenerates it.
 */
export function _resetEphemeralSecretForTests(): void {
  cachedEphemeralSecret = null;
}

function sign(headerB64: string, payloadB64: string, secret: Buffer): string {
  return crypto
    .createHmac('sha256', secret)
    .update(`${headerB64}.${payloadB64}`)
    .digest('base64url');
}

/**
 * Issues an HS256-signed JWT carrying the local-mode session subject.
 * The token is server-issued; it is never a Microsoft Graph access token.
 */
export function issueLocalToken(opts: IssueOptions, secret: Buffer = resolveSigningSecret()): string {
  const now = Math.floor(Date.now() / 1000);
  const payload: LocalTokenPayload = {
    iss: ISSUER,
    aud: AUDIENCE,
    sub: opts.subject,
    typ: opts.type,
    iat: now,
    exp: now + opts.ttlSeconds,
    jti: crypto.randomBytes(16).toString('base64url'),
  };

  const headerB64 = base64UrlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payloadB64 = base64UrlEncode(JSON.stringify(payload));
  const signature = sign(headerB64, payloadB64, secret);
  return `${headerB64}.${payloadB64}.${signature}`;
}

export class LocalTokenError extends Error {
  constructor(
    public readonly code:
      | 'malformed'
      | 'bad_signature'
      | 'expired'
      | 'wrong_issuer'
      | 'wrong_audience'
      | 'wrong_type',
    message: string
  ) {
    super(message);
    this.name = 'LocalTokenError';
  }
}

export interface VerifyOptions {
  expectedType?: LocalTokenType;
  clockSkewSeconds?: number;
}

/**
 * Verifies an HS256-signed local token.
 * Checks signature, expiry, issuer, audience, and (optionally) token type.
 */
export function verifyLocalToken(
  token: string,
  secret: Buffer = resolveSigningSecret(),
  opts: VerifyOptions = {}
): LocalTokenPayload {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new LocalTokenError('malformed', 'Token must have three segments');
  }
  const [headerB64, payloadB64, signature] = parts;

  let header: { alg?: string; typ?: string };
  try {
    header = JSON.parse(base64UrlDecode(headerB64).toString('utf8'));
  } catch {
    throw new LocalTokenError('malformed', 'Invalid header encoding');
  }
  if (header.alg !== 'HS256') {
    throw new LocalTokenError('malformed', `Unsupported alg: ${header.alg}`);
  }

  const expected = sign(headerB64, payloadB64, secret);
  if (!timingSafeEqualStrings(expected, signature)) {
    throw new LocalTokenError('bad_signature', 'Signature mismatch');
  }

  let payload: LocalTokenPayload;
  try {
    payload = JSON.parse(base64UrlDecode(payloadB64).toString('utf8'));
  } catch {
    throw new LocalTokenError('malformed', 'Invalid payload encoding');
  }

  if (payload.iss !== ISSUER) {
    throw new LocalTokenError('wrong_issuer', `Unexpected iss: ${payload.iss}`);
  }
  if (payload.aud !== AUDIENCE) {
    throw new LocalTokenError('wrong_audience', `Unexpected aud: ${payload.aud}`);
  }
  if (opts.expectedType && payload.typ !== opts.expectedType) {
    throw new LocalTokenError('wrong_type', `Expected typ=${opts.expectedType}, got ${payload.typ}`);
  }

  const skew = opts.clockSkewSeconds ?? 5;
  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== 'number' || payload.exp + skew < now) {
    throw new LocalTokenError('expired', 'Token has expired');
  }

  return payload;
}

export const LOCAL_TOKEN_CONSTANTS = {
  ISSUER,
  AUDIENCE,
};
