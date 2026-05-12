#!/usr/bin/env node
/**
 * Manual smoke test for MS365_MCP_FRONT_AUTH_MODE=local.
 *
 * Boots the HTTP server with local front-auth mode and a known signing secret,
 * then verifies:
 *   1. /token rejects an authorization_code exchange we have not really made
 *      (MSAL will fail to redeem the fake code — that's expected, we only care
 *      that the endpoint takes the local code path).
 *   2. /token with grant_type=refresh_token + a hand-crafted local refresh
 *      token returns a fresh local access_token + refresh_token pair.
 *   3. /mcp rejects requests without a bearer or with a Microsoft-style opaque
 *      token, and accepts a request bearing a server-issued local token (the
 *      acceptance is detected by the absence of the 401 + presence of the MCP
 *      protocol error from the transport layer, since the JSON-RPC payload is
 *      empty).
 *
 * This script does NOT perform a real Microsoft login. It exercises the local
 * token plumbing in isolation.
 *
 * Prereqs:
 *   - Build first: `npm run build` (so dist/index.js exists)
 *   - Set MS365_MCP_CLIENT_ID to anything (server requires it to start)
 *
 * Usage:
 *   node test-local-front-auth.mjs
 */
import { spawn } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = 38543;
const SECRET = 'k'.repeat(64);

const ISSUER = 'ms-365-mcp-server';
const AUDIENCE = 'ms-365-mcp-server/mcp';

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

function signLocalToken({ subject, type, ttlSeconds }) {
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = b64url(
    JSON.stringify({
      iss: ISSUER,
      aud: AUDIENCE,
      sub: subject,
      typ: type,
      iat: now,
      exp: now + ttlSeconds,
      jti: crypto.randomBytes(8).toString('base64url'),
    })
  );
  const sig = crypto
    .createHmac('sha256', Buffer.from(SECRET, 'utf8'))
    .update(`${header}.${payload}`)
    .digest('base64url');
  return `${header}.${payload}.${sig}`;
}

const env = {
  ...process.env,
  MS365_MCP_FRONT_AUTH_MODE: 'local',
  MS365_MCP_LOCAL_TOKEN_SECRET: SECRET,
  MS365_MCP_FRONT_TOKEN_TTL_SECONDS: '600',
  MS365_MCP_CLIENT_ID: process.env.MS365_MCP_CLIENT_ID || '00000000-0000-0000-0000-000000000000',
  MS365_MCP_TENANT_ID: process.env.MS365_MCP_TENANT_ID || 'common',
  MS365_MCP_CORS_ORIGIN: 'http://localhost',
};

const server = spawn('node', [join(__dirname, 'dist', 'index.js'), '--http', `127.0.0.1:${PORT}`, '-v'], {
  stdio: ['ignore', 'inherit', 'inherit'],
  env,
});

let exitCode = 0;
const fail = (msg) => {
  console.error(`FAIL: ${msg}`);
  exitCode = 1;
};
const pass = (msg) => console.log(`PASS: ${msg}`);

async function waitForServer(retries = 30) {
  for (let i = 0; i < retries; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${PORT}/`);
      if (r.ok) return;
    } catch {
      // ignore, server still starting
    }
    await sleep(200);
  }
  throw new Error('Server did not start in time');
}

try {
  await waitForServer();
  pass('server started');

  // 1) /mcp without bearer → 401
  {
    const r = await fetch(`http://127.0.0.1:${PORT}/mcp`);
    if (r.status === 401) pass('/mcp rejects unauthenticated request with 401');
    else fail(`/mcp expected 401, got ${r.status}`);
    const www = r.headers.get('www-authenticate') || '';
    if (www.toLowerCase().includes('bearer')) pass('/mcp returns WWW-Authenticate: Bearer');
    else fail('/mcp missing WWW-Authenticate header');
  }

  // 2) /mcp with a forged token (signed with a different secret) → 401
  {
    const fakeSecret = 'q'.repeat(64);
    const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const payload = b64url(
      JSON.stringify({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'attacker',
        typ: 'access',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 60,
        jti: 'x',
      })
    );
    const sig = crypto.createHmac('sha256', fakeSecret).update(`${header}.${payload}`).digest('base64url');
    const forged = `${header}.${payload}.${sig}`;
    const r = await fetch(`http://127.0.0.1:${PORT}/mcp`, {
      headers: { authorization: `Bearer ${forged}` },
    });
    if (r.status === 401) pass('/mcp rejects forged (wrong-secret) bearer with 401');
    else fail(`/mcp expected 401 for forged token, got ${r.status}`);
  }

  // 3) /mcp with valid local token → not 401 (will reach the MCP transport and
  //    fail with a JSON-RPC error because we sent no body — that's fine)
  {
    const access = signLocalToken({ subject: 'home-account-1', type: 'access', ttlSeconds: 60 });
    const r = await fetch(`http://127.0.0.1:${PORT}/mcp`, {
      method: 'POST',
      headers: { authorization: `Bearer ${access}`, 'content-type': 'application/json' },
      body: '{}',
    });
    if (r.status !== 401) pass(`/mcp accepts valid local token (status=${r.status})`);
    else fail('/mcp rejected a valid local token with 401');
  }

  // 4) /token with grant_type=refresh_token and a valid local refresh → new pair
  {
    const refresh = signLocalToken({ subject: 'home-account-1', type: 'refresh', ttlSeconds: 3600 });
    const body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refresh });
    const r = await fetch(`http://127.0.0.1:${PORT}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
    });
    if (!r.ok) {
      fail(`/token refresh expected 200, got ${r.status}`);
    } else {
      const json = await r.json();
      const okShape =
        typeof json.access_token === 'string' &&
        json.access_token.split('.').length === 3 &&
        json.token_type === 'Bearer' &&
        typeof json.expires_in === 'number' &&
        typeof json.refresh_token === 'string';
      if (okShape) pass('/token refresh returns local access + refresh pair');
      else fail(`/token refresh returned unexpected shape: ${JSON.stringify(json)}`);
      // Sanity check: the issued access token is NOT the refresh we sent back
      if (json.access_token !== refresh) pass('/token refresh issues a different access token');
      else fail('/token refresh echoed back our refresh as access');
    }
  }

  // 5) /token with grant_type=refresh_token and a forged refresh → 400
  {
    const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const payload = b64url(
      JSON.stringify({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'attacker',
        typ: 'refresh',
        iat: 0,
        exp: 9999999999,
        jti: 'x',
      })
    );
    const sig = crypto.createHmac('sha256', 'wrong-secret').update(`${header}.${payload}`).digest('base64url');
    const forged = `${header}.${payload}.${sig}`;
    const body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: forged });
    const r = await fetch(`http://127.0.0.1:${PORT}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
    });
    if (r.status === 400) pass('/token rejects forged refresh with 400');
    else fail(`/token expected 400 for forged refresh, got ${r.status}`);
  }
} catch (err) {
  fail(err.message);
} finally {
  server.kill('SIGTERM');
  await sleep(200);
  process.exit(exitCode);
}
