/**
 * MFA for the admin panel: challenge-based login, the /auth/mfa/verify
 * endpoint, and the high-risk-action gate (mfaActionGate + the wired
 * `room.dispose` endpoint).
 *
 * Fakes follow the operator-gate test's pattern: a minimal EndpointContext
 * plus a stub `database` — no real DB, no matchmaker.
 */
import assert from 'node:assert';
import { describe, it, before, beforeEach, afterEach } from 'node:test';
import {
  JWT, auth as colyseusAuth, Hash,
  generateMfaSecret, generateRecoveryCodes, generateTotp, hashRecoveryCode,
  signMfaChallenge,
} from '@colyseus/auth';
import { authEndpoints } from '../src-backend/auth/endpoints.ts';
import { signSession, verifySession, COOKIE_NAME } from '../src-backend/auth/sessions.ts';
import { createTokenBucketLimiter } from '../src-backend/auth/rate-limit.ts';
import { mfaActionGate } from '../src-backend/internal/context.ts';
import { disposeRoomEndpoint } from '../src-backend/rooms/endpoint.ts';

const PASSWORD = 'correct-horse-battery';

let passwordHash: string;
let recoveryCode: string;
let recoveryEntries: Array<{ hash: string; consumedAt?: Date }>;
let mfaSecret: string;
let tokenVersion: number;
let auditRows: Array<{ action: string; payload: any }>;

function fakeDatabase(userRow: any) {
  return {
    auth: {
      getTokenVersion: async () => tokenVersion,
      settings: { onFindUserByEmail: async (email: string) => (email === userRow?.email ? userRow : null) },
    },
    moderation: { getRole: async () => 'admin' as const },
    audit: {
      record: async (entry: any) => { auditRows.push(entry); return entry; },
    },
  } as any;
}

function mfaUserRow(): any {
  return {
    id: 'op-1',
    email: 'admin@example.com',
    password: passwordHash,
    mfaSecret,
    mfaRecoveryCodes: recoveryEntries,
  };
}

function legacyUserRow(): any {
  return { id: 'op-2', email: 'legacy@example.com', password: passwordHash };
}

function makeEndpoints(userRow: any, extra: Record<string, any> = {}) {
  return authEndpoints({
    database: fakeDatabase(userRow),
    apiPath: '/admin-api',
    logger: null,
    ...extra,
  });
}

async function bodyOf(res: Response): Promise<any> {
  return res.json();
}

function sessionFromCookieHeader(res: Response) {
  const setCookie = res.headers.get('set-cookie') ?? '';
  const token = setCookie.split(';')[0]!.slice(`${COOKIE_NAME}=`.length);
  return verifySession(decodeURIComponent(token));
}

before(async () => {
  JWT.settings.secret = 'test-secret-do-not-use-in-prod';
  passwordHash = await Hash.make(PASSWORD);
});

beforeEach(() => {
  mfaSecret = generateMfaSecret();
  [recoveryCode] = generateRecoveryCodes(1);
  recoveryEntries = [{ hash: hashRecoveryCode(recoveryCode!) }];
  tokenVersion = 3;
  auditRows = [];
  colyseusAuth.settings.onConsumeRecoveryCode = async (_user, hash) => {
    const entry = recoveryEntries.find((r) => r.hash === hash);
    if (entry) { entry.consumedAt = new Date(); }
  };
});

afterEach(() => {
  colyseusAuth.settings.onConsumeRecoveryCode = undefined;
  colyseusAuth.settings.mfaChallengeTtlSeconds = undefined;
});

describe('admin auth + MFA', () => {
  it('login with an enrolled account returns a challenge, not a cookie', async () => {
    const eps = makeEndpoints(mfaUserRow());
    const res = await eps.authLogin({ body: { email: 'admin@example.com', password: PASSWORD } }) as Response;
    assert.equal(res.status, 200);
    const body = await bodyOf(res);
    assert.equal(body.mfa, 'required');
    assert.ok(body.challenge);
    assert.equal(body.expiresIn, 300);
    assert.equal(res.headers.get('set-cookie'), null, 'no session cookie yet');
    assert.deepEqual(auditRows.map((r) => r.action), ['auth.mfa_challenge']);
  });

  it('verify with a valid TOTP sets an mfa-stamped session cookie', async () => {
    const eps = makeEndpoints(mfaUserRow());
    const loginRes = await eps.authLogin({ body: { email: 'admin@example.com', password: PASSWORD } }) as Response;
    const { challenge } = await bodyOf(loginRes);

    const res = await eps.authMfaVerify({
      body: { challenge, code: generateTotp(mfaSecret) },
    }) as Response;
    assert.equal(res.status, 200);
    const body = await bodyOf(res);
    assert.equal(body.userId, 'op-1');
    assert.equal(body.role, 'admin');
    assert.equal(body.mfa, 'totp');

    const session = await sessionFromCookieHeader(res);
    assert.ok(session);
    assert.equal(session!.userId, 'op-1');
    assert.equal(session!.mfa, true, 'session carries the MFA-complete claim');
    assert.equal(session!.tv, 3);

    assert.deepEqual(auditRows.map((r) => r.action), ['auth.mfa_challenge', 'auth.login']);
    assert.equal(auditRows[1]!.payload.mfa, 'totp');
  });

  it('wrong TOTP → 401 mfa_invalid_code + auth.mfa_failed audit', async () => {
    const eps = makeEndpoints(mfaUserRow());
    const loginRes = await eps.authLogin({ body: { email: 'admin@example.com', password: PASSWORD } }) as Response;
    const { challenge } = await bodyOf(loginRes);

    const wrong = generateTotp(mfaSecret) === '000000' ? '000001' : '000000';
    const res = await eps.authMfaVerify({ body: { challenge, code: wrong } }) as Response;
    assert.equal(res.status, 401);
    assert.equal((await bodyOf(res)).error, 'mfa_invalid_code');
    assert.equal(res.headers.get('set-cookie'), null);
    assert.deepEqual(auditRows.map((r) => r.action), ['auth.mfa_challenge', 'auth.mfa_failed']);
    assert.equal(auditRows[1]!.payload.reason, 'mfa_invalid_code');
  });

  it('expired challenge → 401 mfa_challenge_expired', async () => {
    colyseusAuth.settings.mfaChallengeTtlSeconds = -10;
    const eps = makeEndpoints(mfaUserRow());
    const loginRes = await eps.authLogin({ body: { email: 'admin@example.com', password: PASSWORD } }) as Response;
    const { challenge } = await bodyOf(loginRes);

    const res = await eps.authMfaVerify({
      body: { challenge, code: generateTotp(mfaSecret) },
    }) as Response;
    assert.equal(res.status, 401);
    assert.equal((await bodyOf(res)).error, 'mfa_challenge_expired');
  });

  it('tokenVersion bump mid-challenge → 401 mfa_session_revoked', async () => {
    const eps = makeEndpoints(mfaUserRow());
    const loginRes = await eps.authLogin({ body: { email: 'admin@example.com', password: PASSWORD } }) as Response;
    const { challenge } = await bodyOf(loginRes);

    tokenVersion = 4; // "log out everywhere" happened between login and verify
    const res = await eps.authMfaVerify({
      body: { challenge, code: generateTotp(mfaSecret) },
    }) as Response;
    assert.equal(res.status, 401);
    assert.equal((await bodyOf(res)).error, 'mfa_session_revoked');
  });

  it('recovery code signs in once; reuse → 401 recovery_code_consumed', async () => {
    const eps = makeEndpoints(mfaUserRow());

    const login1 = await eps.authLogin({ body: { email: 'admin@example.com', password: PASSWORD } }) as Response;
    const { challenge: c1 } = await bodyOf(login1);
    const ok = await eps.authMfaVerify({ body: { challenge: c1, recoveryCode } }) as Response;
    assert.equal(ok.status, 200);
    assert.equal((await bodyOf(ok)).mfa, 'recovery_code');
    assert.ok(recoveryEntries[0]!.consumedAt, 'code marked consumed');
    assert.deepEqual(
      auditRows.map((r) => r.action),
      ['auth.mfa_challenge', 'auth.mfa_recovery_consumed', 'auth.login'],
    );

    const login2 = await eps.authLogin({ body: { email: 'admin@example.com', password: PASSWORD } }) as Response;
    const { challenge: c2 } = await bodyOf(login2);
    const reused = await eps.authMfaVerify({ body: { challenge: c2, recoveryCode } }) as Response;
    assert.equal(reused.status, 401);
    assert.equal((await bodyOf(reused)).error, 'recovery_code_consumed');
  });

  it('verify attempts are rate-limited per (ip, user)', async () => {
    const eps = makeEndpoints(mfaUserRow(), {
      mfaLimiter: createTokenBucketLimiter({ capacity: 2, refillPerSec: 0, retryAfterSec: 9 }),
    });
    const loginRes = await eps.authLogin({ body: { email: 'admin@example.com', password: PASSWORD } }) as Response;
    const { challenge } = await bodyOf(loginRes);
    const wrong = generateTotp(mfaSecret) === '000000' ? '000001' : '000000';

    const r1 = await eps.authMfaVerify({ body: { challenge, code: wrong } }) as Response;
    const r2 = await eps.authMfaVerify({ body: { challenge, code: wrong } }) as Response;
    const r3 = await eps.authMfaVerify({ body: { challenge, code: wrong } }) as Response;
    assert.equal(r1.status, 401);
    assert.equal(r2.status, 401);
    assert.equal(r3.status, 429);
    assert.equal(r3.headers.get('retry-after'), '9');
  });

  it('legacy account (no enrollment) signs in with password only', async () => {
    const eps = makeEndpoints(legacyUserRow());
    const res = await eps.authLogin({ body: { email: 'legacy@example.com', password: PASSWORD } }) as Response;
    assert.equal(res.status, 200);
    const body = await bodyOf(res);
    assert.equal(body.userId, 'op-2');
    assert.equal(body.mfa, undefined);
    const session = await sessionFromCookieHeader(res);
    assert.ok(session);
    assert.equal(session!.mfa, undefined, 'no MFA claim on legacy sessions');
    assert.deepEqual(auditRows.map((r) => r.action), ['auth.login']);
  });

  it('wrong password still yields the uniform 401 (no account oracle)', async () => {
    const eps = makeEndpoints(mfaUserRow());
    const res = await eps.authLogin({ body: { email: 'admin@example.com', password: 'wrong' } }) as Response;
    assert.equal(res.status, 401);
    assert.equal((await bodyOf(res)).error, 'invalid credentials');
    assert.deepEqual(auditRows.map((r) => r.action), ['auth.login_failed']);
  });

  it('a challenge JWT is not accepted as a session cookie', async () => {
    const challenge = await signMfaChallenge({ sub: 'op-1', email: 'admin@example.com', tv: 3 });
    const session = await verifySession(challenge);
    assert.equal(session, null);
  });
});

describe('mfaActionGate', () => {
  const enrollment = () => ({ secret: mfaSecret, recoveryCodes: [] });

  function gateCtx(opts: {
    actions?: string[];
    enrollment?: any;
    enforceRbac?: boolean;
  }): any {
    return {
      enforceRbac: opts.enforceRbac ?? true,
      mfaRequiredActions: new Set(opts.actions ?? ['room.dispose']),
      resolveMfaEnrollment: async () => opts.enrollment ?? null,
    };
  }

  async function reqWithSession(session?: Record<string, unknown>) {
    const token = session ? await signSession(session as any) : undefined;
    return {
      getHeader: (k: string) =>
        k === 'cookie' && token ? `${COOKIE_NAME}=${encodeURIComponent(token)}` : null,
    };
  }

  it('ignores actions not in the required set', async () => {
    const ctx = gateCtx({ enrollment: enrollment() });
    const req = await reqWithSession({ userId: 'op-1', role: 'admin' });
    assert.equal(await mfaActionGate(ctx, req, 'room.kick'), null);
  });

  it('passes when the session completed MFA', async () => {
    const ctx = gateCtx({ enrollment: enrollment() });
    const req = await reqWithSession({ userId: 'op-1', role: 'admin', mfa: true });
    assert.equal(await mfaActionGate(ctx, req, 'room.dispose'), null);
  });

  it('blocks an enrolled operator whose session lacks MFA', async () => {
    const ctx = gateCtx({ enrollment: enrollment() });
    const req = await reqWithSession({ userId: 'op-1', role: 'admin' });
    const res = await mfaActionGate(ctx, req, 'room.dispose');
    assert.ok(res instanceof Response);
    assert.equal(res!.status, 403);
    assert.match((await res!.json()).error, /^mfa_required/);
  });

  it('passes legacy accounts (no enrollment) — original flow preserved', async () => {
    const ctx = gateCtx({ enrollment: null });
    const req = await reqWithSession({ userId: 'op-2', role: 'admin' });
    assert.equal(await mfaActionGate(ctx, req, 'room.dispose'), null);
  });

  it('passes when there is no cookie session (dev header / custom resolver)', async () => {
    const ctx = gateCtx({ enrollment: enrollment() });
    assert.equal(await mfaActionGate(ctx, { getHeader: () => null }, 'room.dispose'), null);
  });

  it('is inert when RBAC is disabled', async () => {
    const ctx = gateCtx({ enrollment: enrollment(), enforceRbac: false });
    const req = await reqWithSession({ userId: 'op-1', role: 'admin' });
    assert.equal(await mfaActionGate(ctx, req, 'room.dispose'), null);
  });
});

describe('disposeRoomEndpoint MFA wiring', () => {
  function disposeCtx(enrollment: any): any {
    return {
      apiPath: '/admin-api',
      enforceRbac: true,
      resolveUserId: async () => 'op-1',
      database: {
        moderation: { can: async () => true, getRole: async () => 'admin' },
        audit: { record: async () => {} },
      },
      resources: {},
      mfaRequiredActions: new Set(['room.dispose']),
      resolveMfaEnrollment: async () => enrollment,
      logger: null,
    };
  }

  it('DELETE /rooms/:id → 403 mfa_required for enrolled operator without MFA session', async () => {
    const ctx = disposeCtx({ secret: mfaSecret, recoveryCodes: [] });
    const endpoint = disposeRoomEndpoint(ctx);
    const token = await signSession({ userId: 'op-1', role: 'admin' });
    const res = await endpoint({
      params: { roomId: 'room-1' },
      headers: new Headers({ cookie: `${COOKIE_NAME}=${encodeURIComponent(token)}` }),
    }) as Response;
    assert.equal(res.status, 403);
    assert.match((await res.json()).error, /^mfa_required/);
  });
});
