/**
 * Admin MFA — end-to-end against a real GameDatabase (sqlite) and the
 * admin() express middleware:
 *
 *   enroll → confirm → login challenge → verify (TOTP + recovery) →
 *   high-risk action gating (ban + custom action) → disable.
 *
 * Also covers the distinct login states: mfa_required, invalid_code,
 * too_many_attempts, mfa_challenge_expired, recovery_code_consumed,
 * session_revoked — and the audit rows each transition records.
 */
import assert from 'node:assert';
import { describe, it, before, after } from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { Server } from 'node:http';
import express from 'express';
import { GameDatabase } from '@colyseus/database';
import { JWT, Hash, totp, signMfaChallenge } from '@colyseus/auth';

process.env.JWT_SECRET = process.env.JWT_SECRET || 'admin-mfa-test-secret';
const { admin, defineAdminResource, createTokenBucketLimiter } = await import('../src-backend/index.ts');
const { COOKIE_NAME } = await import('../src-backend/auth/sessions.ts');

const ADMIN_EMAIL = 'admin@example.com';
const ADMIN_PASSWORD = 'correct-horse-battery';
const SECOND_EMAIL = 'second@example.com';
const TARGET_EMAIL = 'target@example.com';

let db: GameDatabase;
let dbPath: string;
let distDir: string;
let server: Server;
let base: string;

function makeDist(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'admin-mfa-dist-'));
  fs.writeFileSync(path.join(dir, 'index.html'), '<!doctype html><html><head></head><body><div id="root"></div></body></html>');
  return dir;
}

/** Minimal cookie jar — captures Set-Cookie and replays it. */
class Session {
  cookie = '';
  async call(method: string, path: string, body?: unknown): Promise<{ status: number; body: any; setCookie: string | null }> {
    const res = await fetch(`${base}${path}`, {
      method,
      headers: {
        'content-type': 'application/json',
        ...(this.cookie ? { cookie: this.cookie } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const setCookie = res.headers.get('set-cookie');
    if (setCookie) {
      const pair = setCookie.split(';')[0]!;
      if (pair.endsWith('=')) { this.cookie = ''; }
      else { this.cookie = pair; }
    }
    return { status: res.status, body: await res.json().catch(() => null), setCookie };
  }
  get(path: string) { return this.call('GET', path); }
  post(path: string, body?: unknown) { return this.call('POST', path, body); }
}

async function auditActions(): Promise<string[]> {
  const rows = await db.audit.list({ resource: 'auth', limit: 500 });
  return rows.map((r) => r.action);
}

before(async () => {
  dbPath = path.join(os.tmpdir(), `admin-mfa-${Date.now()}-${Math.random().toString(36).slice(2)}.db`);
  db = new GameDatabase({ connectionString: dbPath });
  await db.boot();
  distDir = makeDist();

  const panel = admin({
    database: db,
    uiDistDir: distDir,
    logger: null,
    requireMfaForActions: true,
    rateLimit: {
      // Keep the limiter wiring real but un-hittable — every request in
      // this suite comes from 127.0.0.1, and the default per-ip buckets
      // (10/min) would 429 later tests. The per-challenge attempt cap
      // under test lives in @colyseus/auth's challenge limiter instead.
      login: createTokenBucketLimiter({ capacity: 1000, refillPerSec: 100 }),
      mfa: createTokenBucketLimiter({ capacity: 1000, refillPerSec: 100 }),
    },
    resources: {
      users: defineAdminResource(db.tables.users, {
        actions: [
          { name: 'testop', requiresMfa: true, handler: () => 'did-it' },
          { name: 'safeop', handler: () => 'safe' },
        ],
      }),
    },
  });
  const app = express();
  app.use(panel);
  server = await new Promise<Server>((resolve) => {
    const s = app.listen(0, () => resolve(s));
  });
  base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;

  // Bootstrap the first admin + a target user to ban later.
  const boot = new Session();
  const res = await boot.post('/admin-api/auth/bootstrap', { email: ADMIN_EMAIL, password: ADMIN_PASSWORD });
  assert.strictEqual(res.status, 200, JSON.stringify(res.body));
  await db.auth.settings.onRegisterWithEmailAndPassword!(TARGET_EMAIL, 'x'.repeat(64), {});
});

after(async () => {
  server?.close();
  await db?.shutdown();
  for (const ext of ['', '-shm', '-wal']) {
    try { fs.unlinkSync(dbPath + ext); } catch { /* ignore */ }
  }
  fs.rmSync(distDir, { recursive: true, force: true });
});

describe('admin MFA', () => {
  let adminId: string;
  let secret: string;
  let recoveryCodes: string[];

  it('logs in without MFA before enrollment (legacy flow) and reports mfa:false', async () => {
    const s = new Session();
    const login = await s.post('/admin-api/auth/login', { email: ADMIN_EMAIL, password: ADMIN_PASSWORD });
    assert.strictEqual(login.status, 200);
    adminId = login.body.userId;

    const me = await s.get('/admin-api/auth/me');
    assert.strictEqual(me.status, 200);
    assert.strictEqual(me.body.mfa, false);
  });

  it('enrolls: enroll → otpauth URI → confirm → recovery codes + mfa session', async () => {
    const s = new Session();
    await s.post('/admin-api/auth/login', { email: ADMIN_EMAIL, password: ADMIN_PASSWORD });

    // Confirm before enroll → 400.
    const premature = await s.post('/admin-api/auth/mfa/confirm', { code: '123456' });
    assert.strictEqual(premature.status, 400);

    const enroll = await s.post('/admin-api/auth/mfa/enroll');
    assert.strictEqual(enroll.status, 200);
    assert.match(enroll.body.secret, /^[A-Z2-7]{32}$/);
    assert.ok(enroll.body.otpauthUrl.startsWith('otpauth://totp/'));
    secret = enroll.body.secret;

    // Wrong first code → 400 invalid_code, still not enabled.
    const valid = totp(secret);
    const wrong = valid === '000000' ? '000001' : '000000';
    const badConfirm = await s.post('/admin-api/auth/mfa/confirm', { code: wrong });
    assert.strictEqual(badConfirm.status, 400);
    assert.strictEqual(badConfirm.body.error, 'invalid_code');

    const confirm = await s.post('/admin-api/auth/mfa/confirm', { code: totp(secret) });
    assert.strictEqual(confirm.status, 200);
    assert.strictEqual(confirm.body.recoveryCodes.length, 10);
    recoveryCodes = confirm.body.recoveryCodes;

    // The re-issued session carries the mfa claim.
    const me = await s.get('/admin-api/auth/me');
    assert.strictEqual(me.body.mfa, true);

    // Re-enroll is refused while enabled.
    const reEnroll = await s.post('/admin-api/auth/mfa/enroll');
    assert.strictEqual(reEnroll.status, 409);
  });

  it('challenges at login (mfa_required) and completes with TOTP', async () => {
    const s = new Session();
    const login = await s.post('/admin-api/auth/login', { email: ADMIN_EMAIL, password: ADMIN_PASSWORD });
    assert.strictEqual(login.status, 401);
    assert.strictEqual(login.body.error, 'mfa_required');
    assert.ok(login.body.mfaToken);
    assert.strictEqual(s.cookie, '', 'no session cookie before the challenge completes');

    const verify = await s.post('/admin-api/auth/mfa/verify', {
      token: login.body.mfaToken,
      code: totp(secret),
    });
    assert.strictEqual(verify.status, 200);
    assert.strictEqual(verify.body.mfa, true);
    assert.ok(s.cookie.startsWith(`${COOKIE_NAME}=`), 'session cookie set after verify');

    const me = await s.get('/admin-api/auth/me');
    assert.strictEqual(me.body.mfa, true);
  });

  it('rejects a wrong code (invalid_code) and caps retries (too_many_attempts)', async () => {
    const s = new Session();
    const login = await s.post('/admin-api/auth/login', { email: ADMIN_EMAIL, password: ADMIN_PASSWORD });
    const valid = totp(secret);
    const wrong = valid === '000000' ? '000001' : '000000';

    for (let i = 0; i < 5; i++) {
      const res = await s.post('/admin-api/auth/mfa/verify', { token: login.body.mfaToken, code: wrong });
      assert.strictEqual(res.status, 401, `attempt ${i + 1}`);
      assert.strictEqual(res.body.error, 'invalid_code');
    }
    const capped = await s.post('/admin-api/auth/mfa/verify', { token: login.body.mfaToken, code: wrong });
    assert.strictEqual(capped.status, 429);
    assert.strictEqual(capped.body.error, 'too_many_attempts');
  });

  it('makes a completed challenge single-use', async () => {
    const s = new Session();
    const login = await s.post('/admin-api/auth/login', { email: ADMIN_EMAIL, password: ADMIN_PASSWORD });
    const code = totp(secret);
    const first = await s.post('/admin-api/auth/mfa/verify', { token: login.body.mfaToken, code });
    assert.strictEqual(first.status, 200);
    const replay = await s.post('/admin-api/auth/mfa/verify', { token: login.body.mfaToken, code });
    assert.strictEqual(replay.status, 401);
    assert.strictEqual(replay.body.error, 'invalid_challenge');
  });

  it('reports an expired challenge as mfa_challenge_expired', async () => {
    const token = await signMfaChallenge({ id: adminId, email: ADMIN_EMAIL }, { ttlSeconds: -10 });
    const s = new Session();
    const res = await s.post('/admin-api/auth/mfa/verify', { token, code: '123456' });
    assert.strictEqual(res.status, 401);
    assert.strictEqual(res.body.error, 'mfa_challenge_expired');
  });

  it('distinguishes a revoked session mid-challenge (session_revoked)', async () => {
    const s = new Session();
    const login = await s.post('/admin-api/auth/login', { email: ADMIN_EMAIL, password: ADMIN_PASSWORD });
    assert.strictEqual(login.body.error, 'mfa_required');

    // "Sign out everywhere" between challenge and verify.
    await db.auth.bumpTokenVersion(adminId);

    const res = await s.post('/admin-api/auth/mfa/verify', { token: login.body.mfaToken, code: totp(secret) });
    assert.strictEqual(res.status, 401);
    assert.strictEqual(res.body.error, 'session_revoked');
  });

  it('accepts a recovery code, then rejects its reuse as recovery_code_consumed', async () => {
    const code = recoveryCodes[0]!;

    const first = new Session();
    const login1 = await first.post('/admin-api/auth/login', { email: ADMIN_EMAIL, password: ADMIN_PASSWORD });
    const ok = await first.post('/admin-api/auth/mfa/verify', { token: login1.body.mfaToken, code });
    assert.strictEqual(ok.status, 200);
    assert.strictEqual(ok.body.mfa, true);

    const second = new Session();
    const login2 = await second.post('/admin-api/auth/login', { email: ADMIN_EMAIL, password: ADMIN_PASSWORD });
    const reused = await second.post('/admin-api/auth/mfa/verify', { token: login2.body.mfaToken, code });
    assert.strictEqual(reused.status, 401);
    assert.strictEqual(reused.body.error, 'recovery_code_consumed');
  });

  it('gates high-risk actions on the mfa session claim when requireMfaForActions is on', async () => {
    const target: any = await db.auth.settings.onFindUserByEmail!(TARGET_EMAIL);

    // A second admin WITHOUT MFA — legacy session, no mfa claim.
    await db.auth.settings.onRegisterWithEmailAndPassword!(SECOND_EMAIL, await Hash.make(ADMIN_PASSWORD), {});
    const secondUser: any = await db.auth.settings.onFindUserByEmail!(SECOND_EMAIL);
    await db.moderation.setRole(secondUser.id, 'admin');

    const legacy = new Session();
    const legacyLogin = await legacy.post('/admin-api/auth/login', { email: SECOND_EMAIL, password: ADMIN_PASSWORD });
    assert.strictEqual(legacyLogin.status, 200, 'no MFA enrolled → plain login');

    const banDenied = await legacy.post(`/admin-api/users/${target.id}/ban`, { reason: 'test' });
    assert.strictEqual(banDenied.status, 403);
    assert.match(banDenied.body.error, /mfa_required/);

    const actionDenied = await legacy.post('/admin-api/users/_action/testop', {});
    assert.strictEqual(actionDenied.status, 403);
    assert.match(actionDenied.body.error, /mfa_required/);

    // An action without requiresMfa still runs on the legacy session.
    const safeAllowed = await legacy.post('/admin-api/users/_action/safeop', {});
    assert.strictEqual(safeAllowed.status, 200);

    // The MFA-completed session passes both gates.
    const mfa = new Session();
    const login = await mfa.post('/admin-api/auth/login', { email: ADMIN_EMAIL, password: ADMIN_PASSWORD });
    await mfa.post('/admin-api/auth/mfa/verify', { token: login.body.mfaToken, code: totp(secret) });

    const actionOk = await mfa.post('/admin-api/users/_action/testop', {});
    assert.strictEqual(actionOk.status, 200);
    assert.strictEqual(actionOk.body.result, 'did-it');

    const banOk = await mfa.post(`/admin-api/users/${target.id}/ban`, { reason: 'test ban' });
    assert.strictEqual(banOk.status, 200);
    await db.auth.unban(target.id); // leave no state behind
  });

  it('disables MFA with a valid TOTP and restores the legacy login flow', async () => {
    const s = new Session();
    const login = await s.post('/admin-api/auth/login', { email: ADMIN_EMAIL, password: ADMIN_PASSWORD });
    await s.post('/admin-api/auth/mfa/verify', { token: login.body.mfaToken, code: totp(secret) });

    const valid = totp(secret);
    const wrong = valid === '000000' ? '000001' : '000000';
    const badDisable = await s.post('/admin-api/auth/mfa/disable', { code: wrong });
    assert.strictEqual(badDisable.status, 401);

    const disabled = await s.post('/admin-api/auth/mfa/disable', { code: totp(secret) });
    assert.strictEqual(disabled.status, 200);

    // Login is back to the original password-only flow.
    const legacy = new Session();
    const relogin = await legacy.post('/admin-api/auth/login', { email: ADMIN_EMAIL, password: ADMIN_PASSWORD });
    assert.strictEqual(relogin.status, 200);
    assert.ok(!relogin.body.error);
  });

  it('recorded the MFA transitions in the audit log', async () => {
    const actions = await auditActions();
    for (const expected of [
      'auth.mfa_enrolled',
      'auth.mfa_challenge',
      'auth.mfa_completed',
      'auth.mfa_failed',
      'auth.mfa_recovery_used',
      'auth.mfa_disabled',
    ]) {
      assert.ok(actions.includes(expected), `audit log should contain ${expected}`);
    }

    // The recovery-code completion carries the method for forensics.
    const rows = await db.audit.list({ resource: 'auth', limit: 500 });
    const recovery = rows.find((r) => r.action === 'auth.mfa_recovery_used');
    assert.ok(recovery, 'recovery usage is audited');
    assert.strictEqual(recovery!.operatorId, adminId);
  });
});
