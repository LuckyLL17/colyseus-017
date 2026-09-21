import assert from 'assert';
import { createRouter } from '@colyseus/core';
import {
  JWT, auth, Hash,
  endpoints,
  loginEndpoint,
  mfaVerifyEndpoint,
  registerEndpoint,
  anonymousEndpoint,
  forgotPasswordEndpoint,
  resetPasswordGetEndpoint,
  resetPasswordPostEndpoint,
  confirmEmailEndpoint,
  userdataEndpoint,
  generateMfaSecret,
  generateRecoveryCodes,
  generateTotp,
  hashRecoveryCode,
  createMfaRateLimiter,
} from '../src/index.ts';

JWT.settings.secret = '@%^&';

const passwordPlainText = '123456';

// Helper for the few tests that need to exercise the HTTP wire (urlencoded
// bodies, full router dispatch). Direct endpoint calls bypass this.
function makeRequest(method: string, path: string, opts: { body?: any; headers?: Record<string, string> } = {}) {
  const url = `http://localhost${path}`;
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    ...(opts.headers ?? {}),
  };
  const init: RequestInit = { method, headers };
  if (opts.body !== undefined) {
    init.body = typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body);
  }
  return new Request(url, init);
}

// Catch APIError throws as { status, ...body } so each test can keep its
// existing status-code assertions while the endpoint itself stays typed.
async function tryEndpoint<R>(call: Promise<R>): Promise<R | { status: number; error?: string;[k: string]: any }> {
  try {
    return await call;
  } catch (e: any) {
    if (e?.statusCode && e?.body !== undefined) {
      return { status: e.statusCode, ...(typeof e.body === 'object' ? e.body : { error: String(e.body) }) };
    }
    throw e;
  }
}

describe('auth.endpoints()', () => {
  let fakedb: Record<string, string>;
  let onRegisterOptions: any;

  beforeEach(() => {
    fakedb = {};
    onRegisterOptions = undefined;

    // Mutate `auth.settings` directly — single source of truth.
    auth.settings.onFindUserByEmail = async (email) => {
      if (fakedb[email] !== undefined) {
        return { id: 100, email, password: fakedb[email] };
      }
      return null;
    };
    auth.settings.onRegisterWithEmailAndPassword = async (email, password, options) => {
      fakedb[email] = password;
      onRegisterOptions = options;
      return { id: 100, email };
    };
  });

  describe('POST /auth/anonymous', () => {
    it('returns an anonymous user + token', async () => {
      const data = await anonymousEndpoint()({ body: {} });
      // Type-level proof: `data.user.anonymousId` is reachable without `any` casts.
      assert.ok(data.user);
      assert.ok((data.user as any).anonymousId);
      assert.strictEqual((data.user as any).anonymous, true);
      assert.ok(data.token);
    });
  });

  describe('POST /auth/register + /auth/login', () => {
    const email = 'endel@colyseus.io';

    it('registers a new user', async () => {
      const data = await registerEndpoint()({
        body: { email, password: passwordPlainText },
      });
      assert.strictEqual((data.user as any).email, email);
      assert.ok(data.token);
      assert.ok(fakedb[email]);
      assert.ok(await Hash.verify(passwordPlainText, fakedb[email]));
    });

    it('rejects malformed email with 400', async () => {
      const res = await tryEndpoint(registerEndpoint()({
        body: { email: 'not-an-email', password: passwordPlainText },
      }));
      assert.strictEqual((res as any).status, 400);
    });

    it('rejects short password with 400', async () => {
      const res = await tryEndpoint(registerEndpoint()({
        body: { email, password: '12' },
      }));
      assert.strictEqual((res as any).status, 400);
    });

    it('rejects duplicate email with 401', async () => {
      await registerEndpoint()({ body: { email, password: passwordPlainText } });
      const res = await tryEndpoint(registerEndpoint()({
        body: { email, password: passwordPlainText },
      }));
      assert.strictEqual((res as any).status, 401);
      assert.strictEqual((res as any).error, 'email_already_in_use');
    });

    it('logs in with correct credentials', async () => {
      await registerEndpoint()({ body: { email, password: passwordPlainText } });
      const data = await loginEndpoint()({
        body: { email, password: passwordPlainText },
      });
      // Typed: `data.user` + `data.token` are inferred from the handler.
      assert.strictEqual((data.user as any).email, email);
      assert.ok(data.token);
      assert.strictEqual((data.user as any).password, undefined);
    });

    it('rejects bad password with 401', async () => {
      await registerEndpoint()({ body: { email, password: passwordPlainText } });
      const res = await tryEndpoint(loginEndpoint()({
        body: { email, password: 'wrong' },
      }));
      assert.strictEqual((res as any).status, 401);
    });

    it('rejects unknown email with 401', async () => {
      const res = await tryEndpoint(loginEndpoint()({
        body: { email: 'unknown@example.com', password: passwordPlainText },
      }));
      assert.strictEqual((res as any).status, 401);
    });

    it('returns 403 banned when onCheckBanned reports banned', async () => {
      const previousFind = auth.settings.onFindUserByEmail;
      const previousCheck = auth.settings.onCheckBanned;
      auth.settings.onFindUserByEmail = async (e) =>
        ({ id: 1, email: e, password: await Hash.make(passwordPlainText) } as any);
      auth.settings.onCheckBanned = async () => ({ reason: 'spam', until: null });

      const res = await tryEndpoint(loginEndpoint()({
        body: { email, password: passwordPlainText },
      }));
      assert.strictEqual((res as any).status, 403);
      assert.strictEqual((res as any).error, 'banned');
      assert.strictEqual((res as any).reason, 'spam');

      auth.settings.onFindUserByEmail = previousFind;
      auth.settings.onCheckBanned = previousCheck;
    });
  });

  describe('POST /auth/login + /auth/mfa/verify (MFA)', () => {
    const email = 'mfa@colyseus.io';
    let mfaSecret: string;
    let recoveryCode: string;
    let recoveryEntries: Array<{ hash: string; consumedAt?: Date }>;

    beforeEach(() => {
      mfaSecret = generateMfaSecret();
      [recoveryCode] = generateRecoveryCodes(1);
      recoveryEntries = [{ hash: hashRecoveryCode(recoveryCode!) }];

      // MFA-enrolled user. `password` comes from the shared fakedb (the
      // register endpoint populates it); MFA fields ride along as
      // conventional user-record fields, which the default
      // `onGetMfaEnrollment` picks up.
      auth.settings.onFindUserByEmail = async (e) => {
        if (e === email && fakedb[e] !== undefined) {
          return {
            id: 'mfa-user-1',
            email: e,
            password: fakedb[e],
            mfaSecret,
            mfaRecoveryCodes: recoveryEntries,
            tokenVersion: 5,
          } as any;
        }
        return null;
      };
      // Fake persistence for recovery-code consumption — marks the stored
      // entry so reuse is rejected, like a real `UPDATE ... SET consumed_at`.
      auth.settings.onConsumeRecoveryCode = async (_user, hash) => {
        const entry = recoveryEntries.find((r) => r.hash === hash);
        if (entry) { entry.consumedAt = new Date(); }
      };
      // Deterministic tests: no rate limiting unless a test opts in.
      auth.settings.mfaLimiter = false;
    });

    afterEach(() => {
      auth.settings.onConsumeRecoveryCode = undefined;
      auth.settings.mfaLimiter = undefined;
      auth.settings.mfaChallengeTtlSeconds = undefined;
      JWT.settings.revocationCheck = undefined;
    });

    async function registerAndLogin() {
      await registerEndpoint()({ body: { email, password: passwordPlainText } });
      return loginEndpoint()({ body: { email, password: passwordPlainText } });
    }

    it('login returns a challenge instead of a token when MFA is enrolled', async () => {
      const data = await registerAndLogin();
      assert.strictEqual((data as any).mfa, 'required');
      assert.ok((data as any).challenge);
      assert.strictEqual((data as any).expiresIn, 300);
      assert.strictEqual((data as any).token, undefined);
      assert.strictEqual((data as any).user, undefined);
    });

    it('valid TOTP completes the login and returns user + token', async () => {
      const { challenge } = (await registerAndLogin()) as any;
      const data = await mfaVerifyEndpoint()({
        body: { challenge, code: generateTotp(mfaSecret) },
      });
      assert.strictEqual((data as any).mfa, 'totp');
      assert.strictEqual((data as any).user.email, email);
      assert.ok((data as any).token);
      // MFA material must not leak into the response or the JWT.
      assert.strictEqual((data as any).user.mfaSecret, undefined);
      assert.strictEqual((data as any).user.mfaRecoveryCodes, undefined);
      assert.strictEqual((data as any).user.password, undefined);
      const payload = JWT.decode((data as any).token) as any;
      assert.strictEqual(payload.mfaSecret, undefined);
      assert.strictEqual(payload.mfaRecoveryCodes, undefined);
    });

    it('wrong TOTP → 401 mfa_invalid_code', async () => {
      const { challenge } = (await registerAndLogin()) as any;
      const wrong = generateTotp(mfaSecret) === '000000' ? '000001' : '000000';
      const res = await tryEndpoint(mfaVerifyEndpoint()({
        body: { challenge, code: wrong },
      }));
      assert.strictEqual((res as any).status, 401);
      assert.strictEqual((res as any).error, 'mfa_invalid_code');
    });

    it('expired challenge → 401 mfa_challenge_expired', async () => {
      auth.settings.mfaChallengeTtlSeconds = -10; // already expired at issue time
      const { challenge } = (await registerAndLogin()) as any;
      const res = await tryEndpoint(mfaVerifyEndpoint()({
        body: { challenge, code: generateTotp(mfaSecret) },
      }));
      assert.strictEqual((res as any).status, 401);
      assert.strictEqual((res as any).error, 'mfa_challenge_expired');
    });

    it('tampered challenge → 401 mfa_invalid_challenge', async () => {
      const res = await tryEndpoint(mfaVerifyEndpoint()({
        body: { challenge: 'not.a.token', code: '123456' },
      }));
      assert.strictEqual((res as any).status, 401);
      assert.strictEqual((res as any).error, 'mfa_invalid_challenge');
    });

    it('a full session JWT cannot stand in as a challenge', async () => {
      await registerEndpoint()({ body: { email, password: passwordPlainText } });
      const sessionToken = await JWT.sign({ id: 'mfa-user-1', email });
      const res = await tryEndpoint(mfaVerifyEndpoint()({
        body: { challenge: sessionToken, code: generateTotp(mfaSecret) },
      }));
      assert.strictEqual((res as any).status, 401);
      assert.strictEqual((res as any).error, 'mfa_invalid_challenge');
    });

    it('recovery code completes the login and is consumed', async () => {
      const { challenge } = (await registerAndLogin()) as any;
      const data = await mfaVerifyEndpoint()({
        body: { challenge, recoveryCode },
      });
      assert.strictEqual((data as any).mfa, 'recovery_code');
      assert.ok((data as any).token);
      assert.ok(recoveryEntries[0]!.consumedAt, 'consumer should mark the code');
    });

    it('reusing a consumed recovery code → 401 recovery_code_consumed', async () => {
      const first = (await registerAndLogin()) as any;
      await mfaVerifyEndpoint()({ body: { challenge: first.challenge, recoveryCode } });

      const second = (await loginEndpoint()({ body: { email, password: passwordPlainText } })) as any;
      const res = await tryEndpoint(mfaVerifyEndpoint()({
        body: { challenge: second.challenge, recoveryCode },
      }));
      assert.strictEqual((res as any).status, 401);
      assert.strictEqual((res as any).error, 'recovery_code_consumed');
    });

    it('unknown recovery code → 401 mfa_invalid_code (same shape as wrong TOTP)', async () => {
      const { challenge } = (await registerAndLogin()) as any;
      const res = await tryEndpoint(mfaVerifyEndpoint()({
        body: { challenge, recoveryCode: 'zzzz-zzzz' },
      }));
      assert.strictEqual((res as any).status, 401);
      assert.strictEqual((res as any).error, 'mfa_invalid_code');
    });

    it('recovery codes are refused when onConsumeRecoveryCode is not configured', async () => {
      auth.settings.onConsumeRecoveryCode = undefined;
      const { challenge } = (await registerAndLogin()) as any;
      const res = await tryEndpoint(mfaVerifyEndpoint()({
        body: { challenge, recoveryCode },
      }));
      assert.strictEqual((res as any).status, 401);
      assert.strictEqual((res as any).error, 'mfa_invalid_code');
    });

    it('session revoked mid-challenge → 401 mfa_session_revoked', async () => {
      const seen: any[] = [];
      JWT.settings.revocationCheck = async (payload: any) => { seen.push(payload); return false; };
      const { challenge } = (await registerAndLogin()) as any;
      const res = await tryEndpoint(mfaVerifyEndpoint()({
        body: { challenge, code: generateTotp(mfaSecret) },
      }));
      assert.strictEqual((res as any).status, 401);
      assert.strictEqual((res as any).error, 'mfa_session_revoked');
      // The challenge's (id, tokenVersion) pair is what gets checked.
      assert.deepStrictEqual(seen[0], { id: 'mfa-user-1', tokenVersion: 5 });
    });

    it('retries are rate-limited → 429 after the bucket empties', async () => {
      auth.settings.mfaLimiter = createMfaRateLimiter({ capacity: 2, refillPerSec: 0 });
      const { challenge } = (await registerAndLogin()) as any;
      const wrong = generateTotp(mfaSecret) === '000000' ? '000001' : '000000';

      const first = await tryEndpoint(mfaVerifyEndpoint()({ body: { challenge, code: wrong } }));
      const second = await tryEndpoint(mfaVerifyEndpoint()({ body: { challenge, code: wrong } }));
      const third = await tryEndpoint(mfaVerifyEndpoint()({ body: { challenge, code: wrong } }));
      assert.strictEqual((first as any).status, 401);
      assert.strictEqual((second as any).status, 401);
      assert.strictEqual((third as any).status, 429);
      assert.strictEqual((third as any).error, 'rate_limited');
    });

    it('legacy accounts without MFA fields keep the password-only flow', async () => {
      const legacyEmail = 'legacy@colyseus.io';
      const previous = auth.settings.onFindUserByEmail;
      auth.settings.onFindUserByEmail = async (e) =>
        (e === legacyEmail && fakedb[e] !== undefined
          ? { id: 7, email: e, password: fakedb[e] } as any
          : null);

      await registerEndpoint()({ body: { email: legacyEmail, password: passwordPlainText } });
      const data = await loginEndpoint()({ body: { email: legacyEmail, password: passwordPlainText } });
      assert.ok((data as any).token);
      assert.strictEqual((data as any).mfa, undefined);
      assert.strictEqual((data as any).challenge, undefined);

      auth.settings.onFindUserByEmail = previous;
    });

    it('the challenge JWT is not accepted as a room-auth token', async () => {
      const { challenge } = (await registerAndLogin()) as any;
      // Room.onAuth is patched by src/index.ts — challenge tokens must fail.
      const { Room } = await import('@colyseus/core');
      assert.strictEqual(await (Room as any).onAuth(challenge), false);
    });
  });

  describe('GET /auth/userdata', () => {
    it('returns user from JWT', async () => {
      const token = await JWT.sign({ id: 42, email: 'x@y.z' });
      const data = await userdataEndpoint()({
        headers: new Headers({ authorization: `Bearer ${token}` }),
      });
      // `data` is typed as `{ user: unknown }` — the unknown is from
      // onParseToken's return type (`unknown` in AuthSettings).
      assert.strictEqual((data.user as any).id, 42);
    });

    it('rejects requests without a token', async () => {
      const res = await tryEndpoint(userdataEndpoint()({ headers: new Headers() }));
      assert.strictEqual((res as any).status, 401);
    });
  });

  describe('HTML routes', () => {
    // resetPasswordGet returns a Response (HTML) — call as a function and
    // read it as a Response.
    it('GET /auth/reset-password renders the form with the supplied token', async () => {
      const res = await resetPasswordGetEndpoint()({ query: { token: 'abc123' } });
      assert.match(res.headers.get('content-type') || '', /text\/html/);
      const body = await res.text();
      assert.match(body, /abc123/);
      assert.match(body, /\/auth\/reset-password/);
    });

    it('POST /auth/reset-password redirects to error when token is invalid', async () => {
      const res = await resetPasswordPostEndpoint()({
        body: { token: 'invalid', password: 'newpass1' },
      });
      assert.strictEqual(res.status, 302);
      const location = res.headers.get('location') || '';
      assert.match(location, /\/auth\/reset-password\?token=invalid&error=/);
    });

    it('POST /auth/reset-password redirects to success when token is valid', async () => {
      let resetCalledWith: string | null = null;
      const previous = auth.settings.onResetPassword;
      auth.settings.onResetPassword = async (e) => { resetCalledWith = e; return true; };

      const token = await JWT.sign({ email: 'x@y.z' }, { expiresIn: '5m' });
      const res = await resetPasswordPostEndpoint()({
        body: { token, password: 'newpass1' },
      });
      assert.strictEqual(res.status, 302);
      const location = res.headers.get('location') || '';
      assert.match(location, /\/auth\/reset-password\?success=/);
      assert.strictEqual(resetCalledWith, 'x@y.z');

      auth.settings.onResetPassword = previous;
    });

    it('GET /auth/confirm-email returns 404 when onEmailConfirmed is not configured', async () => {
      const res = await confirmEmailEndpoint()({ query: { token: 'anything' } });
      assert.strictEqual(res.status, 404);
    });

    it('GET /auth/confirm-email confirms valid token and redirects to success', async () => {
      let confirmedEmail: string | null = null;
      const previous = auth.settings.onEmailConfirmed;
      auth.settings.onEmailConfirmed = async (e) => { confirmedEmail = e; };

      const token = await JWT.sign({ email: 'confirm@me.com' }, { expiresIn: '5m' });
      const res = await confirmEmailEndpoint()({ query: { token } });
      assert.strictEqual(res.status, 302);
      const location = res.headers.get('location') || '';
      assert.match(location, /\/auth\/confirm-email\?success=/);
      assert.strictEqual(confirmedEmail, 'confirm@me.com');

      auth.settings.onEmailConfirmed = previous;
    });
  });

  describe('OAuth (exercised through the router — direct call would require cookie session plumbing)', () => {
    let router: ReturnType<typeof createRouter>;
    beforeEach(() => {
      router = createRouter(endpoints()) as ReturnType<typeof createRouter>;
    });

    it('renders the missing-config help page for an unconfigured provider', async () => {
      const res = await router.handler(makeRequest('GET', '/auth/provider/discord'));
      assert.strictEqual(res.status, 200);
      const body = await res.text();
      assert.match(body, /Missing.*discord/i);
    });

    it('issues a 302 to the provider when configured', async () => {
      auth.oauth.addProvider('discord', { key: 'test-key', secret: 'test-secret', scope: ['identify'] });
      const res = await router.handler(makeRequest('GET', '/auth/provider/discord'));
      assert.strictEqual(res.status, 302);
      assert.match(res.headers.get('location') || '', /^https?:\/\/discord\.com\/.+/i);
      assert.match(res.headers.get('set-cookie') || '', /^grant=/);
      delete (auth.oauth.providers as any).discord;
    });

    it('respects `oauth: false` — endpoint absent', async () => {
      const minimal = createRouter(endpoints({ oauth: false })) as ReturnType<typeof createRouter>;
      const res = await minimal.handler(makeRequest('GET', '/auth/provider/discord'));
      assert.strictEqual(res.status, 404);
    });
  });

  describe('settings overrides via auth.settings', () => {
    it('post-mount mutation of auth.settings wins on subsequent requests', async () => {
      const original = auth.settings.onRegisterAnonymously;
      let customCalled = false;
      auth.settings.onRegisterAnonymously = async () => {
        customCalled = true;
        return { id: 'custom', anonymous: true };
      };

      const data = await anonymousEndpoint()({ body: {} });
      assert.strictEqual(customCalled, true);
      assert.strictEqual((data.user as any).id, 'custom');

      auth.settings.onRegisterAnonymously = original;
    });
  });
});
