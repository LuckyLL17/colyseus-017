import assert from 'assert';
import {
  JWT, auth,
  loginEndpoint,
  mfaVerifyEndpoint,
  registerEndpoint,
  generateMfaSecret,
  totp,
  verifyTOTP,
  totpUri,
  generateRecoveryCodes,
  normalizeRecoveryCode,
  hashRecoveryCode,
  signMfaChallenge,
  verifyMfaChallenge,
  MfaChallengeLimiter,
  MFA_CHALLENGE_TTL_SECONDS,
  RECOVERY_CODE_COUNT,
} from '../src/index.ts';
import { base32Decode, base32Encode } from '../src/mfa.ts';

JWT.settings.secret = '@%^&';

const passwordPlainText = '123456';

// Catch APIError throws as { status, ...body } — mirrors Endpoints.test.ts.
async function tryEndpoint<R>(call: Promise<R>): Promise<R | { status: number; error?: string; [k: string]: any }> {
  try {
    return await call;
  } catch (e: any) {
    if (e?.statusCode && e?.body !== undefined) {
      return { status: e.statusCode, ...(typeof e.body === 'object' ? e.body : { error: String(e.body) }) };
    }
    throw e;
  }
}

describe('mfa primitives', () => {
  describe('base32', () => {
    it('round-trips arbitrary bytes', () => {
      const buf = Buffer.from([0x00, 0xff, 0x42, 0x13, 0x37, 0x99]);
      assert.deepStrictEqual(base32Decode(base32Encode(buf)), buf);
    });

    it('matches the RFC 4648 vectors', () => {
      assert.strictEqual(base32Encode(Buffer.from('')), '');
      assert.strictEqual(base32Encode(Buffer.from('f')), 'MY');
      assert.strictEqual(base32Encode(Buffer.from('fo')), 'MZXQ');
      assert.strictEqual(base32Encode(Buffer.from('foo')), 'MZXW6');
      assert.strictEqual(base32Encode(Buffer.from('foob')), 'MZXW6YQ');
      assert.strictEqual(base32Encode(Buffer.from('fooba')), 'MZXW6YTB');
      assert.strictEqual(base32Encode(Buffer.from('foobar')), 'MZXW6YTBOI');
      // Padded input decodes the same.
      assert.strictEqual(base32Decode('MZXW6===', ).toString(), 'foo');
    });
  });

  describe('totp', () => {
    // RFC 6238 Appendix B, SHA-1 vectors (8-digit codes). The ASCII secret
    // "12345678901234567890" is GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ in base32.
    const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
    const vectors: Array<[number, string]> = [
      [59, '94287082'],
      [1111111109, '07081804'],
      [1111111111, '14050471'],
      [1234567890, '89005924'],
      [2000000000, '69279037'],
      [20000000000, '65353130'],
    ];

    for (const [time, expected] of vectors) {
      it(`produces ${expected} at T=${time}`, () => {
        const counter = Math.floor(time / 30);
        assert.strictEqual(totp(secret, counter, 8), expected);
      });
    }
  });

  describe('verifyTOTP', () => {
    it('accepts the current code and ±1 step of drift', () => {
      const secret = generateMfaSecret();
      const now = Date.now();
      const counter = Math.floor(now / 1000 / 30);
      assert.ok(verifyTOTP(secret, totp(secret, counter), { now }));
      assert.ok(verifyTOTP(secret, totp(secret, counter - 1), { now }));
      assert.ok(verifyTOTP(secret, totp(secret, counter + 1), { now }));
    });

    it('rejects codes outside the window', () => {
      const secret = generateMfaSecret();
      const now = Date.now();
      const counter = Math.floor(now / 1000 / 30);
      assert.ok(!verifyTOTP(secret, totp(secret, counter - 2), { now }));
      assert.ok(!verifyTOTP(secret, totp(secret, counter + 2), { now }));
    });

    it('honors window: 0', () => {
      const secret = generateMfaSecret();
      const now = Date.now();
      const counter = Math.floor(now / 1000 / 30);
      assert.ok(verifyTOTP(secret, totp(secret, counter), { now, window: 0 }));
      assert.ok(!verifyTOTP(secret, totp(secret, counter - 1), { now, window: 0 }));
    });

    it('rejects malformed codes', () => {
      const secret = generateMfaSecret();
      assert.ok(!verifyTOTP(secret, ''));
      assert.ok(!verifyTOTP(secret, '12345'));
      assert.ok(!verifyTOTP(secret, '1234567'));
      assert.ok(!verifyTOTP(secret, 'abcdef'));
    });
  });

  describe('generateMfaSecret', () => {
    it('produces 32-char base32 secrets, unique per call', () => {
      const a = generateMfaSecret();
      const b = generateMfaSecret();
      assert.match(a, /^[A-Z2-7]{32}$/);
      assert.match(b, /^[A-Z2-7]{32}$/);
      assert.notStrictEqual(a, b);
    });
  });

  describe('totpUri', () => {
    it('builds an otpauth:// URI with issuer + account', () => {
      const uri = totpUri('ABC123', { issuer: 'My Game', account: 'u1@x.com' });
      assert.ok(uri.startsWith('otpauth://totp/My%20Game:u1%40x.com'));
      assert.ok(uri.includes('secret=ABC123'));
      assert.ok(uri.includes('issuer=My%20Game'));
    });
  });

  describe('recovery codes', () => {
    it('generates unique XXXX-XXXX-XXXX codes', () => {
      const codes = generateRecoveryCodes();
      assert.strictEqual(codes.length, RECOVERY_CODE_COUNT);
      assert.strictEqual(new Set(codes).size, codes.length);
      for (const code of codes) {
        assert.match(code, /^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/);
      }
    });

    it('normalizes case + separators before hashing', () => {
      const code = 'ABCD-EFGH-JKLM';
      assert.strictEqual(normalizeRecoveryCode(code), 'ABCDEFGHJKLM');
      assert.strictEqual(normalizeRecoveryCode('abcd efgh jklm'), 'ABCDEFGHJKLM');
      assert.strictEqual(hashRecoveryCode(code), hashRecoveryCode('abcd-efgh-jklm'));
      assert.notStrictEqual(hashRecoveryCode(code), hashRecoveryCode('AAAA-AAAA-AAAA'));
    });
  });

  describe('challenge tokens', () => {
    it('round-trips sign + verify', async () => {
      const token = await signMfaChallenge({ id: 'u1', email: 'a@b.c', tv: 3 });
      const result = await verifyMfaChallenge(token);
      assert.strictEqual(result.status, 'ok');
      if (result.status !== 'ok') { return; }
      assert.strictEqual(result.claims.id, 'u1');
      assert.strictEqual(result.claims.email, 'a@b.c');
      assert.strictEqual(result.claims.tv, 3);
      assert.strictEqual(result.claims.kind, 'mfa');
      assert.ok(result.claims.jti);
    });

    it('reports expired challenges distinctly', async () => {
      const token = await signMfaChallenge({ id: 'u1', email: 'a@b.c' }, { ttlSeconds: -10 });
      const result = await verifyMfaChallenge(token);
      assert.strictEqual(result.status, 'expired');
    });

    it('rejects tampered + foreign tokens as invalid', async () => {
      assert.strictEqual((await verifyMfaChallenge('not-a-jwt')).status, 'invalid');
      const good = await signMfaChallenge({ id: 'u1', email: 'a@b.c' });
      const tampered = good.slice(0, -4) + 'XXXX';
      assert.strictEqual((await verifyMfaChallenge(tampered)).status, 'invalid');
      // A different token kind (e.g. a password-reset token) is not a challenge.
      const foreign = await JWT.sign({ sub: 'u1', kind: 'reset' }, { expiresIn: 60 });
      assert.strictEqual((await verifyMfaChallenge(foreign)).status, 'invalid');
    });
  });

  describe('MfaChallengeLimiter', () => {
    it('caps attempts per challenge', () => {
      const limiter = new MfaChallengeLimiter({ maxAttempts: 3 });
      const exp = Date.now() + 60_000;
      assert.strictEqual(limiter.check('j1', exp), 'ok');
      limiter.recordFailure('j1');
      assert.strictEqual(limiter.check('j1', exp), 'ok');
      limiter.recordFailure('j1');
      limiter.recordFailure('j1');
      assert.strictEqual(limiter.check('j1', exp), 'too_many_attempts');
    });

    it('marks consumed challenges as used', () => {
      const limiter = new MfaChallengeLimiter();
      const exp = Date.now() + 60_000;
      assert.strictEqual(limiter.check('j2', exp), 'ok');
      limiter.consume('j2');
      assert.strictEqual(limiter.check('j2', exp), 'used');
    });

    it('tracks challenges independently', () => {
      const limiter = new MfaChallengeLimiter({ maxAttempts: 1 });
      const exp = Date.now() + 60_000;
      limiter.recordFailure('j3');
      assert.strictEqual(limiter.check('j3', exp), 'too_many_attempts');
      assert.strictEqual(limiter.check('j4', exp), 'ok');
    });
  });
});

describe('MFA login flow (endpoints)', () => {
  const email = 'mfa-user@colyseus.io';
  const legacyEmail = 'legacy@colyseus.io';

  let fakedb: Record<string, string>;
  let userIds: Record<string, string>;
  let mfaStore: Record<string, { secret: string } | undefined>;
  let recoveryStore: Record<string, Map<string, string | null>>;

  beforeEach(() => {
    fakedb = {};
    userIds = {};
    mfaStore = {};
    recoveryStore = {};

    auth.settings.onFindUserByEmail = async (email: string) => {
      if (fakedb[email] !== undefined) {
        return { id: userIds[email], email, password: fakedb[email], tokenVersion: 0 };
      }
      return null;
    };
    auth.settings.onRegisterWithEmailAndPassword = async (email: string, password: string) => {
      fakedb[email] = password;
      userIds[email] = 'u-' + email;
      return { id: userIds[email], email };
    };
    auth.settings.onFindMfa = async (user: any) => mfaStore[user.email] ?? null;
    auth.settings.onConsumeRecoveryCode = async (user: any, code: string) => {
      const codes = recoveryStore[user.email];
      const hash = hashRecoveryCode(code);
      if (!codes || !codes.has(hash)) { return 'invalid' as const; }
      if (codes.get(hash) !== null) { return 'already_consumed' as const; }
      codes.set(hash, new Date().toISOString());
      return 'ok' as const;
    };
  });

  afterEach(() => {
    auth.settings.onFindMfa = undefined;
    auth.settings.onConsumeRecoveryCode = undefined;
    auth.settings.onCheckBanned = undefined;
    JWT.settings.revocationCheck = undefined;
  });

  async function register(email: string) {
    await registerEndpoint()({ body: { email, password: passwordPlainText } });
  }

  async function login(email: string) {
    return tryEndpoint(loginEndpoint()({ body: { email, password: passwordPlainText } }));
  }

  it('legacy accounts (no MFA enrollment) get a plain token — original flow', async () => {
    await register(legacyEmail);
    const data = await login(legacyEmail) as any;
    assert.ok(data.token, 'expected a session token');
    assert.ok(!data.status, 'should not be an error response');
    assert.strictEqual(data.mfa, undefined);
  });

  it('enrolled accounts get 401 mfa_required + a challenge token instead of a session', async () => {
    await register(email);
    mfaStore[email] = { secret: generateMfaSecret() };

    const res = await login(email) as any;
    assert.strictEqual(res.status, 401);
    assert.strictEqual(res.error, 'mfa_required');
    assert.ok(res.mfaToken);
    assert.strictEqual(res.expiresIn, MFA_CHALLENGE_TTL_SECONDS);

    const challenge = await verifyMfaChallenge(res.mfaToken);
    assert.strictEqual(challenge.status, 'ok');
    if (challenge.status === 'ok') {
      assert.strictEqual(challenge.claims.email, email);
      assert.strictEqual(challenge.claims.id, userIds[email]);
    }
  });

  it('completes the challenge with a valid TOTP and issues a session token', async () => {
    await register(email);
    const secret = generateMfaSecret();
    mfaStore[email] = { secret };

    const { mfaToken } = await login(email) as any;
    const data = await mfaVerifyEndpoint()({ body: { token: mfaToken, code: totp(secret) } });
    assert.ok(data.token);
    assert.strictEqual((data.user as any).email, email);
    assert.deepStrictEqual(data.mfa, { method: 'totp' });
    // The issued token is a real session token.
    const decoded = await JWT.verify<any>(data.token);
    assert.strictEqual(decoded.email, email);
  });

  it('makes a completed challenge single-use', async () => {
    await register(email);
    const secret = generateMfaSecret();
    mfaStore[email] = { secret };

    const { mfaToken } = await login(email) as any;
    await mfaVerifyEndpoint()({ body: { token: mfaToken, code: totp(secret) } });
    const replay = await tryEndpoint(mfaVerifyEndpoint()({ body: { token: mfaToken, code: totp(secret) } })) as any;
    assert.strictEqual(replay.status, 401);
    assert.strictEqual(replay.error, 'invalid_challenge');
  });

  it('rejects wrong TOTP codes and caps retries per challenge', async () => {
    await register(email);
    const secret = generateMfaSecret();
    mfaStore[email] = { secret };

    const { mfaToken } = await login(email) as any;
    // Find a code that is NOT the current valid one.
    const valid = new Set([totp(secret), totp(secret, Math.floor(Date.now() / 1000 / 30) - 1), totp(secret, Math.floor(Date.now() / 1000 / 30) + 1)]);
    let wrong = '000000';
    while (valid.has(wrong)) { wrong = String(Number(wrong) + 1).padStart(6, '0'); }

    for (let i = 0; i < 5; i++) {
      const res = await tryEndpoint(mfaVerifyEndpoint()({ body: { token: mfaToken, code: wrong } })) as any;
      assert.strictEqual(res.status, 401, `attempt ${i + 1}`);
      assert.strictEqual(res.error, 'invalid_code');
    }
    const capped = await tryEndpoint(mfaVerifyEndpoint()({ body: { token: mfaToken, code: wrong } })) as any;
    assert.strictEqual(capped.status, 429);
    assert.strictEqual(capped.error, 'too_many_attempts');
  });

  it('reports an expired challenge as mfa_challenge_expired', async () => {
    await register(email);
    mfaStore[email] = { secret: generateMfaSecret() };
    const token = await signMfaChallenge({ id: userIds[email], email }, { ttlSeconds: -10 });
    const res = await tryEndpoint(mfaVerifyEndpoint()({ body: { token, code: '123456' } })) as any;
    assert.strictEqual(res.status, 401);
    assert.strictEqual(res.error, 'mfa_challenge_expired');
  });

  it('rejects garbage + foreign tokens as invalid_challenge', async () => {
    const garbage = await tryEndpoint(mfaVerifyEndpoint()({ body: { token: 'not-a-jwt', code: '123456' } })) as any;
    assert.strictEqual(garbage.status, 401);
    assert.strictEqual(garbage.error, 'invalid_challenge');

    const foreign = await JWT.sign({ sub: 'x', kind: 'reset' }, { expiresIn: 60 });
    const res = await tryEndpoint(mfaVerifyEndpoint()({ body: { token: foreign, code: '123456' } })) as any;
    assert.strictEqual(res.status, 401);
    assert.strictEqual(res.error, 'invalid_challenge');
  });

  it('accepts a recovery code, then rejects its reuse as recovery_code_consumed', async () => {
    await register(email);
    const secret = generateMfaSecret();
    mfaStore[email] = { secret };
    const [recoveryCode] = generateRecoveryCodes(1);
    recoveryStore[email] = new Map([[hashRecoveryCode(recoveryCode), null]]);

    const first = await login(email) as any;
    const data = await mfaVerifyEndpoint()({ body: { token: first.mfaToken, code: recoveryCode } });
    assert.ok(data.token);
    assert.deepStrictEqual(data.mfa, { method: 'recovery' });

    // Same code, fresh challenge → the distinct "already consumed" state.
    const second = await login(email) as any;
    const reused = await tryEndpoint(mfaVerifyEndpoint()({ body: { token: second.mfaToken, code: recoveryCode } })) as any;
    assert.strictEqual(reused.status, 401);
    assert.strictEqual(reused.error, 'recovery_code_consumed');
  });

  it('rejects unknown recovery codes as invalid_code', async () => {
    await register(email);
    mfaStore[email] = { secret: generateMfaSecret() };
    recoveryStore[email] = new Map();

    const { mfaToken } = await login(email) as any;
    const res = await tryEndpoint(mfaVerifyEndpoint()({ body: { token: mfaToken, code: 'AAAA-BBBB-CCCC' } })) as any;
    assert.strictEqual(res.status, 401);
    assert.strictEqual(res.error, 'invalid_code');
  });

  it('distinguishes a revoked session mid-challenge (session_revoked)', async () => {
    await register(email);
    const secret = generateMfaSecret();
    mfaStore[email] = { secret };

    const { mfaToken } = await login(email) as any;
    // Simulate "password reset / sign out everywhere" between challenge
    // and verify: the revocation check now rejects the challenge's tv.
    JWT.settings.revocationCheck = async () => false;

    const res = await tryEndpoint(mfaVerifyEndpoint()({ body: { token: mfaToken, code: totp(secret) } })) as any;
    assert.strictEqual(res.status, 401);
    assert.strictEqual(res.error, 'session_revoked');
  });

  it('issues a plain token when MFA was disabled mid-challenge', async () => {
    await register(email);
    const secret = generateMfaSecret();
    mfaStore[email] = { secret };

    const { mfaToken } = await login(email) as any;
    delete mfaStore[email]; // operator disabled MFA between the two calls

    const data = await mfaVerifyEndpoint()({ body: { token: mfaToken, code: '000000' } });
    assert.ok(data.token, 'password-auth should complete without a factor');
  });

  it('re-checks the ban state at verify time', async () => {
    await register(email);
    const secret = generateMfaSecret();
    mfaStore[email] = { secret };

    const { mfaToken } = await login(email) as any;
    auth.settings.onCheckBanned = async () => ({ reason: 'cheating', until: null });

    const res = await tryEndpoint(mfaVerifyEndpoint()({ body: { token: mfaToken, code: totp(secret) } })) as any;
    assert.strictEqual(res.status, 403);
    assert.strictEqual(res.error, 'banned');
  });
});
