import assert from 'assert';
import { JWT } from '../src/JWT.ts';
import {
  MFA_CHALLENGE_KIND,
  MfaChallengeError,
  checkMfaCode,
  createMfaRateLimiter,
  findRecoveryCodeEntry,
  generateMfaSecret,
  generateRecoveryCodes,
  generateTotp,
  hashRecoveryCode,
  signMfaChallenge,
  verifyMfaChallenge,
  verifyTotp,
} from '../src/mfa.ts';

JWT.settings.secret = '@%^&';

// RFC 6238 Appendix B test secret (ASCII "12345678901234567890"), base32.
const RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

describe('mfa', () => {
  describe('TOTP', () => {
    it('matches the RFC 6238 SHA-1 test vector (6-digit truncation)', () => {
      // RFC 6238 T=59s → 94287082 (8 digits) → 287082 (6 digits)
      assert.strictEqual(generateTotp(RFC_SECRET, 59_000), '287082');
      // T=1111111109 → 07081804 → 081804
      assert.strictEqual(generateTotp(RFC_SECRET, 1_111_111_109_000), '081804');
    });

    it('round-trips a freshly generated secret', () => {
      const secret = generateMfaSecret();
      const code = generateTotp(secret);
      assert.ok(verifyTotp(secret, code));
    });

    it('accepts codes within ±1 step (clock drift), rejects beyond', () => {
      const t = 1_700_000_000_000;
      const now = generateTotp(RFC_SECRET, t);
      const prev = generateTotp(RFC_SECRET, t - 30_000);
      const next = generateTotp(RFC_SECRET, t + 30_000);
      const outside = generateTotp(RFC_SECRET, t + 60_000);

      assert.ok(verifyTotp(RFC_SECRET, now, { timestampMs: t }));
      assert.ok(verifyTotp(RFC_SECRET, prev, { timestampMs: t }));
      assert.ok(verifyTotp(RFC_SECRET, next, { timestampMs: t }));
      // ±1 window does not reach two steps away (unless it collides with
      // a neighbor's code — pick a counter where it doesn't).
      if (outside !== next && outside !== now) {
        assert.ok(!verifyTotp(RFC_SECRET, outside, { timestampMs: t }));
      }
    });

    it('rejects malformed codes and bad secrets without throwing', () => {
      assert.ok(!verifyTotp(RFC_SECRET, '12345'));      // too short
      assert.ok(!verifyTotp(RFC_SECRET, 'abcdef'));     // not digits
      assert.ok(!verifyTotp(RFC_SECRET, ''));
      assert.ok(!verifyTotp('not!!base32', '123456'));  // undecodable secret
      assert.ok(!verifyTotp(RFC_SECRET, '000000') || generateTotp(RFC_SECRET) === '000000');
    });
  });

  describe('recovery codes', () => {
    it('generates unique xxxx-xxxx codes', () => {
      const codes = generateRecoveryCodes(8);
      assert.strictEqual(codes.length, 8);
      assert.strictEqual(new Set(codes).size, 8);
      for (const code of codes) {
        assert.match(code, /^[a-z2-9]{4}-[a-z2-9]{4}$/);
      }
    });

    it('hash is deterministic and normalization-insensitive', () => {
      const a = hashRecoveryCode('ABCD-EFGH');
      const b = hashRecoveryCode('abcd-efgh');
      const c = hashRecoveryCode('abcd efgh');
      const d = hashRecoveryCode('abcdefgh');
      assert.strictEqual(a, b);
      assert.strictEqual(a, c);
      assert.strictEqual(a, d);
      assert.match(a, /^sha256\$[0-9a-f]{64}$/);
    });

    it('finds stored entries and reports consumption state', () => {
      const [code] = generateRecoveryCodes(1);
      const entries = [
        { hash: hashRecoveryCode(code) },
        { hash: hashRecoveryCode('wxyz-wxyz'), consumedAt: new Date() },
      ];
      const found = findRecoveryCodeEntry(entries, code);
      assert.ok(found);
      assert.ok(!found!.consumedAt);
      const consumed = findRecoveryCodeEntry(entries, 'WXYZ-WXYZ');
      assert.ok(consumed?.consumedAt);
      assert.strictEqual(findRecoveryCodeEntry(entries, 'aaaa-aaaa'), null);
      assert.strictEqual(findRecoveryCodeEntry(undefined, code), null);
    });
  });

  describe('checkMfaCode', () => {
    const secret = generateMfaSecret();
    const [recovery] = generateRecoveryCodes(1);
    const enrollment = {
      secret,
      recoveryCodes: [{ hash: hashRecoveryCode(recovery) }],
    };

    it('accepts a valid TOTP', () => {
      const result = checkMfaCode(enrollment, { code: generateTotp(secret) });
      assert.deepStrictEqual(result, { ok: true, via: 'totp' });
    });

    it('rejects a wrong TOTP with mfa_invalid_code', () => {
      const wrong = generateTotp(secret) === '000000' ? '000001' : '000000';
      const result = checkMfaCode(enrollment, { code: wrong });
      assert.deepStrictEqual(result, { ok: false, error: 'mfa_invalid_code' });
    });

    it('accepts an unconsumed recovery code and returns its hash', () => {
      const result = checkMfaCode(enrollment, { recoveryCode: recovery });
      assert.deepStrictEqual(result, {
        ok: true, via: 'recovery_code', hash: hashRecoveryCode(recovery),
      });
    });

    it('distinguishes a consumed recovery code from an unknown one', () => {
      const consumedEnrollment = {
        secret,
        recoveryCodes: [{ hash: hashRecoveryCode(recovery), consumedAt: new Date() }],
      };
      assert.deepStrictEqual(
        checkMfaCode(consumedEnrollment, { recoveryCode: recovery }),
        { ok: false, error: 'recovery_code_consumed' },
      );
      // Unknown code → same shape as a wrong TOTP (no oracle).
      assert.deepStrictEqual(
        checkMfaCode(enrollment, { recoveryCode: 'zzzz-zzzz' }),
        { ok: false, error: 'mfa_invalid_code' },
      );
    });

    it('prefers code over recoveryCode when both are present', () => {
      const result = checkMfaCode(enrollment, {
        code: generateTotp(secret),
        recoveryCode: 'zzzz-zzzz',
      });
      assert.deepStrictEqual(result, { ok: true, via: 'totp' });
    });
  });

  describe('challenge token', () => {
    it('round-trips sub/email/tv claims', async () => {
      const token = await signMfaChallenge({ sub: 'u1', email: 'a@b.c', tv: 3 });
      const claims = await verifyMfaChallenge(token);
      assert.strictEqual(claims.sub, 'u1');
      assert.strictEqual(claims.email, 'a@b.c');
      assert.strictEqual(claims.tv, 3);
      assert.strictEqual(claims.kind, MFA_CHALLENGE_KIND);
    });

    it('distinguishes expired from invalid', async () => {
      const expired = await signMfaChallenge({ sub: 'u1', email: 'a@b.c' }, -10);
      await assert.rejects(verifyMfaChallenge(expired), (e: any) => {
        assert.ok(e instanceof MfaChallengeError);
        assert.strictEqual(e.code, 'mfa_challenge_expired');
        return true;
      });

      await assert.rejects(verifyMfaChallenge('not-a-token'), (e: any) => {
        assert.strictEqual(e.code, 'mfa_invalid_challenge');
        return true;
      });
    });

    it('rejects non-challenge JWTs (wrong kind)', async () => {
      const sessionLike = await JWT.sign({ userId: 'u1', role: 'admin' });
      await assert.rejects(verifyMfaChallenge(sessionLike), (e: any) => {
        assert.strictEqual(e.code, 'mfa_invalid_challenge');
        return true;
      });
    });
  });

  describe('createMfaRateLimiter', () => {
    it('allows up to capacity then blocks', async () => {
      const limiter = createMfaRateLimiter({ capacity: 2, refillPerSec: 0 });
      assert.strictEqual(await limiter.check('k'), true);
      assert.strictEqual(await limiter.check('k'), true);
      assert.strictEqual(await limiter.check('k'), false);
      // other keys unaffected
      assert.strictEqual(await limiter.check('other'), true);
    });

    it('refills over time', async () => {
      const limiter = createMfaRateLimiter({ capacity: 1, refillPerSec: 100 });
      assert.strictEqual(await limiter.check('k'), true);
      assert.strictEqual(await limiter.check('k'), false);
      await new Promise((r) => setTimeout(r, 30));
      assert.strictEqual(await limiter.check('k'), true);
    });
  });
});
