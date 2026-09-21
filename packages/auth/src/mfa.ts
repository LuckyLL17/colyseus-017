/**
 * Optional one-time MFA (TOTP challenge + single-use recovery codes) for the
 * email/password login flow.
 *
 * Scope notes (deliberately narrow):
 *   - ONE protocol: RFC 6238 TOTP (HMAC-SHA1, 30s step, 6 digits) — the
 *     "authenticator app" de-facto standard. No SMS/WebAuthn/device-trust
 *     here; those need their own enrollment UX and are out of scope.
 *   - Recovery codes are random, high-entropy, and stored HASHED
 *     (`sha256$<hex>`). They're single-use: consumption is persisted via
 *     `auth.settings.onConsumeRecoveryCode`.
 *   - The MFA challenge itself is a short-lived JWT (`kind: 'mfa-challenge'`)
 *     minted after the password check passes. It is NOT a session token —
 *     `Room.onAuth` and the admin's `verifySession` both refuse it.
 *
 * Login state machine (each state is a distinct, observable outcome):
 *   password ok, no enrollment     → normal `{ user, token }` (legacy flow)
 *   password ok, enrolled          → `{ mfa: 'required', challenge }`
 *   challenge JWT expired          → 401 `mfa_challenge_expired`
 *   recovery code already consumed → 401 `recovery_code_consumed`
 *   tokenVersion moved on          → 401 `mfa_session_revoked`
 */
import crypto from 'crypto';
import { JWT } from './JWT.ts';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** One stored recovery code. `hash` is `sha256$<hex>` of the normalized code. */
export interface MfaRecoveryCodeEntry {
  hash: string;
  /** Set once the code has been consumed. Consumed codes can never be reused. */
  consumedAt?: Date | string | null;
}

/**
 * A user's MFA enrollment. Presence of `secret` means the account requires
 * a one-time challenge after the password check. Accounts without an
 * enrollment (legacy rows) skip MFA entirely.
 */
export interface MfaEnrollment {
  /** Base32 TOTP shared secret. */
  secret: string;
  /** Recovery codes as stored hashes — never the plaintext codes. */
  recoveryCodes: MfaRecoveryCodeEntry[];
}

/** Claims embedded in the MFA challenge JWT. */
export interface MfaChallengeClaims {
  /** User id the challenge was issued for. */
  sub: string;
  /** Email the user authenticated with — used to re-fetch the row at verify time. */
  email: string;
  /** `tokenVersion` at challenge-issue time; a bump revokes the challenge. */
  tv?: number;
  kind: typeof MFA_CHALLENGE_KIND;
  iat?: number;
  exp?: number;
}

export const MFA_CHALLENGE_KIND = 'mfa-challenge' as const;
export const MFA_CHALLENGE_TTL_SECONDS = 5 * 60; // 5 minutes

// ---------------------------------------------------------------------------
// TOTP (RFC 6238)
// ---------------------------------------------------------------------------

const TOTP_STEP_SECONDS = 30;
const TOTP_DIGITS = 6;
const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Generate a fresh base32 TOTP secret (160 bits — the conventional size). */
export function generateMfaSecret(): string {
  return base32Encode(crypto.randomBytes(20));
}

/**
 * The TOTP code for `secret` at `timestampMs`. Exposed mainly so apps (and
 * tests) can compute the expected code server-side; clients normally use an
 * authenticator app.
 */
export function generateTotp(secret: string, timestampMs: number = Date.now()): string {
  const key = base32Decode(secret);
  const counter = BigInt(Math.floor(timestampMs / 1000 / TOTP_STEP_SECONDS));
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(counter);
  const digest = crypto.createHmac('sha1', key).update(msg).digest();
  const offset = digest[digest.length - 1]! & 0x0f;
  const binary =
    ((digest[offset]! & 0x7f) << 24) |
    ((digest[offset + 1]! & 0xff) << 16) |
    ((digest[offset + 2]! & 0xff) << 8) |
    (digest[offset + 3]! & 0xff);
  return String(binary % 10 ** TOTP_DIGITS).padStart(TOTP_DIGITS, '0');
}

/**
 * Verify a 6-digit TOTP code. `window` is the number of 30s steps allowed on
 * either side of "now" (default ±1 → 90s effective validity) to tolerate
 * client clock drift. Returns false for malformed input and bad secrets —
 * never throws.
 */
export function verifyTotp(
  secret: string,
  code: string,
  opts: { window?: number; timestampMs?: number } = {},
): boolean {
  const normalized = String(code ?? '').trim();
  if (!/^\d{6}$/.test(normalized)) { return false; }
  const window = opts.window ?? 1;
  const now = opts.timestampMs ?? Date.now();
  try {
    for (let w = -window; w <= window; w++) {
      const candidate = generateTotp(secret, now + w * TOTP_STEP_SECONDS * 1000);
      if (timingSafeEqualString(candidate, normalized)) { return true; }
    }
  } catch {
    return false; // undecodable secret — treat as "no match"
  }
  return false;
}

function base32Decode(input: string): Buffer {
  const clean = input.toUpperCase().replace(/=+$/, '').replace(/[\s-]+/g, '');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = B32_ALPHABET.indexOf(ch);
    if (idx === -1) { throw new Error('invalid base32 secret'); }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += B32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return out;
}

function timingSafeEqualString(a: string, b: string): boolean {
  if (a.length !== b.length) { return false; }
  try {
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Recovery codes
// ---------------------------------------------------------------------------

// Unambiguous alphabet (no 0/o, 1/l/i) so codes survive being read aloud or
// transcribed from a screenshot.
const RECOVERY_ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789';
const RECOVERY_CODE_LENGTH = 8; // 32^8 ≈ 2^40 — plenty behind a rate limiter
export const RECOVERY_CODE_COUNT = 8;

/**
 * Generate `count` plaintext recovery codes (`xxxx-xxxx`). Show them to the
 * user once; store only `hashRecoveryCode(code)` output.
 */
export function generateRecoveryCodes(count: number = RECOVERY_CODE_COUNT): string[] {
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    let raw = '';
    const bytes = crypto.randomBytes(RECOVERY_CODE_LENGTH);
    for (let j = 0; j < RECOVERY_CODE_LENGTH; j++) {
      raw += RECOVERY_ALPHABET[bytes[j]! % RECOVERY_ALPHABET.length];
    }
    codes.push(`${raw.slice(0, 4)}-${raw.slice(4)}`);
  }
  return codes;
}

/**
 * Normalize (case/dash/space-insensitive) and hash a recovery code for
 * storage or lookup. Deterministic — codes are random high-entropy strings,
 * so an unsalted sha256 is not brute-forceable, and determinism is what lets
 * us look a code up without trying every stored entry.
 */
export function hashRecoveryCode(code: string): string {
  const normalized = String(code ?? '').toLowerCase().replace(/[\s-]+/g, '');
  const digest = crypto.createHash('sha256').update(normalized).digest('hex');
  return `sha256$${digest}`;
}

/**
 * Locate the stored entry matching `code`. Returns the entry (so the caller
 * can inspect `consumedAt`) or null when no stored code matches.
 */
export function findRecoveryCodeEntry(
  entries: MfaRecoveryCodeEntry[] | undefined | null,
  code: string,
): MfaRecoveryCodeEntry | null {
  if (!Array.isArray(entries)) { return null; }
  const hash = hashRecoveryCode(code);
  for (const entry of entries) {
    if (entry && typeof entry.hash === 'string' && timingSafeEqualString(entry.hash, hash)) {
      return entry;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Code verification (TOTP or recovery code)
// ---------------------------------------------------------------------------

export type MfaCheckResult =
  | { ok: true; via: 'totp' }
  | { ok: true; via: 'recovery_code'; hash: string }
  | { ok: false; error: 'mfa_invalid_code' | 'recovery_code_consumed' };

/**
 * Verify one MFA attempt against the enrollment. TOTP is tried first when a
 * `code` is supplied; `recoveryCode` is checked against the stored hashes.
 *
 * Failure shapes are deliberately minimal: a wrong TOTP and an unknown
 * recovery code both surface as `mfa_invalid_code` (no oracle for which
 * recovery codes exist). A *recognized but already consumed* recovery code
 * is the one distinct failure — `recovery_code_consumed` — so the legitimate
 * user can tell "typo" apart from "this code was already spent".
 */
export function checkMfaCode(
  enrollment: MfaEnrollment,
  input: { code?: string; recoveryCode?: string },
): MfaCheckResult {
  if (typeof input.code === 'string' && input.code.trim() !== '') {
    return verifyTotp(enrollment.secret, input.code)
      ? { ok: true, via: 'totp' }
      : { ok: false, error: 'mfa_invalid_code' };
  }

  if (typeof input.recoveryCode === 'string' && input.recoveryCode.trim() !== '') {
    const entry = findRecoveryCodeEntry(enrollment.recoveryCodes, input.recoveryCode);
    if (!entry) { return { ok: false, error: 'mfa_invalid_code' }; }
    if (entry.consumedAt) { return { ok: false, error: 'recovery_code_consumed' }; }
    return { ok: true, via: 'recovery_code', hash: entry.hash };
  }

  return { ok: false, error: 'mfa_invalid_code' };
}

// ---------------------------------------------------------------------------
// Challenge token
// ---------------------------------------------------------------------------

/** Error thrown by `verifyMfaChallenge`; `code` is the wire-facing error tag. */
export class MfaChallengeError extends Error {
  code: 'mfa_challenge_expired' | 'mfa_invalid_challenge';
  constructor(code: 'mfa_challenge_expired' | 'mfa_invalid_challenge') {
    super(code);
    this.code = code;
  }
}

/**
 * Mint the short-lived challenge JWT returned by the login endpoint when the
 * account has MFA enabled. Proves "the password check passed" without
 * granting any session — the `kind` claim keeps it from being replayed as a
 * real token (see `Room.onAuth` and the admin's `verifySession`).
 */
export async function signMfaChallenge(
  claims: { sub: string; email: string; tv?: number },
  ttlSeconds: number = MFA_CHALLENGE_TTL_SECONDS,
): Promise<string> {
  return JWT.sign({ ...claims, kind: MFA_CHALLENGE_KIND }, { expiresIn: ttlSeconds });
}

/**
 * Verify a challenge JWT. Expired tokens surface as `mfa_challenge_expired`
 * (a distinct login state the client can react to by restarting the login);
 * anything else wrong — bad signature, wrong `kind`, missing claims — is the
 * uniform `mfa_invalid_challenge`.
 */
export async function verifyMfaChallenge(token: string): Promise<MfaChallengeClaims> {
  let payload: any;
  try {
    payload = await JWT.verify(token);
  } catch (e: any) {
    if (e?.name === 'TokenExpiredError') {
      throw new MfaChallengeError('mfa_challenge_expired');
    }
    throw new MfaChallengeError('mfa_invalid_challenge');
  }
  if (
    payload?.kind !== MFA_CHALLENGE_KIND ||
    typeof payload.sub !== 'string' ||
    typeof payload.email !== 'string'
  ) {
    throw new MfaChallengeError('mfa_invalid_challenge');
  }
  return payload as MfaChallengeClaims;
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

/**
 * Minimal limiter contract for the MFA verify endpoint. `check` returns
 * `true` when the attempt may proceed. Kept boolean (not Response-based) so
 * it stays transport-agnostic; endpoints translate `false` into their own
 * 429 shape.
 */
export interface MfaRateLimiter {
  check(key: string): boolean | Promise<boolean>;
  /** Hint surfaced in the 429 body. */
  retryAfterSec?: number;
}

interface Bucket {
  tokens: number;
  ts: number;
}

/**
 * In-memory token-bucket limiter (same algorithm as the admin panel's).
 * Default for `auth.settings.mfaLimiter`; single-process only — multi-node
 * deployments should plug a shared-store implementation into the setting.
 */
export function createMfaRateLimiter(opts: {
  capacity: number;
  refillPerSec: number;
  retryAfterSec?: number;
}): MfaRateLimiter {
  const { capacity, refillPerSec } = opts;
  const buckets = new Map<string, Bucket>();
  return {
    retryAfterSec: opts.retryAfterSec ?? 1,
    check(key: string): boolean {
      const now = Date.now();
      let b = buckets.get(key);
      if (!b) {
        b = { tokens: capacity, ts: now };
        buckets.set(key, b);
      } else {
        const elapsed = (now - b.ts) / 1000;
        b.tokens = Math.min(capacity, b.tokens + elapsed * refillPerSec);
        b.ts = now;
      }
      if (b.tokens < 1) { return false; }
      b.tokens -= 1;
      return true;
    },
  };
}

/**
 * Best-effort client IP for rate-limit keys. Same convention as the admin
 * panel's limiter: leftmost X-Forwarded-For, then X-Real-IP, then a shared
 * 'unknown' bucket (degrades to strict, never to open).
 */
export function ipFromHeaders(getHeader: (k: string) => string | null): string {
  const xff = getHeader('x-forwarded-for');
  if (xff) {
    const first = xff.split(',')[0]?.trim();
    if (first) { return first; }
  }
  const xri = getHeader('x-real-ip');
  if (xri) { return xri.trim(); }
  return 'unknown';
}
