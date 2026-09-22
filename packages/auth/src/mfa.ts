/**
 * One-time MFA (TOTP, RFC 6238) + single-use recovery codes + the
 * login-challenge token machinery.
 *
 * Scope is deliberately narrow:
 *   - ONE factor protocol (TOTP — the authenticator-app standard). No
 *     SMS/email/WebAuthn fan-out.
 *   - Recovery codes are opaque random strings; only their SHA-256 hash
 *     is ever persisted (by the storage layer, e.g. @colyseus/database).
 *   - The "challenge" is a short-lived JWT minted after a successful
 *     password check. It is single-use and attempt-capped via
 *     `MfaChallengeLimiter`, so a stolen password yields at most
 *     `maxAttempts` code guesses per login.
 *
 * Everything here is storage-agnostic — persistence hooks live on
 * `auth.settings` (`onFindMfa` / `onConsumeRecoveryCode`).
 */
import crypto from 'crypto';
import { generateId } from '@colyseus/core';
import { JWT } from './JWT.ts';

// ---------------------------------------------------------------------------
// Base32 (RFC 4648, no padding) — the encoding authenticator apps expect
// for TOTP secrets.
// ---------------------------------------------------------------------------

const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buf: Buffer): string {
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

export function base32Decode(str: string): Buffer {
  const clean = str.toUpperCase().replace(/=+$/, '').replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    value = (value << 5) | B32_ALPHABET.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

// ---------------------------------------------------------------------------
// TOTP
// ---------------------------------------------------------------------------

export const TOTP_PERIOD_SECONDS = 30;
export const TOTP_DIGITS = 6;

/**
 * Generate a fresh TOTP shared secret, base32-encoded (20 random bytes →
 * 32 chars). Store it server-side; render it to the user once via
 * `totpUri()` (QR/clipboard) during enrollment.
 */
export function generateMfaSecret(bytes: number = 20): string {
  return base32Encode(crypto.randomBytes(bytes));
}

/**
 * Compute the TOTP code for `secret` at `counter` (defaults to the current
 * 30s step). Exported so tests — and only tests, really — can produce the
 * "correct" code an authenticator would show.
 */
export function totp(secret: string, counter?: number, digits: number = TOTP_DIGITS): string {
  const step = counter ?? Math.floor(Date.now() / 1000 / TOTP_PERIOD_SECONDS);
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(step));
  const digest = crypto.createHmac('sha1', base32Decode(secret)).update(msg).digest();
  const offset = digest[digest.length - 1]! & 0x0f;
  const binary =
    ((digest[offset]! & 0x7f) << 24) |
    (digest[offset + 1]! << 16) |
    (digest[offset + 2]! << 8) |
    digest[offset + 3]!;
  return String(binary % 10 ** digits).padStart(digits, '0');
}

/**
 * Verify a 6-digit TOTP code against `secret`, tolerating ±`window` steps
 * of clock drift (default ±1 → codes stay valid ~30–90s).
 */
export function verifyTOTP(
  secret: string,
  code: string,
  opts: { window?: number; now?: number } = {},
): boolean {
  const normalized = code.replace(/\s+/g, '');
  if (!/^\d{6}$/.test(normalized)) { return false; }
  const window = opts.window ?? 1;
  const now = opts.now ?? Date.now();
  const counter = Math.floor(now / 1000 / TOTP_PERIOD_SECONDS);
  for (let drift = -window; drift <= window; drift++) {
    if (totp(secret, counter + drift) === normalized) { return true; }
  }
  return false;
}

/**
 * `otpauth://` URI for authenticator-app enrollment (QR-encode this, or
 * show it for copy/paste).
 */
export function totpUri(secret: string, opts: { issuer: string; account: string }): string {
  const label = `${encodeURIComponent(opts.issuer)}:${encodeURIComponent(opts.account)}`;
  return `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(opts.issuer)}`;
}

// ---------------------------------------------------------------------------
// Recovery codes
// ---------------------------------------------------------------------------

// Crockford-ish alphabet — no I/O/0/1, so codes stay unambiguous when
// transcribed by hand. 12 chars × 5 bits = 60 bits of entropy per code.
const RECOVERY_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

export const RECOVERY_CODE_COUNT = 10;

/**
 * Mint `count` recovery codes in `XXXX-XXXX-XXXX` display form. These are
 * shown to the user ONCE; only `hashRecoveryCode(code)` may be stored.
 */
export function generateRecoveryCodes(count: number = RECOVERY_CODE_COUNT): string[] {
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    // 256 % 32 === 0, so byte % 32 is unbiased.
    const bytes = crypto.randomBytes(12);
    const chars = Array.from(bytes, (b) => RECOVERY_ALPHABET[b % 32]).join('');
    codes.push(`${chars.slice(0, 4)}-${chars.slice(4, 8)}-${chars.slice(8, 12)}`);
  }
  return codes;
}

/** Strip display formatting so `abcd-efgh-ijkl` and `ABCDEFGHIJKL` hash alike. */
export function normalizeRecoveryCode(code: string): string {
  return code.toUpperCase().replace(/[^A-Z0-9]/g, '');
}

/** SHA-256 of the normalized code — the only form that should touch a database. */
export function hashRecoveryCode(code: string): string {
  return crypto.createHash('sha256').update(normalizeRecoveryCode(code)).digest('hex');
}

// ---------------------------------------------------------------------------
// MFA challenge tokens
// ---------------------------------------------------------------------------

/** How long the post-password challenge stays valid. Short on purpose. */
export const MFA_CHALLENGE_TTL_SECONDS = 5 * 60;

export interface MfaChallengeClaims {
  /** User id the challenge was issued for. */
  id: string;
  /** Login email — lets the verify step re-load a fresh user row. */
  email: string;
  /** Distinguishes MFA challenges from session/reset tokens. */
  kind: 'mfa';
  /** tokenVersion at issue time — catches "session revoked mid-challenge". */
  tv?: number;
  /** Unique challenge id — keys the single-use / attempt-cap limiter. */
  jti: string;
  iat?: number;
  exp?: number;
}

export async function signMfaChallenge(
  claims: { id: string; email: string; tv?: number },
  opts: { ttlSeconds?: number } = {},
): Promise<string> {
  return JWT.sign(
    { id: claims.id, email: claims.email, kind: 'mfa', tv: claims.tv, jti: generateId(21) },
    { expiresIn: opts.ttlSeconds ?? MFA_CHALLENGE_TTL_SECONDS },
  );
}

export type MfaChallengeVerification =
  | { status: 'ok'; claims: MfaChallengeClaims }
  | { status: 'expired' }
  | { status: 'invalid' };

/**
 * Verify a challenge token, mapping every failure to a coarse status so
 * callers can answer with the distinct `mfa_challenge_expired` /
 * `invalid_challenge` login states instead of a raw JWT error.
 */
export async function verifyMfaChallenge(token: string): Promise<MfaChallengeVerification> {
  try {
    const claims = await JWT.verify<MfaChallengeClaims>(token);
    if (!claims || claims.kind !== 'mfa' || !claims.id || !claims.email || !claims.jti) {
      return { status: 'invalid' };
    }
    return { status: 'ok', claims };
  } catch (err: any) {
    return { status: err?.name === 'TokenExpiredError' ? 'expired' : 'invalid' };
  }
}

// ---------------------------------------------------------------------------
// Challenge limiter — single-use + per-challenge attempt cap
// ---------------------------------------------------------------------------

export type MfaChallengeLimitStatus = 'ok' | 'used' | 'too_many_attempts';

interface ChallengeEntry {
  attempts: number;
  used: boolean;
  /** ms epoch — entries self-prune once the underlying JWT is dead anyway. */
  expiresAt: number;
}

/**
 * In-memory guard for MFA challenges:
 *   - caps wrong-code attempts per challenge (default 5), so the 10⁶ TOTP
 *     space can't be online-brute-forced through one stolen password;
 *   - makes a successfully-used challenge single-use (no replay).
 *
 * In-memory is the right default for single-process deployments; the JWT's
 * own 5-minute expiry bounds the blast radius of a process restart (a
 * restarted limiter simply forgets prior attempts). Multi-node deployments
 * that need a shared cap should front the verify endpoint with their own
 * store — the admin panel's pluggable `RateLimiter` covers its side.
 */
export class MfaChallengeLimiter {
  private entries = new Map<string, ChallengeEntry>();
  private maxAttempts: number;

  constructor(opts: { maxAttempts?: number } = {}) {
    this.maxAttempts = opts.maxAttempts ?? 5;
  }

  /**
   * May this challenge be attempted right now? Lazily registers unknown
   * challenges (fail-open on restart — the JWT expiry still bounds them).
   */
  check(jti: string, expiresAt: number): MfaChallengeLimitStatus {
    this.pruneIfNeeded();
    let entry = this.entries.get(jti);
    if (!entry) {
      entry = { attempts: 0, used: false, expiresAt };
      this.entries.set(jti, entry);
    }
    if (entry.used) { return 'used'; }
    if (entry.attempts >= this.maxAttempts) { return 'too_many_attempts'; }
    return 'ok';
  }

  recordFailure(jti: string): void {
    // Lazily register like check() does — a failure on an unknown jti
    // still counts, so a limiter restart can't be gamed into free
    // attempts. The expiry is an upper bound; check() refines it.
    let entry = this.entries.get(jti);
    if (!entry) {
      entry = { attempts: 0, used: false, expiresAt: Date.now() + MFA_CHALLENGE_TTL_SECONDS * 1000 };
      this.entries.set(jti, entry);
    }
    entry.attempts++;
  }

  /** Mark a successfully-verified challenge so it can't be replayed. */
  consume(jti: string): void {
    const entry = this.entries.get(jti);
    if (entry) { entry.used = true; }
  }

  private pruneIfNeeded(): void {
    if (this.entries.size < 1024) { return; }
    const now = Date.now();
    for (const [jti, entry] of this.entries) {
      if (entry.expiresAt <= now) { this.entries.delete(jti); }
    }
  }
}

/**
 * Process-wide default shared by the auth endpoints and @colyseus/admin's
 * MFA verify endpoint — one budget per challenge regardless of which
 * surface issued it.
 */
export const mfaChallengeLimiter = new MfaChallengeLimiter();
