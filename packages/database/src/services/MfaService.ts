import { and, count, eq, isNull } from 'drizzle-orm';
import {
  generateMfaSecret,
  generateRecoveryCodes,
  hashRecoveryCode,
  verifyTOTP,
  RECOVERY_CODE_COUNT,
  type RecoveryCodeConsumeStatus,
} from '@colyseus/auth';
import type { UserMfaRecoveryCodesTableShape, UserMfaTableShape } from '../types.ts';
import { affectedRows, type ServiceDb } from './_db.ts';

export interface MfaRecord {
  userId: string;
  /** TOTP shared secret (base32). Present from enrollment start. */
  secret: string;
  /** null while enrollment is pending confirmation — MFA not enforced yet. */
  enabledAt: Date | null;
}

export type { RecoveryCodeConsumeStatus };

/**
 * Result of `confirmEnrollment` — a discriminated union instead of
 * exceptions so endpoint layers can map each outcome to the right HTTP
 * status without string-matching error messages.
 */
export type MfaConfirmResult =
  | { recoveryCodes: string[] }
  | 'no_enrollment'
  | 'invalid_code';

/**
 * Per-user one-time MFA: TOTP enrollment + verification, and single-use
 * recovery codes. Storage lives in the `userMfa` / `userMfaRecoveryCodes`
 * tables; the protocol helpers (TOTP, code hashing) come from
 * `@colyseus/auth`, which also consumes this service through
 * `auth.settings.onFindMfa` / `onConsumeRecoveryCode` (wired in
 * `AuthService.settings`).
 *
 * Lifecycle:
 *   beginEnrollment()   → row with secret, enabledAt = null (pending)
 *   confirmEnrollment() → verifies first TOTP, flips enabledAt, mints
 *                         recovery codes (returned once, in plaintext)
 *   verify()            → TOTP check during a login challenge
 *   consumeRecoveryCode() → atomic single-use recovery path
 *   disable()           → wipes enrollment + codes (legacy login resumes)
 */
export class MfaService<
  M extends UserMfaTableShape = UserMfaTableShape,
  R extends UserMfaRecoveryCodesTableShape = UserMfaRecoveryCodesTableShape,
> {
  private db: ServiceDb;
  private userMfa: M;
  private recoveryCodes: R;

  constructor(db: ServiceDb, userMfa: M, recoveryCodes: R) {
    this.db = db;
    this.userMfa = userMfa;
    this.recoveryCodes = recoveryCodes;
  }

  /** Raw enrollment row, or null when the user never started enrollment. */
  async getRecord(userId: string): Promise<MfaRecord | null> {
    const rows = await this.db
      .select()
      .from(this.userMfa)
      .where(eq(this.userMfa.userId, userId))
      .limit(1);
    return (rows[0] as MfaRecord | undefined) ?? null;
  }

  /** True only when enrollment completed — pending rows don't count. */
  async isEnabled(userId: string): Promise<boolean> {
    const rows = await this.db
      .select({ enabledAt: this.userMfa.enabledAt })
      .from(this.userMfa)
      .where(eq(this.userMfa.userId, userId))
      .limit(1);
    return rows[0]?.enabledAt != null;
  }

  /**
   * Start (or restart) enrollment: stores a fresh TOTP secret in the
   * pending state. Throws `mfa_already_enabled` when the user already has
   * an active factor — they must `disable()` first, so an attacker with a
   * live session can't silently rotate the secret.
   */
  async beginEnrollment(userId: string): Promise<{ secret: string }> {
    const existing = await this.getRecord(userId);
    if (existing?.enabledAt) { throw new Error('mfa_already_enabled'); }

    const secret = generateMfaSecret();
    if (existing) {
      await this.db
        .update(this.userMfa)
        .set({ secret, updatedAt: new Date() })
        .where(eq(this.userMfa.userId, userId));
    } else {
      await this.db
        .insert(this.userMfa)
        .values({ userId, secret, enabledAt: null, createdAt: new Date(), updatedAt: new Date() });
    }
    return { secret };
  }

  /**
   * Confirm a pending enrollment with the first TOTP from the user's
   * authenticator. On success the factor goes live and a fresh set of
   * recovery codes is minted — the plaintext codes are returned here and
   * never stored (only their hashes are).
   */
  async confirmEnrollment(userId: string, code: string): Promise<MfaConfirmResult> {
    const existing = await this.getRecord(userId);
    if (!existing || existing.enabledAt) { return 'no_enrollment'; }
    if (!verifyTOTP(existing.secret, code)) { return 'invalid_code'; }

    await this.db
      .update(this.userMfa)
      .set({ enabledAt: new Date(), updatedAt: new Date() })
      .where(eq(this.userMfa.userId, userId));

    const recoveryCodes = generateRecoveryCodes(RECOVERY_CODE_COUNT);
    await this.replaceRecoveryCodes(userId, recoveryCodes);
    return { recoveryCodes };
  }

  /** Remove the enrollment and every recovery code. Idempotent. */
  async disable(userId: string): Promise<void> {
    await this.db
      .delete(this.recoveryCodes)
      .where(eq(this.recoveryCodes.userId, userId));
    await this.db
      .delete(this.userMfa)
      .where(eq(this.userMfa.userId, userId));
  }

  /** TOTP check against the enabled enrollment. False when not enrolled. */
  async verify(userId: string, code: string): Promise<boolean> {
    const record = await this.getRecord(userId);
    if (!record?.enabledAt) { return false; }
    return verifyTOTP(record.secret, code);
  }

  /**
   * Single-use recovery-code consume. The UPDATE … WHERE consumed_at IS
   * NULL is atomic, so a code replayed concurrently can only win once;
   * the follow-up SELECT exists solely to tell "already spent" apart
   * from "never existed" for the distinct login error states.
   */
  async consumeRecoveryCode(userId: string, code: string): Promise<RecoveryCodeConsumeStatus> {
    const codeHash = hashRecoveryCode(code);
    const result = await this.db
      .update(this.recoveryCodes)
      .set({ consumedAt: new Date() })
      .where(and(
        eq(this.recoveryCodes.userId, userId),
        eq(this.recoveryCodes.codeHash, codeHash),
        isNull(this.recoveryCodes.consumedAt),
      ));
    if (affectedRows(result) === 1) { return 'ok'; }

    const rows = await this.db
      .select({ consumedAt: this.recoveryCodes.consumedAt })
      .from(this.recoveryCodes)
      .where(and(
        eq(this.recoveryCodes.userId, userId),
        eq(this.recoveryCodes.codeHash, codeHash),
      ))
      .limit(1);
    return rows[0] ? 'already_consumed' : 'invalid';
  }

  /**
   * Mint a fresh set of recovery codes, voiding all previous ones.
   * Requires an enabled enrollment — codes without a live factor would
   * be a standing backdoor.
   */
  async regenerateRecoveryCodes(userId: string): Promise<string[]> {
    if (!(await this.isEnabled(userId))) { throw new Error('mfa_not_enabled'); }
    const codes = generateRecoveryCodes(RECOVERY_CODE_COUNT);
    await this.replaceRecoveryCodes(userId, codes);
    return codes;
  }

  /** Unconsumed recovery codes left — useful for "N codes remaining" UX. */
  async countRemainingRecoveryCodes(userId: string): Promise<number> {
    const rows = await this.db
      .select({ c: count() })
      .from(this.recoveryCodes)
      .where(and(
        eq(this.recoveryCodes.userId, userId),
        isNull(this.recoveryCodes.consumedAt),
      ));
    return Number(rows[0]?.c ?? 0);
  }

  private async replaceRecoveryCodes(userId: string, codes: string[]): Promise<void> {
    await this.db
      .delete(this.recoveryCodes)
      .where(eq(this.recoveryCodes.userId, userId));
    if (codes.length === 0) { return; }
    await this.db
      .insert(this.recoveryCodes)
      .values(codes.map((code) => ({
        userId,
        codeHash: hashRecoveryCode(code),
        consumedAt: null,
        createdAt: new Date(),
      })));
  }
}
