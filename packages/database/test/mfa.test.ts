import assert from 'assert';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { describe, it, beforeEach, afterEach } from 'node:test';
import { totp, generateRecoveryCodes } from '@colyseus/auth';
import { GameDatabase } from '../src/index.ts';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * MfaService — TOTP enrollment lifecycle + single-use recovery codes.
 * Runs against sqlite and pglite (same dual-backend pattern as
 * services.test.ts) so the atomic recovery-code consume is exercised
 * under both affected-rows result shapes.
 */

interface Backend {
  name: string;
  newDb(): GameDatabase;
  cleanupOne(db: GameDatabase): Promise<void>;
}

const BACKENDS: Backend[] = [
  {
    name: 'sqlite',
    newDb() {
      const dbPath = path.join(__dirname, `.t-mfa-sqlite-${Date.now()}-${Math.random().toString(36).slice(2)}.db`);
      const db = new GameDatabase({ connectionString: dbPath });
      (db as any).__cleanupPath = dbPath;
      return db;
    },
    async cleanupOne(db) {
      await db.shutdown();
      const dbPath = (db as any).__cleanupPath as string;
      for (const ext of ['', '-shm', '-wal']) {
        try { fs.unlinkSync(dbPath + ext); } catch { /* ignore */ }
      }
    },
  },
  {
    name: 'pglite',
    newDb() {
      const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'colyseus-mfa-pglite-'));
      const db = new GameDatabase({ connectionString: `pglite://${dataDir}` });
      (db as any).__cleanupPath = dataDir;
      return db;
    },
    async cleanupOne(db) {
      await db.shutdown();
      const dataDir = (db as any).__cleanupPath as string;
      try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* ignore */ }
    },
  },
];

for (const backend of BACKENDS) {
  let db: GameDatabase;

  describe(`MfaService (${backend.name})`, () => {
    beforeEach(async () => {
      db = backend.newDb();
      await db.boot();
    });
    afterEach(async () => { await backend.cleanupOne(db); });

    async function enrollAndConfirm(userId: string): Promise<{ secret: string; recoveryCodes: string[] }> {
      const { secret } = await db.mfa.beginEnrollment(userId);
      const result = await db.mfa.confirmEnrollment(userId, totp(secret));
      assert.ok(typeof result === 'object', 'confirm should succeed');
      return { secret, recoveryCodes: result.recoveryCodes };
    }

    it('starts disabled for unknown users', async () => {
      assert.strictEqual(await db.mfa.isEnabled('nobody'), false);
      assert.strictEqual(await db.mfa.getRecord('nobody'), null);
      assert.strictEqual(await db.mfa.verify('nobody', '123456'), false);
    });

    it('begins enrollment in the pending state (not yet enforced)', async () => {
      const { secret } = await db.mfa.beginEnrollment('u1');
      assert.ok(secret.length > 0);
      assert.strictEqual(await db.mfa.isEnabled('u1'), false);
      const record = await db.mfa.getRecord('u1');
      assert.ok(record);
      assert.strictEqual(record!.enabledAt, null);
      assert.strictEqual(record!.secret, secret);
    });

    it('re-beginning enrollment rotates the pending secret', async () => {
      const first = await db.mfa.beginEnrollment('u1');
      const second = await db.mfa.beginEnrollment('u1');
      assert.notStrictEqual(first.secret, second.secret);
      const record = await db.mfa.getRecord('u1');
      assert.strictEqual(record!.secret, second.secret);
      assert.strictEqual(record!.enabledAt, null);
    });

    it('rejects confirm without a pending enrollment', async () => {
      assert.strictEqual(await db.mfa.confirmEnrollment('nobody', '123456'), 'no_enrollment');
    });

    it('rejects a wrong first code as invalid_code', async () => {
      const { secret } = await db.mfa.beginEnrollment('u1');
      const valid = totp(secret);
      const wrong = valid === '000000' ? '000001' : '000000';
      assert.strictEqual(await db.mfa.confirmEnrollment('u1', wrong), 'invalid_code');
      assert.strictEqual(await db.mfa.isEnabled('u1'), false);
    });

    it('confirms enrollment with a valid TOTP and mints recovery codes', async () => {
      const { recoveryCodes } = await enrollAndConfirm('u1');
      assert.strictEqual(await db.mfa.isEnabled('u1'), true);
      assert.strictEqual(recoveryCodes.length, 10);
      assert.strictEqual(await db.mfa.countRemainingRecoveryCodes('u1'), 10);
    });

    it('refuses to re-begin enrollment once enabled', async () => {
      await enrollAndConfirm('u1');
      await assert.rejects(db.mfa.beginEnrollment('u1'), /mfa_already_enabled/);
    });

    it('verifies TOTP codes only while enabled', async () => {
      const { secret } = await enrollAndConfirm('u1');
      assert.strictEqual(await db.mfa.verify('u1', totp(secret)), true);
      assert.strictEqual(await db.mfa.verify('u1', '999999' === totp(secret) ? '000000' : '999999'), false);
    });

    it('consumes recovery codes exactly once (ok → already_consumed → invalid)', async () => {
      const { recoveryCodes } = await enrollAndConfirm('u1');
      const [code] = recoveryCodes;

      assert.strictEqual(await db.mfa.consumeRecoveryCode('u1', code), 'ok');
      assert.strictEqual(await db.mfa.countRemainingRecoveryCodes('u1'), 9);
      // The spent code is recognized as consumed, not merely wrong.
      assert.strictEqual(await db.mfa.consumeRecoveryCode('u1', code), 'already_consumed');
      // Formatting differences (case/dashes) normalize to the same code.
      assert.strictEqual(await db.mfa.consumeRecoveryCode('u1', code.toLowerCase().replaceAll('-', '')), 'already_consumed');
      // A never-issued code is invalid.
      assert.strictEqual(await db.mfa.consumeRecoveryCode('u1', 'AAAA-AAAA-AAAA'), 'invalid');
      // Codes are per-user.
      assert.strictEqual(await db.mfa.consumeRecoveryCode('someone-else', code), 'invalid');
    });

    it('regenerates recovery codes, voiding the previous set', async () => {
      const { recoveryCodes } = await enrollAndConfirm('u1');
      const fresh = await db.mfa.regenerateRecoveryCodes('u1');
      assert.strictEqual(fresh.length, 10);
      assert.strictEqual(await db.mfa.consumeRecoveryCode('u1', recoveryCodes[0]!), 'invalid');
      assert.strictEqual(await db.mfa.consumeRecoveryCode('u1', fresh[0]!), 'ok');
    });

    it('refuses to regenerate codes without an enabled factor', async () => {
      await assert.rejects(db.mfa.regenerateRecoveryCodes('u1'), /mfa_not_enabled/);
    });

    it('disable() wipes the enrollment and all recovery codes', async () => {
      const { secret, recoveryCodes } = await enrollAndConfirm('u1');
      await db.mfa.disable('u1');
      assert.strictEqual(await db.mfa.isEnabled('u1'), false);
      assert.strictEqual(await db.mfa.getRecord('u1'), null);
      assert.strictEqual(await db.mfa.verify('u1', totp(secret)), false);
      assert.strictEqual(await db.mfa.consumeRecoveryCode('u1', recoveryCodes[0]!), 'invalid');
      assert.strictEqual(await db.mfa.countRemainingRecoveryCodes('u1'), 0);
      // Idempotent.
      await db.mfa.disable('u1');
    });

    it('wires auth.settings.onFindMfa / onConsumeRecoveryCode for the login flow', async () => {
      const settings = db.auth.settings;
      const email = 'player@example.com';
      await settings.onRegisterWithEmailAndPassword!(email, 'hashed-password', {});
      const user: any = await settings.onFindUserByEmail!(email);
      assert.ok(user?.id);

      // Legacy account: no enrollment → null → login skips the challenge.
      assert.strictEqual(await settings.onFindMfa!(user), null);

      // Pending enrollment does not count as enabled either.
      const { secret } = await db.mfa.beginEnrollment(user.id);
      assert.strictEqual(await settings.onFindMfa!(user), null);

      const confirmed = await db.mfa.confirmEnrollment(user.id, totp(secret));
      assert.ok(typeof confirmed === 'object');
      const found = await settings.onFindMfa!(user);
      assert.deepStrictEqual(found, { secret });

      // Recovery codes flow through the same hook the endpoint uses.
      const [code] = confirmed.recoveryCodes;
      assert.strictEqual(await settings.onConsumeRecoveryCode!(user, code), 'ok');
      assert.strictEqual(await settings.onConsumeRecoveryCode!(user, code), 'already_consumed');
      assert.strictEqual(await settings.onConsumeRecoveryCode!(user, 'AAAA-AAAA-AAAA'), 'invalid');
    });

    it('does not store recovery codes in plaintext', async () => {
      const { recoveryCodes } = await enrollAndConfirm('u1');
      const rows = await db.drizzle.select().from(db.tables.userMfaRecoveryCodes);
      assert.strictEqual(rows.length, recoveryCodes.length);
      for (const row of rows as any[]) {
        assert.match(row.codeHash, /^[0-9a-f]{64}$/);
        assert.ok(!recoveryCodes.includes(row.codeHash), 'hash must not equal a plaintext code');
        assert.strictEqual(row.consumedAt, null);
      }
    });
  });
}
