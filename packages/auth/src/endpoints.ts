import { createEndpoint, debugAndPrintError, generateId, logger, matchMaker, type Endpoint } from '@colyseus/core';
import { APIError } from '@colyseus/better-call';
import { z } from 'zod';

import { JWT } from './JWT.ts';
import { Hash } from './Hash.ts';
import { auth, type AuthSettings, type MayHaveUpgradeToken } from './auth.ts';
import {
  MFA_CHALLENGE_TTL_SECONDS,
  checkMfaCode,
  createMfaRateLimiter,
  ipFromHeaders,
  signMfaChallenge,
  verifyMfaChallenge,
  type MfaRateLimiter,
} from './mfa.ts';
import { oauth } from './oauth.ts';
import { oauthEndpoints } from './oauth-endpoints.ts';
import { readTemplate } from './templates.ts';

function html(body: string, status = 200): Response {
  return new Response(body, { status, headers: { 'content-type': 'text/html; charset=utf-8' } });
}
function redirect(to: string): Response {
  return new Response(null, { status: 302, headers: { location: to } });
}

const RESET_PASSWORD_TOKEN_EXPIRATION_MINUTES = 30;
const MIN_PASSWORD_LENGTH = 6;

// Login + forgot-password accept email as plain string (no format check) so
// 400-vs-401 doesn't leak which emails exist. Format validation is done
// inside the handler and surfaces as 401 invalid_credentials.
const credentialsBody = z.object({
  email: z.string(),
  password: z.string(),
});

const emailFormat = z.email();

function isValidEmail(email: string) {
  return emailFormat.safeParse(email).success;
}

// Lazily derive auth.backend_url from the request when it hasn't been set
// explicitly. Mirrors the OAuth endpoints' originFromContext — needed so
// confirm-email / reset-password links resolve to a real host now that the
// express `originDetector` middleware is gone.
function ensureBackendUrl(ctx: any) {
  if (auth.backend_url) { return; }
  const proto = ctx.getHeader('x-forwarded-proto')
    ?? (ctx.request?.url?.startsWith('https://') ? 'https' : 'http');
  const host = ctx.getHeader('host') ?? 'localhost';
  auth.backend_url = `${proto}://${host}`;
}

const tokenStatusQuery = z.object({
  token: z.string().optional(),
  success: z.string().optional(),
  error: z.string().optional(),
});

// MFA verify accepts the challenge JWT plus either a TOTP `code` or a
// `recoveryCode`. Both are plain strings — format problems surface as the
// same 401 `mfa_invalid_code` as a wrong code, never a 400 that could
// discriminate between accounts.
const mfaVerifyBody = z.object({
  challenge: z.string(),
  code: z.string().optional(),
  recoveryCode: z.string().optional(),
});

/**
 * Strip fields that must never leave the server: the password hash (already
 * handled historically) and the MFA material. The user object is both
 * returned in the response body AND encoded into the JWT by the default
 * `onGenerateToken` — a leaked `mfaSecret` would defeat MFA entirely.
 */
function stripSensitiveFields(user: any) {
  delete user.password;
  delete user.mfaSecret;
  delete user.mfaRecoveryCodes;
}

function mfaChallengeTtl(): number {
  return auth.settings.mfaChallengeTtlSeconds ?? MFA_CHALLENGE_TTL_SECONDS;
}

// Lazily-created default limiter (5 attempts, ~1 per 12s refill). Resolved
// per-request so `auth.settings.mfaLimiter` can be assigned any time before
// the first verify call.
let defaultMfaLimiter: MfaRateLimiter | undefined;
function resolveMfaLimiter(): MfaRateLimiter | null {
  const setting = auth.settings.mfaLimiter;
  if (setting === false) { return null; }
  if (setting) { return setting; }
  defaultMfaLimiter ??= createMfaRateLimiter({ capacity: 5, refillPerSec: 1 / 12, retryAfterSec: 12 });
  return defaultMfaLimiter;
}

// ---------------------------------------------------------------------------
// Endpoint factories. Each is a small builder that returns a strongly-typed
// callable Endpoint. Call them as functions from tests
// (`await loginEndpoint()({ body: {...} })`) for end-to-end typed contracts.
// `endpoints()` below assembles them into a map for `createRouter()` spread.
// ---------------------------------------------------------------------------

export function userdataEndpoint(prefix: string = auth.prefix) {
  return createEndpoint(`${prefix}/userdata`, {
    method: 'GET',
    use: [auth.middleware()],
  }, async (ctx) => {
    try {
      return { user: await auth.settings.onParseToken(ctx.context.auth as any) };
    } catch (e: any) {
      throw new APIError(401, { error: e.message });
    }
  });
}

export function loginEndpoint(prefix: string = auth.prefix) {
  return createEndpoint(`${prefix}/login`, {
    method: 'POST',
    body: credentialsBody,
  }, async (ctx) => {
    try {
      if (!isValidEmail(ctx.body.email)) { throw new Error('email_malformed'); }

      const user: any = Object.assign({}, await auth.settings.onFindUserByEmail(ctx.body.email));
      if (user && await Hash.verify(ctx.body.password, user.password)) {
        if (auth.settings.onCheckBanned) {
          const banned = await auth.settings.onCheckBanned(user);
          if (banned) {
            throw new APIError(403, {
              error: 'banned',
              reason: banned.reason ?? null,
              until: banned.until instanceof Date
                ? banned.until.toISOString()
                : banned.until ?? null,
            });
          }
        }

        // MFA branch: the password is right, but the account requires a
        // one-time challenge before a real token is issued. The challenge
        // JWT proves "password ok" for `/auth/mfa/verify` without granting
        // a session. Accounts without an enrollment fall through to the
        // legacy password-only response.
        const enrollment = await auth.settings.onGetMfaEnrollment?.(user);
        if (enrollment?.secret) {
          const ttl = mfaChallengeTtl();
          const challenge = await signMfaChallenge({
            sub: String(user.id ?? user.email),
            email: ctx.body.email,
            tv: typeof user.tokenVersion === 'number' ? user.tokenVersion : undefined,
          }, ttl);
          return { mfa: 'required' as const, challenge, expiresIn: ttl };
        }

        stripSensitiveFields(user);
        return { user, token: await auth.settings.onGenerateToken(user) };
      }
      throw new Error('invalid_credentials');
    } catch (e: any) {
      if (e instanceof APIError) { throw e; }
      logger.error(e);
      throw new APIError(401, { error: e.message });
    }
  });
}

/**
 * POST /auth/mfa/verify — complete the MFA challenge started by `/login`.
 *
 * Body: `{ challenge, code }` (TOTP) or `{ challenge, recoveryCode }`.
 * Success returns the same `{ user, token }` shape as a password-only
 * login, plus `mfa: 'totp' | 'recovery_code'` recording which factor was
 * used. Failure states are distinct 401 error tags:
 *
 *   mfa_invalid_challenge   — malformed / wrong-kind / superseded challenge
 *   mfa_challenge_expired   — challenge JWT past its 5-minute TTL
 *   mfa_session_revoked     — tokenVersion bumped since the challenge was
 *                             issued (password reset, "sign out everywhere")
 *   mfa_invalid_code        — wrong TOTP, or unknown recovery code
 *   recovery_code_consumed  — that recovery code was already spent
 *
 * Attempts are rate-limited per (ip, user) AFTER the challenge signature
 * is verified — so strangers can't burn a legitimate user's budget — and
 * the 429 shape is identical whether or not the account exists.
 */
export function mfaVerifyEndpoint(prefix: string = auth.prefix) {
  return createEndpoint(`${prefix}/mfa/verify`, {
    method: 'POST',
    body: mfaVerifyBody,
  }, async (ctx) => {
    try {
      if (!ctx.body.code && !ctx.body.recoveryCode) {
        throw new APIError(400, { error: 'code_or_recovery_code_required' });
      }

      // 1. Challenge JWT — distinguishes "expired" from "invalid".
      const claims = await verifyMfaChallenge(ctx.body.challenge).catch((e: any) => {
        throw new APIError(401, { error: e?.code ?? 'mfa_invalid_challenge' });
      });

      // 2. Rate limit per (ip, challenge subject). Keyed on the VERIFIED
      //    subject, so an attacker spraying garbage challenges can't lock
      //    out the real user — they can only throttle themselves.
      const limiter = resolveMfaLimiter();
      if (limiter) {
        const key = `mfa:${ipFromHeaders(ctx.getHeader)}:${claims.sub}`;
        if (!(await limiter.check(key))) {
          throw new APIError(429, { error: 'rate_limited', retryAfterSec: limiter.retryAfterSec ?? 1 });
        }
      }

      // 3. Session revocation: if the user's tokenVersion moved since the
      //    challenge was issued, the challenge is void — same check the
      //    room-join path applies to full tokens.
      if (claims.tv !== undefined && JWT.settings.revocationCheck) {
        const stillValid = await JWT.settings.revocationCheck({ id: claims.sub, tokenVersion: claims.tv });
        if (!stillValid) { throw new APIError(401, { error: 'mfa_session_revoked' }); }
      }

      // 4. Re-fetch the user for the CURRENT enrollment state (MFA could
      //    have been disabled — or enabled — after the challenge was minted).
      const found = await auth.settings.onFindUserByEmail(claims.email);
      if (!found) { throw new APIError(401, { error: 'mfa_invalid_challenge' }); }
      const user: any = Object.assign({}, found);
      const enrollment = await auth.settings.onGetMfaEnrollment?.(user);
      if (!enrollment?.secret) { throw new APIError(401, { error: 'mfa_invalid_challenge' }); }

      // 5. Recovery codes require a persistence callback — without one we
      //    couldn't mark the code consumed, making it silently reusable.
      if (ctx.body.recoveryCode && typeof auth.settings.onConsumeRecoveryCode !== 'function') {
        throw new APIError(401, { error: 'mfa_invalid_code' });
      }

      // 6. Verify the factor.
      const result = checkMfaCode(enrollment, {
        code: ctx.body.code,
        recoveryCode: ctx.body.recoveryCode,
      });
      if (result.ok === false) { throw new APIError(401, { error: result.error }); }
      if (result.via === 'recovery_code') {
        await auth.settings.onConsumeRecoveryCode!(user, result.hash);
      }

      stripSensitiveFields(user);
      return { user, token: await auth.settings.onGenerateToken(user), mfa: result.via };
    } catch (e: any) {
      if (e instanceof APIError) { throw e; }
      logger.error(e);
      throw new APIError(401, { error: e.message });
    }
  });
}

export function registerEndpoint(prefix: string = auth.prefix) {
  return createEndpoint(`${prefix}/register`, {
    method: 'POST',
    body: z.object({
      email: z.email({ error: 'email_malformed' }),
      password: z.string().min(MIN_PASSWORD_LENGTH, { error: 'password_too_short' }),
      options: z.record(z.string(), z.unknown()).optional(),
    }),
  }, async (ctx) => {
    const { email, password } = ctx.body;

    let existingUser: any;
    try {
      existingUser = await auth.settings.onFindUserByEmail(email);
    } catch (e: any) {
      logger.error('@colyseus/auth, onFindUserByEmail exception:' + e.stack);
    }

    try {
      if (existingUser) { throw new Error('email_already_in_use'); }

      const options: MayHaveUpgradeToken = (ctx.body.options as any) || {};
      const authHeader = ctx.getHeader('authorization');
      if (authHeader) {
        const token = authHeader.startsWith('Bearer ') ? authHeader.substring(7) : undefined;
        options.upgradingToken = await JWT.verify(token!);
      }

      await auth.settings.onRegisterWithEmailAndPassword(email, await Hash.make(password), options);

      const user: any = Object.assign({}, await auth.settings.onFindUserByEmail(email));
      delete user.password;
      const token = await auth.settings.onGenerateToken(user);

      if (typeof auth.settings.onSendEmailConfirmation === 'function') {
        ensureBackendUrl(ctx);
        const confirmEmailLink = `${auth.backend_url}${prefix}/confirm-email?token=${token}`;
        const filledHtml = (await readTemplate('address-confirmation-email.html'))
          .replace('[LINK]', confirmEmailLink);
        await auth.settings.onSendEmailConfirmation(email, filledHtml, confirmEmailLink);
      }

      return { user, token };
    } catch (e: any) {
      if (e instanceof APIError) { throw e; }
      logger.error(e);
      throw new APIError(401, { error: e.message });
    }
  });
}

export function anonymousEndpoint(prefix: string = auth.prefix) {
  return createEndpoint(`${prefix}/anonymous`, {
    method: 'POST',
    body: z.object({ options: z.record(z.string(), z.unknown()).optional() }).optional(),
  }, async (ctx) => {
    try {
      const options = ctx.body?.options;
      const user = auth.settings.onRegisterAnonymously
        ? await auth.settings.onRegisterAnonymously(options)
        : { ...options, id: undefined, anonymousId: generateId(21), anonymous: true };

      return { user, token: await auth.settings.onGenerateToken(user) };
    } catch (e: any) {
      debugAndPrintError(e);
      throw new APIError(401, { error: e.message });
    }
  });
}

// Permissive email type (plain string) so a malformed address doesn't 400 and
// reveal which inputs look valid.
export function forgotPasswordEndpoint(prefix: string = auth.prefix) {
  return createEndpoint(`${prefix}/forgot-password`, {
    method: 'POST',
    body: z.object({ email: z.string() }),
  }, async (ctx) => {
    try {
      if (typeof auth.settings.onForgotPassword !== 'function') {
        // Misconfiguration, not a client error: log loudly so an
        // operator notices, but return a generic success-shaped
        // response so the endpoint can't be used to probe accounts
        // (same anti-enumeration posture as a normal request).
        logger.error(
          '[@colyseus/auth] /auth/forgot-password was called but ' +
          'auth.settings.onForgotPassword is not configured — NO email ' +
          'was sent. Wire it to your email provider to enable password resets.',
        );
        return true;
      }
      if (typeof auth.settings.onResetPassword !== 'function') {
        throw new Error('auth.settings.onResetPassword must be implemented.');
      }

      const { email } = ctx.body;
      const user = await auth.settings.onFindUserByEmail(email);
      if (!user) { throw new Error('email_not_found'); }

      ensureBackendUrl(ctx);
      const token = await JWT.sign({ email }, { expiresIn: `${RESET_PASSWORD_TOKEN_EXPIRATION_MINUTES}m` });
      const passwordResetLink = `${auth.backend_url}${prefix}/reset-password?token=${token}`;
      const filledHtml = (await readTemplate('reset-password-email.html')).replace('[LINK]', passwordResetLink);

      return (await auth.settings.onForgotPassword(email, filledHtml, passwordResetLink)) ?? true;
    } catch (e: any) {
      debugAndPrintError(e);
      throw new APIError(401, { error: e.message });
    }
  });
}

export function resetPasswordGetEndpoint(prefix: string = auth.prefix) {
  return createEndpoint(`${prefix}/reset-password`, {
    method: 'GET',
    query: tokenStatusQuery,
  }, async (ctx) => {
    try {
      const token = ctx.query.token ?? '';
      const filled = (await readTemplate('reset-password-form.html'))
        .replace('[ACTION]', `${prefix}/reset-password`)
        .replace('[TOKEN]', token);
      return html(filled);
    } catch (e: any) {
      logger.debug(e);
      return new Response(`Error: ${e.message}`);
    }
  });
}

export function resetPasswordPostEndpoint(prefix: string = auth.prefix) {
  return createEndpoint(`${prefix}/reset-password`, {
    method: 'POST',
    body: z.object({
      token: z.string(),
      password: z.string().min(MIN_PASSWORD_LENGTH, { error: 'Password is too short.' }),
    }),
  }, async (ctx) => {
    const { token, password } = ctx.body;

    try {
      const data = await JWT.verify<{ email: string }>(token);

      if (matchMaker.presence?.get('reset-password:' + token)) {
        throw new Error('token_already_used');
      }

      const result = await auth.settings.onResetPassword!(data.email, await Hash.make(password)) ?? true;
      if (!result) { throw new Error('Could not reset password.'); }

      matchMaker.presence?.setex(
        'reset-password:' + token, '1',
        60 * RESET_PASSWORD_TOKEN_EXPIRATION_MINUTES,
      );

      return redirect(`${prefix}/reset-password?success=` + encodeURIComponent('Password reset successfully!'));
    } catch (e: any) {
      return redirect(`${prefix}/reset-password?token=${token}&error=` + encodeURIComponent(e.message));
    }
  });
}

export function confirmEmailEndpoint(prefix: string = auth.prefix) {
  return createEndpoint(`${prefix}/confirm-email`, {
    method: 'GET',
    query: tokenStatusQuery,
  }, async (ctx) => {
    if (ctx.query.success || ctx.query.error) {
      return html(await readTemplate('address-confirmation.html'));
    }

    if (typeof auth.settings.onEmailConfirmed !== 'function') {
      return new Response('Not found.', { status: 404 });
    }

    try {
      const token = ctx.query.token ?? '';
      const data = await JWT.verify<{ email: string }>(token);
      await auth.settings.onEmailConfirmed(data.email);
      return redirect(`${prefix}/confirm-email?success=` + encodeURIComponent('Email confirmed successfully!'));
    } catch (e: any) {
      return redirect(`${prefix}/confirm-email?error=` + encodeURIComponent(e.message));
    }
  });
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface EndpointsOptions {
  /** Callbacks merged into the `auth.settings` singleton. Equivalent to `Object.assign(auth.settings, settings)`. */
  settings?: Partial<AuthSettings>;
  /** Route prefix. Defaults to `auth.prefix` (`'/auth'`). */
  prefix?: string;
  /** Set to `false` to skip OAuth endpoints (no `SESSION_SECRET` needed). */
  oauth?: boolean | { cookieSecret?: string };
}

export function endpoints(opts: EndpointsOptions = {}): Record<string, Endpoint> {
  if (opts.settings) {
    for (const key of Object.keys(opts.settings)) {
      (auth.settings as any)[key] = (opts.settings as any)[key];
    }
    // Mirror auth.routes() behavior: a supplied onOAuthProviderCallback wires
    // into the oauth singleton (the OAuth endpoints read from there).
    if (opts.settings.onOAuthProviderCallback) {
      oauth.onCallback(opts.settings.onOAuthProviderCallback);
    }
  }

  const prefix = opts.prefix ?? auth.prefix;

  const map: Record<string, Endpoint> = {
    'auth-userdata': userdataEndpoint(prefix),
    'auth-login': loginEndpoint(prefix),
    'auth-mfa-verify': mfaVerifyEndpoint(prefix),
    'auth-register': registerEndpoint(prefix),
    'auth-anonymous': anonymousEndpoint(prefix),
    'auth-forgot-password': forgotPasswordEndpoint(prefix),
    'auth-reset-password-get': resetPasswordGetEndpoint(prefix),
    'auth-reset-password-post': resetPasswordPostEndpoint(prefix),
    'auth-confirm-email': confirmEmailEndpoint(prefix),
  };

  if (opts.oauth !== false) {
    const oauthOpts = typeof opts.oauth === 'object' ? opts.oauth : {};
    Object.assign(map, oauthEndpoints({
      prefix,
      cookieSecret: oauthOpts.cookieSecret,
    }));
  }

  return map;
}
