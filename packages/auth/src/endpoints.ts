import { createEndpoint, debugAndPrintError, generateId, logger, matchMaker, type Endpoint } from '@colyseus/core';
import { APIError } from '@colyseus/better-call';
import { z } from 'zod';

import { JWT } from './JWT.ts';
import { Hash } from './Hash.ts';
import { auth, type AuthSettings, type MayHaveUpgradeToken } from './auth.ts';
import {
  MFA_CHALLENGE_TTL_SECONDS,
  mfaChallengeLimiter,
  signMfaChallenge,
  verifyMfaChallenge,
  verifyTOTP,
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

        // MFA fork: password is valid, but an enrolled account must still
        // complete the one-time challenge. We answer 401 `mfa_required`
        // with a short-lived challenge token instead of a session token —
        // the "password ok, challenge pending" login state. Accounts
        // without an MFA record fall through to the legacy token issue.
        if (auth.settings.onFindMfa && user.id != null) {
          let mfa: { secret: string } | null | undefined = null;
          try {
            mfa = await auth.settings.onFindMfa(user);
          } catch (lookupError: any) {
            // Fail open: a broken MFA store (e.g. migration not applied
            // yet) must not lock every user out. Logged loudly so the
            // operator notices the downgrade.
            logger.error('[@colyseus/auth] onFindMfa failed — issuing token without MFA challenge: ' + (lookupError?.message ?? lookupError));
          }
          if (mfa) {
            const mfaToken = await signMfaChallenge({
              id: user.id,
              email: ctx.body.email,
              tv: user.tokenVersion,
            });
            throw new APIError(401, {
              error: 'mfa_required',
              mfaToken,
              expiresIn: MFA_CHALLENGE_TTL_SECONDS,
            });
          }
        }

        delete user.password;
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
 * POST /auth/mfa/verify — complete the one-time challenge issued by
 * `/auth/login` (401 `mfa_required`). Body: `{ token, code }` where `code`
 * is either the 6-digit authenticator code or a recovery code.
 *
 * Distinct failure states (all 401 unless noted):
 *   - `mfa_challenge_expired`  — challenge token TTL ran out; log in again.
 *   - `invalid_challenge`      — malformed, replayed, or orphaned challenge.
 *   - `session_revoked`        — tokenVersion moved since the challenge was
 *                                issued (password reset / sign-out-everywhere).
 *   - `invalid_code`           — wrong TOTP or unknown recovery code.
 *   - `recovery_code_consumed` — the recovery code was valid once but is spent.
 *   - 429 `too_many_attempts`  — per-challenge retry cap hit; log in again.
 */
export function mfaVerifyEndpoint(prefix: string = auth.prefix) {
  return createEndpoint(`${prefix}/mfa/verify`, {
    method: 'POST',
    body: z.object({
      token: z.string(),
      code: z.string(),
    }),
  }, async (ctx) => {
    try {
      if (typeof auth.settings.onFindMfa !== 'function') {
        // Login can only have issued a challenge when the hook existed —
        // reaching here without it means a misconfigured deployment.
        throw new Error('auth.settings.onFindMfa is not implemented.');
      }

      const { token, code } = ctx.body;

      const verification = await verifyMfaChallenge(token);
      if (verification.status === 'expired') {
        throw new APIError(401, { error: 'mfa_challenge_expired' });
      } else if (verification.status !== 'ok') {
        throw new APIError(401, { error: 'invalid_challenge' });
      }
      const { claims } = verification;

      // Single-use + per-challenge attempt cap (anti online-brute-force).
      const limit = mfaChallengeLimiter.check(claims.jti, (claims.exp ?? 0) * 1000);
      if (limit === 'used') { throw new APIError(401, { error: 'invalid_challenge' }); }
      if (limit === 'too_many_attempts') { throw new APIError(429, { error: 'too_many_attempts' }); }

      const fail = (error: string, status: 401 | 429 = 401): never => {
        mfaChallengeLimiter.recordFailure(claims.jti);
        throw new APIError(status, { error });
      };

      // "Session revoked" — the user's tokenVersion moved after the
      // challenge was issued (password reset, sign-out-everywhere, ban).
      if (claims.tv !== undefined && JWT.settings.revocationCheck) {
        const valid = await JWT.settings.revocationCheck({ id: claims.id, tokenVersion: claims.tv });
        if (!valid) { throw new APIError(401, { error: 'session_revoked' }); }
      }

      // Re-load a fresh user row: the challenge only proves the password
      // was right a moment ago — ban/MFA state may have moved since.
      const user: any = Object.assign({}, await auth.settings.onFindUserByEmail(claims.email));
      if (!user) { fail('invalid_challenge'); }

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

      let mfa: { secret: string } | null | undefined = null;
      try {
        mfa = await auth.settings.onFindMfa(user);
      } catch (lookupError: any) {
        logger.error('[@colyseus/auth] onFindMfa failed during verify: ' + (lookupError?.message ?? lookupError));
        throw new APIError(401, { error: 'mfa_unavailable' });
      }

      // MFA was disabled between challenge and verify — the password check
      // already passed, so complete the sign-in without a second factor.
      if (!mfa) {
        delete user.password;
        return { user, token: await auth.settings.onGenerateToken(user) };
      }

      // Route by code shape: 6 digits → authenticator TOTP; anything else
      // → recovery code. (The two formats can't collide by construction.)
      let method: 'totp' | 'recovery';
      const normalized = code.trim();
      if (/^\d{6}$/.test(normalized)) {
        if (!verifyTOTP(mfa.secret, normalized)) { fail('invalid_code'); }
        method = 'totp';
      } else {
        if (typeof auth.settings.onConsumeRecoveryCode !== 'function') { fail('invalid_code'); }
        const status = await auth.settings.onConsumeRecoveryCode(user, normalized);
        if (status === 'already_consumed') { fail('recovery_code_consumed'); }
        if (status !== 'ok') { fail('invalid_code'); }
        method = 'recovery';
      }

      mfaChallengeLimiter.consume(claims.jti);
      delete user.password;
      return { user, token: await auth.settings.onGenerateToken(user), mfa: { method } };
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
