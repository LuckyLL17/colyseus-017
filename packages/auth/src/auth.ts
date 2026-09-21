import { dualModeEndpoints, type ExpressMiddleware } from '@colyseus/core';
import { type OAuthProviderCallback, oauth } from './oauth.ts';
import { JWT, type JwtPayload } from './JWT.ts';
import { Hash } from './Hash.ts';
import type { MfaEnrollment, MfaRateLimiter } from './mfa.ts';

export type MayHaveUpgradeToken = { upgradingToken?: JwtPayload };

export type RegisterWithEmailAndPasswordCallback<T = any> = (email: string, password: string, options: T & MayHaveUpgradeToken) => Promise<unknown>;
export type RegisterAnonymouslyCallback<T = any> = (options: T) => Promise<unknown>;
export type FindUserByEmailCallback = (email: string) => Promise<(unknown & { password: string }) | null | undefined>;

export type SendEmailConfirmationCallback = (email: string, html: string, confirmLink: string) => Promise<unknown>;
export type EmailConfirmedCallback = (email: string) => Promise<unknown>;

export type ForgotPasswordCallback = (email: string, html: string, resetLink: string) => Promise<boolean | unknown>;
export type ResetPasswordCallback = (email: string, password: string) => Promise<unknown>;

export type ParseTokenCallback = (token: JwtPayload) => Promise<unknown> | unknown;
export type GenerateTokenCallback = (userdata: unknown) => Promise<unknown>;
export type HashPasswordCallback = (password: string) => Promise<string>;

/**
 * Return the user's MFA enrollment, or `null`/`undefined` when the account
 * doesn't have MFA enabled (legacy accounts keep the original
 * password-only flow). Called with the user object produced by
 * `onFindUserByEmail`, both at login time and when the challenge is
 * verified (so enrollment changes between the two take effect).
 *
 * The default implementation reads the conventional `mfaSecret` /
 * `mfaRecoveryCodes` fields off the user record — mirroring how
 * `user.password` is a convention. Apps storing MFA state elsewhere
 * (separate table, vault) override this.
 */
export type GetMfaEnrollmentCallback = (user: unknown) =>
  Promise<MfaEnrollment | null | undefined> | MfaEnrollment | null | undefined;

/**
 * Persist that a recovery code was consumed. Called with the user object
 * and the code's stored hash (`sha256$<hex>`) after a successful
 * recovery-code sign-in. When this callback is NOT configured, recovery
 * codes are refused outright — accepting them without persisting
 * consumption would make them silently reusable.
 */
export type ConsumeRecoveryCodeCallback = (user: unknown, codeHash: string) => Promise<unknown>;

/**
 * Info returned by `onCheckBanned` when the user is banned. Both
 * fields are optional — apps that don't want to expose either keep
 * the field absent in their response.
 */
export interface BannedInfo {
  reason?: string | null;
  until?: Date | string | null;
}
/**
 * Optional ban check called after credentials are verified (login)
 * or after an OAuth profile is matched. Return a `BannedInfo` to
 * reject the sign-in as banned; return `null` / `false` / `undefined`
 * to allow.
 *
 * Lets the auth layer distinguish "your credentials are valid but
 * you're banned" from "invalid credentials" — the former needs a
 * different status code (403) and a clearer message for the client.
 */
export type CheckBannedCallback = (user: unknown) =>
  Promise<BannedInfo | null | false | undefined> | BannedInfo | null | false | undefined;

export interface AuthSettings {
  onFindUserByEmail: FindUserByEmailCallback,
  onRegisterWithEmailAndPassword: RegisterWithEmailAndPasswordCallback,
  onRegisterAnonymously: RegisterAnonymouslyCallback,

  onSendEmailConfirmation?: SendEmailConfirmationCallback,
  onEmailConfirmed?: EmailConfirmedCallback,

  onForgotPassword?: ForgotPasswordCallback,
  onResetPassword?: ResetPasswordCallback,

  onOAuthProviderCallback?: OAuthProviderCallback,
  onParseToken?: ParseTokenCallback,
  onGenerateToken?: GenerateTokenCallback,
  onHashPassword?: HashPasswordCallback,
  onCheckBanned?: CheckBannedCallback,

  onGetMfaEnrollment?: GetMfaEnrollmentCallback,
  onConsumeRecoveryCode?: ConsumeRecoveryCodeCallback,
  /**
   * Rate limiter for `/auth/mfa/verify`. Defaults to an in-memory token
   * bucket (5 attempts, ~1 per 12s refill) keyed by (ip, user). Pass
   * `false` to disable, or a custom limiter for multi-node deployments.
   */
  mfaLimiter?: MfaRateLimiter | false,
  /** TTL of the MFA challenge JWT in seconds. Default 300 (5 minutes). */
  mfaChallengeTtlSeconds?: number,
};

let onFindUserByEmail: FindUserByEmailCallback = (email: string) => { throw new Error('`auth.settings.onFindUserByEmail` not implemented.'); };
let onRegisterWithEmailAndPassword: RegisterWithEmailAndPasswordCallback = () => { throw new Error('`auth.settings.onRegisterWithEmailAndPassword` not implemented.'); };
let onParseToken: ParseTokenCallback = (jwt: JwtPayload) => jwt;
let onGenerateToken: GenerateTokenCallback = async (userdata: unknown) => await JWT.sign(userdata);
let onHashPassword: HashPasswordCallback = async (password: string) => Hash.make(password);

/**
 * Default MFA enrollment lookup: reads the conventional `mfaSecret` /
 * `mfaRecoveryCodes` fields off the user record. Rows without
 * `mfaSecret` (legacy accounts) get `null` → password-only flow.
 */
const defaultGetMfaEnrollment: GetMfaEnrollmentCallback = (user: any) => {
  if (!user || typeof user.mfaSecret !== 'string' || user.mfaSecret === '') {
    return null;
  }
  return {
    secret: user.mfaSecret,
    recoveryCodes: Array.isArray(user.mfaRecoveryCodes) ? user.mfaRecoveryCodes : [],
  };
};

export const auth = {
  /**
   * Backend URL (used for OAuth callbacks and email confirmation links)
   */
  backend_url: "",

  /**
   * OAuth utilities
   */
  oauth: oauth,

  settings: {
    /**
     * Find user by email.
     */
    onFindUserByEmail,

    /**
     * Register user by email and password.
     */
    onRegisterWithEmailAndPassword,

    /**
     * (Optional) Register anonymous user.
     */
    onRegisterAnonymously: undefined as RegisterAnonymouslyCallback,

    /**
     * (Optional) Send email address verification confirmation email.
     */
    onSendEmailConfirmation: undefined as SendEmailConfirmationCallback,

    /**
     * (Optional) Send email address verification confirmation email.
     */
    onEmailConfirmed: undefined as EmailConfirmedCallback,

    /**
     * (Optional) Send reset password link via email. Unset by default —
     * `/auth/forgot-password` logs a loud error and no-ops when it's
     * missing (no throw), and `@colyseus/admin`'s reset bridge falls
     * back to logging the link.
     */
    onForgotPassword: undefined as ForgotPasswordCallback,

    /**
     * (Optional) Reset password action.
     */
    onResetPassword: undefined as ResetPasswordCallback,

    /**
     * By default, it returns the contents of the JWT token. (onGenerateToken)
     */
    onParseToken,

    /**
     * By default, it encodes the full `userdata` object into the JWT token.
     */
    onGenerateToken,

    /**
     * Hash password before storing it. By default, it uses scrypt with a
     * fresh per-password random salt (stored inline as `<algo>$<salt>$<hash>`).
     */
    onHashPassword,

    /**
     * (Optional) MFA enrollment lookup. Default reads `mfaSecret` /
     * `mfaRecoveryCodes` off the user record; accounts without them skip
     * MFA entirely.
     */
    onGetMfaEnrollment: defaultGetMfaEnrollment,

    /**
     * (Optional) Persist recovery-code consumption. Unset by default —
     * recovery-code sign-in is refused until this is wired.
     */
    onConsumeRecoveryCode: undefined as ConsumeRecoveryCodeCallback | undefined,

    /**
     * (Optional) Rate limiter for `/auth/mfa/verify`. `undefined` →
     * in-memory token bucket; `false` → disabled.
     */
    mfaLimiter: undefined as MfaRateLimiter | false | undefined,

    /**
     * (Optional) MFA challenge JWT TTL in seconds. Default 300.
     */
    mfaChallengeTtlSeconds: undefined as number | undefined,
  } as AuthSettings,

  prefix: "/auth",

  /**
   * Middleware that verifies JsonWebTokens.
   * Works with both Express and better-call.
   *
   * Express: sets `req.auth`
   * better-call: decoded JWT payload is available in `ctx.context.auth`
   */
  middleware: JWT.middleware,

  /**
   * Better-call endpoint map. Spread into `createRouter({ ...auth.endpoints(...) })`.
   * Same coverage as `auth.routes()` but no express dependency. Bound below
   * (after the `endpoints.ts` module loads — avoids circular import).
   */
  endpoints: null as unknown as typeof import('./endpoints.ts').endpoints,

  /**
   * Express-compatible auth middleware. Returns the same handler logic as
   * `auth.endpoints()` (the better-call map) wrapped as express middleware,
   * so `app.use(auth.routes())` keeps working. The return value also carries
   * the endpoint map, so it can be spread into `createRouter({ ...auth.routes() })`.
   *
   * This is a thin adapter over `auth.endpoints()` + `dualModeEndpoints` —
   * there is a single source of truth for the handler logic (endpoints.ts).
   */
  routes: function (settings: Partial<AuthSettings> = {}): ExpressMiddleware {
    if (process.env.NODE_ENV !== 'production') {
      // do not warn in production
      console.warn(`
  @colyseus/auth API's are in beta and may change in the future.
  Please give feedback and report any issues you may find at https://github.com/colyseus/colyseus/issues/660
      `);
    }

    // Single source of truth: auth.endpoints() builds the better-call map
    // (login / register / anonymous / forgot / reset / confirm-email + OAuth).
    // It also merges `settings` into auth.settings and wires the OAuth
    // callback, so the legacy per-key copy + onParseToken/onGenerateToken
    // defaulting is no longer needed (auth.settings already carries those
    // defaults). dualModeEndpoints wraps the map as express middleware while
    // keeping it spreadable into createRouter({ ...auth.routes() }).
    const map = auth.endpoints({ settings, prefix: auth.prefix });

    return dualModeEndpoints(map, {
      buildMiddleware: ({ specificRouter, specificHandler }) => (req, res, next) => {
        // Match on originalUrl (the same string better-call's getRequest uses
        // to build the dispatched Request URL) so the match check and the
        // actual dispatch always agree.
        const url = ((req as any).originalUrl ?? req.url ?? '').split('?')[0];
        if (specificRouter.findRoute(req.method ?? 'GET', url)) {
          return specificHandler(req as any, res as any).catch(next);
        }
        next();
      },
    });
  },
};

// Late binding to avoid a circular import — endpoints.ts imports `auth`.
import { endpoints as _endpointsImpl } from './endpoints.ts';
auth.endpoints = _endpointsImpl;
