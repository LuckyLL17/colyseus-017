/**
 * Shared state every admin endpoint needs. Built once in `admin()`
 * and threaded through each endpoint factory so the endpoint files stay
 * pure functions of `(ctx) => Endpoint` — easy to read, easy to test.
 *
 * The `tableOrError`, `pkOrError`, and `guard` helpers live here because
 * they all close over the same fields and are used by 3+ endpoints. Pure
 * helpers that don't need the context (coerce, projection, body-translate,
 * filters, audit-helpers) stay in their own modules at the top of
 * `src-backend/`.
 */
import type { GameDatabase, Action } from '@colyseus/database';
import type { MfaEnrollment } from '@colyseus/auth';
import { type SQL } from 'drizzle-orm';
import type { ResourceDefinition } from '../catalog/define-resource.js';
import type { Logger } from './logger.js';
import { errorResponse } from './http.js';
import { buildPkWhere, type TableConfig } from './helpers.js';
import { clearSessionCookie, readSessionFromHeader } from '../auth/sessions.js';

export interface EndpointContext {
  apiPath: string;
  uiPath: string;
  uiDistDir: string;
  database: GameDatabase;
  /** Index of drizzle tables keyed by canonical name. */
  tables: Record<string, any>;
  /** ResourceDefinition overrides keyed by drizzle table name. */
  resources: Record<string, ResourceDefinition>;
  /** Dialect-aware getTableConfig (sqlite-core or pg-core). */
  getTableConfig: (table: any) => TableConfig;
  /** Identity resolver — reads session cookie or X-User-Id header. */
  resolveUserId: (ctx: { getHeader: (k: string) => string | null }) => Promise<string | undefined> | string | undefined;
  /** When false, every endpoint skips RBAC entirely (dev only). */
  enforceRbac: boolean;
  /** Pino-compatible logger (or null when silenced). */
  logger: Logger | null;
  /**
   * Audit-action tags that require an MFA-verified session (cookie with
   * `mfa: true`). Built from `AdminOptions.mfa.requiredActions`.
   */
  mfaRequiredActions: ReadonlySet<string>;
  /**
   * Live MFA-enrollment lookup for a user id. Returns `null` for accounts
   * without MFA — those keep the legacy (ungated) flow.
   */
  resolveMfaEnrollment: (userId: string) => Promise<MfaEnrollment | null>;
}

/**
 * RBAC gate. Returns `null` when the request is allowed; a `Response` (401
 * or 403) when it should be rejected. Used by every CRUD endpoint as the
 * first thing they do.
 */
export async function guard(
  ctx: EndpointContext,
  reqCtx: any,
  action: Action,
  resource: string,
): Promise<Response | null> {
  if (!ctx.enforceRbac) { return null; }
  const userId = await ctx.resolveUserId({ getHeader: reqCtx.getHeader });
  if (!userId) { return errorResponse(401, 'not authenticated — sign in at /admin/login'); }

  // Per-resource policy override takes precedence
  const policy = ctx.resources[resource]?.policies?.[action];
  if (policy !== undefined) {
    if (policy === 'deny') { return errorResponse(403, `forbidden: ${action} on ${resource}`); }
    if (policy === 'everyone') { return null; }
    const role = await ctx.database.moderation.getRole(userId);
    if (!policy.includes(role)) { return errorResponse(403, `forbidden: ${action} on ${resource}`); }
    return null;
  }

  const ok = await ctx.database.moderation.can(userId, action, resource);
  if (!ok) {
    // Stale-cookie self-heal: cookie says admin, live DB disagrees
    // (roles row wiped or demoted). Clear the cookie and tag the
    // 403 so the frontend can route them back to /login.
    const session = await readSessionFromHeader(reqCtx.getHeader('cookie'));
    if (session?.role === 'admin') {
      ctx.logger?.warn?.(
        { userId, action, resource, cachedRole: session.role },
        '[admin] role mismatch — cookie says admin, live DB disagrees; clearing session',
      );
      return errorResponse(
        403,
        'role_mismatch: your session is stale (DB role no longer admin). Please sign in again.',
        { 'set-cookie': clearSessionCookie() },
      );
    }
    return errorResponse(403, `forbidden: ${action} on ${resource}`);
  }
  return null;
}

/**
 * Operator gate — "is this caller allowed to use the panel at all".
 * Returns `null` when allowed, a `Response` (401/403) when not.
 *
 * Distinct from `guard()`: `guard()` answers "can this user do <action>
 * on <resource>" via the per-resource RBAC matrix. Some surfaces aren't
 * resource-scoped — the catalog (`GET /admin-api`, drives every UI page)
 * and the dashboard (the panel's home screen). Those must be reachable
 * by any operator (admin OR mod, regardless of a mod's collection
 * scopes) but NOT by a plain `user`-role account — the auth table is
 * shared with @colyseus/auth, so a game player with credentials could
 * otherwise log into the panel and read schema + aggregate widgets.
 *
 * `guard()` can't express this for a synthetic resource: its `can()`
 * fallback only admits a mod for collections they're explicitly scoped
 * to, so gating the catalog through `guard()` would 403 every mod and
 * break the whole UI for them.
 */
export async function requireOperator(
  ctx: EndpointContext,
  reqCtx: any,
): Promise<Response | null> {
  if (!ctx.enforceRbac) { return null; }
  const userId = await ctx.resolveUserId({ getHeader: reqCtx.getHeader });
  if (!userId) { return errorResponse(401, 'not authenticated — sign in at /admin/login'); }
  const role = await ctx.database.moderation.getRole(userId);
  if (role === 'user') {
    return errorResponse(403, 'forbidden: the admin panel requires an operator role');
  }
  return null;
}

/**
 * MFA gate for high-risk actions. Returns `null` when the request may
 * proceed; a 403 `mfa_required` Response when the action is configured as
 * MFA-required, the caller's session never completed the MFA challenge,
 * and the operator's account HAS an enrollment (so completing MFA is
 * possible). Accounts without an enrollment — legacy rows — pass through:
 * there is no factor they could present, and un-enrolled accounts must
 * keep their original (password-only) flow.
 *
 * Runs AFTER `guard()` in the endpoint: RBAC decides "may this role do
 * it at all", this gate decides "is this session fresh enough for it".
 * Enrollment is checked live (not cached in the JWT) so enabling MFA
 * takes effect on the very next request — same philosophy as the role
 * check in `guard()`.
 */
export async function mfaActionGate(
  ctx: EndpointContext,
  reqCtx: any,
  action: string,
): Promise<Response | null> {
  if (!ctx.enforceRbac) { return null; }
  if (!ctx.mfaRequiredActions.has(action)) { return null; }

  const session = await readSessionFromHeader(reqCtx.getHeader('cookie'));
  // No cookie session ⇒ the caller authenticated some other way (dev
  // header, custom resolver) where MFA state doesn't exist. guard()
  // already vetted them; don't invent a factor requirement here.
  if (!session) { return null; }
  if (session.mfa === true) { return null; }

  const enrollment = await ctx.resolveMfaEnrollment(session.userId);
  if (!enrollment?.secret) { return null; }

  return errorResponse(
    403,
    'mfa_required: this action requires an MFA-verified session — sign in again and complete the MFA challenge',
  );
}

/** Look up a table + cfg by canonical name, or return a 404 Response. */
export function tableOrError(
  ctx: EndpointContext,
  name: string,
): { table: any; cfg: TableConfig } | Response {
  const table = ctx.tables[name];
  if (!table) { return errorResponse(404, `unknown resource '${name}'`); }
  return { table, cfg: ctx.getTableConfig(table) };
}

/**
 * Map a `buildPkWhere` failure into an HTTP error Response. The decode
 * logic is in helpers.ts and tested standalone; this is the response-shaping
 * adapter.
 */
export function pkOrError(cfg: TableConfig, id: string): { where: SQL } | Response {
  const built = buildPkWhere(cfg, id);
  if (!built.ok) { return errorResponse(built.status, built.message); }
  return { where: built.where };
}
