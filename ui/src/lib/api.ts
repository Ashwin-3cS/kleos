/**
 * The two services this page talks to, and which credential each one takes.
 *
 * The split is the whole security model, so it is worth stating once here rather
 * than at every call site:
 *
 * - **The gateway** verifies owner sessions and grant signatures. Device
 *   registration, revocation and key listing take an owner session in an
 *   `Authorization: Bearer` header. `scope/introspect` takes a grant token and
 *   nothing else -- it is the authoritative reading of what a grant permits.
 * - **The orchestrator** serves memory. Its grant-authorised routes take the
 *   token in the request *body*; its owner-authorised routes take a
 *   `session_token` body field and resolve it by asking the gateway.
 *
 * Nothing here holds a key. Signing is `grants.ts`, key custody is `keys.ts`, and
 * this file only moves bytes.
 *
 * The orchestrator is called through same-origin relative paths because this page
 * is served by it, which is why that service needs no CORS middleware -- the one
 * change most likely to make its owner-authenticated routes reachable from
 * somewhere else. The gateway is called absolutely; it already allows any origin.
 */

import type { Scope } from "./grants";

/** Where the gateway is. Same default as `scripts/run_local.sh`. */
export const GATEWAY =
  (globalThis as { KLEOS_GATEWAY?: string }).KLEOS_GATEWAY ?? "http://127.0.0.1:8080";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly detail: string,
  ) {
    super(detail);
    this.name = "ApiError";
  }
}

async function unwrap<T>(response: Response): Promise<T> {
  const text = await response.text();
  let body: unknown = undefined;
  try {
    body = text ? JSON.parse(text) : undefined;
  } catch {
    body = undefined;
  }
  if (!response.ok) {
    const detail =
      (body as { detail?: string; error?: string } | undefined)?.detail ??
      (body as { error?: string } | undefined)?.error ??
      text ??
      response.statusText;
    throw new ApiError(response.status, detail);
  }
  return body as T;
}

function post<T>(url: string, json: unknown, session?: string): Promise<T> {
  return fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(session ? { authorization: `Bearer ${session}` } : {}),
    },
    body: JSON.stringify(json),
  }).then(unwrap<T>);
}

// -- the gateway -------------------------------------------------------

export interface DeviceKeyView {
  key_id: string;
  label: string;
  registered_at_ms: number;
  revoked_at_ms: number | null;
}

/** Issues an owner session from an identity proof. In mock mode: `mock_google_alice`. */
export function openSession(googleToken: string): Promise<{
  session_token: string;
  identity: { owner_id: string };
}> {
  return post(`${GATEWAY}/auth/session`, { google_token: googleToken });
}

export function authorizeUrl(provider: "google" | "github"): Promise<{
  authorize_url: string;
  state: string;
}> {
  return fetch(`${GATEWAY}/auth/authorize?provider=${provider}`).then(
    unwrap<{ authorize_url: string; state: string }>,
  );
}

/**
 * Completes the OAuth flow.
 *
 * Called with the `code` and `state` this page read off its **own** query string,
 * which is what `GOOGLE_REDIRECT_URI` pointing at `/ui/oauth/land` arranges. The
 * gateway's `/auth/callback` is therefore never loaded as a document: if it were,
 * the browser would land on a JSON page on the gateway's origin and this page
 * could never read the session. See ADR 0023.
 *
 * Single-use by construction -- `PendingAuthStore::take` removes the state -- so
 * a retry after a failure needs a fresh authorize, not a repeated call.
 */
export function completeCallback(
  code: string,
  state: string,
): Promise<{ session_token: string; identity: { owner_id: string } }> {
  const url = new URL(`${GATEWAY}/auth/callback`);
  url.searchParams.set("code", code);
  url.searchParams.set("state", state);
  return fetch(url).then(unwrap<{ session_token: string; identity: { owner_id: string } }>);
}

export function listDeviceKeys(session: string): Promise<DeviceKeyView[]> {
  return fetch(`${GATEWAY}/auth/device/keys`, {
    headers: { authorization: `Bearer ${session}` },
  }).then(unwrap<DeviceKeyView[]>);
}

export function registerDeviceKey(
  session: string,
  publicKeyB64: string,
  label: string,
): Promise<DeviceKeyView> {
  return post(
    `${GATEWAY}/auth/device/register`,
    { public_key_b64: publicKeyB64, label },
    session,
  );
}

export function revokeDeviceKey(
  session: string,
  keyId: string,
): Promise<{ revoked: boolean }> {
  return post(`${GATEWAY}/auth/device/revoke`, { key_id: keyId }, session);
}

/**
 * What a grant actually permits, as the gateway reads it.
 *
 * The only honest preview. It checks the signature, the registration, the
 * revocation and the expiry, and applies the TTL clamp -- so a scope rendered
 * from this is the gateway's reading rather than the UI agreeing with itself.
 */
export function introspectScope(grantToken: string): Promise<{
  active: boolean;
  scope: Scope;
  key_id: string;
}> {
  return post(`${GATEWAY}/memory/scope/introspect`, { grant_token: grantToken });
}

// -- the orchestrator --------------------------------------------------

export interface SessionEntry {
  id: string;
  agent_id: string;
  device_id: string;
  opened_at_ms: number;
  expires_at_ms: number;
  closed_at_ms: number | null;
  block_count: number;
  byte_len: number;
  consolidated_into: string[];
  consolidated_at_ms: number | null;
}

export interface ActionEntry {
  id: string;
  action_id: string;
  agent_id: string;
  device_id: string | null;
  ok: boolean;
  digest: string;
  summary: string;
  error: string | null;
  args_fp: string;
  at_ms: number;
}

export interface MutationEntry {
  id: string;
  object_id: string;
  kind: string;
  field_name: string;
  before: string | null;
  after: string | null;
  reason: string | null;
  rule: string | null;
  actor_agent_id: string | null;
  actor_device_id: string | null;
  at_ms: number;
}

export function listSessions(
  sessionToken: string,
  deviceId?: string,
): Promise<{
  sessions: number;
  undistilled: number;
  entries: SessionEntry[];
}> {
  return post("/memory/sessions", {
    session_token: sessionToken,
    ...(deviceId ? { device_id: deviceId } : {}),
  });
}

export function listActions(
  sessionToken: string,
): Promise<{ actions: number; entries: ActionEntry[] }> {
  return post("/memory/actions", { session_token: sessionToken });
}

export function listMutations(
  sessionToken: string,
): Promise<{ mutations: number; entries: MutationEntry[] }> {
  return post("/memory/mutations", { session_token: sessionToken });
}

export function readLog(sessionToken: string): Promise<Record<string, unknown>> {
  return post("/memory/reads", { session_token: sessionToken });
}

/**
 * Turns one session's blocks into memory.
 *
 * Grant-authorised, not owner-authorised, even though the owner pressed the
 * button: the dashboard signs a short-lived grant with the owner's own key so
 * that one gate decides every claim-producing write and every such write carries
 * a grant fingerprint.
 *
 * **`errors` is where a refusal arrives, not `refused`.** Consolidation declines
 * per conclusion so a grant covering episodes but not procedures keeps the
 * episodes -- which means `refused` stays false even when every conclusion was
 * turned away. A client reading `refused` alone reports a wholly refused run as
 * a success.
 */
export function consolidate(
  grantToken: string,
  sessionId: string,
): Promise<{
  refused: boolean;
  reason?: string;
  blocks?: number;
  claims?: string[];
  conclusions?: { kind: string; statement: string }[];
  errors?: string[];
}> {
  return post("/memory/consolidate", { grant_token: grantToken, session_id: sessionId });
}

export function query(
  grantToken: string,
  question: string,
): Promise<Record<string, unknown>> {
  return post("/query", { grant_token: grantToken, question });
}
